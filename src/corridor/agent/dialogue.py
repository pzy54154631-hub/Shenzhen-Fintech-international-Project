"""Conversation candidates and bounded planning without device signing authority."""

from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from pydantic import Field

from corridor.agent.extractor import (
    ExtractedIntent,
    amount_candidate,
    extract_intent,
    injection_detected,
)
from corridor.agent.llm import LLMClient
from corridor.agent.prover import transfer_triple
from corridor.agent.scripted_planner import ScriptedPlanner, TransferProposal
from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, verify
from corridor.gateway.handles import available_handles
from corridor.gateway.service import Gateway, GatewayResult, Proposal
from corridor.kernel.binding import dependency_hashes
from corridor.schemas.bank import (
    ApprovalToken,
    AuthorizationRevocation,
    BankAction,
    BankCertificate,
    OperationAuthorization,
    Plan,
    PlanNode,
    SessionAuthorization,
    StateTerm,
    UserInput,
)
from corridor.schemas.base import Model
from corridor.schemas.models import Identifier
from corridor.schemas.narrative import FactRef, Narrative
from corridor.schemas.state import BankState
from corridor.sim.keys import stable_id

T = TypeVar("T", bound=Model)


class ReceiptFactHandle(Model):
    """Reference selection cannot supply a model-authored economic assertion."""

    receipt_ref: Identifier
    field: Identifier


class ReceiptNarrative(Model):
    """Receipt prose comes exclusively from the gateway's authenticated templates."""

    fact_refs: list[ReceiptFactHandle] = Field(default_factory=list, max_length=32)
    note: Literal[""] = ""


class Candidate(Model):
    intent_id: str
    status: Literal["awaiting_input", "clarify", "refused", "query"]
    contact_refs: list[str] = Field(default_factory=list)
    amount: str | None = None
    source_ref: str | None = None
    injection_flag: bool = False
    reasons: list[str] = Field(default_factory=list)


@dataclass
class PreparedTransfer:
    plan: Plan
    action: BankAction
    cert: BankCertificate
    proposal: Proposal


class Conversation:
    def __init__(
        self,
        gateway: Gateway,
        client: LLMClient,
        *,
        principal: str,
        session_id: str,
        task_id: str = "CHAT",
    ) -> None:
        self.gateway, self.client = gateway, client
        self.principal, self.session_id, self.task_id = principal, session_id, task_id
        self._requests: dict[str, tuple[str, Candidate]] = {}
        self._candidates: dict[str, Candidate] = {}
        self._prepared: dict[str, PreparedTransfer] = {}
        self._previous_contact: str | None = None
        self._previous_amount: str | None = None
        self._counter = 0

    @property
    def state(self) -> BankState:
        return self.gateway.store.snapshot()

    def _validated(
        self,
        schema: type[T],
        *,
        step: str,
        prompt: dict[str, Any],
        tool_state: dict[str, Any],
        scripted: Any,
    ) -> T:
        for repair in range(3):
            request = {**prompt, "response_schema": schema.model_json_schema(), "repair": repair}
            if repair:
                request["repair_instruction"] = (
                    "Return only the declared schema and allowed handles."
                )
            self.gateway.vault.ensure_safe(request)
            self.gateway.vault.ensure_safe(tool_state)
            result = self.client.complete(
                task_id=self.task_id,
                step=f"{step}:{repair}",
                prompt=request,
                tool_state=tool_state,
                scripted=scripted,
            )
            try:
                self.gateway.vault.ensure_safe(result.output)
                return schema.model_validate(result.output)
            except ValueError:
                if repair == 2:
                    raise ValueError("Planner repair limit reached") from None
        raise AssertionError("Unreachable repair loop")

    def receive(
        self,
        text: str,
        *,
        request_id: str,
        external_texts: list[str] | None = None,
    ) -> Candidate:
        digest = self.gateway.utterance_digest(text, external_texts)
        if request_id in self._requests:
            old_hash, candidate = self._requests[request_id]
            if old_hash != digest:
                raise ValueError("Request ID cannot replace an existing utterance")
            return candidate
        self._counter += 1
        intent_id = stable_id(f"{self.task_id}:{self.session_id}", self._counter, "intent")
        state = self.state
        if state.security.active_device_sessions.get(self.principal) != self.session_id:
            self._previous_contact = self._previous_amount = None
            return Candidate(intent_id=intent_id, status="clarify", reasons=["Login required"])
        if extract_intent(text, {}).kind == "refuse":
            candidate = Candidate(
                intent_id=intent_id, status="refused", reasons=["TIER-BLACK-KIND"]
            )
            self.gateway.audit.append(
                "user_utterance_refused",
                now=state.now,
                principal_token=self.principal,
                payload={"utterance_hash": digest, "intent_id": intent_id},
            )
            self._requests[request_id] = (digest, candidate)
            self._candidates[intent_id] = candidate
            return candidate
        safe_text = self.gateway.vault.tokenize(text)
        self.gateway.vault.ensure_safe(safe_text)
        views = available_handles(state, self.principal, self.session_id)
        labels = {
            view.id: [
                value for value in [view.name_token, view.phone_token, *view.aliases] if value
            ]
            for view in views
            if view.kind == "contact" and view.verified
        }
        sources = [
            view.id for view in views if view.kind == "account" and view.account_kind == "current"
        ]
        # External text never enters a prompt or contact index; only this boolean leaves quarantine.
        flag = injection_detected(external_texts or [])
        lexical = extract_intent(safe_text, labels, self._previous_contact)
        output = self._validated(
            ExtractedIntent,
            step=f"extract:{self._counter}",
            prompt={
                "instruction": "Classify the request and return candidate contact handles only.",
                "user_text": safe_text,
            },
            tool_state={"contacts": labels, "previous_contact": self._previous_contact},
            scripted=lambda: extract_intent(safe_text, labels, self._previous_contact).model_dump(
                mode="json"
            ),
        )
        if (
            any(ref not in labels for ref in output.contact_refs)
            or sorted(set(output.contact_refs)) != lexical.contact_refs
        ):
            output = ExtractedIntent(kind="clarify")
        contacts = sorted(set(output.contact_refs))
        amount = amount_candidate(safe_text, self._previous_amount)
        status: Literal["awaiting_input", "clarify", "refused", "query"] = "clarify"
        if output.kind == "refuse":
            status = "refused"
        elif output.kind == "balance_query":
            status = "query"
        elif output.kind == "transfer" and len(contacts) == 1 and amount and len(sources) == 1:
            status = "awaiting_input"
        candidate = Candidate(
            intent_id=intent_id,
            status=status,
            contact_refs=contacts,
            amount=amount,
            source_ref=sources[0] if len(sources) == 1 else None,
            injection_flag=flag,
            reasons=[] if status != "clarify" else ["Confirm an exact contact and amount"],
        )
        self.gateway.audit.append(
            "user_utterance",
            now=state.now,
            principal_token=self.principal,
            payload={"utterance_hash": digest, "intent_id": intent_id},
        )
        self._requests[request_id] = (digest, candidate)
        self._candidates[intent_id] = candidate
        return candidate

    def prepare(
        self,
        candidate: Candidate,
        amount_input: UserInput,
        selection_input: UserInput,
        authorization: OperationAuthorization,
    ) -> PreparedTransfer:
        original = self._candidates.get(candidate.intent_id)
        if original != candidate or candidate.status in {"refused", "query"}:
            raise ValueError("Unrecognized transfer candidate")
        if candidate.intent_id in self._prepared:
            return self._prepared[candidate.intent_id]
        contact_ref = selection_input.value
        if (
            not isinstance(contact_ref, str)
            or contact_ref not in candidate.contact_refs
            or selection_input.slot != "contact_ref"
            or amount_input.slot != "amount"
            or selection_input.scope_id != candidate.intent_id
            or amount_input.scope_id != candidate.intent_id
            or amount_input.value != {"amount": candidate.amount, "ccy": "CNY"}
            or candidate.source_ref is None
            or candidate.amount is None
        ):
            raise ValueError("Clarification or signed input mismatch")
        for item in (amount_input, selection_input):
            if self.gateway.submit_input(item).status != "accepted":
                raise ValueError("Device input rejected")
        if self.gateway.submit_authorization(authorization).status != "accepted":
            raise ValueError("Device authorization rejected")
        scripted = ScriptedPlanner().transfer(candidate.source_ref, contact_ref, amount_input.id)
        proposal = self._validated(
            TransferProposal,
            step=f"plan:{candidate.intent_id}",
            prompt={
                "instruction": "Propose one transfer using only these signed input/state handles."
            },
            tool_state=scripted.model_dump(mode="json"),
            scripted=lambda: scripted.model_dump(mode="json"),
        )
        if proposal != scripted:
            raise ValueError("Planner attempted to change signed handles")
        plan, action, cert = transfer_triple(
            state=self.state,
            principal=self.principal,
            session_id=self.session_id,
            intent_id=candidate.intent_id,
            source_ref=proposal.source.ref,
            contact_ref=proposal.contact.ref,
            amount_ref=proposal.amount.ref,
            selection_ref=selection_input.id,
            authorization_ref=authorization.id,
        )
        if self.gateway.submit_plan(plan).status != "registered":
            raise ValueError("Plan rejected")
        canonical = self.gateway.propose(
            action,
            cert,
            request_id=candidate.intent_id,
            injection_flag=candidate.injection_flag,
        )
        prepared = PreparedTransfer(plan, action, cert, canonical)
        self._prepared[candidate.intent_id] = prepared
        if canonical.verdict.outcome != "Reject":
            self._previous_contact, self._previous_amount = contact_ref, candidate.amount
        return prepared

    def dispatch(self, prepared: PreparedTransfer, token: ApprovalToken | None) -> GatewayResult:
        return self.gateway.dispatch(prepared.action, prepared.cert, token)

    def query_balance(self) -> GatewayResult:
        state = self.state
        refs = available_handles(state, self.principal, self.session_id)
        accounts = [
            item.id for item in refs if item.kind == "account" and item.account_kind == "current"
        ]
        revoked = {
            item.authorization_ref
            for item in state.authorizations.values()
            if isinstance(item, AuthorizationRevocation) and item.revoked_at <= state.now
        }
        auths = [
            item
            for item in state.authorizations.values()
            if isinstance(item, SessionAuthorization)
            and item.principal == self.principal
            and item.device_session_id == self.session_id
            and item.expires_at > state.now
            and item.id not in revoked
            and "balance_query" in item.read_kinds
            and verify(state.customers[self.principal].device_pubkey, CONTROL, item, item.sig)
        ]
        if len(accounts) != 1 or not auths:
            raise ValueError("READ-ROLE")
        self._counter += 1
        intent = stable_id(f"{self.task_id}:{self.session_id}", self._counter, "query")
        term = StateTerm(
            collection="accounts",
            object_ref=accounts[0],
            field="id",
            version=state.accounts[accounts[0]].version,
        )
        node = PlanNode(
            node_id=stable_id(intent, 0, "node"), tool="balance_query", args={"account_ref": term}
        )
        plan = Plan(
            plan_id=stable_id(intent, 0, "plan"),
            revision=1,
            principal=self.principal,
            device_session_id=self.session_id,
            intent_id=intent,
            goal_input_refs=[],
            nodes=[node],
            ownership_epoch=0,
        )
        action = BankAction(
            action_id=stable_id(intent, 0, "action"),
            intent_id=intent,
            principal=self.principal,
            device_session_id=self.session_id,
            plan_id=plan.plan_id,
            plan_hash=H(plan),
            node_id=node.node_id,
            kind="balance_query",
            args={"account_ref": accounts[0]},
        )
        cert = BankCertificate(
            action_hash=H(action),
            authorization_ref=auths[-1].id,
            derivations={"args.account_ref": term},
            dependency_hashes={},
        )
        cert = cert.model_copy(update={"dependency_hashes": dependency_hashes(action, cert, state)})
        if self.gateway.submit_plan(plan).status != "registered":
            raise ValueError("Query plan rejected")
        return self.gateway.query(action, cert)

    def narrative(self, receipt_ref: str) -> Any:
        narrative = self._validated(
            ReceiptNarrative,
            step=f"narrative:{receipt_ref}",
            prompt={
                "instruction": (
                    "Reference the verified receipt status, amount and resulting balance. "
                    "The note must be the empty string. Return fact references only; "
                    "the gateway renders the verified receipt facts. Select receipt_ref and "
                    "field only; do not supply expected values."
                )
            },
            tool_state={
                "receipt_ref": receipt_ref,
                "fields": ["status", "amount", "balance_after"],
            },
            scripted=lambda: {
                "fact_refs": [
                    {"receipt_ref": receipt_ref, "field": name}
                    for name in ("status", "amount", "balance_after")
                ],
                "note": "",
            },
        )
        if any(ref.receipt_ref != receipt_ref for ref in narrative.fact_refs):
            raise ValueError("RCPT-MISMATCH: Narrative changed the requested receipt")
        return self.gateway.render_narrative(
            Narrative(
                fact_refs=[
                    FactRef(receipt_ref=ref.receipt_ref, field=ref.field)
                    for ref in narrative.fact_refs
                ],
                note=narrative.note,
            ),
            self.principal,
        )
