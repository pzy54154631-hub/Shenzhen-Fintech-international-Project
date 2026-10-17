"""Explicit device gestures over privately retained canonical business facts."""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from corridor.agent.dialogue import Candidate, Conversation
from corridor.agent.prover import transfer_triple
from corridor.crypto.jcs import H
from corridor.gateway.preview import PreviewRequest
from corridor.gateway.service import Gateway
from corridor.schemas.bank import ApprovalToken, OperationAuthorization, UserInput
from corridor.schemas.models import Accept, Escalate
from corridor.schemas.state import BankState
from corridor.sim.device import Device
from corridor.sim.keys import stable_id
from corridor.stores.bank import add_seconds


@dataclass
class DeviceDisplay:
    display_id: str
    card: dict


@dataclass
class DeviceConfirmation:
    status: str
    display: DeviceDisplay | None = None
    prepared: Any = None
    token: ApprovalToken | None = None
    rule_ids: list[str] = field(default_factory=list)


@dataclass
class PlanDisplay:
    display_id: str
    cards: dict[str, dict]


@dataclass
class PlanConfirmation:
    status: str
    tokens: dict[str, ApprovalToken] = field(default_factory=dict)
    results: dict[str, Any] = field(default_factory=dict)
    displays: dict[str, DeviceDisplay] = field(default_factory=dict)
    rule_ids: list[str] = field(default_factory=list)
    prepared: dict[str, Any] = field(default_factory=dict)


def business_facts(card: dict) -> dict:
    """Compare every canonical fact except the draft-sensitive dependency digest."""
    return {key: deepcopy(value) for key, value in card.items() if key != "dependency_hash"}


class DeviceWorkflow:
    def __init__(self, device: Device):
        self.device = device
        self._displays: dict[str, dict] = {}
        self._plans: dict[str, dict] = {}
        self._requests: dict[str, tuple[str, Any]] = {}

    def _cache(self, request_id: str, fingerprint: str) -> Any:
        old = self._requests.get(request_id)
        if old is not None:
            if old[0] != fingerprint:
                raise ValueError("Device request ID cannot authorize different facts")
            return deepcopy(old[1])
        return None

    def _save(self, request_id: str, fingerprint: str, result: Any) -> Any:
        self._requests[request_id] = (fingerprint, deepcopy(result))
        return result

    def _display(self, card: dict, **context: Any) -> DeviceDisplay:
        display_id = H({"card": card, "principal": self.device.principal})
        self._displays[display_id] = {"card": deepcopy(card), **context}
        return DeviceDisplay(display_id, deepcopy(card))

    def _draft_transfer(
        self, chat: Conversation, candidate: Candidate, contact_ref: str
    ) -> PreviewRequest:
        if chat.principal != self.device.principal or candidate.status in {"refused", "query"}:
            raise ValueError("Device candidate identity mismatch")
        if (
            not candidate.amount
            or not candidate.source_ref
            or contact_ref not in candidate.contact_refs
        ):
            raise ValueError("An exact contact, source and amount are required")
        inputs = [
            UserInput(
                id=stable_id(candidate.intent_id, 1, f"input-{slot}"),
                principal=self.device.principal,
                batch_id=stable_id(candidate.intent_id, 0, "batch"),
                slot=slot,
                value=value,
                submitted_at=chat.state.now,
                scope_id=candidate.intent_id,
                sig="0" * 128,
            )
            for slot, value in (
                ("amount", {"amount": candidate.amount, "ccy": "CNY"}),
                ("contact_ref", contact_ref),
            )
        ]
        auth = OperationAuthorization(
            id=stable_id(candidate.intent_id, 0, "operation-authorization"),
            principal=self.device.principal,
            intent_id=candidate.intent_id,
            allowed_kind="transfer",
            object_refs=[candidate.source_ref, contact_ref],
            amount_bound=candidate.amount,
            expires_at=add_seconds(chat.state.now, 3600),
            input_hashes=[H(value) for value in inputs],
            sig="0" * 128,
        )
        data = chat.state.model_dump(mode="python")
        data["user_inputs"].update({value.id: value for value in inputs})
        data["authorizations"][auth.id] = auth
        state = BankState.model_validate(data)
        _, action, cert = transfer_triple(
            state=state,
            principal=self.device.principal,
            session_id=chat.session_id,
            intent_id=candidate.intent_id,
            source_ref=candidate.source_ref,
            contact_ref=contact_ref,
            amount_ref=inputs[0].id,
            selection_ref=inputs[1].id,
            authorization_ref=auth.id,
        )
        return PreviewRequest(action, cert, inputs, [auth])

    def show_transfer(
        self, chat: Conversation, candidate: Candidate, *, contact_ref: str | None = None
    ) -> DeviceDisplay:
        if contact_ref is None:
            if len(candidate.contact_refs) != 1:
                raise ValueError("Choose exactly one contact before preview")
            contact_ref = candidate.contact_refs[0]
        request = self._draft_transfer(chat, candidate, contact_ref)
        card = chat.gateway.preview(
            request.action,
            request.cert,
            inputs=request.inputs,
            authorizations=request.authorizations,
        )
        return self._display(
            card,
            candidate=candidate.model_copy(deep=True),
            contact_ref=contact_ref,
            request=deepcopy(request),
            gateway=chat.gateway,
        )

    def confirm_transfer(
        self, chat: Conversation, display_id: str, *, request_id: str
    ) -> DeviceConfirmation:
        fingerprint = H({"operation": "transfer", "display": display_id})
        cached = self._cache(request_id, fingerprint)
        if cached is not None:
            return cached
        stored = self._displays[display_id]
        if stored.get("gateway") is not chat.gateway:
            raise ValueError("Device display gateway mismatch")
        request = stored["request"]
        current = chat.gateway.preview(
            request.action,
            request.cert,
            inputs=request.inputs,
            authorizations=request.authorizations,
        )
        if business_facts(current) != business_facts(stored["card"]):
            result = DeviceConfirmation(
                "redisplay",
                self.show_transfer(chat, stored["candidate"], contact_ref=stored["contact_ref"]),
            )
            return self._save(request_id, fingerprint, result)
        values = [
            self.device.confirm_input(
                intent_id=value.scope_id, slot=value.slot, value=value.value, now=value.submitted_at
            )
            for value in request.inputs
        ]
        auth = self.device.authorize(
            request.authorizations[0].model_dump(mode="python", exclude={"principal", "sig"})
        )
        prepared = chat.prepare(stored["candidate"], values[0], values[1], auth)
        result = self._approve(chat.gateway, prepared, stored["card"], display_id)
        return self._save(request_id, fingerprint, result)

    def show_prepared(self, gateway: Gateway, prepared: Any) -> DeviceDisplay:
        if prepared.action.principal != self.device.principal:
            raise ValueError("Device principal mismatch")
        prepared.proposal = gateway.propose(
            prepared.action, prepared.cert, request_id=prepared.action.intent_id
        )
        return self._display(
            prepared.proposal.card,
            prepared=prepared,
            action_hash=H(prepared.action),
            gateway=gateway,
        )

    def _approve(
        self, gateway: Gateway, prepared: Any, expected: dict, display_id: str
    ) -> DeviceConfirmation:
        if business_facts(prepared.proposal.card) != business_facts(expected):
            # Even the replacement must come directly from the trusted renderer;
            # a caller may have modified the supplied proposal after preparation.
            prepared.proposal = gateway.propose(
                prepared.action, prepared.cert, request_id=prepared.action.intent_id
            )
            return DeviceConfirmation(
                "redisplay",
                self._display(
                    prepared.proposal.card,
                    prepared=prepared,
                    action_hash=H(prepared.action),
                    gateway=gateway,
                ),
                prepared,
            )
        proposal = gateway.propose(
            prepared.action, prepared.cert, request_id=prepared.action.intent_id
        )
        prepared.proposal = proposal
        display = DeviceDisplay(display_id, deepcopy(expected))
        if business_facts(proposal.card) != business_facts(expected):
            return DeviceConfirmation(
                "redisplay",
                self._display(
                    proposal.card,
                    prepared=prepared,
                    action_hash=H(prepared.action),
                    gateway=gateway,
                ),
                prepared,
            )
        verdict = proposal.verdict
        rules = list(getattr(verdict, "rule_ids", []))
        if isinstance(verdict, Escalate):
            return DeviceConfirmation("waiting_mfa", display, prepared, rule_ids=rules)
        if not isinstance(verdict, Accept):
            return DeviceConfirmation("rejected", display, prepared, rule_ids=rules)
        if verdict.tier == "green":
            return DeviceConfirmation("approved", display, prepared)
        state = gateway.store.snapshot()
        if any(ref in state.security.consumed_grant_ids for ref in prepared.cert.mfa_grant_refs):
            return DeviceConfirmation("rejected", display, prepared, rule_ids=["MFA-REUSE"])
        epoch = prepared.plan.ownership_epoch
        token = self.device.approve(
            prepared.action, prepared.cert, proposal.card, now=state.now, ownership_epoch=epoch
        )
        return DeviceConfirmation("approved", display, prepared, token)

    def confirm_prepared(
        self, gateway: Gateway, display_id: str, *, request_id: str, prepared: Any = None
    ) -> DeviceConfirmation:
        fingerprint = H({"operation": "prepared", "display": display_id})
        cached = self._cache(request_id, fingerprint)
        if cached is not None:
            return cached
        stored = self._displays[display_id]
        prepared = prepared if prepared is not None else stored["prepared"]
        if stored.get("gateway") is not gateway or H(prepared.action) != stored["action_hash"]:
            raise ValueError("Device display context changed")
        result = self._approve(gateway, prepared, stored["card"], display_id)
        return self._save(request_id, fingerprint, result)

    def confirm_selected(
        self,
        gateway: Gateway,
        displays: dict[str, DeviceDisplay],
        selected_nodes: list[str],
        *,
        request_id: str,
    ) -> PlanConfirmation:
        fingerprint = H({
            "operation": "selected",
            "nodes": selected_nodes,
            "displays": {node: display.display_id for node, display in displays.items()},
        })
        cached = self._cache(request_id, fingerprint)
        if cached is not None:
            return cached
        if (
            len(set(selected_nodes)) != len(selected_nodes)
            or not set(selected_nodes) <= displays.keys()
        ):
            raise ValueError("Unknown or duplicate selected node")
        result = PlanConfirmation("approved")
        for node in selected_nodes:
            display = displays[node]
            approved = self.confirm_prepared(
                gateway, display.display_id, request_id=f"{request_id}:{node}"
            )
            result.displays[node] = approved.display
            result.prepared[node] = approved.prepared
            if approved.token:
                result.tokens[node] = approved.token
            if approved.status != "approved":
                result.status, result.rule_ids = approved.status, approved.rule_ids
                break
        return self._save(request_id, fingerprint, result)

    def show_plan(
        self,
        gateway: Gateway,
        requests: list[PreviewRequest],
        preparers: dict[str, Callable[[], Any]],
    ) -> PlanDisplay:
        if any(request.action.principal != self.device.principal for request in requests):
            raise ValueError("Device plan principal mismatch")
        nodes = [request.action.node_id for request in requests]
        if set(nodes) != preparers.keys():
            raise ValueError("Every displayed selected node needs one preparer")
        requests = deepcopy(requests)
        cards = gateway.preview_sequence(requests)
        display_id = H({"cards": cards, "nodes": nodes, "principal": self.device.principal})
        self._plans[display_id] = {
            "requests": requests,
            "cards": deepcopy(cards),
            "nodes": nodes,
            "preparers": dict(preparers),
            "gateway": gateway,
        }
        return PlanDisplay(display_id, deepcopy(cards))

    def confirm_plan(
        self, gateway: Gateway, display_id: str, selected_nodes: list[str], *, request_id: str
    ) -> PlanConfirmation:
        fingerprint = H({"operation": "plan", "display": display_id, "selected": selected_nodes})
        cached = self._cache(request_id, fingerprint)
        if cached is not None:
            return cached
        stored = self._plans[display_id]
        if stored["gateway"] is not gateway:
            raise ValueError("Device plan gateway mismatch")
        result = PlanConfirmation("approved")
        if selected_nodes != stored["nodes"]:
            result.status = "redisplay"
            return self._save(request_id, fingerprint, result)
        current = gateway.preview_sequence(stored["requests"])
        if any(
            business_facts(current[node]) != business_facts(stored["cards"][node])
            for node in selected_nodes
        ):
            result.status = "redisplay"
            result.displays = {node: self._display(card) for node, card in current.items()}
            return self._save(request_id, fingerprint, result)
        for node in selected_nodes:
            prepared = stored["preparers"][node]()
            approved = self._approve(gateway, prepared, stored["cards"][node], display_id)
            result.displays[node], result.prepared[node] = approved.display, prepared
            if approved.status != "approved":
                result.status, result.rule_ids = approved.status, approved.rule_ids
                break
            if approved.token is not None:
                result.tokens[node] = approved.token
            dispatched = gateway.dispatch(prepared.action, prepared.cert, approved.token)
            result.results[node] = dispatched
            if dispatched.status not in {
                "settled",
                "accepted",
                "created",
                "completed",
                "controlled",
            }:
                result.status, result.rule_ids = dispatched.status, dispatched.rule_ids
                break
        return self._save(request_id, fingerprint, result)
