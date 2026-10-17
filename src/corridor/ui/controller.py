"""One isolated CCA demo session and explicit device-gesture orchestration.

Unsigned previews use separate temporary state. Only confirmation callbacks can
produce input/operation/SPA signatures; every effect goes through the gateway.
"""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

from corridor.agent.dialogue import Conversation
from corridor.agent.llm import LLMClient
from corridor.bench.bank_cases import BankCase
from corridor.bench.billing_runner import prepare_analysis
from corridor.bench.investment_runner import prepare_investment, prepare_redemption
from corridor.bench.planning_runner import birthday_prepared, prepare_birthday, prepare_funds
from corridor.crypto.jcs import H
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.privacy import PIIVault
from corridor.gateway.runtime import create_gateway
from corridor.gateway.service import GatewayResult, Proposal
from corridor.kernel.binding import dependency_hashes
from corridor.kernel.check import check
from corridor.kernel.investment import evaluate_investment
from corridor.schemas.bank import (
    CardChangeRequest,
    InputTerm,
    OperationAuthorization,
    ScheduledPaymentAuthorization,
    StateTerm,
    UserInput,
)
from corridor.schemas.domain import MarketingMetadata
from corridor.schemas.money import fraction_string
from corridor.schemas.narrative import FactRef, Narrative
from corridor.sim.billing import report_state, subscription_state
from corridor.sim.device import Device
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key, stable_id
from corridor.stores.bank import BankStore, add_seconds, available


def demo_state():
    state, bills, subscriptions = make_state(), report_state(), subscription_state()
    return state.model_copy(
        update={
            "transactions": {**bills.transactions, **subscriptions.transactions},
            "merchants": {**state.merchants, **bills.merchants, **subscriptions.merchants},
            "subscriptions": subscriptions.subscriptions,
        }
    )


class _UnsignedDevice:
    """Build exact wire bodies with an unmistakably invalid signature; never sign."""

    principal = "C_DEMO"

    def confirm_input(self, *, intent_id, slot, value, now, step=1, supersedes=None):
        return UserInput.model_validate({
            "id": stable_id(intent_id, step, f"input-{slot}"),
            "principal": self.principal,
            "batch_id": stable_id(intent_id, 0, "batch"),
            "slot": slot,
            "value": value,
            "submitted_at": now,
            "scope_id": intent_id,
            "supersedes": supersedes,
            "sig": "0" * 128,
        })

    def authorize(self, body):
        return OperationAuthorization.model_validate({
            **body,
            "principal": self.principal,
            "sig": "0" * 128,
        })

    def sign_spa(self, body):
        return ScheduledPaymentAuthorization.model_validate({
            **body,
            "principal": self.principal,
            "sig": "0" * 128,
        })


class _DraftGateway:
    """Collect draft inputs in an isolated snapshot, never in the live store."""

    def __init__(self, gateway):
        self.live = gateway
        self.store = BankStore(gateway.store.snapshot())
        self.inputs: list[UserInput] = []
        self.authorizations = []
        self.plans = []

    def submit_input(self, item):
        self.inputs.append(item)
        self.store.update(user_inputs={**self.store.snapshot().user_inputs, item.id: item})
        return GatewayResult("accepted")

    def submit_authorization(self, item):
        self.authorizations.append(item)
        self.store.update(authorizations={**self.store.snapshot().authorizations, item.id: item})
        return GatewayResult("accepted")

    def submit_plan(self, plan):
        self.plans.append(plan)
        return GatewayResult("registered")

    def propose(self, action, cert):
        card = self.live.preview(
            action, cert, inputs=self.inputs, authorizations=self.authorizations
        )
        # This remains an actual rejecting verdict for unsigned drafts. Its card
        # comes from the separate preview API, never from a fabricated Accept.
        verdict = check(action, cert, self.store.snapshot(), phase="propose")
        return Proposal(verdict, card, H(action), H(cert))


class _BuilderGateway:
    """Retain a stable prompt identity across builder, display and MFA rechecks."""

    def __init__(self, gateway):
        self.live = gateway

    def __getattr__(self, name):
        return getattr(self.live, name)

    def propose(self, action, cert):
        return self.live.propose(action, cert, request_id=action.intent_id)


class _Builder(BankCase):
    def __init__(self, controller, request_id, *, draft=False):
        self.task_id, self.subcase_id = "DEMO", request_id
        self.identity = f"DEMO:{request_id}"
        self.gateway = (
            _DraftGateway(controller.gateway) if draft else _BuilderGateway(controller.gateway)
        )
        self.device = _UnsignedDevice() if draft else controller.device
        self.session = controller.session
        self.session_authorization = controller.session_authorization
        self.initial = self.state
        self.preparations = []
        self.evidence_dir = None


class DemoController:
    def __init__(self, *, evidence_dir: Path | None = None, initial_state=None, device=None):
        self.device = device or Device()
        self.session = stable_id("DEMO", 0, "device-session")
        self.gateway = create_gateway(
            BankStore(initial_state if initial_state is not None else demo_state()),
            bank_key=signing_key("bank"),
            gateway_key=signing_key("gateway"),
            risk_key=signing_key("risk"),
            mfa=MFAVerifier(signing_key("mfa")),
            vault=PIIVault({
                "NAME_CHEN": "Chen",
                "NAME_LIN": "Lin",
                "NAME_NEW": "New",
                "PHONE_CHEN": "13900001001",
                "PHONE_LIN_A": "13900001002",
                "PHONE_LIN_B": "13900001003",
                "PHONE_NEW": "13900001004",
            }),
            evidence_dir=evidence_dir,
        )
        self.client = LLMClient(
            mode="scripted", env_file=None, context_guard=self.gateway.vault.ensure_safe
        )
        self.chat = Conversation(
            self.gateway,
            self.client,
            principal=self.device.principal,
            session_id=self.session,
            task_id="DEMO",
        )
        self.session_authorization = None
        self.workflow = None
        self._counter = 0
        self._drafts: dict[str, dict[str, Any]] = {}
        self._pending: dict[str, dict[str, Any]] = {}
        self._plans: dict[str, dict[str, Any]] = {}
        self._results: dict[str, dict[str, Any]] = {}
        self._requests: dict[str, Any] = {}
        self._request_facts: dict[str, str] = {}
        self._last_comparison: dict[str, Any] | None = None
        self._comparison_action = None
        self._objective = "net_return"

    @property
    def state(self):
        return self.gateway.store.snapshot()

    def _id(self, kind):
        self._counter += 1
        return stable_id("DEMO", self._counter, kind)

    def _require_login(self):
        if (
            self.session_authorization is None
            or self.session_authorization.expires_at <= self.state.now
        ):
            raise ValueError("Enter the simulated bank and confirm device login first.")

    def _claim_request(self, request_id, facts):
        digest = H(facts)
        if request_id in self._request_facts and self._request_facts[request_id] != digest:
            raise ValueError("Request ID cannot replace previously displayed facts")
        self._request_facts[request_id] = digest

    def start_session(self):
        from corridor.sim.device_workflow import DeviceWorkflow

        if (
            self.session_authorization is not None
            and self.session_authorization.expires_at > self.state.now
        ):
            return {"status": "ready", "planner_mode": "scripted"}
        if self.session_authorization is not None:
            self.session = self._id("device-session")
            self.chat = Conversation(
                self.gateway,
                self.client,
                principal=self.device.principal,
                session_id=self.session,
                task_id="DEMO",
            )
            self._pending.clear()
            self._drafts.clear()
            self._requests.clear()
            self._request_facts.clear()
        self.session_authorization = self.device.login(
            session_id=self.session,
            expires_at=add_seconds(self.state.now, 3600),
        )
        result = self.gateway.login(self.session_authorization)
        self.workflow = DeviceWorkflow(self.device)
        return {
            "status": "ready" if result.status == "accepted" else result.status,
            "rule_ids": result.rule_ids,
            "planner_mode": "scripted",
        }

    def _result(self, result):
        receipt = result.receipt.model_dump(mode="json") if result.receipt else None
        analysis = (
            result.analysis_receipt.model_dump(mode="json") if result.analysis_receipt else None
        )
        data = {
            "status": result.status,
            "rule_ids": list(result.rule_ids),
            "receipt": receipt,
            "analysis_receipt": analysis,
            "details": deepcopy(result.details),
            "audit_checkpoint": self.gateway.audit.checkpoint(),
        }
        if result.analysis_receipt:
            refs = [
                FactRef(receipt_ref=result.analysis_receipt.id, field=field)
                for field in result.analysis_receipt.results
            ]
            data["facts"] = self.gateway.render_narrative(
                Narrative(fact_refs=refs), self.device.principal
            ).model_dump(mode="json")
            fields = result.analysis_receipt.results
            if "cancellable_authorizations" in fields:
                data["cancellable"] = list(fields["cancellable_authorizations"].value)
                data["subscriptions"] = [
                    self.state.subscriptions[ref].model_dump(mode="json")
                    for ref in data["cancellable"]
                    if ref in self.state.subscriptions
                ]
                data["items"] = deepcopy(data["subscriptions"])
        elif result.receipt and result.receipt.kind in {
            "transfer",
            "balance_query",
            "purchase_product",
            "redeem_product",
        }:
            fields = ["status", "balance_after"]
            if result.receipt.kind != "balance_query":
                fields.append("amount")
            data["facts"] = self.gateway.render_narrative(
                Narrative(
                    fact_refs=[
                        FactRef(receipt_ref=result.receipt.id, field=field) for field in fields
                    ]
                ),
                self.device.principal,
            ).model_dump(mode="json")
        return data

    def preview_transfer(self, text, *, request_id):
        self._require_login()
        self._claim_request(request_id, {"kind": "transfer", "text_hash": H(text)})
        if request_id in self._requests:
            return deepcopy(self._requests[request_id])
        candidate = self.chat.receive(text, request_id=request_id)
        draft_id = candidate.intent_id
        data = {
            "draft_id": draft_id,
            "status": candidate.status,
            "contacts": candidate.contact_refs,
            "card": {},
            "canonical": True,
            "reasons": candidate.reasons,
        }
        self._drafts[draft_id] = {"candidate": candidate, "request_id": request_id}
        if candidate.status == "awaiting_input":
            display = self.workflow.show_transfer(self.chat, candidate)
            self._drafts[draft_id]["display"] = display
            data["card"] = deepcopy(display.card)
        self._requests[request_id] = deepcopy(data)
        return data

    def select_contact(self, draft_id, contact_ref):
        draft = self._drafts[draft_id]
        candidate = draft["candidate"]
        if contact_ref not in candidate.contact_refs:
            raise ValueError("The recipient is not in the verified candidate set.")
        display = self.workflow.show_transfer(self.chat, candidate, contact_ref=contact_ref)
        draft["display"] = display
        return {
            "draft_id": draft_id,
            "status": "awaiting_input",
            "contacts": candidate.contact_refs,
            "card": deepcopy(display.card),
            "canonical": True,
        }

    def confirm_transfer(self, draft_id, contact_ref=None, *, request_id=None):
        self._require_login()
        if draft_id in self._results:
            return deepcopy(self._results[draft_id])
        if contact_ref:
            self.select_contact(draft_id, contact_ref)
        draft = self._drafts[draft_id]
        if "display" not in draft:
            return {"status": "clarify", "rule_ids": ["PROV-AMBIGUOUS"]}
        confirmed = self.workflow.confirm_transfer(
            self.chat,
            draft["display"].display_id,
            request_id=f"{request_id or draft_id}:{draft['display'].display_id}",
        )
        if confirmed.status == "approved":
            result = self._result(
                self.gateway.dispatch(
                    confirmed.prepared.action, confirmed.prepared.cert, confirmed.token
                )
            )
            self._results[draft_id] = result
            return deepcopy(result)
        if confirmed.status == "waiting_mfa":
            if draft_id in self._pending:
                pending = self._pending[draft_id]
                return {
                    "status": "awaiting_approval" if pending["verified"] else "waiting_mfa",
                    "pending_id": draft_id,
                    "card": deepcopy(pending["display"].card),
                    "canonical": True,
                }
            return self._store_prepared(confirmed.prepared, pending_id=draft_id)
        if confirmed.status == "redisplay" and confirmed.display is not None:
            if confirmed.prepared is not None:
                data = self._store_prepared(confirmed.prepared, pending_id=draft_id)
                self._pending[draft_id]["display"] = confirmed.display
                return {**data, "status": "redisplay"}
            draft["display"] = confirmed.display
        return {
            "draft_id": draft_id,
            "status": confirmed.status,
            "rule_ids": confirmed.rule_ids,
            "card": deepcopy(confirmed.display.card) if confirmed.display else {},
            "contacts": draft["candidate"].contact_refs,
            "canonical": True,
        }

    def query_balance(self):
        self._require_login()
        return self._result(self.chat.query_balance())

    def bill_report(self, period="2026-09"):
        self._require_login()
        builder = _Builder(self, self._id("report"))
        prepared = prepare_analysis(builder, "bill_report", period=period)
        return self._result(self.gateway.query(prepared.action, prepared.cert))

    def _preview_operation(self, factory: Callable, *, request_id):
        from corridor.gateway.preview import PreviewRequest

        if request_id in self._requests:
            return deepcopy(self._requests[request_id])
        draft = _Builder(self, request_id, draft=True)
        prepared = factory(draft)
        request = PreviewRequest(
            prepared.action,
            prepared.cert,
            inputs=draft.gateway.inputs,
            authorizations=draft.gateway.authorizations,
        )
        live = _Builder(self, request_id)
        display = self.workflow.show_plan(
            self.gateway, [request], {prepared.action.node_id: lambda: factory(live)}
        )
        pending_id = request_id
        self._pending[pending_id] = {
            "mode": "draft",
            "display": display,
            "node_id": prepared.action.node_id,
            "factory": factory,
        }
        data = {
            "pending_id": pending_id,
            "status": "awaiting_approval",
            "canonical": True,
            "card": deepcopy(display.cards[prepared.action.node_id]),
        }
        self._requests[request_id] = deepcopy(data)
        return data

    def preview_subscriptions(self, *, request_id=None):
        self._require_login()
        request_id = request_id or self._id("subscriptions")
        self._claim_request(request_id, {"kind": "subscription_query", "period": "2026"})
        return self._preview_operation(
            lambda builder: prepare_analysis(builder, "subscription_query", period="2026"),
            request_id=request_id,
        )

    def cancel_subscription(self, ref, *, request_id):
        self._require_login()
        self._claim_request(request_id, {"kind": "cancel_subscription", "ref": ref})
        if ref not in self.state.subscriptions:
            raise ValueError("No cancellable debit authorization is available.")

        def build(builder):
            item = builder.device.confirm_input(
                intent_id=builder.intent(), slot="subscription", value=ref, now=builder.state.now
            )
            authorization = builder.operation("cancel_subscription", [ref], [item])
            term = StateTerm(
                collection="subscriptions",
                object_ref=ref,
                field="id",
                version=builder.state.subscriptions[ref].version,
            )
            return builder.prepare(
                "cancel_subscription",
                {"authorization_ref": ref},
                {"authorization_ref": term},
                inputs=[item],
                authorization=authorization,
            )

        return self._preview_operation(build, request_id=request_id)

    def _store_prepared(self, prepared, *, pending_id=None):
        pending_id = pending_id or prepared.action.action_id
        display = self.workflow.show_prepared(self.gateway, prepared)
        self._pending[pending_id] = {
            "mode": "prepared",
            "prepared": prepared,
            "display": display,
            "challenge_id": None,
            "verified": False,
        }
        return {
            "pending_id": pending_id,
            "status": "waiting_mfa"
            if prepared.proposal.verdict.tier == "red"
            else "awaiting_approval",
            "card": deepcopy(display.card),
            "canonical": True,
        }

    def preview_card_operation(
        self, kind, *, card_ref=None, change=None, account_ref="A_CURRENT", request_id=None
    ):
        """Display unsigned card facts; only the later device gesture signs them."""
        self._require_login()
        state_changes = {
            "freeze_card": "frozen",
            "unfreeze_card": "active",
            "report_card_lost": "lost",
            "restore_card": "frozen",
        }
        changes = {
            "lower_card_limit",
            "raise_card_limit",
            "restrict_card",
            "relax_card_restriction",
        }
        if kind not in {"apply_virtual_card", *state_changes, *changes}:
            raise ValueError("Unsupported card operation")
        request_id = request_id or self._id(kind)
        value = None
        if kind == "apply_virtual_card":
            if card_ref is not None or change is not None:
                raise ValueError("Card application accepts only an owned account")
        else:
            payload = {"status": state_changes[kind]} if kind in state_changes else change
            if not isinstance(payload, dict) or set(payload) & {"card_ref", "kind"}:
                raise ValueError("Card controls require explicit resulting facts")
            if kind in state_changes and change is not None:
                raise ValueError("State operation has a fixed resulting status")
            value = CardChangeRequest.model_validate({
                **deepcopy(payload),
                "card_ref": card_ref,
                "kind": kind,
            }).model_dump(mode="json", exclude_none=True)
        self._claim_request(
            request_id,
            {"kind": kind, "account_ref": account_ref, "card_ref": card_ref, "change": value},
        )

        def build(builder):
            ref = account_ref if kind == "apply_virtual_card" else card_ref
            collection = "accounts" if kind == "apply_virtual_card" else "cards"
            field = "account_ref" if kind == "apply_virtual_card" else "card_ref"
            obj = getattr(builder.state, collection)[ref]
            if obj.owner != builder.device.principal:
                raise ValueError("Card object belongs to another customer")
            item = builder.device.confirm_input(
                intent_id=builder.intent(),
                slot="card_application" if value is None else "card_change",
                value={"account_ref": ref} if value is None else deepcopy(value),
                now=builder.state.now,
            )
            authorization = builder.operation(kind, [ref], [item])
            args = {field: ref}
            terms = {
                field: StateTerm(
                    collection=collection, object_ref=ref, field="id", version=obj.version
                )
            }
            if value is not None:
                args["change_ref"] = item.id
                terms["change_ref"] = InputTerm(input_ref=item.id, slot="card_change")
            return builder.prepare(kind, args, terms, inputs=[item], authorization=authorization)

        return self._preview_operation(build, request_id=request_id)

    def approve_pending(self, pending_id):
        self._require_login()
        if pending_id in self._results:
            return deepcopy(self._results[pending_id])
        pending = self._pending[pending_id]
        if pending["mode"] == "draft":
            confirmation = self.workflow.confirm_plan(
                self.gateway,
                pending["display"].display_id,
                selected_nodes=[pending["node_id"]],
                request_id=pending_id,
            )
            if confirmation.results:
                result = self._result(confirmation.results[pending["node_id"]])
                self._results[pending_id] = result
                return deepcopy(result)
            if confirmation.status == "waiting_mfa":
                prepared = confirmation.prepared.get(pending["node_id"])
                if prepared is not None:
                    return self._store_prepared(prepared, pending_id=pending_id)
            if confirmation.status == "redisplay":
                replacement = self._preview_operation(
                    pending["factory"], request_id=self._id("redisplay")
                )
                self._pending.pop(pending_id)
                return {**replacement, "status": "redisplay", "replacement": replacement}
            return {"status": confirmation.status, "rule_ids": confirmation.rule_ids}
        prepared = pending["prepared"]
        if prepared.proposal.verdict.tier == "red" and not pending["verified"]:
            return {
                "status": "waiting_mfa",
                "pending_id": pending_id,
                "rule_ids": ["TIER-MFA-REQUIRED"],
            }
        confirmation = self.workflow.confirm_prepared(
            self.gateway,
            pending["display"].display_id,
            request_id=f"{pending_id}:final:{pending['display'].display_id}",
            prepared=prepared,
        )
        if confirmation.status != "approved":
            if confirmation.display is not None:
                pending["display"] = confirmation.display
            return {"status": confirmation.status, "rule_ids": confirmation.rule_ids}
        result = self._result(
            self.gateway.dispatch(prepared.action, prepared.cert, confirmation.token)
        )
        self._results[pending_id] = result
        return deepcopy(result)

    def request_mfa(self, pending_id):
        self._require_login()
        pending = self._pending[pending_id]
        if pending["mode"] == "draft":
            return {"status": "intent_confirmation_required", "pending_id": pending_id}
        prepared = pending["prepared"]
        if pending["challenge_id"] is None:
            pending["challenge_id"] = self.gateway.request_mfa(
                prepared.action, prepared.cert, request_id=pending_id
            )
        return {
            "status": "waiting_mfa",
            "challenge_id": pending["challenge_id"],
            "pending_id": pending_id,
        }

    def complete_mfa(self, pending_id):
        self._require_login()
        pending = self._pending[pending_id]
        if pending["verified"]:
            return {"status": "mfa_verified", "pending_id": pending_id}
        challenge = pending.get("challenge_id")
        if challenge is None:
            return {"status": "waiting_mfa", "rule_ids": ["MFA-INVALID"]}
        grant = self.device.complete_mfa(self.gateway.mfa, challenge, now=self.state.now)
        if grant is None or self.gateway.submit_mfa(grant).status != "accepted":
            return {"status": "rejected", "rule_ids": ["MFA-INVALID"]}
        prepared = pending["prepared"]
        cert = prepared.cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
        cert = cert.model_copy(
            update={"dependency_hashes": dependency_hashes(prepared.action, cert, self.state)}
        )
        updated = replace(
            prepared,
            cert=cert,
            proposal=self.gateway.propose(
                prepared.action, cert, request_id=prepared.action.intent_id
            ),
        )
        pending["prepared"], pending["verified"] = updated, True
        return {"status": "mfa_verified", "pending_id": pending_id}

    def compare_investments(self, objective="net_return"):
        self._require_login()
        builder = _Builder(self, self._id("compare"))
        prepared, _ = prepare_investment(builder, changes={"objective": objective})
        result = self._result(self.gateway.query(prepared.action, prepared.cert))
        result["bic"] = (
            prepared.cert.best_interest.model_dump(mode="json")
            if prepared.cert.best_interest
            else None
        )
        if result["bic"]:
            result["rows"] = deepcopy(result["bic"]["rows"])
            result["candidate_ids"] = [row["product_id"] for row in result["rows"]]
            result["exclusions"] = deepcopy(result["bic"].get("exclusions", []))
        self._last_comparison, self._objective = deepcopy(result), objective
        self._comparison_action = prepared.action
        result["exclusions"] = deepcopy(evaluate_investment(prepared.action, self.state).exclusions)
        return result

    def marketing_twin(self, sponsored):
        """Recompute a detached comparison; marketing never enters trusted state."""
        self._require_login()
        if self._comparison_action is None or self._last_comparison is None:
            return {"status": "comparison_required"}
        metadata = MarketingMetadata(
            product_id="P_B",
            sponsored=sponsored,
            campaign_text_handle="PROMO" if sponsored else "NONE",
        )
        detached = self.state.model_copy(deep=True)
        evaluation = evaluate_investment(self._comparison_action, detached)
        certificate = evaluation.certificate
        bic = certificate.model_dump(mode="json") if certificate is not None else None
        previous = self._last_comparison["bic"]
        unchanged = bool(
            bic
            and previous
            and all(
                bic[field] == previous[field]
                for field in ("candidate_ids", "rows", "chosen_product_id")
            )
        )
        return {
            "status": "validated",
            "unchanged": unchanged,
            "bic": bic,
            "marketing": metadata.model_dump(mode="json"),
            "catalog_hash": H(detached.catalog),
            "planner_mode": "scripted",
            "synthetic": True,
        }

    def preview_investment(self, product_ref=None, *, reason_code="user_choice", request_id=None):
        self._require_login()
        request_id = request_id or self._id("purchase")
        self._claim_request(
            request_id,
            {
                "kind": "purchase_product",
                "product_ref": product_ref,
                "objective": self._objective,
                "reason_code": reason_code,
            },
        )
        if request_id in self._requests:
            return deepcopy(self._requests[request_id])
        builder = _Builder(self, request_id)
        changes = {"objective": self._objective}
        if product_ref is not None:
            changes.update(
                selection_mode="explicit", selected_product_ref=product_ref, reason_code=reason_code
            )
        prepared, _ = prepare_investment(
            builder, purchase=True, changes=changes, chosen=product_ref
        )
        data = self._store_prepared(prepared)
        self._requests[request_id] = deepcopy(data)
        return data

    def redeem(self, position_ref, amount=None, *, request_id=None):
        self._require_login()
        position = self.state.positions.get(position_ref)
        if position is None or position.owner != self.device.principal:
            raise ValueError("No eligible position is available for this customer.")
        value = amount or fraction_string(position.units - position.reserved_units)
        request_id = request_id or self._id("redemption")
        self._claim_request(
            request_id, {"kind": "redeem_product", "position_ref": position_ref, "amount": value}
        )
        return self._preview_operation(
            lambda builder: prepare_redemption(builder, value, position_ref=position_ref),
            request_id=request_id,
        )

    def preview_birthday(self, *, selected_indices=None, request_id=None):
        from corridor.gateway.preview import PreviewRequest

        self._require_login()
        selected = list(range(4)) if selected_indices is None else list(selected_indices)
        if not selected or selected != list(range(len(selected))) or len(selected) > 4:
            return {
                "status": "selection_required",
                "rule_ids": ["PLAN-SCOPE"],
                "nodes": [],
                "message": (
                    "Select each task and its prerequisites; unchecked items receive no authority."
                ),
            }
        request_id = request_id or self._id("birthday")
        self._claim_request(request_id, {"kind": "birthday", "selected_indices": selected})
        if request_id in self._requests:
            return deepcopy(self._requests[request_id])
        draft = _Builder(self, request_id, draft=True)
        bundle = prepare_birthday(draft, selected_indices=selected)
        requests = []
        for index in selected:
            prepared = birthday_prepared(draft, bundle, index)
            requests.append(
                PreviewRequest(
                    prepared.action,
                    prepared.cert,
                    inputs=draft.gateway.inputs,
                    authorizations=draft.gateway.authorizations,
                )
            )
        live = _Builder(self, request_id)
        actual = {}

        def prepare(index):
            if "bundle" not in actual:
                actual["bundle"] = prepare_birthday(live, selected_indices=selected)
            return birthday_prepared(live, actual["bundle"], index)

        preparers = {
            request.action.node_id: lambda index=index: prepare(index)
            for index, request in zip(selected, requests, strict=True)
        }
        display = self.workflow.show_plan(self.gateway, requests, preparers)
        plan_id = bundle["plan"].plan_id
        self._plans[plan_id] = {
            "display": display,
            "bundle": bundle,
            "actual": actual,
            "builder": live,
            "selected": selected,
        }
        names = ["Lock birthday budget", "Unlock when due", "Order flowers", "Order cake"]
        data = {
            "plan_id": plan_id,
            "status": "draft",
            "canonical": True,
            "nodes": [
                {
                    "id": request.action.node_id,
                    "label": names[index],
                    "card": deepcopy(display.cards[request.action.node_id]),
                    "depends_on": bundle["plan"].nodes[index].depends_on,
                }
                for index, request in zip(selected, requests, strict=True)
            ],
        }
        self._requests[request_id] = deepcopy(data)
        return data

    def confirm_plan(self, plan_id, selected_node_ids):
        self._require_login()
        if plan_id in self._results:
            return deepcopy(self._results[plan_id])
        plan = self._plans[plan_id]
        displayed = [node.node_id for node in plan["bundle"]["plan"].nodes]
        if selected_node_ids != displayed:
            if (
                not selected_node_ids
                or len(set(selected_node_ids)) != len(selected_node_ids)
                or selected_node_ids != displayed[: len(selected_node_ids)]
            ):
                return {
                    "status": "selection_required",
                    "rule_ids": ["PLAN-SCOPE"],
                    "message": (
                        "Select each task and its prerequisites; "
                        "unchecked items receive no authority."
                    ),
                }
            replacement = self.preview_birthday(
                selected_indices=list(range(len(selected_node_ids)))
            )
            return {
                "status": "redisplay",
                "plan_id": replacement["plan_id"],
                "replacement": replacement,
                "results": {},
                "rule_ids": [],
            }
        confirmation = self.workflow.confirm_plan(
            self.gateway,
            plan["display"].display_id,
            selected_nodes=selected_node_ids,
            request_id=plan_id,
        )
        results = {key: self._result(value) for key, value in confirmation.results.items()}
        if confirmation.status == "redisplay" and not results and not plan["actual"]:
            replacement = self.preview_birthday(selected_indices=plan["selected"])
            return {
                "status": "redisplay",
                "plan_id": replacement["plan_id"],
                "replacement": replacement,
                "results": {},
                "rule_ids": confirmation.rule_ids,
            }
        success = (
            confirmation.status == "approved"
            and set(results) == set(selected_node_ids)
            and all(value["status"] in {"settled", "controlled"} for value in results.values())
        )
        result = {
            "status": "settled" if success else confirmation.status,
            "plan_id": plan_id,
            "results": results,
            "rule_ids": confirmation.rule_ids,
        }
        if success:
            self._results[plan_id] = result
        return deepcopy(result)

    def _registered_plan_ids(self):
        return list(
            dict.fromkeys(
                record["plan_id"]
                for record in self.gateway.audit.records()
                if record["event"] == "plan_registered"
            )
        )

    def stop(self, plan_id=None):
        plans = [plan_id] if plan_id else self._registered_plan_ids()
        retired = 0
        if plan_id is None:
            retired = len(self._drafts) + len(self._pending)
            self._drafts.clear()
            self._pending.clear()
            self._plans = {key: value for key, value in self._plans.items() if key in plans}
        if not plans:
            return {
                "status": "interrupted" if retired else "no_active_plan",
                "results": {},
                "retired_drafts": retired,
            }
        results = {ref: self._result(self.gateway.interrupt(ref)) for ref in plans}
        if plan_id:
            return results[plan_id]
        return {"status": "interrupted", "results": results}

    def handoff(self, plan_id=None):
        plans = self._registered_plan_ids()
        plan_id = plan_id or (plans[-1] if plans else None)
        if plan_id is None:
            return {"status": "no_active_plan"}
        return self._result(self.gateway.handoff(plan_id))

    def resume(self, plan_id):
        self._require_login()
        scope = self.gateway.resume_scope(plan_id)
        confirmation = self.device.confirm_input(
            intent_id=H(scope), slot="plan_resume", value=scope, now=self.state.now
        )
        return self._result(self.gateway.resume(plan_id, confirmation))

    def resume_scope(self, plan_id):
        return deepcopy(self.gateway.resume_scope(plan_id))

    def compensate(self, plan_id):
        proposed = self.gateway.request_compensation(plan_id)
        suggestions = proposed.details.get("suggestions", [])
        suggestion = next((item for item in suggestions if item["tool"] == "unlock_funds"), None)
        if suggestion is None:
            return {"status": "no_compensation", "suggestions": suggestions}
        receipt_ref = suggestion["receipt_ref"]
        amount = suggestion["amount"]
        return self._preview_operation(
            lambda builder: prepare_funds(
                builder,
                "unlock_funds",
                amount,
                step=0,
                purpose={"original_receipt_ref": receipt_ref},
            ),
            request_id=self._id("compensation"),
        )

    def advance_clock(self, target):
        if isinstance(target, int):
            target = add_seconds(self.state.now, target)
        results = self.gateway.advance_clock(target)
        return {
            "status": "advanced",
            "clock": self.state.now,
            "events": len(results),
            "results": [self._result(result) for result in results],
        }

    def snapshot(self):
        plans = []
        for plan_id in self._registered_plan_ids():
            try:
                plans.append(self.gateway.plan_snapshot(plan_id))
            except (KeyError, ValueError):
                continue
        logged_in = (
            self.session_authorization is not None
            and self.session_authorization.expires_at > self.state.now
        )
        pending = []
        for key, value in self._pending.items():
            display = value["display"]
            card = display.cards[value["node_id"]] if value["mode"] == "draft" else display.card
            pending.append({
                "pending_id": key,
                "mode": value["mode"],
                "completed": key in self._results,
                "result": deepcopy(self._results.get(key)),
                "card": deepcopy(card),
                "canonical": True,
                "needs_mfa": card.get("tier") == "red",
                "verified": value.get("verified", False),
            })
        return {
            "logged_in": logged_in,
            "status": "ready" if logged_in else "login_required",
            "clock": self.state.now,
            "planner_mode": "scripted",
            "synthetic": True,
            "balances": {
                ref: fraction_string(available(self.state, ref)) for ref in self.state.accounts
            },
            "locked": self.device.principal in self.state.security.locked_at,
            "dispatch_count": self.gateway.bank.execute_count,
            "receipts": [item.model_dump(mode="json") for item in self.state.receipts.values()],
            "audit": self.gateway.audit.records(),
            "audit_valid": self.gateway.verify_log(),
            "plans": plans,
            "schedules": [item.model_dump(mode="json") for item in self.state.schedules.values()],
            "positions": [item.model_dump(mode="json") for item in self.state.positions.values()],
            "cards": [
                item.model_dump(mode="json")
                for item in self.state.cards.values()
                if item.owner == self.device.principal
            ],
            "pending": pending,
        }
