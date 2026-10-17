"""Serialized approval, bank execution, and append-only recovery boundary."""

from calendar import monthrange
from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import date
from hashlib import sha256
from hmac import digest as hmac_digest
from pathlib import Path
from secrets import token_bytes
from threading import RLock
from typing import TYPE_CHECKING, Any, cast
from uuid import NAMESPACE_URL, uuid5

from nacl.signing import SigningKey

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import APPROVE, CONTROL, INPUT, MFA, RECEIPT, sign, verify
from corridor.eval.mockbank.exec import MockBank
from corridor.gateway.analysis import build_analysis
from corridor.gateway.audit import AuditLog
from corridor.gateway.bank_adapter import (
    compile_order,
    movements,
    receipt_updates,
    reservation_updates,
    validate_receipt,
)
from corridor.gateway.facts import render_narrative
from corridor.gateway.handles import HandleView, available_handles
from corridor.gateway.investments import build_investment_analysis
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.plans import node_due_at, project_runtime, resolve_node_terms, validate_plan
from corridor.gateway.preview import PreviewRequest, preview_card, preview_sequence
from corridor.gateway.privacy import PIIVault
from corridor.gateway.sandbox import SandboxRegistry, exploratory_receipt
from corridor.kernel import check
from corridor.kernel.binding import binding, intent_key, mfa_scope, resolve_amount
from corridor.kernel.rules import RULES
from corridor.kernel.spa import inspect_spa
from corridor.schemas.bank import (
    AnalysisReceipt,
    AnalysisResult,
    ApprovalToken,
    Authorization,
    BankAction,
    BankCertificate,
    BankOrder,
    BankReceipt,
    BusinessEvent,
    Handle,
    InputTerm,
    MFAGrant,
    OperationAuthorization,
    Plan,
    ReadTerm,
    ScheduledPaymentAuthorization,
    SessionAuthorization,
    StateTerm,
    UserInput,
)
from corridor.schemas.domain import Contact, ScheduledTask
from corridor.schemas.models import Accept, JsonValue, Reject, Verdict
from corridor.schemas.narrative import Narrative, NarrativeResult
from corridor.schemas.state import ApprovalRequest, BankState
from corridor.stores.bank import BankStore, add_seconds, latest_events

if TYPE_CHECKING:
    from corridor.gateway.allocations import AllocationDraft

_LOCK = RLock()
_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")
_GREEN = {
    "balance_query",
    "transactions_query",
    "bill_analyze",
    "bill_report",
    "anomaly_query",
    "sandbox_analyze",
    "risk_assess",
    "product_compare",
    "allocation_compare",
    "investment_income_query",
}
_ANALYSIS_FUNCTIONS = {
    "bill_analyze": "bill_summary_v1",
    "bill_report": "bill_summary_v1",
    "anomaly_query": "anomaly_v1",
}
_ANALYSIS = set(_ANALYSIS_FUNCTIONS) | {"subscription_query", "subscription_reminders"}
_INVESTMENT_ANALYSIS = {
    "risk_assess",
    "product_compare",
    "allocation_compare",
    "investment_income_query",
}
_READ_ONLY = _GREEN - {"risk_assess"}
_CONTROL = {"password_change_request", "register_contact_request"}
_B4_TOOLS = (
    _GREEN
    | _CONTROL
    | {
        "transfer",
        "schedule_transfer",
        "cancel_schedule",
        "subscription_query",
        "subscription_reminders",
        "cancel_subscription",
        "lock_funds",
        "unlock_funds",
        "merchant_order",
        "cancel_order",
        "refund_request",
        "purchase_product",
        "redeem_product",
        "aa_request",
        "apply_virtual_card",
        "freeze_card",
        "unfreeze_card",
        "report_card_lost",
        "restore_card",
        "lower_card_limit",
        "raise_card_limit",
        "restrict_card",
        "relax_card_restriction",
    }
)
_STATE_FIELDS = {
    "account_ref": "accounts",
    "source_ref": "accounts",
    "locked_ref": "accounts",
    "contact_ref": "contacts",
    "merchant_ref": "merchants",
    "offer_ref": "merchants",
    "authorization_ref": "subscriptions",
    "order_ref": "orders",
    "schedule_ref": "authorizations",
    "principal": "customers",
    "product_ref": "catalog",
    "position_ref": "positions",
    "card_ref": "cards",
}


def _period(value: JsonValue) -> bool:
    if not isinstance(value, str) or len(value) not in {4, 7, 10}:
        return False
    try:
        completed = value + ("-01-01" if len(value) == 4 else "-01" if len(value) == 7 else "")
        return date.fromisoformat(completed).isoformat() == completed
    except ValueError:
        return False


def _id(task: str, step: int, kind: str) -> str:
    return str(uuid5(_NAMESPACE, f"{task}:{step}:{kind}"))


def _reject(*rules: str) -> Reject:
    unique = list(dict.fromkeys(rules))
    first = unique[0]
    return Reject(
        rule_ids=unique, first=first, obligation=RULES[first].obligation, counterexample_code=first
    )


@dataclass(frozen=True)
class Proposal:
    verdict: Verdict
    card: dict[str, JsonValue]
    action_hash: str
    cert_hash: str


@dataclass(frozen=True)
class GatewayResult:
    status: str
    rule_ids: list[str] = field(default_factory=list)
    receipt: BankReceipt | None = None
    verdict: Verdict | None = None
    analysis_receipt: AnalysisReceipt | None = None
    details: dict[str, Any] = field(default_factory=dict)


class Gateway:
    """All instances share the lock; the store and bank never become planner tools."""

    def __init__(
        self,
        store: BankStore,
        bank: MockBank,
        *,
        audit: AuditLog | None = None,
        mfa: MFAVerifier | None = None,
        evidence_dir: Path | None = None,
        vault: PIIVault | None = None,
        analysis_key: SigningKey | None = None,
        risk_key: SigningKey | None = None,
    ) -> None:
        self.store, self.bank = store, bank
        self.audit = audit if audit is not None else AuditLog()
        self.mfa, self.evidence_dir = mfa, evidence_dir
        self.vault = vault if vault is not None else PIIVault()
        self._sandbox = SandboxRegistry(self.vault)
        self._analysis_key = analysis_key
        self._utterance_key = (
            hmac_digest(bytes(analysis_key), b"corridor/bank/utterance-key/v1", "sha256")
            if analysis_key is not None
            else token_bytes(32)
        )
        self._risk_key = risk_key
        self._plans: dict[str, Plan] = {}
        self._blocked_plans: set[str] = set()
        self._voided_plans: set[str] = set()
        self._handoff_plans: set[str] = set()
        self._cards: dict[str, dict[str, JsonValue]] = {}
        self._challenge_requests: dict[str, tuple[str, str]] = {}
        self._approval_challenges: dict[str, str] = {}
        self._restored_approval_keys: set[str] = set()
        self._unlock_challenges: dict[str, tuple[str, str]] = {}
        self._sequence = 0
        self._write_failed = False
        with _LOCK:
            try:
                records = self.audit.records()
                self._sequence = len(records)
                for record in records:
                    if record["event"] == "plan_registered":
                        plan = Plan.model_validate(record["payload"]["plan"])
                        self._plans[plan.plan_id] = plan
                    if record["event"] in {"plan_interrupted", "plan_handoff", "plan_voided"}:
                        self._blocked_plans.add(record["plan_id"])
                    if record["event"] == "plan_voided":
                        self._voided_plans.add(record["plan_id"])
                        self._handoff_plans.discard(record["plan_id"])
                    if record["event"] == "plan_handoff":
                        self._handoff_plans.add(record["plan_id"])
                    if (
                        record["event"] == "plan_resumed"
                        and record["plan_id"] not in self._voided_plans
                    ):
                        self._blocked_plans.discard(record["plan_id"])
                        self._handoff_plans.discard(record["plan_id"])
                    if record["event"] == "mfa_challenge":
                        self._sequence = max(self._sequence, record["payload"]["sequence"])
                        if "approval_key" in record["payload"]:
                            self._restored_approval_keys.add(record["payload"]["approval_key"])
                            self._approval_challenges[record["payload"]["approval_key"]] = record[
                                "payload"
                            ]["challenge_id"]
                for event in latest_events(store.snapshot()).values():
                    if event.event == "reserved":
                        receipt = store.snapshot().receipts.get(event.bank_receipt_id or "")
                        if (
                            event.kind == "redeem_product"
                            and isinstance(receipt, BankReceipt)
                            and receipt.status == "pending"
                            and validate_receipt(
                                BankOrder.model_validate(event.object_delta.get("order")),
                                receipt,
                                store.snapshot(),
                            )
                        ):
                            continue
                        self._unknown(event, "restart")
            except (OSError, ValueError, KeyError, TypeError):
                self._write_failed = True

    def _next(self) -> int:
        self._sequence += 1
        return self._sequence

    def utterance_digest(self, text: str, external_texts: list[str] | None = None) -> str:
        """Commit to private input without exposing a public offline guessing oracle."""
        body = jcs_bytes({"text": text, "external_hashes": [H(x) for x in external_texts or []]})
        return hmac_digest(
            self._utterance_key, b"corridor/bank/utterance/v1\0" + body, "sha256"
        ).hex()

    def register_dataset(self, principal: str, account_ref: str, period: str) -> str:
        with _LOCK:
            return self._sandbox.register_dataset(
                self.store.snapshot(), principal, account_ref, period
            )

    def register_program(self, principal: str, program: str) -> str:
        with _LOCK:
            try:
                return self._sandbox.register_program(self.store.snapshot(), principal, program)
            except ValueError as exc:
                self._audit(
                    "sandbox_rejected",
                    principal,
                    {
                        "program_hash": sha256(program.encode("utf-8")).hexdigest()
                        if isinstance(program, str)
                        else H(None),
                        "status": "rejected",
                        "reason": str(exc),
                    },
                )
                raise

    def _audit(
        self, event: str, principal: str, payload: dict[str, Any], action: BankAction | None = None
    ) -> None:
        self.vault.ensure_safe(
            {
                "principal": principal,
                "payload": payload,
                "plan_id": action.plan_id if action else None,
                "node_id": action.node_id if action else None,
            },
            rule="PII-OUT",
        )
        self.audit.append(
            event,
            now=self.store.snapshot().now,
            principal_token=principal,
            plan_id=action.plan_id if action else None,
            node_id=action.node_id if action else None,
            payload=payload,
        )

    def _security(self, **changes: Any) -> None:
        security = self.store.snapshot().security.model_dump(mode="python")
        security.update(changes)
        self.store.update(security=security)

    def _failure(self, principal: str, rule: str) -> GatewayResult:
        if rule in {"AUD-WRITE", "AUD-CHAIN"}:
            self._write_failed = True
            self.lock(principal, rule)
        return GatewayResult("rejected", [rule], verdict=_reject(rule))

    def _record_verdict(self, action: BankAction, verdict: Verdict) -> None:
        self.vault.ensure_safe(verdict, rule="PII-OUT")
        state = self.store.snapshot()
        if verdict.outcome == "Reject":
            streaks = dict(state.security.reject_streak)
            streaks[action.principal] = streaks.get(action.principal, 0) + 1
            self._security(reject_streak=streaks)
            if streaks[action.principal] >= state.policy.reject_limit:
                self.lock(action.principal, "kernel_rejections")
            if (
                action.kind == "purchase_product"
                and action.device_session_id
                == state.security.active_device_sessions.get(action.principal)
            ):
                from corridor.kernel.investment import effective_risk_level

                try:
                    cap = effective_risk_level(action.principal, self.store.snapshot())
                except (ValueError, KeyError, TypeError):
                    cap = 1
                self._suitability_event(action.principal, "purchase_refused", cap)
        self._audit(
            "kernel_verdict",
            action.principal,
            {
                "outcome": verdict.outcome,
                "rule_ids": getattr(verdict, "rule_ids", []),
                "action_hash": H(action),
            },
            action,
        )

    def _suitability_event(self, principal: str, signal: str, cap: int) -> None:
        """Append a non-monetary, session-scoped restriction; never rewrite a profile."""
        state = self.store.snapshot()
        session = state.security.active_device_sessions.get(principal)
        if principal not in state.customers or session is None:
            return
        key = H({"suitability": principal, "session": session, "signal": signal, "cap": cap})
        if key in latest_events(state):
            return
        event = BusinessEvent(
            id=_id(key, 0, "suitability"),
            intent_key=key,
            event="settled",
            kind="allocation_compare",
            principal=principal,
            ts=state.now,
            object_delta={
                "suitability_signal": signal,
                "device_session_id": session,
                "effective_level_cap": cap,
                "source": "untrusted_dialogue_hint"
                if signal == "cannot_accept_loss"
                else "gateway_purchase_rejection",
            },
        )
        self._audit("suitability_restriction", principal, event.object_delta)
        self.store.update(ledger=[*state.ledger, event])

    def suitability_signal(self, principal: str, signal: str) -> GatewayResult:
        """Allowlisted dialogue hints only add friction; the device alone supplies answers."""
        with _LOCK:
            try:
                state = self.store.snapshot()
                if principal not in state.security.active_device_sessions:
                    return self._failure(principal, "AUTH-PRINCIPAL")
                if signal == "coaching_request":
                    self._audit("suitability_coaching_refused", principal, {"signal": signal})
                    return GatewayResult(
                        "refused",
                        details={
                            "message": "I cannot choose or coach questionnaire answers "
                            "to obtain a risk level. "
                            "Please answer on your device using your own circumstances."
                        },
                    )
                if signal != "cannot_accept_loss":
                    return self._failure(principal, "BIC-RISK")
                self._suitability_event(principal, signal, 1)
                return GatewayResult(
                    "clarification_required",
                    details={
                        "effective_level_cap": 1,
                        "message": "A dialogue hint indicates that you may not accept loss. "
                        "Please clarify your loss "
                        "tolerance on the device. The effective risk level can only decrease "
                        "during this session; performance benchmarks are not guaranteed.",
                    },
                )
            except OSError:
                return self._failure(principal, "AUD-WRITE")

    def lock(self, principal: str, reason: str) -> None:
        with _LOCK:
            state = self.store.snapshot()
            if principal in state.security.locked_at:
                return
            try:
                self.vault.ensure_safe({"principal": principal, "reason": reason}, rule="PII-OUT")
                self._security(
                    locked_at={**state.security.locked_at, principal: state.now},
                    lock_reason={**state.security.lock_reason, principal: reason},
                )
                self._audit("locked", principal, {"reason": reason, "locked_at": state.now})
                self._void_plans(principal)
            except (OSError, ValueError):
                self._write_failed = True

    def _void_plans(self, principal: str) -> None:
        """A safety unlock never restores the pre-lock business plans."""
        state = self.store.snapshot()
        for parent in state.allocation_plans.values():
            marker = latest_events(state).get(H({"allocation_control": parent.id}))
            if (
                parent.principal == principal
                and marker is not None
                and marker.object_delta.get("status") == "ready"
            ):
                from corridor.gateway.allocations import mark_allocation

                mark_allocation(self, parent, "failed")
        for plan in self._plans.values():
            if plan.principal != principal or all(node.tool in _READ_ONLY for node in plan.nodes):
                continue
            self._blocked_plans.add(plan.plan_id)
            self._voided_plans.add(plan.plan_id)
            self._handoff_plans.discard(plan.plan_id)
            self.audit.append(
                "plan_voided",
                now=self.store.snapshot().now,
                principal_token=principal,
                plan_id=plan.plan_id,
                payload={"plan_hash": H(plan), "rule_ids": ["APR-LOCK"]},
            )

    def submit_input(self, value: UserInput) -> GatewayResult:
        with _LOCK:
            try:
                self.vault.ensure_safe(value)
                value = UserInput.model_validate(value.model_dump(mode="python"))
                if value.principal in self.store.snapshot().security.locked_at:
                    return self._failure(value.principal, "APR-LOCK")
                if value.submitted_at > self.store.snapshot().now:
                    return self._failure(value.principal, "SCHEMA-TIME")
                self.store.append_input(value)
                self._audit("input_confirmed", value.principal, {"input_hash": H(value)})
                return GatewayResult("accepted")
            except OSError:
                return self._failure(value.principal, "AUD-WRITE")
            except (ValueError, TypeError, AttributeError) as exc:
                return self._failure(
                    value.principal, "PII-CTX" if str(exc) == "PII-CTX" else "AUTH-SIG"
                )

    def submit_authorization(self, value: Authorization) -> GatewayResult:
        with _LOCK:
            try:
                self.vault.ensure_safe(value)
                if value.principal in self.store.snapshot().security.locked_at:
                    return self._failure(value.principal, "APR-LOCK")
                self.store.append_authorization(value)
                self._audit(
                    "authorization_confirmed", value.principal, {"authorization_hash": H(value)}
                )
                return GatewayResult("accepted")
            except OSError:
                return self._failure(value.principal, "AUD-WRITE")
            except (ValueError, TypeError, AttributeError) as exc:
                return self._failure(
                    value.principal, "PII-CTX" if str(exc) == "PII-CTX" else "AUTH-SIG"
                )

    def login(self, authorization: SessionAuthorization) -> GatewayResult:
        with _LOCK:
            try:
                self.vault.ensure_safe(authorization)
                authorization = SessionAuthorization.model_validate(
                    authorization.model_dump(mode="python")
                )
                state = self.store.snapshot()
                customer = state.customers.get(authorization.principal)
                if customer is None or not verify(
                    customer.device_pubkey, CONTROL, authorization, authorization.sig
                ):
                    return self._failure(authorization.principal, "AUTH-SIG")
                if authorization.expires_at <= state.now or self.store.is_revoked(authorization.id):
                    return self._failure(authorization.principal, "AUTH-SCOPE")
                if authorization.id not in state.authorizations:
                    self.store.append_authorization(authorization)
                self._security(
                    active_device_sessions={
                        **state.security.active_device_sessions,
                        authorization.principal: authorization.device_session_id,
                    }
                )
                self._audit(
                    "login", authorization.principal, {"authorization_hash": H(authorization)}
                )
                return GatewayResult("accepted")
            except OSError:
                return self._failure(authorization.principal, "AUD-WRITE")
            except (ValueError, TypeError, AttributeError):
                return self._failure(authorization.principal, "AUTH-SIG")

    def submit_plan(self, plan: Plan) -> GatewayResult:
        with _LOCK:
            try:
                self.vault.ensure_safe(plan)
                plan = Plan.model_validate(plan.model_dump(mode="python"))
                state = self.store.snapshot()
                if plan.principal in state.security.locked_at and any(
                    node.tool not in _READ_ONLY for node in plan.nodes
                ):
                    return self._failure(plan.principal, "APR-LOCK")
                customer = state.customers.get(plan.principal)
                if (
                    customer is None
                    or state.security.active_device_sessions.get(plan.principal)
                    != plan.device_session_id
                ):
                    return self._failure(plan.principal, "PLAN-OWNER")
                rule = validate_plan(plan, state, supported_tools=_B4_TOOLS)
                if rule:
                    return self._failure(plan.principal, rule)
                for node in plan.nodes:
                    if node.tool == "sandbox_analyze":
                        for field, term in node.args.items():
                            ref = (
                                term.value
                                if isinstance(term, ReadTerm)
                                else term.ref
                                if isinstance(term, Handle)
                                else None
                            )
                            if not self._sandbox.has_handle(plan.principal, field, ref):
                                return self._failure(plan.principal, "PLAN-SCOPE")
                previous = self._plans.get(plan.plan_id)
                if previous is None and plan.ownership_epoch != 0:
                    return self._failure(plan.principal, "PLAN-OWNER")
                if previous is not None and previous != plan:
                    return self._failure(plan.principal, "PLAN-SCOPE")
                if plan.plan_id in self._blocked_plans:
                    return self._failure(plan.principal, "APR-VOID")
                self.audit.append(
                    "plan_registered",
                    now=state.now,
                    principal_token=plan.principal,
                    plan_id=plan.plan_id,
                    payload={"plan": plan.model_dump(mode="json")},
                )
                self._plans[plan.plan_id] = plan
                return GatewayResult("registered")
            except OSError:
                return self._failure(getattr(plan, "principal", "unknown"), "AUD-WRITE")
            except (ValueError, TypeError, AttributeError) as exc:
                return self._failure(
                    getattr(plan, "principal", "unknown"),
                    "PII-CTX" if str(exc) == "PII-CTX" else "PLAN-SCHEMA",
                )

    def _plan_terms_valid(self, plan: Plan, state: BankState) -> bool:
        return validate_plan(plan, state, supported_tools=_B4_TOOLS) is None

    def _plan_rule(self, action: BankAction, cert: BankCertificate, state: BankState) -> str | None:
        if action.kind == "purchase_product" and state.allocation_plans:
            from corridor.kernel.allocation_execution import allocation_purchase_errors

            parents = [
                parent
                for parent in state.allocation_plans.values()
                if any(
                    item.child_plan_id == action.plan_id or item.child_intent_id == action.intent_id
                    for item in parent.items
                )
            ]
            if parents or action.args.model_dump().get("allocation_ref"):
                errors = allocation_purchase_errors(action, cert, state)
                if errors:
                    return errors[0]
                budget = self.allocation_approval_budget(
                    str(action.args.model_dump()["allocation_ref"])
                )
                if budget["preflight_required"] and not budget["can_start"]:
                    return "APR-BUDGET"
        if action.plan_id in self._voided_plans:
            return "APR-VOID"
        if action.plan_id in self._handoff_plans:
            return "PLAN-OWNER"
        if action.plan_id in self._blocked_plans:
            return "APR-VOID"
        plan = self._plans.get(action.plan_id)
        if plan is None:
            return "PLAN-SCHEMA"
        if H(plan) != action.plan_hash:
            return "PLAN-OWNER" if plan.ownership_epoch else "PLAN-SCHEMA"
        if plan.principal != action.principal:
            return "PLAN-OWNER"
        node = next((item for item in plan.nodes if item.node_id == action.node_id), None)
        if node is None:
            return "PLAN-SCOPE"
        auth = state.authorizations.get(cert.authorization_ref)
        spa = auth if isinstance(auth, ScheduledPaymentAuthorization) else None
        if action.intent_id != (spa.id if spa else plan.intent_id):
            return "PLAN-OWNER"
        if spa and (spa.plan_id != plan.plan_id or spa.node_id != node.node_id):
            return "PLAN-SCOPE"
        creation = spa is not None and action.kind == "schedule_transfer"
        runtime = spa is not None and action.action_id in state.schedules and not creation
        snapshot = self.plan_snapshot(plan.plan_id)
        if not runtime and snapshot["nodes"][node.node_id]["status"] == "cancelled":
            return "PLAN-SCOPE"
        if not creation and any(
            snapshot["nodes"][ref]["status"] != "succeeded" for ref in node.depends_on
        ):
            return "PLAN-SCOPE"
        try:
            due = node_due_at(plan, node.node_id, state)
            if not creation and due is not None and state.now < due:
                return "PLAN-SCOPE"
            expected = resolve_node_terms(
                plan,
                node.node_id,
                state,
                {
                    key: value["receipt_ref"]
                    for key, value in snapshot["nodes"].items()
                    if value["status"] == "succeeded" and value.get("receipt_ref")
                },
                check_current=False,
            )
        except (ValueError, KeyError, TypeError):
            return "PLAN-SCOPE"
        terms = {key.removeprefix("args."): value for key, value in cert.derivations.items()}
        if runtime and spa is not None:
            expected.pop("schedule_ref", None)
            if spa.target.kind == "merchant_order":
                expected.pop("amount_ref", None)
        if creation and spa is not None and node.tool != "schedule_transfer":
            if node.tool != spa.target.kind:
                return "PLAN-SCOPE"
            compare = dict(terms)
            schedule_term = compare.pop("schedule_ref", None)
            if not isinstance(schedule_term, StateTerm) or schedule_term.object_ref != spa.id:
                return "PLAN-SCOPE"
            if node.tool == "merchant_order":
                amount_term = compare.pop("amount_ref", None)
                if (
                    not isinstance(amount_term, InputTerm)
                    or amount_term.input_ref not in plan.goal_input_refs
                ):
                    return "PLAN-SCOPE"
            if compare != expected:
                return "PLAN-SCOPE"
        elif terms != expected or (
            node.tool != action.kind and not (runtime and node.tool == "schedule_transfer")
        ):
            return "PLAN-SCOPE"
        if not runtime and plan.device_session_id != action.device_session_id:
            return "PLAN-SCOPE"
        return None

    def _scheduled_action_rule(self, action: BankAction, state: BankState) -> str | None:
        """Reject external run mutations before any evaluation changes trusted state."""
        from corridor.gateway.orchestration import compile_node

        run = state.schedules.get(action.action_id)
        if run is None:
            return None
        try:
            canonical, _ = compile_node(self, self._plans[run.plan_id], run.node_id, run_id=run.id)
        except (ValueError, KeyError, TypeError, AttributeError):
            return "DOMAIN-SPA"
        return None if H(action) == H(canonical) else "DOMAIN-SPA"

    @staticmethod
    def _card_key(action: BankAction, cert: BankCertificate) -> str:
        return H({"action": action, "cert": cert.model_copy(update={"mfa_grant_refs": []})})

    def _approval_request(
        self,
        principal: str,
        request_id: str | None,
        action_hash: str,
        card_hash: str,
        *,
        reuse_card: bool = False,
    ) -> str:
        state = self.store.snapshot()
        request_id = request_id or H({"action_hash": action_hash, "card_hash": card_hash})
        request_id = H({
            "request_id": request_id,
            "action_hash": action_hash,
            "card_hash": card_hash,
        })
        cutoff = add_seconds(state.now, -state.policy.approval_window_seconds)
        requests = [
            item for item in state.security.approval_requests.get(principal, []) if item.ts > cutoff
        ]
        existing = next(
            (
                item
                for item in reversed(requests)
                if item.request_id == request_id
                or (reuse_card and item.action_hash == action_hash and item.card_hash == card_hash)
            ),
            None,
        )
        if existing is None:
            existing = ApprovalRequest(
                request_id=request_id, ts=state.now, action_hash=action_hash, card_hash=card_hash
            )
            requests.append(existing)
            self._audit("approval_requested", principal, {"request_id": request_id})
        self._security(approval_requests={**state.security.approval_requests, principal: requests})
        if len(requests) >= state.policy.approval_limit:
            self.lock(principal, "approval_rate")
        return H(existing)

    def approval_budget(self, principal: str) -> dict[str, Any]:
        """Read the simulated rolling window; the locking request is not spendable."""
        with _LOCK:
            state = self.store.snapshot()
            if principal not in state.customers:
                raise ValueError("READ-ROLE")
            cutoff = add_seconds(state.now, -state.policy.approval_window_seconds)
            active = [
                r for r in state.security.approval_requests.get(principal, []) if r.ts > cutoff
            ]
            expiries = sorted(
                add_seconds(r.ts, state.policy.approval_window_seconds) for r in active
            )
            locked = principal in state.security.locked_at
            return {
                "used": len(active),
                "limit": state.policy.approval_limit,
                "remaining": 0 if locked else max(0, state.policy.approval_limit - 1 - len(active)),
                "locked": locked,
                "next_release_at": expiries[0] if expiries else None,
                "window_clears_at": expiries[-1] if expiries else None,
            }

    def allocation_approval_budget(self, parent_id: str) -> dict[str, Any]:
        """Conservatively price all remaining legs before the first money movement."""
        from corridor.gateway.orchestration import compile_node
        from corridor.kernel.allocation_execution import inspect_allocation_plan

        with _LOCK:
            state = self.store.snapshot()
            parent = state.allocation_plans[parent_id]
            inspection = inspect_allocation_plan(parent_id, state, require_ready=False)
            budget = self.approval_budget(parent.principal)
            remaining = set(inspection.remaining_item_refs)
            required = len(remaining)
            cutoff = add_seconds(state.now, -state.policy.approval_window_seconds)
            active = [
                r
                for r in state.security.approval_requests.get(parent.principal, [])
                if r.ts > cutoff
            ]
            # Only the next card can survive the next debit. Do not discount pre-rendered
            # later cards whose balance dependency will change after that debit.
            next_item = next((item for item in parent.items if item.item_ref in remaining), None)
            if next_item is not None:
                try:
                    action, cert = compile_node(
                        self, self._plans[next_item.child_plan_id], next_item.child_node_id
                    )
                    card_hash = H(binding(action, cert, state).card_core)
                    if any(r.action_hash == H(action) and r.card_hash == card_hash for r in active):
                        required -= 1
                except (ValueError, KeyError, TypeError):
                    pass  # Missing context cannot earn a discount.
            child_intents = {item.child_intent_id for item in parent.items}
            started = any(
                event.principal == parent.principal
                and event.kind == "purchase_product"
                and event.event in {"reserved", "unknown", "settled"}
                and any(
                    event.intent_key
                    == H({
                        "principal": parent.principal,
                        "intent_id": intent,
                        "kind": "purchase_product",
                    })
                    for intent in child_intents
                )
                for event in state.ledger
            )
            can_start = (
                not inspection.errors and not budget["locked"] and required <= budget["remaining"]
            )
            return {
                **budget,
                "required": required,
                "preflight_required": not started,
                "can_start": can_start,
                "rule_ids": list(inspection.errors),
                "message": f"Needs {required} approvals, {budget['remaining']} left; "
                + (
                    f"window clears at {budget['window_clears_at']}."
                    if budget["window_clears_at"]
                    else "no earlier approvals are expiring."
                ),
            }

    def propose(
        self,
        action: BankAction,
        cert: BankCertificate,
        request_id: str | None = None,
        injection_flag: bool = False,
    ) -> Proposal:
        with _LOCK:
            try:
                self.vault.ensure_safe((action, cert, request_id))
                action = BankAction.model_validate(action.model_dump(mode="python"))
                cert = BankCertificate.model_validate(cert.model_dump(mode="python"))
                state = self.store.snapshot()
                rule = self._plan_rule(action, cert, state)
                verdict = _reject(rule) if rule else check(action, cert, state, phase="propose")
                self._record_verdict(action, verdict)
                card = verdict.verified_facts.get("card_core", {})
                if not isinstance(card, dict):
                    card = {}
                if rule == "APR-BUDGET":
                    card = self._cards.get(self._card_key(action, cert), {})
                if (
                    action.kind not in _GREEN
                    and action.action_id not in state.schedules
                    and (rule != "APR-BUDGET" or (request_id is not None and bool(card)))
                ):
                    self._approval_request(action.principal, request_id, H(action), H(card))
                if injection_flag and (
                    verdict.tier == "red"
                    or (
                        rule == "APR-BUDGET"
                        and check(action, cert, state, phase="propose").tier == "red"
                    )
                ):
                    self.lock(action.principal, "red_injection")
                if (
                    action.principal in self.store.snapshot().security.locked_at
                    and action.kind not in _READ_ONLY
                ):
                    verdict = _reject("APR-LOCK")
                if card:
                    self._cards[self._card_key(action, cert)] = deepcopy(card)
                return Proposal(verdict, deepcopy(card), H(action), H(cert))
            except OSError:
                self._failure(getattr(action, "principal", "unknown"), "AUD-WRITE")
                return Proposal(_reject("AUD-WRITE"), {}, "", "")
            except (ValueError, TypeError, AttributeError, KeyError) as exc:
                rule = str(exc) if str(exc) in {"PII-CTX", "PII-OUT"} else "SCHEMA-INVALID"
                return Proposal(_reject(rule), {}, "", "")

    def render_card(self, action: BankAction, cert: BankCertificate) -> dict[str, JsonValue]:
        return self.propose(action, cert).card

    def preview(
        self,
        action: BankAction,
        cert: BankCertificate,
        *,
        inputs: list[UserInput] | tuple[UserInput, ...] = (),
        authorizations: list[Any] | tuple[Any, ...] = (),
    ) -> dict[str, JsonValue]:
        """Render unsigned facts without recording inputs, authority, or approval."""
        with _LOCK:
            self.vault.ensure_safe((action, cert, inputs, authorizations))
            card = preview_card(
                PreviewRequest(action, cert, inputs, authorizations), self.store.snapshot()
            )
            self.vault.ensure_safe(card)
            return card

    def preview_sequence(self, requests: list[PreviewRequest]) -> dict[str, dict[str, JsonValue]]:
        """Project the documented effects of the exact selected node sequence."""
        with _LOCK:
            for request in requests:
                self.vault.ensure_safe((
                    request.action,
                    request.cert,
                    request.inputs,
                    request.authorizations,
                ))
            cards = preview_sequence(requests, self.store.snapshot())
            self.vault.ensure_safe(cards)
            return cards

    def available_handles(self, principal: str, session_id: str) -> list[HandleView]:
        with _LOCK:
            views = available_handles(self.store.snapshot(), principal, session_id)
            self.vault.ensure_safe(views, rule="PII-CTX")
            return views

    def render_narrative(self, narrative: Narrative, principal: str) -> NarrativeResult:
        with _LOCK:
            result = render_narrative(narrative, self.store.snapshot(), principal, self.vault)
            self._audit(
                "narrative_rendered",
                principal,
                {"rule_ids": result.rule_ids, "fact_hash": H(result.facts)},
            )
            return result

    def _grant_rule(
        self, grant: MFAGrant, principal: str, scope: str, state: BankState
    ) -> str | None:
        customer = state.customers.get(principal)
        if grant.grant_id in state.security.consumed_grant_ids:
            return "MFA-REUSE"
        if (
            customer is None
            or grant.principal != principal
            or grant.device_session_id != state.security.active_device_sessions.get(principal)
            or grant.scope_hash != scope
            or grant.method != "sms_sim"
            or not grant.issued_at <= state.now < grant.expiry
            or grant.expiry > add_seconds(grant.issued_at, 120)
            or not verify(customer.mfa_pubkey, MFA, grant, grant.sig)
        ):
            return "MFA-INVALID"
        return None

    def request_mfa(
        self, action: BankAction, cert: BankCertificate, request_id: str | None = None
    ) -> str | None:
        try:
            return self._request_mfa(action, cert, request_id)
        except OSError:
            self._failure(action.principal, "AUD-WRITE")
        except (ValueError, TypeError, KeyError, AttributeError):
            self._failure(action.principal, "MFA-INVALID")
        return None

    def _request_mfa(
        self, action: BankAction, cert: BankCertificate, request_id: str | None = None
    ) -> str | None:
        with _LOCK:
            if self.mfa is None:
                return None
            state = self.store.snapshot()
            if self._plan_rule(action, cert, state) or action.principal in state.security.locked_at:
                return None
            card = self._cards.get(self._card_key(action, cert))
            if not card or card.get("tier") != "red":
                return None
            scope = mfa_scope(action, H(card))
            request_id = request_id or _id(action.principal, self._next(), "mfa-request")
            request_key = H({"principal": action.principal, "request_id": request_id})
            previous = self._challenge_requests.get(request_key)
            if previous is not None:
                return previous[1] if previous[0] == scope else None
            approval_identity = self._approval_request(
                action.principal, request_id, H(action), H(card), reuse_card=True
            )
            if action.principal in self.store.snapshot().security.locked_at:
                return None
            approval_key = H({"approval_identity": approval_identity, "scope": scope})
            if approval_key in self._restored_approval_keys:
                # Verifier attempt state is private and is not reconstructed with zero attempts.
                # A new, counted explicit approval is required after a gateway restart.
                return None
            if approval_key in self._approval_challenges:
                challenge_id = self._approval_challenges[approval_key]
                self._challenge_requests[request_key] = (scope, challenge_id)
                return challenge_id
            sequence = self._next()
            challenge_id = self.mfa.challenge(
                principal=action.principal,
                device_session_id=action.device_session_id,
                scope_hash=scope,
                now=state.now,
                sequence=sequence,
            )
            self._audit(
                "mfa_challenge",
                action.principal,
                {
                    "scope_hash": scope,
                    "challenge_id": challenge_id,
                    "sequence": sequence,
                    "approval_key": approval_key,
                },
                action,
            )
            self._challenge_requests[request_key] = (scope, challenge_id)
            self._approval_challenges[approval_key] = challenge_id
            return challenge_id

    def submit_mfa(self, grant: MFAGrant) -> GatewayResult:
        with _LOCK:
            try:
                grant = MFAGrant.model_validate(grant.model_dump(mode="python"))
                state = self.store.snapshot()
                if grant.principal in state.security.locked_at:
                    return self._failure(grant.principal, "APR-LOCK")
                rule = self._grant_rule(grant, grant.principal, grant.scope_hash, state)
                if rule:
                    return self._failure(grant.principal, rule)
                existing = state.security.mfa_grants.get(grant.grant_id)
                if existing is not None and existing != grant:
                    return self._failure(grant.principal, "MFA-INVALID")
                self._security(mfa_grants={**state.security.mfa_grants, grant.grant_id: grant})
                self._audit("mfa_verified", grant.principal, {"grant_hash": H(grant)})
                return GatewayResult("accepted")
            except OSError:
                return self._failure(getattr(grant, "principal", "unknown"), "AUD-WRITE")
            except (ValueError, TypeError, AttributeError):
                return self._failure(getattr(grant, "principal", "unknown"), "MFA-INVALID")

    def _token_rule(
        self, action: BankAction, cert: BankCertificate, token: ApprovalToken, state: BankState
    ) -> str | None:
        customer = state.customers.get(action.principal)
        if customer is None or not verify(customer.device_pubkey, APPROVE, token, token.sig):
            return "APR-SIG"
        if (
            token.principal != action.principal
            or token.device_session_id != action.device_session_id
            or state.security.active_device_sessions.get(action.principal)
            != token.device_session_id
        ):
            return "APR-ROLE"
        if token.token_id in state.security.void_token_ids or action.plan_id in self._blocked_plans:
            return "APR-VOID"
        if token.nonce in state.security.consumed_nonces:
            return "APR-REUSE"
        if not token.issued_at <= state.now < token.expiry or token.expiry > add_seconds(
            token.issued_at, 300
        ):
            return "APR-EXPIRED"
        card = self._cards.get(self._card_key(action, cert))
        if (
            token.action_hash != H(action)
            or token.cert_hash != H(cert)
            or token.plan_id != action.plan_id
            or token.plan_hash != action.plan_hash
            or token.node_id != action.node_id
            or token.ownership_epoch != self._plans[action.plan_id].ownership_epoch
            or card is None
            or token.card_hash != H(card)
            or token.tier != card.get("tier")
        ):
            return "APR-SWAP"
        return None

    def dispatch(
        self, action: BankAction, cert: BankCertificate, token: ApprovalToken | None = None
    ) -> GatewayResult:
        with _LOCK:
            result = self._dispatch(action, cert, token)
            if result.status in {"failed", "unknown"}:
                try:
                    self._allocation_outcome(action, result.status)
                except (ValueError, OSError):
                    self._write_failed = True
                    return GatewayResult("unknown", ["AUD-WRITE"])
            if result.status == "rejected":
                return result
            try:
                self._note_node(action, result)
            except (ValueError, OSError):
                self._failure(getattr(action, "principal", "unknown"), "AUD-WRITE")
                return GatewayResult("unknown", ["AUD-WRITE"])
            return result

    def query(self, action: BankAction, cert: BankCertificate) -> GatewayResult:
        if action.kind not in _GREEN:
            return self._audit_dispatch_rejection(
                action, cert, None, self._failure(action.principal, "READ-ROLE")
            )
        return self.dispatch(action, cert, None)

    def _dispatch(
        self,
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken | None,
        *,
        device_control: bool = False,
        contact: Contact | None = None,
        confirmation: UserInput | None = None,
    ) -> GatewayResult:
        with _LOCK:
            result = self._dispatch_checked(
                action,
                cert,
                token,
                device_control=device_control,
                contact=contact,
                confirmation=confirmation,
            )
            if result.status not in {"rejected", "waiting_mfa"}:
                return result
            return self._audit_dispatch_rejection(action, cert, token, result)

    def _audit_dispatch_rejection(
        self,
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken | None,
        result: GatewayResult,
    ) -> GatewayResult:
        def digest(value: object) -> str:
            try:
                return H(value)
            except (TypeError, ValueError, AttributeError):
                return H({"invalid_type": type(value).__name__})

        principal = getattr(action, "principal", "unknown")
        try:
            self._audit(
                "dispatch_rejected",
                digest(principal),
                {
                    "rule_ids": result.rule_ids,
                    "action_hash": digest(action),
                    "cert_hash": digest(cert),
                    "token_hash": digest(token),
                },
            )
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            rule = "AUD-CHAIN" if str(exc) == "AUD-CHAIN" else "AUD-WRITE"
            return self._failure(principal, rule)
        return result

    def _dispatch_checked(
        self,
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken | None,
        *,
        device_control: bool = False,
        contact: Contact | None = None,
        confirmation: UserInput | None = None,
    ) -> GatewayResult:
        with _LOCK:
            principal = getattr(action, "principal", "unknown")
            reserved: BusinessEvent | None = None
            try:
                self.vault.ensure_safe((action, cert, token, contact, confirmation))
                action = BankAction.model_validate(action.model_dump(mode="python"))
                cert = BankCertificate.model_validate(cert.model_dump(mode="python"))
                if token is not None:
                    token = ApprovalToken.model_validate(token.model_dump(mode="python"))
                state = self.store.snapshot()
                if action.kind in _CONTROL and not device_control:
                    return self._failure(principal, "CTRL-MFA")
                if self._write_failed or not self.audit.verify():
                    return self._failure(principal, "AUD-CHAIN")
                rule = self._scheduled_action_rule(action, state)
                if rule:
                    return self._failure(principal, rule)
                if action.kind not in _READ_ONLY and principal in state.security.locked_at:
                    self._skip_locked_run(action.action_id, principal)
                    return self._failure(principal, "APR-LOCK")
                rule = self._plan_rule(action, cert, state)
                if rule:
                    if action.plan_id in self._voided_plans:
                        self._skip_locked_run(action.action_id, principal)
                    return self._failure(principal, rule)
                spa = inspect_spa(action, cert, state, resolve_amount(action, state))
                runtime = spa.is_spa and not spa.is_creation and not spa.errors
                if spa.is_spa and not spa.is_creation and spa.errors:
                    verdict = check(action, cert, state, phase="dispatch")
                    self._record_verdict(action, verdict)
                    run = state.schedules.get(action.action_id)
                    if run and run.status in {"pending", "due", "waiting_mfa"}:
                        if state.now >= run.expires_at:
                            self._schedule_status(run.id, "expired")
                        elif state.now >= run.due_at:
                            self._schedule_status(run.id, "skipped")
                    return GatewayResult(
                        "rejected", list(getattr(verdict, "rule_ids", spa.errors)), verdict=verdict
                    )
                if action.kind not in _GREEN and not runtime:
                    if token is None:
                        return self._failure(principal, "APR-REQUIRED")
                    rule = self._token_rule(action, cert, token, state)
                    if rule:
                        return self._failure(principal, rule)
                    self._security(consumed_nonces=[*state.security.consumed_nonces, token.nonce])
                    self._audit(
                        "approval_consumed",
                        principal,
                        {"token_id": token.token_id, "token_hash": H(token)},
                        action,
                    )
                state = self.store.snapshot()
                key = intent_key(action, state)
                previous = latest_events(state).get(key)
                if previous is not None and previous.event != "failed":
                    return self._failure(principal, "IDEM-DUP")
                if cert.mfa_grant_refs:
                    scope = mfa_scope(
                        action,
                        token.card_hash if token else H(binding(action, cert, state).card_core),
                    )
                    for ref in cert.mfa_grant_refs:
                        state = self.store.snapshot()
                        grant = state.security.mfa_grants.get(ref)
                        rule = (
                            "MFA-INVALID"
                            if grant is None
                            else self._grant_rule(grant, principal, scope, state)
                        )
                        if rule:
                            return self._failure(principal, rule)
                state = self.store.snapshot()
                verdict = check(
                    action,
                    cert,
                    state,
                    phase="dispatch",
                    approved_at=token.issued_at if token else None,
                )
                self._record_verdict(action, verdict)
                if token is not None:
                    try:
                        drift = H(binding(action, cert, state).card_core) != token.card_hash
                    except (KeyError, ValueError, TypeError):
                        drift = True
                    if drift:
                        return self._failure(principal, "APR-DRIFT")
                if verdict.outcome != "Accept":
                    if runtime and verdict.outcome == "Escalate":
                        self._schedule_status(action.action_id, "waiting_mfa")
                    elif runtime:
                        canonical_action, canonical_cert = self.prepare_scheduled_run(
                            action.action_id
                        )
                        canonical_verdict = check(
                            canonical_action, canonical_cert, state, phase="dispatch"
                        )
                        if canonical_verdict.outcome == "Reject":
                            self._schedule_status(action.action_id, "skipped")
                    return GatewayResult(
                        "waiting_mfa" if runtime and verdict.outcome == "Escalate" else "rejected",
                        list(verdict.rule_ids),
                        verdict=verdict,
                    )
                if cert.mfa_grant_refs:
                    state = self.store.snapshot()
                    self._security(
                        consumed_grant_ids=[
                            *state.security.consumed_grant_ids,
                            *cert.mfa_grant_refs,
                        ]
                    )
                    state = self.store.snapshot()
                if action.kind in _CONTROL:
                    return self._control(action, cert, token, verdict, contact, confirmation)
                if action.kind in _ANALYSIS | _INVESTMENT_ANALYSIS | {
                    "aa_request",
                    "sandbox_analyze",
                }:
                    return self._analyze(action, cert, token, verdict)
                if action.kind == "schedule_transfer":
                    return self._create_schedule(action, cert, token, verdict)
                if action.kind == "cancel_schedule":
                    ref = action.args.model_dump()["schedule_ref"]
                    schedules = {
                        key: run.model_copy(
                            update={"status": "cancelled", "version": run.version + 1}
                        )
                        if run.spa_ref == ref and run.status in {"pending", "due", "waiting_mfa"}
                        else run
                        for key, run in state.schedules.items()
                    }
                    return self._controlled_event(
                        action,
                        {"spa_ref": ref},
                        verdict,
                        cert=cert,
                        token=token,
                        schedules=schedules,
                    )
                order = compile_order(action, cert, state)
                self.vault.ensure_safe(order, rule="PII-OUT")
                debit, credit = movements(order, state)
                self._audit(
                    "dispatch_intent",
                    principal,
                    {
                        "intent_key": key,
                        "action_hash": H(action),
                        "cert_hash": H(cert),
                        "token_id": token.token_id if token else None,
                    },
                    action,
                )
                reserved = BusinessEvent(
                    id=_id(key, len(state.ledger), "reserved"),
                    intent_key=key,
                    event="reserved",
                    kind=action.kind,
                    principal=principal,
                    commitment_id=order.commitment_id,
                    debit=debit,
                    credit=credit,
                    object_delta={
                        "order": order.model_dump(mode="json"),
                        "action": action.model_dump(mode="json"),
                        "cert": cert.model_dump(mode="json"),
                        "token": token.model_dump(mode="json") if token else None,
                        "verdict": verdict.model_dump(mode="json"),
                        **(
                            {
                                "original_position": state.positions[
                                    order.args.model_dump()["position_ref"]
                                ].model_dump(mode="json")
                            }
                            if action.kind == "redeem_product"
                            else {}
                        ),
                    },
                    ts=state.now,
                )
                if action.kind == "redeem_product":
                    if any(event.id == reserved.id for event in state.ledger):
                        raise ValueError("Duplicate business event ID")
                    self.store.update(
                        ledger=[*state.ledger, reserved], **reservation_updates(order, state)
                    )
                else:
                    self.store.append_event(reserved)
                try:
                    receipt = self.bank.execute(order)
                except Exception:
                    self._unknown(reserved, "bank_response")
                    return GatewayResult("unknown", ["BANK-RECEIPT"], verdict=verdict)
                return self._finish(
                    order, receipt, reserved, verdict, action=action, cert=cert, token=token
                )
            except OSError:
                if reserved is not None:
                    self._unknown(reserved, "AUD-WRITE")
                    return GatewayResult("unknown", ["AUD-WRITE"])
                return self._failure(principal, "AUD-WRITE")
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                rule = (
                    str(exc)
                    if str(exc) in {"AUD-CHAIN", "PII-CTX", "PII-OUT"}
                    else "SCHEMA-INVALID"
                )
                if reserved is not None:
                    self._unknown(reserved, rule)
                    return GatewayResult("unknown", [rule])
                return self._failure(principal, rule)

    def _analyze(
        self,
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken | None,
        verdict: Verdict,
    ) -> GatewayResult:
        state = self.store.snapshot()
        if (
            self._analysis_key is None
            or self._analysis_key.verify_key.encode().hex() != state.roots.gateway_pubkey
        ):
            return self._failure(action.principal, "TOOL-UNAVAILABLE")
        updates: dict[str, Any] = {}
        if action.kind == "sandbox_analyze":
            from corridor.gateway.sandbox_monitor import run_sandbox

            dataset, program = self._sandbox.resolve(action, state)
            run = run_sandbox(program, dataset.rows)
            payload: dict[str, Any] = {
                "program_hash": sha256(program.encode("utf-8")).hexdigest(),
                "input_hash": H(dataset.rows),
                "output_hash": H(run.results),
                "status": run.status,
                "reason": run.reason,
                "account_ref": dataset.account_ref,
                "period": dataset.period,
                "row_count": len(dataset.rows),
                "program": program,
            }
            if run.status == "ok":
                payload.update(results=run.results)
            self._audit("sandbox_run", action.principal, payload, action)
            if run.status != "ok":
                return self._failure(action.principal, run.rule_ids[0])
            receipt = exploratory_receipt(
                action, state, dataset, program, run.results, self._analysis_key
            )
        elif action.kind == "aa_request":
            amount = resolve_amount(action, state)
            if amount is None:
                return self._failure(action.principal, "DOMAIN-AA")
            args = action.args.model_dump()
            participants = sorted(args["participant_refs"])
            quotient, remainder = divmod(int(amount * 100), len(participants))
            results = {
                "total": AnalysisResult(
                    value=str(amount.numerator) + "/" + str(amount.denominator),
                    unit="CNY",
                    source_tx_ids=[],
                ),
                "request_ids": AnalysisResult(
                    value=[
                        _id(action.intent_id, index, f"aa-{ref}")
                        for index, ref in enumerate(participants)
                    ],
                    unit="request_ids",
                    source_tx_ids=[],
                ),
                "status": AnalysisResult(
                    value="requested", unit="request_status", source_tx_ids=[]
                ),
            }
            from fractions import Fraction

            for index, ref in enumerate(participants):
                share = Fraction(quotient + (index < remainder), 100)
                results[f"shares.{ref}"] = AnalysisResult(
                    value=f"{share.numerator}/{share.denominator}", unit="CNY", source_tx_ids=[]
                )
            receipt = AnalysisReceipt(
                receipt_id=_id(action.intent_id, 0, "aa-receipt"),
                dataset_hash=H({"total": amount, "participants": participants}),
                function_id="aa_split_v1",
                parameters={"principal": action.principal, "action_hash": H(action)},
                results=results,
                trust="builtin",
                computed_at=state.now,
                sig="0" * 128,
            )
            receipt = receipt.model_copy(update={"sig": sign(self._analysis_key, RECEIPT, receipt)})
        elif action.kind in _INVESTMENT_ANALYSIS:
            receipt, updates = build_investment_analysis(
                action, state, self._analysis_key, self._risk_key
            )
        else:
            receipt = build_analysis(action, state, self._analysis_key)
        self.vault.ensure_safe(receipt, rule="PII-OUT")
        effective_level = (
            receipt.results["effective_level"].value
            if "effective_level" in receipt.results
            else None
        )
        suitability_metadata = receipt.parameters.get("suitability")
        if isinstance(suitability_metadata, dict):
            effective_level = suitability_metadata.get("effective_level")
        event = BusinessEvent(
            id=_id(action.intent_id, len(state.ledger), "analysis"),
            intent_key=intent_key(action, state),
            event="settled",
            kind=action.kind,
            principal=action.principal,
            object_delta={
                "authorization_ref": cert.authorization_ref,
                "analysis_receipt_id": receipt.id,
                **(
                    {
                        "device_session_id": action.device_session_id,
                        "effective_level_cap": effective_level,
                    }
                    if effective_level is not None
                    else {}
                ),
                **(
                    {
                        "answers_input_ref": action.args.model_dump()["answers_input_ref"],
                        "risk_assessment_ref": receipt.results["risk_assessment_ref"].value,
                    }
                    if action.kind == "risk_assess"
                    else {}
                ),
                "action_hash": H(action),
                "receipt_hash": H(receipt),
            },
            ts=state.now,
        )
        self._audit(
            "analysis_completed",
            action.principal,
            {
                "receipt_hash": H(receipt),
                "receipt_id": receipt.id,
                "function_id": receipt.function_id,
            },
            action,
        )
        result = GatewayResult("settled", verdict=verdict, analysis_receipt=receipt)
        self._decision(action, cert, token, result)
        self.store.update(
            ledger=[*state.ledger, event],
            receipts={**state.receipts, receipt.id: receipt},
            **updates,
        )
        self.audit.checkpoint()
        return result

    def _finish(
        self,
        order: BankOrder,
        receipt: BankReceipt,
        reserved: BusinessEvent,
        verdict: Verdict | None = None,
        *,
        action: BankAction | None = None,
        cert: BankCertificate | None = None,
        token: ApprovalToken | None = None,
    ) -> GatewayResult:
        state = self.store.snapshot()
        self.vault.ensure_safe(receipt, rule="PII-OUT")
        if not validate_receipt(order, receipt, state):
            self._unknown(reserved, "BANK-RECEIPT")
            return GatewayResult("unknown", ["BANK-RECEIPT"], verdict=verdict)
        updates = receipt_updates(order, receipt, state)
        terminal = reserved.model_copy(
            update={
                "id": _id(order.intent_key, len(state.ledger), receipt.status),
                "event": "reserved" if receipt.status == "pending" else receipt.status,
                "ts": state.now,
                "bank_receipt_id": receipt.id,
            }
        )
        security = state.security.model_copy(
            update={
                "unknown_intent_ids": [
                    key for key in state.security.unknown_intent_ids if key != order.intent_key
                ],
                "reject_streak": {**state.security.reject_streak, order.principal: 0}
                if order.kind not in _GREEN and receipt.status == "settled"
                else state.security.reject_streak,
            }
        )
        schedules = dict(state.schedules)
        run = schedules.get(order.action_id)
        if run is not None:
            schedules[run.id] = run.model_copy(
                update={
                    "status": "executed" if receipt.status == "settled" else "skipped",
                    "version": run.version + 1,
                }
            )
        self._audit(
            "bank_receipt_verified",
            order.principal,
            {"receipt_hash": H(receipt), "intent_key": order.intent_key, "status": receipt.status},
        )
        result = GatewayResult(receipt.status, receipt=receipt, verdict=verdict)
        if action is not None and cert is not None:
            self._decision(action, cert, token, result)
        self.store.update(
            ledger=[*state.ledger, terminal], security=security, schedules=schedules, **updates
        )
        self.audit.checkpoint()
        return result

    def _unknown(self, reserved: BusinessEvent, reason: str) -> None:
        try:
            state = self.store.snapshot()
            event = reserved.model_copy(
                update={
                    "id": _id(reserved.intent_key, len(state.ledger), "unknown"),
                    "event": "unknown",
                    "ts": state.now,
                }
            )
            security = state.security.model_copy(
                update={
                    "unknown_intent_ids": list(
                        dict.fromkeys([*state.security.unknown_intent_ids, reserved.intent_key])
                    ),
                    "locked_at": {
                        **state.security.locked_at,
                        reserved.principal: state.security.locked_at.get(
                            reserved.principal, state.now
                        ),
                    },
                    "lock_reason": {**state.security.lock_reason, reserved.principal: reason},
                }
            )
            self.store.update(ledger=[*state.ledger, event], security=security)
            saved_action = reserved.object_delta.get("action")
            if isinstance(saved_action, dict):
                self._allocation_outcome(BankAction.model_validate(saved_action), "unknown")
            self._void_plans(reserved.principal)
            self._audit(
                "unknown", reserved.principal, {"intent_key": reserved.intent_key, "reason": reason}
            )
        except (OSError, ValueError):
            self._write_failed = True

    def reconcile(self, key: str) -> GatewayResult:
        with _LOCK:
            state = self.store.snapshot()
            event = latest_events(state).get(key)
            if event is None or event.event not in {"unknown", "reserved"}:
                return GatewayResult("rejected", ["IDEM-DUP"])
            try:
                order = BankOrder.model_validate(event.object_delta["order"])
                action = BankAction.model_validate(event.object_delta["action"])
                cert = BankCertificate.model_validate(event.object_delta["cert"])
                token_data = event.object_delta["token"]
                token = ApprovalToken.model_validate(token_data) if token_data is not None else None
                verdict = Accept.model_validate(event.object_delta["verdict"])
                if (
                    cert.action_hash != H(action)
                    or action.action_id != order.action_id
                    or action.kind != order.kind
                    or action.principal != order.principal
                    or event.principal != order.principal
                    or event.kind != order.kind
                    or key != order.intent_key
                    or (
                        intent_key(action, state) != order.intent_key
                        and not self._legacy_reconciliation_key(
                            action, cert, token, verdict, order, state
                        )
                    )
                ):
                    return GatewayResult("unknown", ["BANK-RECEIPT"])
                receipt = self.bank.lookup(key)
                if receipt is None:
                    return GatewayResult("unknown", ["BANK-RECEIPT"])
                result = self._finish(
                    order, receipt, event, verdict, action=action, cert=cert, token=token
                )
                self._note_node(action, result)
                return result
            except (OSError, ValueError, TypeError, KeyError):
                return GatewayResult("unknown", ["BANK-RECEIPT"])

    @staticmethod
    def _legacy_reconciliation_key(
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken | None,
        verdict: Accept,
        order: BankOrder,
        state: BankState,
    ) -> bool:
        """Recognize a persisted pre-F1 dispatch only while reconciling its bank receipt."""
        authorization = state.authorizations.get(cert.authorization_ref)
        customer = state.customers.get(action.principal)
        if (
            not isinstance(authorization, OperationAuthorization)
            or customer is None
            or authorization.principal != action.principal
            or authorization.intent_id != action.intent_id
            or authorization.allowed_kind != action.kind
            or order.requested_at >= authorization.expires_at
            or not verify(customer.device_pubkey, CONTROL, authorization, authorization.sig)
            or order.intent_key
            != H({
                "principal": action.principal,
                "intent_id": action.intent_id,
                "node_id": action.node_id,
                "kind": action.kind,
            })
            or token is None
            or token.principal != action.principal
            or token.device_session_id != action.device_session_id
            or token.action_hash != H(action)
            or token.cert_hash != H(cert)
            or token.plan_id != action.plan_id
            or token.plan_hash != action.plan_hash
            or token.node_id != action.node_id
            or token.tier != verdict.tier
            or token.card_hash != H(verdict.verified_facts.get("card_core", {}))
            or not token.issued_at <= order.requested_at < token.expiry
            or token.expiry > add_seconds(token.issued_at, 300)
            or token.nonce not in state.security.consumed_nonces
            or not verify(customer.device_pubkey, APPROVE, token, token.sig)
        ):
            return False
        expected = compile_order(action, cert, state).model_copy(
            update={
                "intent_key": order.intent_key,
                "requested_at": order.requested_at,
            }
        )
        return expected == order

    def _decision(
        self,
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken | None,
        result: GatewayResult,
    ) -> None:
        compensation_field = {
            "refund_request": "receipt_ref",
            "cancel_order": "order_ref",
            "cancel_schedule": "schedule_ref",
            "cancel_subscription": "authorization_ref",
        }.get(action.kind)
        compensation_ref = action.args.model_dump().get(compensation_field or "")
        record: dict[str, Any] = {
            "action": action,
            "cert": cert,
            "verdict": result.verdict,
            "token_id": token.token_id if token else None,
            "tier": result.verdict.tier if result.verdict else None,
            "card_hash": token.card_hash
            if token
            else H(result.verdict.verified_facts.get("card_core", {}) if result.verdict else {}),
            "mfa_grant_id": cert.mfa_grant_refs[0] if cert.mfa_grant_refs else None,
            "bank_receipt": result.receipt,
            "analysis_receipt": result.analysis_receipt,
            "compensation_refs": [compensation_ref] if compensation_ref else [],
            "audit_checkpoint": self.audit.checkpoint(),
        }
        parent_ref = action.args.model_dump().get("allocation_ref")
        if parent_ref:
            parent = self.store.snapshot().allocation_plans.get(parent_ref)
            if parent is not None:
                record["allocation"] = {
                    "parent_ref": parent.id,
                    "parent_intent_id": parent.parent_intent_id,
                    "parent_plan_hash": parent.plan_hash,
                    "biac_hash": parent.biac_hash,
                    "item_ref": action.args.model_dump()["allocation_item_ref"],
                }
        self.vault.ensure_safe(record, rule="PII-OUT")
        if self.evidence_dir is not None:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            key = (
                result.receipt.intent_key
                if result.receipt
                else intent_key(action, self.store.snapshot())
            )
            data = jcs_bytes(record)
            path = self.evidence_dir / f"{key}.json"
            if path.exists():
                path = self.evidence_dir / f"{key}-{H(record)[:16]}.json"
            if path.exists():
                if path.read_bytes() != data:
                    raise OSError("AUD-WRITE")
                return
            with path.open("xb") as stream:
                if stream.write(data) != len(data):
                    raise OSError("AUD-WRITE")

    def verify_log(self, checkpoint: dict[str, Any] | None = None) -> bool:
        return self.audit.verify(checkpoint)

    def interrupt(self, plan_id: str) -> GatewayResult:
        parent_id = self._allocation_parent(plan_id)
        if parent_id is not None:
            return self.stop_allocation(parent_id)
        return self._stop_plan(plan_id, "plan_interrupted")

    def handoff(self, plan_id: str) -> GatewayResult:
        parent_id = self._allocation_parent(plan_id)
        if parent_id is not None:
            return self.stop_allocation(parent_id, handoff=True)
        return self._stop_plan(plan_id, "plan_handoff")

    def _allocation_parent(self, plan_id: str) -> str | None:
        state = self.store.snapshot()
        if plan_id in state.allocation_plans:
            return plan_id
        if not state.allocation_plans:
            return None
        from corridor.gateway.allocations import allocation_parent_for_child

        return allocation_parent_for_child(state, plan_id)

    def _allocation_outcome(self, action: BankAction, status: str) -> None:
        parent_id = self._allocation_parent(action.plan_id)
        if parent_id is None:
            return
        from corridor.gateway.allocations import mark_allocation

        mark_allocation(self, self.store.snapshot().allocation_plans[parent_id], status)

    def draft_allocation(
        self, principal: str, parent_intent_id: str, request_ref: str
    ) -> "AllocationDraft":
        from corridor.gateway.allocations import draft_allocation

        with _LOCK:
            return draft_allocation(self, principal, parent_intent_id, request_ref)

    def allocation_alternatives(
        self, principal: str, parent_intent_id: str, request_ref: str
    ) -> dict[str, Any]:
        """Read-only deterministic alternatives; selection needs a new device signature."""
        from corridor.gateway.investments import build_allocation_alternatives

        with _LOCK:
            state = self.store.snapshot()
            if principal not in state.security.active_device_sessions:
                raise ValueError("AUTH-PRINCIPAL")
            self.vault.ensure_safe((principal, parent_intent_id, request_ref))
            preview = build_allocation_alternatives(principal, parent_intent_id, request_ref, state)
            result: dict[str, Any] = preview.model_dump(mode="json")
            self.vault.ensure_safe(result, rule="PII-OUT")
            return result

    def allocation_correction_diff(
        self, principal: str, before_request_ref: str, after_request_ref: str
    ) -> dict[str, Any]:
        """Compare signed requests without granting execution or approval authority."""
        from corridor.gateway.investments import build_allocation_correction_diff

        with _LOCK:
            state = self.store.snapshot()
            if principal not in state.security.active_device_sessions:
                raise ValueError("AUTH-PRINCIPAL")
            self.vault.ensure_safe((principal, before_request_ref, after_request_ref))
            diff = build_allocation_correction_diff(
                principal, before_request_ref, after_request_ref, state
            )
            result: dict[str, Any] = diff.model_dump(mode="json")
            self.vault.ensure_safe(result, rule="PII-OUT")
            return result

    def register_allocation(
        self,
        draft: "AllocationDraft",
        *,
        selection: UserInput | None,
        inputs: Sequence[UserInput],
        authorizations: Sequence[OperationAuthorization],
    ) -> GatewayResult:
        from corridor.gateway.allocations import register_allocation

        with _LOCK:
            return register_allocation(
                self, draft, selection=selection, inputs=inputs, authorizations=authorizations
            )

    def allocation_snapshot(self, parent_id: str) -> dict[str, Any]:
        from corridor.gateway.allocations import allocation_snapshot

        with _LOCK:
            snapshot = allocation_snapshot(self, parent_id)
            rows = snapshot["items"]
            parent = self.store.snapshot().allocation_plans[parent_id]
            for index, row in enumerate(rows, start=1):
                row["leg_index"] = index
                row["leg_count"] = len(rows)
                item = parent.items[index - 1]
                if row["status"] == "pending" and item.child_plan_id in self._plans:
                    runtime = self.plan_snapshot(item.child_plan_id)
                    row["status"] = runtime["nodes"][item.child_node_id]["status"]
            snapshot["approval_budget"] = self.allocation_approval_budget(parent_id)
            snapshot["next_leg"] = next((row for row in rows if row["status"] != "settled"), None)
            return snapshot

    def advance_allocation(self, parent_id: str) -> GatewayResult:
        from corridor.gateway.allocations import advance_allocation

        with _LOCK:
            budget = self.allocation_approval_budget(parent_id)
            principal = self.store.snapshot().allocation_plans[parent_id].principal
            if budget["locked"]:
                return self._failure(principal, "APR-LOCK")
            if (
                budget["preflight_required"]
                and not budget["rule_ids"]
                and not budget["can_start"]
                and budget["required"] > budget["remaining"]
            ):
                self._audit(
                    "allocation_preflight_refused",
                    self.store.snapshot().allocation_plans[parent_id].principal,
                    {"allocation_ref": parent_id, "approval_budget": budget},
                )
                return GatewayResult(
                    "rejected",
                    ["APR-BUDGET"],
                    details={"approval_budget": budget, "message": budget["message"]},
                )
            result = advance_allocation(self, parent_id)
            snapshot = self.allocation_snapshot(parent_id)
            result.details["approval_budget"] = snapshot["approval_budget"]
            result.details["leg"] = snapshot["next_leg"]
            return result

    def stop_allocation(self, parent_id: str, *, handoff: bool = False) -> GatewayResult:
        from corridor.gateway.allocations import stop_allocation

        with _LOCK:
            return stop_allocation(self, parent_id, handoff=handoff)

    def plan_snapshot(self, plan_id: str) -> dict[str, Any]:
        with _LOCK:
            plan = self._plans[plan_id]
            runtime = project_runtime(plan, self.audit.records())
            return {
                "plan": plan.model_dump(mode="json"),
                "ownership_epoch": plan.ownership_epoch,
                "nodes": {
                    node.node_id: {
                        "status": runtime.statuses[node.node_id],
                        "receipt_ref": runtime.receipt_refs.get(node.node_id),
                    }
                    for node in plan.nodes
                },
                "audit_checkpoint": self.audit.checkpoint(),
                "blocked": plan_id in self._blocked_plans,
            }

    def _node_status(
        self, plan_id: str, node_id: str, status: str, receipt_ref: str | None = None
    ) -> None:
        plan = self._plans[plan_id]
        current = self.plan_snapshot(plan_id)["nodes"][node_id]
        if current["status"] == status and current.get("receipt_ref") == receipt_ref:
            return
        self.audit.append(
            "plan_node_status",
            now=self.store.snapshot().now,
            principal_token=plan.principal,
            plan_id=plan_id,
            node_id=node_id,
            payload={
                "status": status,
                "receipt_ref": receipt_ref,
                "plan_hash": H(plan),
                "ownership_epoch": plan.ownership_epoch,
            },
        )

    def _note_node(self, action: BankAction, result: GatewayResult) -> None:
        plan = self._plans.get(getattr(action, "plan_id", ""))
        if plan is None or not any(node.node_id == action.node_id for node in plan.nodes):
            return
        receipt_ref = (
            result.receipt.id
            if result.receipt
            else result.analysis_receipt.id
            if result.analysis_receipt
            else None
        )
        status = {
            "settled": "succeeded",
            "pending": "waiting_settlement",
            "failed": "failed",
            "unknown": "unknown",
            "waiting_mfa": "waiting_mfa",
        }.get(result.status)
        if result.status == "controlled":
            status = "scheduled" if action.kind == "schedule_transfer" else "succeeded"
            event = latest_events(self.store.snapshot()).get(
                intent_key(action, self.store.snapshot())
            )
            receipt_ref = event.id if event else None
        if status:
            self._node_status(plan.plan_id, action.node_id, status, receipt_ref)

    def advance_plan(self, plan_id: str, ownership_epoch: int = 0) -> list[GatewayResult]:
        from corridor.gateway.orchestration import advance_plan

        with _LOCK:
            return advance_plan(self, plan_id, ownership_epoch)

    def prepare_scheduled_run(self, run_id: str) -> tuple[BankAction, BankCertificate]:
        from corridor.gateway.orchestration import compile_node

        with _LOCK:
            run = self.store.snapshot().schedules[run_id]
            return compile_node(self, self._plans[run.plan_id], run.node_id, run_id=run_id)

    def tick(self) -> list[GatewayResult]:
        with _LOCK:
            results = []
            for run in self.store.snapshot().schedules.values():
                if run.plan_id in self._voided_plans:
                    self._skip_locked_run(run.id, run.owner)
            for plan_id in sorted(self._plans):
                if plan_id in self._blocked_plans:
                    continue
                if any(
                    run.plan_id == plan_id and run.status in {"pending", "due", "waiting_mfa"}
                    for run in self.store.snapshot().schedules.values()
                ):
                    results.extend(self.advance_plan(plan_id, self._plans[plan_id].ownership_epoch))
            return results

    def advance_clock(self, now: str) -> list[GatewayResult]:
        from corridor.schemas.time import parse_time

        with _LOCK:
            parse_time(now)
            if now < self.store.snapshot().now:
                raise ValueError("The simulated clock cannot move backward")
            self.store.update(now=now)
            emitted = self.bank.advance_clock(now)
            results = []
            for receipt in emitted:
                if receipt.kind == "redeem_product":
                    results.append(self.reconcile(receipt.intent_key))
                elif receipt.kind == "subscription_debit":
                    results.append(self._subscription_event(receipt))
            results.extend(self.tick())
            return results

    def _subscription_event(self, receipt: BankReceipt) -> GatewayResult:
        from fractions import Fraction

        from corridor.schemas.bank import AccountMovement
        from corridor.schemas.time import parse_time

        state = self.store.snapshot()
        if (
            not verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig)
            or receipt.executed_at > state.now
        ):
            return self._failure("unknown", "BANK-RECEIPT")
        effect = receipt.exact_effects[-1] if receipt.exact_effects else None
        sub = state.subscriptions.get(effect.object_ref) if effect else None
        if (
            sub is None
            or sub.status != "active"
            or effect is None
            or effect.effect_type != "state"
            or effect.account_ref is not None
            or effect.counterparty_ref is not None
            or effect.amount is not None
            or effect.field != "next_due"
            or effect.before != sub.next_due
            or not isinstance(effect.after, str)
            or effect.after <= sub.next_due
            or receipt.intent_key != H({"subscription_ref": sub.id, "due_at": sub.next_due})
        ):
            return self._failure(sub.owner if sub else "unknown", "BANK-RECEIPT")
        previous = parse_time(sub.next_due)
        year, month_zero = divmod(previous.year * 12 + previous.month - 1 + sub.period_months, 12)
        next_due = previous.replace(
            year=year,
            month=month_zero + 1,
            day=min(previous.day, monthrange(year, month_zero + 1)[1]),
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        if (
            effect.after != next_due
            or receipt.executed_at != sub.next_due
            or receipt.kind != "subscription_debit"
            or receipt.settle_at is not None
        ):
            return self._failure(sub.owner, "BANK-RECEIPT")
        if receipt.intent_key in latest_events(state):
            return GatewayResult("rejected", ["IDEM-DUP"])
        debit = None
        if receipt.status == "settled":
            from corridor.stores.bank import available

            merchant = state.merchants[sub.merchant_ref]
            effects = receipt.exact_effects
            if (
                len(effects) != 3
                or effects[0].effect_type != "debit"
                or effects[1].effect_type != "credit"
                or effects[0].account_ref != sub.source_account_ref
                or effects[0].object_ref != sub.source_account_ref
                or effects[0].counterparty_ref != merchant.destination_ref
                or effects[0].field != "balance"
                or effects[0].amount != sub.amount
                or effects[1].amount != sub.amount
                or effects[1].account_ref != merchant.destination_ref
                or effects[1].object_ref != merchant.destination_ref
                or effects[1].counterparty_ref != sub.source_account_ref
                or effects[1].field != "balance"
                or Fraction(str(effects[0].before)) != available(state, sub.source_account_ref)
                or Fraction(str(effects[0].after))
                != available(state, sub.source_account_ref) - sub.amount
                or Fraction(str(effects[1].after)) - Fraction(str(effects[1].before)) != sub.amount
            ):
                return self._failure(sub.owner, "BANK-RECEIPT")
            debit = AccountMovement(account_ref=sub.source_account_ref, amount=sub.amount)
        elif receipt.status != "failed" or len(receipt.exact_effects) != 1:
            return self._failure(sub.owner, "BANK-RECEIPT")
        event = BusinessEvent(
            id=_id(receipt.intent_key, 0, "mandate"),
            intent_key=receipt.intent_key,
            event=receipt.status,
            kind="subscription_debit",
            principal=sub.owner,
            debit=debit,
            ts=receipt.executed_at,
            bank_receipt_id=receipt.id,
        )
        self._audit("subscription_debit", sub.owner, {"receipt_hash": H(receipt)})
        self.store.update(
            ledger=[*state.ledger, event],
            receipts={**state.receipts, receipt.id: receipt},
            subscriptions={
                **state.subscriptions,
                sub.id: sub.model_copy(
                    update={"next_due": effect.after, "version": sub.version + 1}
                ),
            },
        )
        return GatewayResult(receipt.status, receipt=receipt)

    def birthday_suggestions(self, principal: str) -> list[dict[str, str]]:
        from corridor.gateway.orchestration import birthday_suggestions

        with _LOCK:
            return birthday_suggestions(self, principal)

    def request_compensation(self, plan_id: str, node_id: str | None = None) -> GatewayResult:
        from corridor.gateway.orchestration import compensation_suggestions

        with _LOCK:
            plan = self._plans.get(plan_id)
            if plan is None:
                return GatewayResult("rejected", ["PLAN-SCHEMA"])
            suggestions = compensation_suggestions(self, plan_id, node_id)
            self.audit.append(
                "compensation_proposed",
                now=self.store.snapshot().now,
                principal_token=plan.principal,
                plan_id=plan_id,
                payload=cast(dict[str, JsonValue], {"suggestions": suggestions}),
            )
            return GatewayResult("compensation_proposed", details={"suggestions": suggestions})

    def _stop_plan(self, plan_id: str, event: str) -> GatewayResult:
        with _LOCK:
            plan = self._plans.get(plan_id)
            if plan is None:
                return GatewayResult("rejected", ["PLAN-SCHEMA"])
            try:
                handoff = event == "plan_handoff"
                new = (
                    plan.model_copy(
                        update={
                            "revision": plan.revision + 1,
                            "ownership_epoch": plan.ownership_epoch + 1,
                        }
                    )
                    if handoff
                    else plan
                )
                self.audit.append(
                    event,
                    now=self.store.snapshot().now,
                    principal_token=plan.principal,
                    plan_id=plan_id,
                    payload={"plan_hash": H(plan), "ownership_epoch": new.ownership_epoch},
                )
                self._blocked_plans.add(plan_id)
                if handoff:
                    self._handoff_plans.add(plan_id)
                    self.audit.append(
                        "plan_registered",
                        now=self.store.snapshot().now,
                        principal_token=plan.principal,
                        plan_id=plan_id,
                        payload={"plan": new.model_dump(mode="json")},
                    )
                    self._plans[plan_id] = new
                state = self.store.snapshot()
                self.store.update(
                    schedules={
                        key: run.model_copy(
                            update={"status": "cancelled", "version": run.version + 1}
                        )
                        if run.plan_id == plan_id
                        and run.status in {"pending", "due", "waiting_mfa"}
                        else run
                        for key, run in state.schedules.items()
                    }
                )
                return GatewayResult(
                    "handoff" if handoff else "interrupted", details=self.plan_snapshot(plan_id)
                )
            except (ValueError, OSError):
                self._blocked_plans.add(plan_id)
                return self._failure(plan.principal, "AUD-WRITE")

    def resume_scope(self, plan_id: str) -> dict[str, JsonValue]:
        plan = self._plans[plan_id]
        return {
            "control": "plan_resume",
            "plan_id": plan_id,
            "plan_hash": H(plan),
            "ownership_epoch": plan.ownership_epoch,
        }

    def resume(self, plan_id: str, confirmation: UserInput | None = None) -> GatewayResult:
        with _LOCK:
            plan = self._plans.get(plan_id)
            if plan is None or plan_id not in self._handoff_plans or confirmation is None:
                return GatewayResult("rejected", ["PLAN-OWNER"])
            state = self.store.snapshot()
            if plan_id in self._voided_plans:
                return self._failure(plan.principal, "APR-VOID")
            if plan.principal in state.security.locked_at:
                return self._failure(plan.principal, "APR-LOCK")
            scope = self.resume_scope(plan_id)
            customer = state.customers[plan.principal]
            try:
                confirmation = UserInput.model_validate(confirmation.model_dump(mode="python"))
                if (
                    confirmation.principal != plan.principal
                    or confirmation.scope_id != H(scope)
                    or confirmation.slot != "plan_resume"
                    or confirmation.value != scope
                    or any(
                        item.supersedes == confirmation.id for item in state.user_inputs.values()
                    )
                    or not confirmation.submitted_at
                    <= state.now
                    < add_seconds(confirmation.submitted_at, 300)
                    or not verify(customer.device_pubkey, INPUT, confirmation, confirmation.sig)
                ):
                    return self._failure(plan.principal, "PLAN-OWNER")
                if confirmation.id not in state.user_inputs:
                    self.store.append_input(confirmation)
                elif state.user_inputs[confirmation.id] != confirmation:
                    return self._failure(plan.principal, "PLAN-OWNER")
                new = plan.model_copy(
                    update={
                        "revision": plan.revision + 1,
                        "ownership_epoch": plan.ownership_epoch + 1,
                        "device_session_id": state.security.active_device_sessions[plan.principal],
                    }
                )
                self.audit.append(
                    "plan_registered",
                    now=state.now,
                    principal_token=plan.principal,
                    plan_id=plan_id,
                    payload={"plan": new.model_dump(mode="json")},
                )
                self.audit.append(
                    "plan_resumed",
                    now=state.now,
                    principal_token=plan.principal,
                    plan_id=plan_id,
                    payload={
                        "plan_hash": H(new),
                        "ownership_epoch": new.ownership_epoch,
                        "confirmation_hash": H(confirmation),
                    },
                )
                self._plans[plan_id] = new
                self._blocked_plans.discard(plan_id)
                self._handoff_plans.discard(plan_id)
                for node in new.nodes:
                    runs = [
                        run
                        for run in state.schedules.values()
                        if run.plan_id == plan_id and run.node_id == node.node_id
                    ]
                    if runs and all(run.status == "cancelled" for run in runs):
                        self._node_status(plan_id, node.node_id, "cancelled")
                return GatewayResult("resumed", details=self.plan_snapshot(plan_id))
            except (ValueError, OSError, KeyError):
                return self._failure(plan.principal, "PLAN-OWNER")

    def unlock_scope(self, principal: str) -> dict[str, JsonValue]:
        state = self.store.snapshot()
        return {
            "control": "unlock",
            "principal": principal,
            "device_session_id": state.security.active_device_sessions.get(principal),
            "locked_at": state.security.locked_at.get(principal),
        }

    def request_unlock_mfa(self, principal: str) -> str | None:
        try:
            return self._request_unlock_mfa(principal)
        except OSError:
            self._failure(principal, "AUD-WRITE")
        except (ValueError, TypeError, KeyError, AttributeError):
            self._failure(principal, "MFA-INVALID")
        return None

    def _request_unlock_mfa(self, principal: str) -> str | None:
        with _LOCK:
            state = self.store.snapshot()
            if self.mfa is None or principal not in state.security.locked_at:
                return None
            session = state.security.active_device_sessions.get(principal)
            if session is None:
                return None
            scope = H(self.unlock_scope(principal))
            previous = self._unlock_challenges.get(scope)
            if previous is not None and state.now < previous[1]:
                return previous[0]
            sequence = self._next()
            challenge_id = self.mfa.challenge(
                principal=principal,
                device_session_id=session,
                scope_hash=scope,
                now=state.now,
                sequence=sequence,
            )
            self._audit(
                "mfa_challenge",
                principal,
                {"scope_hash": scope, "challenge_id": challenge_id, "sequence": sequence},
            )
            self._unlock_challenges[scope] = (challenge_id, add_seconds(state.now, 120))
            return challenge_id

    def unlock(self, principal: str, confirmation: UserInput, grant: MFAGrant) -> GatewayResult:
        with _LOCK:
            try:
                confirmation = UserInput.model_validate(confirmation.model_dump(mode="python"))
                grant = MFAGrant.model_validate(grant.model_dump(mode="python"))
                state = self.store.snapshot()
                locked = state.security.locked_at.get(principal)
                scope = self.unlock_scope(principal)
                customer = state.customers.get(principal)
                nonce = H({"unlock_confirmation": confirmation.id})[:32]
                if (
                    locked is None
                    or state.now < add_seconds(locked, state.policy.unlock_cooldown_seconds)
                    or state.security.unknown_intent_ids
                    or self._write_failed
                    or not self.audit.verify()
                    or customer is None
                    or confirmation.principal != principal
                    or confirmation.slot != "unlock"
                    or confirmation.scope_id != H(scope)
                    or confirmation.value != scope
                    or not add_seconds(state.now, -300) <= confirmation.submitted_at <= state.now
                    or nonce in state.security.consumed_nonces
                    or not verify(customer.device_pubkey, INPUT, confirmation, confirmation.sig)
                ):
                    return self._unlock_failure(principal, "APR-LOCK")
                rule = self._grant_rule(grant, principal, H(scope), state)
                if rule:
                    return self._unlock_failure(principal, rule)
                self._audit(
                    "unlocked",
                    principal,
                    {"confirmation_hash": H(confirmation), "grant_hash": H(grant)},
                )
                self._security(
                    locked_at={
                        key: value
                        for key, value in state.security.locked_at.items()
                        if key != principal
                    },
                    lock_reason={
                        key: value
                        for key, value in state.security.lock_reason.items()
                        if key != principal
                    },
                    reject_streak={**state.security.reject_streak, principal: 0},
                    approval_requests={**state.security.approval_requests, principal: []},
                    consumed_nonces=[*state.security.consumed_nonces, nonce],
                    consumed_grant_ids=[*state.security.consumed_grant_ids, grant.grant_id],
                )
                return GatewayResult("unlocked")
            except (ValueError, TypeError, AttributeError):
                return self._unlock_failure(principal, "APR-LOCK")
            except OSError:
                return self._failure(principal, "AUD-WRITE")

    def _unlock_failure(self, principal: str, rule: str) -> GatewayResult:
        """Retain the original rejection and expose the device-control obligation."""
        result = self._failure(principal, rule)
        rules = [*result.rule_ids, "CTRL-MFA"]
        return GatewayResult(
            "rejected",
            rules,
            verdict=Reject(
                rule_ids=rules,
                first=rule,
                obligation=RULES[rule].obligation,
                counterexample_code="unlock_control_requirements",
            ),
        )

    def _skip_locked_run(self, ref: str, principal: str) -> None:
        state = self.store.snapshot()
        run = state.schedules.get(ref)
        if (
            run is None
            or run.owner != principal
            or (principal not in state.security.locked_at and run.plan_id not in self._voided_plans)
            or run.status not in {"pending", "due", "waiting_mfa"}
            or state.now < run.due_at
            or any(
                event.commitment_id == run.commitment_id and event.event != "failed"
                for event in latest_events(state).values()
            )
        ):
            return
        self._schedule_status(run.id, "skipped", rule_ids=["APR-LOCK"])

    def _schedule_status(self, ref: str, status: str, *, rule_ids: list[str] | None = None) -> None:
        state = self.store.snapshot()
        run = state.schedules[ref]
        self._audit(
            "schedule_status",
            run.owner,
            {"run_hash": H(run), "status": status, "rule_ids": rule_ids or []},
        )
        self.store.update(
            schedules={
                **state.schedules,
                ref: run.model_copy(update={"status": status, "version": run.version + 1}),
            }
        )
        siblings = [
            item
            for item in self.store.snapshot().schedules.values()
            if item.plan_id == run.plan_id and item.node_id == run.node_id
        ]
        if (
            status in {"expired", "skipped", "cancelled"}
            and all(item.status not in {"pending", "due", "waiting_mfa"} for item in siblings)
            and not any(item.status == "executed" for item in siblings)
        ):
            self._node_status(
                run.plan_id, run.node_id, "cancelled" if status == "cancelled" else "failed"
            )

    def _controlled_event(
        self,
        action: BankAction,
        delta: dict[str, Any],
        verdict: Verdict,
        *,
        cert: BankCertificate,
        token: ApprovalToken | None,
        **updates: Any,
    ) -> GatewayResult:
        state = self.store.snapshot()
        key = intent_key(action, state)
        delta = {**delta, "authorization_ref": cert.authorization_ref}
        event = BusinessEvent(
            id=_id(key, len(state.ledger), "controlled"),
            intent_key=key,
            event="settled",
            kind=action.kind,
            principal=action.principal,
            object_delta=delta,
            ts=state.now,
        )
        self._audit("controlled", action.principal, {"intent_key": key, "delta": delta}, action)
        result = GatewayResult("controlled", verdict=verdict)
        self._decision(action, cert, token, result)
        self.store.update(ledger=[*state.ledger, event], **updates)
        return result

    def _create_schedule(
        self,
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken | None,
        verdict: Verdict,
    ) -> GatewayResult:
        state = self.store.snapshot()
        spa = state.authorizations[cert.authorization_ref]
        if not isinstance(spa, ScheduledPaymentAuthorization) or token is None:
            return self._failure(action.principal, "DOMAIN-SPA")
        from corridor.kernel.spa import due_at

        runs = {}
        for index in range(spa.max_runs):
            due = due_at(spa, index)
            if due is None:
                break
            run = ScheduledTask(
                id=_id(spa.id, index, "scheduled-run"),
                owner=action.principal,
                plan_id=action.plan_id,
                node_id=action.node_id,
                spa_ref=spa.id,
                run_index=index,
                action_template={"kind": spa.target.kind},
                input_refs=sorted({
                    term.input_ref
                    for term in cert.derivations.values()
                    if isinstance(term, InputTerm)
                }),
                due_at=due,
                expires_at=min(add_seconds(due, 86400), spa.end),
                commitment_id=H({"spa_id": spa.id, "run_index": index}),
                status="pending",
            )
            runs[run.id] = run
        if not runs:
            return self._failure(action.principal, "DOMAIN-SPA")
        delta = {
            "spa_hash": H(spa),
            "creation_tier": spa.creation_tier,
            "approval_verified": True,
            "approval_hash": H(token),
            "mfa_verified": spa.creation_tier == "red",
            "mfa_hash": H(state.security.mfa_grants[cert.mfa_grant_refs[0]])
            if cert.mfa_grant_refs
            else None,
            "source_version": state.accounts[spa.source_ref].version,
            "destination_version": spa.destination_version,
        }
        return self._controlled_event(
            action, delta, verdict, cert=cert, token=token, schedules={**state.schedules, **runs}
        )

    def device_control(
        self,
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken,
        *,
        contact: Contact | None = None,
        confirmation: UserInput | None = None,
    ) -> GatewayResult:
        if action.kind not in _CONTROL:
            return self._audit_dispatch_rejection(
                action, cert, token, self._failure(action.principal, "CTRL-MFA")
            )
        return self._dispatch(
            action, cert, token, device_control=True, contact=contact, confirmation=confirmation
        )

    def _control(
        self,
        action: BankAction,
        cert: BankCertificate,
        token: ApprovalToken | None,
        verdict: Verdict,
        contact: Contact | None,
        confirmation: UserInput | None,
    ) -> GatewayResult:
        state = self.store.snapshot()
        if token is None or verdict.tier != "red" or not cert.mfa_grant_refs:
            return self._failure(action.principal, "CTRL-MFA")
        if action.kind == "password_change_request":
            customer = state.customers[action.principal]
            changed = customer.model_copy(
                update={
                    "version": customer.version + 1,
                    "credential_version": customer.credential_version + 1,
                }
            )
            return self._controlled_event(
                action,
                {"credential_version": changed.credential_version},
                verdict,
                cert=cert,
                token=token,
                customers={**state.customers, changed.id: changed},
            )
        if contact is None or confirmation is None:
            return self._failure(action.principal, "CTRL-MFA")
        contact = Contact.model_validate(contact.model_dump(mode="python"))
        confirmation = UserInput.model_validate(confirmation.model_dump(mode="python"))
        scope = {
            "action_hash": H(action),
            "contact_hash": H(contact),
            "draft_handle": action.args.model_dump()["draft_handle"],
        }
        customer = state.customers[action.principal]
        if (
            contact.owner != action.principal
            or contact.id in state.contacts
            or contact.version != 1
            or contact.verified_at != state.now
            or contact.verification_ref != confirmation.id
            or not contact.is_new
            or confirmation.principal != action.principal
            or confirmation.slot != "contact_verification"
            or confirmation.scope_id != action.intent_id
            or confirmation.value != scope
            or not add_seconds(state.now, -300) <= confirmation.submitted_at <= state.now
            or not verify(customer.device_pubkey, INPUT, confirmation, confirmation.sig)
        ):
            return self._failure(action.principal, "CTRL-MFA")
        return self._controlled_event(
            action,
            {"contact_ref": contact.id, "contact_hash": H(contact)},
            verdict,
            cert=cert,
            token=token,
            contacts={**state.contacts, contact.id: contact},
        )
