"""Pure plan validation and audit projections; execution remains in the gateway."""

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any, cast

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT, RECEIPT, SPA, verify
from corridor.schemas.bank import (
    ACTION_ARGS,
    AnalysisReceipt,
    AuthorizationRevocation,
    BankReceipt,
    Handle,
    InputTerm,
    NodeOutputTerm,
    Plan,
    PlanNode,
    ReadTerm,
    ReceiptTerm,
    ScheduledPaymentAuthorization,
    SessionAuthorization,
    StateTerm,
    Term,
)
from corridor.schemas.money import parse_fraction
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time
from corridor.stores.bank import latest_events

GREEN_TOOLS = frozenset({
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
})
SUPPORTED_TOOLS = GREEN_TOOLS | {
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
    "password_change_request",
    "register_contact_request",
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
_STATE_FIELDS = {
    "account_ref": "accounts",
    "source_ref": "accounts",
    "locked_ref": "accounts",
    "contact_ref": "contacts",
    "participant_refs": "contacts",
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
_INPUT_SLOTS = {
    "amount_ref": "amount",
    "total_ref": "total",
    "purpose_ref": "purpose",
    "period": "period",
    "draft_handle": "draft_handle",
    "preference_ref": "preference",
    "request_ref": "allocation",
    "allocation_ref": "allocation_binding",
    "allocation_item_ref": "allocation_binding",
    "answers_input_ref": "answers",
    "source_bill_ref": "total",
    "change_ref": "card_change",
}
_AA_RECEIPT_FIELDS = {"source_bill_ref": "receipt_id", "total_ref": "net_spend"}
_ANALYSIS = {
    "bill_analyze": "bill_summary_v1",
    "bill_report": "bill_summary_v1",
    "anomaly_query": "anomaly_v1",
}
_OUTPUTS = {
    ("receipt_ref", "receipt_id"): frozenset({"transfer", "merchant_order"}),
    ("position_ref", "position_ref"): frozenset({"purchase_product"}),
    ("order_ref", "order_ref"): frozenset({"merchant_order"}),
}
_INVERSES = {
    "lock_funds": {"unlock_funds"},
    "purchase_product": {"redeem_product"},
    "schedule_transfer": {"cancel_schedule"},
    "merchant_order": {"refund_request"},
    "transfer": {"refund_request"},
}
_STATUSES = frozenset({
    "pending",
    "ready",
    "running",
    "waiting_input",
    "waiting_approval",
    "waiting_mfa",
    "waiting_settlement",
    "unknown",
    "scheduled",
    "succeeded",
    "failed",
    "cancelled",
    "compensating",
    "compensated",
    "non_reversible",
    "handoff",
})
_PRESERVE_ON_STOP = frozenset({
    "running",
    "waiting_settlement",
    "unknown",
    "succeeded",
    "failed",
    "cancelled",
    "compensated",
    "non_reversible",
})


def _nodes(plan: Plan) -> dict[str, PlanNode]:
    nodes = {node.node_id: node for node in plan.nodes}
    if len(nodes) != len(plan.nodes):
        raise ValueError("PLAN-SCHEMA")
    for node in nodes.values():
        if len(node.depends_on) != len(set(node.depends_on)):
            raise ValueError("PLAN-SCOPE")
        if any(ref not in nodes for ref in node.depends_on):
            raise ValueError("PLAN-SCOPE")
    return nodes


def topological_order(plan: Plan) -> list[str]:
    """Kahn traversal with each newly ready batch ordered by node identity."""
    nodes = _nodes(plan)
    remaining = set(nodes)
    completed: set[str] = set()
    result: list[str] = []
    while remaining:
        ready = sorted(ref for ref in remaining if set(nodes[ref].depends_on) <= completed)
        if not ready:
            raise ValueError("PLAN-CYCLE")
        result.extend(ready)
        completed.update(ready)
        remaining.difference_update(ready)
    return result


def dependency_closure(plan: Plan, node_id: str) -> set[str]:
    nodes = _nodes(plan)
    if node_id not in nodes:
        raise ValueError("PLAN-SCOPE")
    topological_order(plan)
    result: set[str] = set()
    pending = list(nodes[node_id].depends_on)
    while pending:
        current = pending.pop()
        if current not in result:
            result.add(current)
            pending.extend(nodes[current].depends_on)
    return result


def _period(value: object) -> bool:
    if not isinstance(value, str) or len(value) not in {4, 7, 10}:
        return False
    try:
        completed = value + ("-01-01" if len(value) == 4 else "-01" if len(value) == 7 else "")
        return date.fromisoformat(completed).isoformat() == completed
    except ValueError:
        return False


def _object(state: BankState, collection: str, ref: str) -> Any:
    if collection == "catalog":
        return next((item for item in state.catalog.products if item.id == ref), None)
    return getattr(state, collection).get(ref)


def _owned(obj: Any, principal: str) -> bool:
    return getattr(obj, "owner", getattr(obj, "principal", principal)) == principal


def _scope_valid(plan: Plan, scope: str, state: BankState, node_id: str | None) -> bool:
    if scope == plan.intent_id:
        return True
    authorization = state.authorizations.get(scope)
    customer = state.customers.get(plan.principal)
    nodes = {node.node_id: node for node in plan.nodes}
    return (
        isinstance(authorization, ScheduledPaymentAuthorization)
        and customer is not None
        and authorization.principal == plan.principal
        and authorization.plan_id == plan.plan_id
        and authorization.node_id in nodes
        and (node_id is None or node_id == authorization.node_id)
        and nodes[authorization.node_id].tool in {"schedule_transfer", authorization.target.kind}
        and verify(customer.device_pubkey, SPA, authorization, authorization.sig)
    )


def _input_valid(plan: Plan, ref: str, state: BankState, node_id: str | None = None) -> bool:
    item = state.user_inputs.get(ref)
    customer = state.customers.get(plan.principal)
    return (
        item is not None
        and customer is not None
        and item.principal == plan.principal
        and _scope_valid(plan, item.scope_id, state, node_id)
        and item.submitted_at <= state.now
        and not any(value.supersedes == ref for value in state.user_inputs.values())
        and verify(customer.device_pubkey, INPUT, item, item.sig)
    )


def _receipt_owned(ref: str, plan: Plan, state: BankState) -> bool:
    receipt = state.receipts.get(ref)
    if isinstance(receipt, BankReceipt):
        event = latest_events(state).get(receipt.intent_key)
        return (
            receipt.status == "settled"
            and receipt.executed_at <= state.now
            and event is not None
            and event.principal == plan.principal
            and event.event == "settled"
            and event.bank_receipt_id == receipt.id
            and verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig)
        )
    if isinstance(receipt, AnalysisReceipt):
        return (
            receipt.trust == "builtin"
            and receipt.parameters.get("principal") == plan.principal
            and receipt.computed_at <= state.now
            and verify(state.roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
            and any(
                event.principal == plan.principal
                and event.event == "settled"
                and event.object_delta.get("analysis_receipt_id") == receipt.id
                and event.object_delta.get("receipt_hash") == H(receipt)
                for event in state.ledger
            )
        )
    return False


def _handle_term(plan: Plan, key: str, handle: Handle, state: BankState) -> Term:
    if (key, handle.handle_type) in {("dataset_ref", "dataset"), ("program_ref", "program")}:
        authorities = [
            auth
            for auth in state.authorizations.values()
            if isinstance(auth, SessionAuthorization)
            and auth.principal == plan.principal
            and auth.device_session_id == plan.device_session_id
            and "sandbox_analyze" in auth.read_kinds
            and auth.expires_at > state.now
        ]
        if authorities:
            return ReadTerm(
                session_authorization_ref=sorted(authorities, key=lambda auth: auth.id)[0].id,
                query_field=key,
                value=handle.ref,
            )
    if handle.handle_type == "state" and key in _STATE_FIELDS:
        collection = _STATE_FIELDS[key]
        obj = _object(state, collection, handle.ref)
        if obj is not None and _owned(obj, plan.principal):
            return StateTerm.model_validate({
                "collection": collection,
                "object_ref": handle.ref,
                "field": "offers" if key == "offer_ref" else "id",
                "version": obj.version,
            })
    if handle.handle_type == "input" and key in _INPUT_SLOTS:
        return InputTerm(input_ref=handle.ref, slot=_INPUT_SLOTS[key])
    if handle.handle_type == "receipt" and key == "receipt_ref":
        return ReceiptTerm(receipt_ref=handle.ref, field="receipt_id")
    if handle.handle_type == "receipt" and key in _AA_RECEIPT_FIELDS:
        return ReceiptTerm(receipt_ref=handle.ref, field=_AA_RECEIPT_FIELDS[key])
    raise ValueError("PLAN-SCOPE")


def _aa_receipt_valid(ref: str, plan: Plan, state: BankState) -> bool:
    receipt = state.receipts.get(ref)
    if (
        not isinstance(receipt, AnalysisReceipt)
        or receipt.function_id != "bill_summary_v1"
        or not _receipt_owned(ref, plan, state)
    ):
        return False
    account = state.accounts.get(str(receipt.parameters.get("account_ref", "")))
    total = receipt.results.get("net_spend")
    if (
        account is None
        or account.owner != plan.principal
        or total is None
        or total.unit != "CNY"
        or not any(
            event.kind in {"bill_report", "bill_analyze"}
            and event.principal == plan.principal
            and event.event == "settled"
            and event.object_delta.get("analysis_receipt_id") == ref
            and event.object_delta.get("receipt_hash") == H(receipt)
            for event in state.ledger
        )
    ):
        return False
    amount = parse_fraction(total.value)
    return amount > 0 and (amount * 100).denominator == 1


def _term_valid(plan: Plan, node: PlanNode, key: str, term: Term, state: BankState) -> bool:
    if isinstance(term, StateTerm):
        if term.collection != _STATE_FIELDS.get(key):
            return False
        obj = _object(state, term.collection, term.object_ref)
        return (
            obj is not None
            and obj.version == term.version
            and _owned(obj, plan.principal)
            and term.field == ("offers" if key == "offer_ref" else "id")
        )
    if isinstance(term, InputTerm):
        return (
            term.slot == _INPUT_SLOTS.get(key)
            and (
                key not in {"allocation_ref", "allocation_item_ref"}
                or node.tool == "purchase_product"
            )
            and term.input_ref in plan.goal_input_refs
            and _input_valid(plan, term.input_ref, state, node.node_id)
            and state.user_inputs[term.input_ref].slot == term.slot
        )
    if isinstance(term, ReceiptTerm):
        if node.tool == "aa_request" and key in _AA_RECEIPT_FIELDS:
            return term.field == _AA_RECEIPT_FIELDS[key] and _aa_receipt_valid(
                term.receipt_ref, plan, state
            )
        return (
            key == "receipt_ref"
            and node.tool == "refund_request"
            and term.field == "receipt_id"
            and _receipt_owned(term.receipt_ref, plan, state)
        )
    if isinstance(term, NodeOutputTerm):
        nodes = _nodes(plan)
        return (
            term.node_id in dependency_closure(plan, node.node_id)
            and nodes[term.node_id].tool in _OUTPUTS.get((key, term.field), frozenset())
            and (key != "receipt_ref" or node.tool == "refund_request")
        )
    if isinstance(term, ReadTerm):
        auth = state.authorizations.get(term.session_authorization_ref)
        customer = state.customers[plan.principal]
        revoked = any(
            isinstance(item, AuthorizationRevocation)
            and item.authorization_ref == term.session_authorization_ref
            and item.revoked_at <= state.now
            for item in state.authorizations.values()
        )
        return (
            node.tool in GREEN_TOOLS
            and key
            in (
                {"dataset_ref", "program_ref"}
                if node.tool == "sandbox_analyze"
                else {"period", "analysis_spec"}
            )
            and term.query_field == key
            and isinstance(auth, SessionAuthorization)
            and auth.principal == plan.principal
            and auth.device_session_id == plan.device_session_id
            and auth.expires_at > state.now
            and node.tool in auth.read_kinds
            and not revoked
            and verify(customer.device_pubkey, CONTROL, auth, auth.sig)
            and (
                isinstance(term.value, str)
                and re.fullmatch(
                    ("DSET_" if key == "dataset_ref" else "PROG_") + "[a-p]{64}", term.value
                )
                is not None
                if node.tool == "sandbox_analyze"
                else _period(term.value)
                if key == "period"
                else term.value == _ANALYSIS.get(node.tool)
            )
        )
    return False


def _flat_args(node: PlanNode) -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, term in node.args.items():
        if isinstance(term, list):
            if key != "participant_refs" or not 1 <= len(term) <= 10:
                raise ValueError("PLAN-SCOPE")
            flat.update({f"{key}.{index}": item for index, item in enumerate(term)})
        else:
            flat[key] = term
    return flat


def node_due_at(plan: Plan, node_id: str, state: BankState) -> str | None:
    """Resolve an optional device-confirmed due time for this exact plan node."""
    node = _nodes(plan).get(node_id)
    if node is None:
        raise ValueError("PLAN-SCOPE")
    if node.due_at_ref is None:
        return None
    due = state.user_inputs.get(node.due_at_ref)
    if (
        due is None
        or node.due_at_ref not in plan.goal_input_refs
        or due.slot != "due_at"
        or not isinstance(due.value, str)
        or not _input_valid(plan, due.id, state, node_id)
    ):
        raise ValueError("PLAN-SCOPE")
    parse_time(due.value)
    return due.value


def validate_plan(
    plan: Plan, state: BankState, *, supported_tools: Collection[str] | None = None
) -> str | None:
    try:
        plan = Plan.model_validate(plan.model_dump(mode="python"))
        if (
            plan.principal not in state.customers
            or state.security.active_device_sessions.get(plan.principal) != plan.device_session_id
        ):
            return "PLAN-OWNER"
        topological_order(plan)
        if len(plan.goal_input_refs) != len(set(plan.goal_input_refs)) or any(
            not _input_valid(plan, ref, state) for ref in plan.goal_input_refs
        ):
            return "PLAN-SCOPE"
        allowed = SUPPORTED_TOOLS if supported_tools is None else supported_tools
        for node in plan.nodes:
            if node.tool not in state.policy.tool_whitelist or node.tool not in allowed:
                return "TOOL-UNAVAILABLE"
            fields = ACTION_ARGS[node.tool].model_fields
            required = {key for key, value in fields.items() if value.is_required()}
            if not required <= set(node.args) <= set(fields):
                return "PLAN-SCOPE"
            if not plan.goal_input_refs and node.tool not in GREEN_TOOLS:
                return "PLAN-SCOPE"
            for field_name, value in _flat_args(node).items():
                key = field_name.split(".")[0]
                term = _handle_term(plan, key, value, state) if isinstance(value, Handle) else value
                if not _term_valid(plan, node, key, term, state):
                    return "PLAN-SCOPE"
            node_due_at(plan, node.node_id, state)
            if node.compensation is not None:
                if (
                    node.compensation.original_node_ref != node.node_id
                    or node.compensation.tool not in _INVERSES.get(node.tool, set())
                ):
                    return "PLAN-SCOPE"
        return None
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return str(exc) if str(exc) in {"PLAN-CYCLE", "PLAN-SCOPE", "PLAN-OWNER"} else "PLAN-SCHEMA"


def resolve_node_terms(
    plan: Plan,
    node_id: str,
    state: BankState,
    outputs: Mapping[str, str],
    *,
    check_current: bool = True,
) -> dict[str, Term]:
    """Resolve references; dispatch may defer explicit-term freshness to the kernel."""
    node = _nodes(plan)[node_id]
    resolved: dict[str, Term] = {}
    for field_name, value in _flat_args(node).items():
        key = field_name.split(".")[0]
        term = _handle_term(plan, key, value, state) if isinstance(value, Handle) else value
        if (check_current or isinstance(term, NodeOutputTerm)) and not _term_valid(
            plan, node, key, term, state
        ):
            raise ValueError("PLAN-SCOPE")
        if isinstance(term, NodeOutputTerm):
            receipt_ref = outputs.get(term.node_id)
            if receipt_ref is None or not _receipt_owned(receipt_ref, plan, state):
                raise ValueError("PLAN-SCOPE")
            receipt = state.receipts[receipt_ref]
            if not isinstance(receipt, BankReceipt):
                raise ValueError("PLAN-SCOPE")
            event = latest_events(state)[receipt.intent_key]
            action = event.object_delta.get("action")
            if (
                not isinstance(action, dict)
                or action.get("plan_id") != plan.plan_id
                or action.get("node_id") != term.node_id
                or action.get("intent_id") != plan.intent_id
            ):
                raise ValueError("PLAN-SCOPE")
            if term.field == "receipt_id":
                term = ReceiptTerm(receipt_ref=receipt_ref, field="receipt_id")
            else:
                effect_type = "position" if term.field == "position_ref" else "order"
                matches = [
                    item
                    for item in receipt.exact_effects
                    if item.effect_type == effect_type and item.field == effect_type
                ]
                if len(matches) != 1:
                    raise ValueError("PLAN-SCOPE")
                term = _handle_term(
                    plan, key, Handle(handle_type="state", ref=matches[0].object_ref), state
                )
        resolved[field_name] = term
    return resolved


@dataclass
class PlanRuntime:
    statuses: dict[str, str]
    receipt_refs: dict[str, str] = field(default_factory=dict)
    ownership_epoch: int = 0
    revision: int = 1
    blocked: bool = False


def project_runtime(plan: Plan, records: Sequence[Mapping[str, Any]]) -> PlanRuntime:
    known_plans = {H(plan): plan}
    for record in records:
        if record.get("plan_id") != plan.plan_id or record.get("principal_token") != plan.principal:
            continue
        payload = record.get("payload", {})
        if record.get("event") == "plan_registered" and isinstance(payload, dict):
            previous = Plan.model_validate(payload.get("plan"))
            if previous.principal == plan.principal and previous.intent_id == plan.intent_id:
                known_plans[H(previous)] = previous
    runtime = PlanRuntime(
        {node.node_id: "pending" for node in plan.nodes},
        ownership_epoch=min(previous.ownership_epoch for previous in known_plans.values()),
        revision=plan.revision,
    )
    current_nodes = _nodes(plan)
    for record in records:
        if record.get("plan_id") != plan.plan_id or record.get("principal_token") != plan.principal:
            continue
        payload = record.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("PLAN-SCHEMA")
        event = record.get("event")
        if event == "plan_node_status":
            prior_plan = known_plans.get(str(payload.get("plan_hash")))
            node = record.get("node_id")
            if (
                prior_plan is None
                or payload.get("ownership_epoch") != runtime.ownership_epoch
                or node not in current_nodes
                or _nodes(prior_plan).get(node) != current_nodes[node]
                or (
                    runtime.blocked
                    and runtime.statuses[node] not in {"running", "unknown", "waiting_settlement"}
                )
            ):
                continue
            status, receipt = payload.get("status"), payload.get("receipt_ref")
            if node not in runtime.statuses or status not in _STATUSES:
                raise ValueError("PLAN-SCOPE")
            if status == "succeeded" and (not isinstance(receipt, str) or not receipt):
                raise ValueError("PLAN-SCOPE")
            if runtime.statuses[node] == "cancelled":
                continue
            if runtime.statuses[node] == "succeeded" and status not in {
                "compensating",
                "compensated",
                "non_reversible",
            }:
                continue
            runtime.statuses[node] = cast(str, status)
            if status == "succeeded":
                runtime.receipt_refs[node] = cast(str, receipt)
        elif event in {"plan_handoff", "plan_interrupted"}:
            runtime.blocked = True
            for node, status in runtime.statuses.items():
                if status not in _PRESERVE_ON_STOP:
                    runtime.statuses[node] = "handoff" if event == "plan_handoff" else "cancelled"
            if event == "plan_handoff":
                runtime.ownership_epoch = max(
                    runtime.ownership_epoch + 1,
                    int(payload.get("ownership_epoch", runtime.ownership_epoch + 1)),
                )
        elif event == "plan_resumed":
            resumed_plan = known_plans.get(str(payload.get("plan_hash")))
            if (
                resumed_plan is not None
                and payload.get("ownership_epoch") == resumed_plan.ownership_epoch
                and resumed_plan.ownership_epoch
                in {runtime.ownership_epoch, runtime.ownership_epoch + 1}
            ):
                runtime.ownership_epoch = resumed_plan.ownership_epoch
                runtime.blocked = False
                for node, status in runtime.statuses.items():
                    if status == "handoff":
                        runtime.statuses[node] = "pending"
    return runtime


def ready_nodes(plan: Plan, runtime: PlanRuntime) -> list[str]:
    if runtime.blocked or runtime.ownership_epoch != plan.ownership_epoch:
        return []
    return sorted(
        node.node_id
        for node in plan.nodes
        if runtime.statuses.get(node.node_id) in {"pending", "ready"}
        and all(runtime.statuses.get(ref) == "succeeded" for ref in node.depends_on)
    )
