"""Pure parent-plan authorization and receipt-backed allocation budget reconstruction."""

from dataclasses import dataclass
from fractions import Fraction
from uuid import NAMESPACE_URL, uuid5

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT, RECEIPT, verify
from corridor.kernel.allocation import evaluate_allocation, verify_allocation
from corridor.schemas.allocation import (
    AllocationPlan,
    AllocationPlanItem,
    AllocationRequest,
    BestInterestAllocationCertificate,
)
from corridor.schemas.bank import (
    AuthorizationRevocation,
    BankAction,
    BankCertificate,
    BankOrder,
    BankReceipt,
    BusinessEvent,
    InputTerm,
    OperationAuthorization,
    UserInput,
)
from corridor.schemas.domain import Position
from corridor.schemas.money import Money, parse_fraction
from corridor.schemas.state import BankState
from corridor.stores.bank import available, latest_events

_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")
_ZERO = Fraction()


def allocation_child_intent(parent: str, product: str) -> str:
    return str(uuid5(_NAMESPACE, f"{parent}:0:allocation-child-{product}"))


def allocation_item_id(parent: str, product: str) -> str:
    return str(uuid5(_NAMESPACE, f"{parent}:0:allocation-item-{product}"))


def allocation_plan_hash(plan: AllocationPlan) -> str:
    return H(plan.model_dump(mode="json", exclude={"plan_hash"}))


def _child_key(principal: str, intent: str) -> str:
    return H({"principal": principal, "intent_id": intent, "kind": "purchase_product"})


@dataclass(frozen=True)
class AllocationExecution:
    plan: AllocationPlan | None = None
    certificate: BestInterestAllocationCertificate | None = None
    settled_item_refs: tuple[str, ...] = ()
    remaining_item_refs: tuple[str, ...] = ()
    settled_debit: Fraction = _ZERO
    current_budget: Fraction = _ZERO
    remaining_debit: Fraction = _ZERO
    control_status: str | None = None
    errors: tuple[str, ...] = ()


def _input(
    ref: str, owner: str, scope: str, slot: str, state: BankState, *, current: bool = True
) -> UserInput:
    value = state.user_inputs.get(ref)
    customer = state.customers.get(owner)
    if (
        value is None
        or customer is None
        or value.principal != owner
        or value.scope_id != scope
        or value.slot != slot
        or value.submitted_at > state.now
        or (current and any(item.supersedes == ref for item in state.user_inputs.values()))
        or not verify(customer.device_pubkey, INPUT, value, value.sig)
    ):
        raise ValueError("AUTH-SCOPE")
    return value


def _control(plan: AllocationPlan, state: BankState) -> tuple[str | None, str | None]:
    event = latest_events(state).get(H({"allocation_control": plan.id}))
    if event is None:
        return None, "PLAN-SCOPE"
    status = event.object_delta.get("status")
    expected = {
        "allocation_ref": plan.id,
        "parent_intent_id": plan.parent_intent_id,
        "plan_hash": plan.plan_hash,
        "status": status,
    }
    if (
        event.kind != "allocation_compare"
        or event.event != "settled"
        or event.principal != plan.principal
        or event.ts > state.now
        or event.debit is not None
        or event.credit is not None
        or event.object_delta != expected
        or not isinstance(status, str)
        or status not in {"ready", "stopped", "handoff", "failed", "unknown"}
    ):
        return None, "PLAN-SCOPE"
    return str(status), None


def _selection(plan: AllocationPlan, state: BankState, *, current: bool = True) -> None:
    value = _input(
        plan.selection_input_ref or "",
        plan.principal,
        plan.parent_intent_id,
        "allocation_selection",
        state,
        current=current,
    )
    if value.value != {
        "parent_id": plan.id,
        "plan_hash": plan.plan_hash,
        "biac_hash": plan.biac_hash,
        "request_ref": plan.request_ref,
        "selected_items": sorted(item.item_ref for item in plan.items),
    }:
        raise ValueError("PLAN-SCOPE")


def _inputs(
    plan: AllocationPlan,
    item: AllocationPlanItem,
    request: AllocationRequest,
    request_hash: str,
    state: BankState,
) -> tuple[UserInput, UserInput]:
    if len(item.input_refs) != 2 or len(set(item.input_refs)) != 2:
        raise ValueError("AUTH-SCOPE")
    values = [state.user_inputs.get(ref) for ref in item.input_refs]
    amount_ref = next((v.id for v in values if v is not None and v.slot == "amount"), "")
    binding_ref = next(
        (v.id for v in values if v is not None and v.slot == "allocation_binding"), ""
    )
    amount = _input(amount_ref, plan.principal, item.child_intent_id, "amount", state)
    binding = _input(binding_ref, plan.principal, item.child_intent_id, "allocation_binding", state)
    if (
        amount.batch_id != binding.batch_id
        or Money.model_validate(amount.value).amount != item.principal
    ):
        raise ValueError("AUTH-SCOPE")
    if not isinstance(binding.value, dict):
        raise ValueError("AUTH-SCOPE")
    body: dict[str, object] = dict(binding.value)
    body["principal"] = parse_fraction(body.get("principal"))
    body["fee_buy"] = parse_fraction(body.get("fee_buy"))
    if body != {
        "allocation_ref": plan.id,
        "allocation_item_ref": item.item_ref,
        "parent_intent_id": plan.parent_intent_id,
        "request_hash": request_hash,
        "biac_hash": plan.biac_hash,
        "product_ref": item.product_ref,
        "principal": item.principal,
        "fee_buy": item.fee_buy,
        "parent_plan_hash": plan.plan_hash,
    }:
        raise ValueError("PLAN-SCOPE")
    auth = state.authorizations.get(item.authorization_ref)
    customer = state.customers.get(plan.principal)
    if (
        not isinstance(auth, OperationAuthorization)
        or customer is None
        or auth.principal != plan.principal
        or auth.intent_id != item.child_intent_id
        or auth.allowed_kind != "purchase_product"
        or auth.expires_at <= state.now
        or auth.amount_bound != item.principal + item.fee_buy
        or set(auth.object_refs) != {request.source_account_ref, item.product_ref, plan.id}
        or len(auth.input_hashes) != 2
        or set(auth.input_hashes) != {H(amount), H(binding)}
        or not verify(customer.device_pubkey, CONTROL, auth, auth.sig)
    ):
        raise ValueError("AUTH-SCOPE")
    if any(
        isinstance(value, AuthorizationRevocation)
        and value.authorization_ref == auth.id
        and value.revoked_at <= state.now
        for value in state.authorizations.values()
    ):
        raise ValueError("AUTH-SCOPE")
    return amount, binding


def _action_matches(
    action: BankAction, item: AllocationPlanItem, plan: AllocationPlan, source: str, amount_ref: str
) -> bool:
    return (
        action.kind == "purchase_product"
        and action.principal == plan.principal
        and action.intent_id == item.child_intent_id
        and action.plan_id == item.child_plan_id
        and action.plan_hash == item.child_plan_hash
        and action.node_id == item.child_node_id
        and action.args.model_dump(mode="json")
        == {
            "source_ref": source,
            "product_ref": item.product_ref,
            "amount_ref": amount_ref,
            "allocation_ref": plan.id,
            "allocation_item_ref": item.item_ref,
        }
    )


def _settled_debit(
    event: BusinessEvent,
    item: AllocationPlanItem,
    plan: AllocationPlan,
    request: AllocationRequest,
    state: BankState,
) -> Fraction:
    """Verify saved bank evidence before adding its debit back to this plan's budget."""
    key = _child_key(plan.principal, item.child_intent_id)
    receipt = state.receipts.get(event.bank_receipt_id or "")
    if (
        event.intent_key != key
        or event.event != "settled"
        or event.kind != "purchase_product"
        or event.principal != plan.principal
        or event.credit is not None
        or event.debit is None
        or event.debit.account_ref != request.source_account_ref
        or event.debit.amount != item.principal + item.fee_buy
        or not isinstance(receipt, BankReceipt)
        or receipt.status != "settled"
        or receipt.intent_key != key
        or receipt.kind != "purchase_product"
        or receipt.settle_at is not None
        or receipt.executed_at > state.now
        or not verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig)
        or len(receipt.exact_effects) != 2
    ):
        raise ValueError("BANK-RECEIPT")
    action = BankAction.model_validate(event.object_delta.get("action"))
    cert = BankCertificate.model_validate(event.object_delta.get("cert"))
    order = BankOrder.model_validate(event.object_delta.get("order"))
    amount_ref = next(
        (
            ref
            for ref in item.input_refs
            if state.user_inputs.get(ref) and state.user_inputs[ref].slot == "amount"
        ),
        "",
    )
    if (
        not _action_matches(action, item, plan, request.source_account_ref, amount_ref)
        or cert.action_hash != H(action)
        or cert.authorization_ref != item.authorization_ref
        or cert.best_interest is not None
        or cert.allocation is None
        or H(cert.allocation) != plan.biac_hash
        or order.intent_key != key
        or order.kind != "purchase_product"
        or order.principal != plan.principal
        or order.action_id != action.action_id
        or order.requested_at != receipt.executed_at
        or order.args.model_dump(mode="json")
        != {
            "source_ref": request.source_account_ref,
            "product_ref": item.product_ref,
            "amount": f"{item.principal.numerator}/{item.principal.denominator}",
            "fee_buy": f"{item.fee_buy.numerator}/{item.fee_buy.denominator}",
        }
    ):
        raise ValueError("BANK-RECEIPT")
    debit, creation = receipt.exact_effects
    if (
        debit.effect_type != "debit"
        or debit.object_ref != request.source_account_ref
        or debit.account_ref != request.source_account_ref
        or debit.counterparty_ref != item.product_ref
        or debit.amount != event.debit.amount
        or debit.field != "balance"
        or not isinstance(debit.before, str)
        or not isinstance(debit.after, str)
        or parse_fraction(debit.before) - parse_fraction(debit.after) != debit.amount
        or parse_fraction(debit.after) < 0
        or creation.effect_type != "position"
        or creation.field != "position"
        or creation.account_ref is not None
        or creation.counterparty_ref is not None
        or creation.amount is not None
        or creation.before is not None
    ):
        raise ValueError("BANK-RECEIPT")
    position = Position.model_validate(creation.after)
    expected_id = str(uuid5(_NAMESPACE, f"{key}:0:position"))
    if (
        creation.object_ref != expected_id
        or position.id != expected_id
        or position.owner != plan.principal
        or position.product_ref != item.product_ref
        or position.principal_amount != item.principal
        or position.units != item.principal
        or position.reserved_units != 0
        or position.nav != 1
        or position.status != "active"
        or position.acquired_at != receipt.executed_at
    ):
        raise ValueError("BANK-RECEIPT")
    return debit.amount


def _inspect_allocation_plan(
    plan_ref: str, state: BankState, *, require_ready: bool = True
) -> AllocationExecution:
    plan = state.allocation_plans.get(plan_ref)
    if plan is None:
        return AllocationExecution(errors=("PLAN-SCOPE",))
    errors: list[str] = []
    try:
        plan = AllocationPlan.model_validate(plan.model_dump(mode="python"))
        if plan.id != plan_ref or plan.plan_hash != allocation_plan_hash(plan):
            errors.append("PLAN-SCOPE")
        if (
            sum(
                p.principal == plan.principal and p.parent_intent_id == plan.parent_intent_id
                for p in state.allocation_plans.values()
            )
            != 1
        ):
            errors.append("PLAN-SCOPE")
        request_input = _input(
            plan.request_ref,
            plan.principal,
            plan.parent_intent_id,
            "allocation",
            state,
            current=False,
        )
        request = AllocationRequest.model_validate(request_input.value)
        _selection(plan, state, current=False)
    except ValueError as exc:
        rule = str(exc) if str(exc) in {"PLAN-SCOPE", "AUTH-SCOPE"} else "PLAN-SCOPE"
        return AllocationExecution(plan=plan, errors=tuple(dict.fromkeys([*errors, rule])))
    try:
        _input(plan.request_ref, plan.principal, plan.parent_intent_id, "allocation", state)
        _selection(plan, state)
    except ValueError:
        errors.append("AUTH-SCOPE")
    control_status, control_error = _control(plan, state)
    if require_ready:
        if control_error:
            errors.append(control_error)
        elif control_status != "ready":
            errors.append("PLAN-OWNER" if control_status == "handoff" else "APR-VOID")
    account = state.accounts.get(request.source_account_ref)
    current_budget = available(state, account.id) - account.floor if account is not None else _ZERO
    if account is None:
        errors.append("BIC-PREFERENCE")
    settled_refs: list[str] = []
    remaining_refs: list[str] = []
    settled_debit = remaining_debit = _ZERO
    events = latest_events(state)
    for item in plan.items:
        if item.item_ref != allocation_item_id(
            plan.parent_intent_id, item.product_ref
        ) or item.child_intent_id != allocation_child_intent(
            plan.parent_intent_id, item.product_ref
        ):
            errors.append("PLAN-SCOPE")
        try:
            _inputs(plan, item, request, H(request_input), state)
        except ValueError as exc:
            errors.append(str(exc) if str(exc) == "PLAN-SCOPE" else "AUTH-SCOPE")
        event = events.get(_child_key(plan.principal, item.child_intent_id))
        if event is not None and event.event == "settled":
            try:
                settled_debit += _settled_debit(event, item, plan, request, state)
                settled_refs.append(item.item_ref)
                continue
            except ValueError:
                errors.append("BANK-RECEIPT")
        elif event is not None:
            errors.append(
                "BANK-RECEIPT" if event.event in {"reserved", "unknown"} else "PLAN-SCOPE"
            )
        remaining_refs.append(item.item_ref)
        remaining_debit += item.principal + item.fee_buy
    if current_budget + settled_debit != plan.initial_budget:
        errors.append("APR-DRIFT")
    if remaining_debit > current_budget:
        errors.append("BAL-AVAILABLE")
    evaluation = evaluate_allocation(
        plan.principal,
        plan.parent_intent_id,
        plan.request_ref,
        state,
        budget_override=plan.initial_budget,
    )
    errors.extend(evaluation.errors)
    certificate = evaluation.certificate
    if certificate is not None:
        if certificate.policy_hash != plan.policy_hash:
            errors.append("ALLOC-POLICY")
        if certificate.catalog_hash != plan.catalog_hash:
            errors.append("BIC-CATALOG")
        if certificate.risk_assessment_hash != plan.risk_assessment_hash:
            errors.append("BIC-RISK")
        if H(certificate) != plan.biac_hash:
            errors.append("APR-DRIFT")
        if [(i.product_ref, i.principal, i.fee_buy) for i in plan.items] != [
            (i.product_id, i.principal, i.fee_buy) for i in certificate.allocation
        ]:
            errors.append("PLAN-SCOPE")
    return AllocationExecution(
        plan,
        certificate,
        tuple(settled_refs),
        tuple(remaining_refs),
        settled_debit,
        current_budget,
        remaining_debit,
        control_status,
        tuple(dict.fromkeys(errors)),
    )


def inspect_allocation_plan(
    plan_ref: str, state: BankState, *, require_ready: bool = True
) -> AllocationExecution:
    """Inspect without mutating state; malformed persisted evidence never grants execution."""
    try:
        return _inspect_allocation_plan(plan_ref, state, require_ready=require_ready)
    except (ValueError, KeyError, TypeError):
        return AllocationExecution(
            plan=state.allocation_plans.get(plan_ref), errors=("PLAN-SCOPE",)
        )


def allocation_purchase_errors(
    action: BankAction, cert: BankCertificate, state: BankState
) -> list[str]:
    args = action.args.model_dump(mode="python")
    result = inspect_allocation_plan(str(args.get("allocation_ref", "")), state)
    errors = list(result.errors)
    plan = result.plan
    if plan is None:
        return errors
    item = next((i for i in plan.items if i.item_ref == args.get("allocation_item_ref")), None)
    if item is None:
        return [*errors, "PLAN-SCOPE"]
    if item.item_ref in result.settled_item_refs:
        errors.append("AUTH-CONSUMED")
    elif not result.remaining_item_refs or item.item_ref != result.remaining_item_refs[0]:
        errors.append("PLAN-SCOPE")
    try:
        request_value = _input(
            plan.request_ref, plan.principal, plan.parent_intent_id, "allocation", state
        )
        request = AllocationRequest.model_validate(request_value.value)
        amount, binding = _inputs(plan, item, request, H(request_value), state)
        if (
            not _action_matches(action, item, plan, request.source_account_ref, amount.id)
            or cert.authorization_ref != item.authorization_ref
            or action.device_session_id != state.security.active_device_sessions.get(plan.principal)
        ):
            errors.append("PLAN-SCOPE")
        if cert.derivations.get("args.amount_ref") != InputTerm(input_ref=amount.id, slot="amount"):
            errors.append("PROV-MISMATCH")
        for field in ("args.allocation_ref", "args.allocation_item_ref"):
            if cert.derivations.get(field) != InputTerm(
                input_ref=binding.id, slot="allocation_binding"
            ):
                errors.append("PROV-MISMATCH")
    except ValueError as exc:
        errors.append(str(exc) if str(exc) == "PLAN-SCOPE" else "AUTH-SCOPE")
    if cert.best_interest is not None:
        errors.append("ALLOC-SELECT")
    if result.certificate is not None:
        evaluation = evaluate_allocation(
            plan.principal,
            plan.parent_intent_id,
            plan.request_ref,
            state,
            budget_override=plan.initial_budget,
        )
        errors.extend(verify_allocation(cert.allocation, evaluation, state))
    return list(dict.fromkeys(errors))


def allocation_dependency_projection(action: BankAction, state: BankState) -> dict[str, str]:
    """Parent scope and controls join each fresh child's ordinary approval dependencies."""
    ref = action.args.model_dump().get("allocation_ref")
    plan = state.allocation_plans.get(str(ref))
    if plan is None:
        return {"parent": H(None)}
    return {
        "parent": H(plan),
        "parent_inputs": H({
            key: value
            for key, value in state.user_inputs.items()
            if value.principal == plan.principal and value.scope_id == plan.parent_intent_id
        }),
        "control": H(latest_events(state).get(H({"allocation_control": plan.id}))),
    }
