"""Immutable allocation registration and sequential, separately approved execution."""

from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import TYPE_CHECKING, Any
from uuid import NAMESPACE_URL, uuid5

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import CONTROL, INPUT, verify
from corridor.gateway.plans import validate_plan
from corridor.i18n import tr
from corridor.kernel.allocation import build_allocation
from corridor.kernel.allocation_execution import (
    allocation_child_intent,
    allocation_item_id,
    allocation_plan_hash,
    inspect_allocation_plan,
)
from corridor.schemas.allocation import (
    AllocationPlan,
    AllocationPlanItem,
    BestInterestAllocationCertificate,
)
from corridor.schemas.bank import (
    BusinessEvent,
    InputTerm,
    OperationAuthorization,
    Plan,
    PlanNode,
    StateTerm,
    UserInput,
)
from corridor.schemas.money import fraction_string
from corridor.schemas.state import BankState
from corridor.stores.bank import available, latest_events

if TYPE_CHECKING:
    from corridor.gateway.service import Gateway, GatewayResult

_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")
_CONTROL_STATUSES = frozenset({"ready", "stopped", "handoff", "failed", "unknown"})


def _id(task: str, step: int, kind: str) -> str:
    return str(uuid5(_NAMESPACE, f"{task}:{step}:{kind}"))


@dataclass(frozen=True)
class AllocationDraft:
    parent: AllocationPlan
    children: tuple[Plan, ...]
    biac: BestInterestAllocationCertificate
    overview: dict[str, Any]


def allocation_parent_for_child(state: BankState, child_plan_id: str) -> str | None:
    matches = [
        parent.id
        for parent in state.allocation_plans.values()
        if any(item.child_plan_id == child_plan_id for item in parent.items)
    ]
    if len(matches) > 1:
        raise ValueError("PLAN-SCOPE")
    return matches[0] if matches else None


def _control(state: BankState, parent_id: str) -> str | None:
    event = latest_events(state).get(H({"allocation_control": parent_id}))
    if event is None:
        return None
    status = event.object_delta.get("status")
    return status if isinstance(status, str) else None


def _used_parent(state: BankState, parent: AllocationPlan) -> bool:
    child_intents = {item.child_intent_id for item in parent.items}
    for event in state.ledger:
        action = event.object_delta.get("action")
        if (
            event.kind == "purchase_product"
            and isinstance(action, dict)
            and action.get("intent_id") in child_intents
            and event.event in {"reserved", "unknown", "settled"}
        ):
            return True
    return False


def draft_allocation(
    gateway: "Gateway", principal: str, parent_intent_id: str, request_ref: str
) -> AllocationDraft:
    """Render a complete unsigned overview without creating payment authority."""
    from corridor.gateway.service import _LOCK

    with _LOCK:
        state = gateway.store.snapshot()
        if principal in state.security.locked_at:
            raise ValueError("APR-LOCK")
        session = state.security.active_device_sessions.get(principal)
        if session is None:
            raise ValueError("AUTH-PRINCIPAL")
        for old in state.allocation_plans.values():
            if (
                old.principal == principal
                and old.parent_intent_id == parent_intent_id
                and _used_parent(state, old)
            ):
                raise ValueError("AUTH-CONSUMED")
            if (
                old.principal == principal
                and old.parent_intent_id == parent_intent_id
                and old.request_ref != request_ref
            ):
                raise ValueError("PLAN-SCOPE")
        biac = build_allocation(principal, parent_intent_id, request_ref, state)
        request = state.user_inputs[request_ref]
        revision = request.version
        suffix = H(request)[:16]
        parent_id = _id(parent_intent_id, revision, f"allocation-plan-{suffix}")
        selection_ref = _id(parent_intent_id, revision, f"input-allocation-selection-{suffix}")
        children: list[Plan] = []
        items: list[AllocationPlanItem] = []
        source = state.accounts[biac.source_account_ref]
        products = {product.id: product for product in state.catalog.products}
        for row in biac.allocation:
            child_intent = allocation_child_intent(parent_intent_id, row.product_id)
            item_ref = allocation_item_id(parent_intent_id, row.product_id)
            amount_ref = _id(child_intent, revision, f"input-amount-{suffix}")
            binding_ref = _id(child_intent, revision, f"input-allocation-binding-{suffix}")
            plan_id = _id(child_intent, revision, f"allocation-plan-{suffix}")
            node_id = _id(child_intent, 0, "allocation-node")
            child = Plan(
                plan_id=plan_id,
                revision=revision,
                principal=principal,
                device_session_id=session,
                intent_id=child_intent,
                goal_input_refs=[amount_ref, binding_ref],
                ownership_epoch=0,
                nodes=[
                    PlanNode(
                        node_id=node_id,
                        tool="purchase_product",
                        args={
                            "source_ref": StateTerm(
                                collection="accounts",
                                object_ref=source.id,
                                field="id",
                                version=source.version,
                            ),
                            "product_ref": StateTerm(
                                collection="catalog",
                                object_ref=row.product_id,
                                field="id",
                                version=products[row.product_id].version,
                            ),
                            "amount_ref": InputTerm(input_ref=amount_ref, slot="amount"),
                            "allocation_ref": InputTerm(
                                input_ref=binding_ref, slot="allocation_binding"
                            ),
                            "allocation_item_ref": InputTerm(
                                input_ref=binding_ref, slot="allocation_binding"
                            ),
                        },
                    )
                ],
            )
            children.append(child)
            items.append(
                AllocationPlanItem(
                    item_ref=item_ref,
                    product_ref=row.product_id,
                    principal=row.principal,
                    fee_buy=row.fee_buy,
                    child_intent_id=child_intent,
                    input_refs=[amount_ref, binding_ref],
                    authorization_ref=_id(
                        child_intent, revision, f"allocation-authorization-{suffix}"
                    ),
                    child_plan_id=plan_id,
                    child_plan_hash=H(child),
                    child_node_id=node_id,
                )
            )
        parent = AllocationPlan(
            id=parent_id,
            version=revision,
            principal=principal,
            parent_intent_id=parent_intent_id,
            request_ref=request_ref,
            biac_hash=H(biac),
            policy_hash=biac.policy_hash,
            catalog_hash=biac.catalog_hash,
            risk_assessment_hash=biac.risk_assessment_hash,
            initial_budget=available(state, source.id) - source.floor,
            items=items,
            plan_hash="0" * 64,
            selection_input_ref=selection_ref,
        )
        parent = parent.model_copy(update={"plan_hash": allocation_plan_hash(parent)})
        overview = {
            "parent_id": parent.id,
            "plan_hash": parent.plan_hash,
            "biac_hash": H(biac),
            "items": [item.model_dump(mode="json") for item in items],
            "totals": biac.totals.model_dump(mode="json"),
            "checks": [check.model_dump(mode="json") for check in biac.checks],
            "selection_mode": biac.selection_mode,
            "deviation_notice": (
                tr("Deviation from model allocation", locale="en")
                if biac.selection_mode != "default"
                else None
            ),
            "deviations": biac.deviations.model_dump(mode="json") if biac.deviations else None,
            # The overview participates in canonical device confirmation. Translate
            # its presentation at the UI boundary, never its retained content.
            "notice": tr(
                "Each purchase requires separate MFA and approval. "
                "Settled purchases are not automatically reversed.",
                locale="en",
            ),
        }
        return AllocationDraft(parent, tuple(children), biac, overview)


def mark_allocation(gateway: "Gateway", parent: AllocationPlan, status: str) -> None:
    """Persist a parent control fact before any subsequent child can execute."""
    from corridor.gateway.service import _LOCK

    with _LOCK:
        state = gateway.store.snapshot()
        if status not in _CONTROL_STATUSES or state.allocation_plans.get(parent.id) != parent:
            raise ValueError("PLAN-SCOPE")
        previous = _control(state, parent.id)
        if previous == status:
            return
        if previous in {"stopped", "handoff", "failed", "unknown"}:
            return
        if status == "ready" and previous is not None:
            raise ValueError("APR-VOID")
        event = BusinessEvent(
            id=_id(parent.id, len(state.ledger), f"allocation-control-{status}"),
            intent_key=H({"allocation_control": parent.id}),
            event="settled",
            kind="allocation_compare",
            principal=parent.principal,
            ts=state.now,
            object_delta={
                "allocation_ref": parent.id,
                "parent_intent_id": parent.parent_intent_id,
                "plan_hash": parent.plan_hash,
                "status": status,
            },
        )
        gateway.store.append_event(event)
        gateway._audit(
            "allocation_control",
            parent.principal,
            {
                "allocation_ref": parent.id,
                "plan_hash": parent.plan_hash,
                "status": status,
                "event_hash": H(event),
            },
        )


def _write_manifest(gateway: "Gateway", parent: AllocationPlan) -> None:
    if gateway.evidence_dir is None:
        return
    state = gateway.store.snapshot()
    payload = {
        "schema_version": "allocation-manifest-v1",
        "allocation_ref": parent.id,
        "parent_intent_id": parent.parent_intent_id,
        "plan_hash": parent.plan_hash,
        "biac_hash": parent.biac_hash,
        "request_hash": H(state.user_inputs[parent.request_ref]),
        "selection_hash": H(state.user_inputs[parent.selection_input_ref or ""]),
        "policy_hash": parent.policy_hash,
        "catalog_hash": parent.catalog_hash,
        "risk_assessment_hash": parent.risk_assessment_hash,
        "children": [
            {
                "item_ref": item.item_ref,
                "child_plan_id": item.child_plan_id,
                "child_plan_hash": item.child_plan_hash,
                "child_intent_id": item.child_intent_id,
                "authorization_hash": H(state.authorizations[item.authorization_ref]),
                "input_hashes": [H(state.user_inputs[ref]) for ref in item.input_refs],
                "decision_key": H({
                    "principal": parent.principal,
                    "intent_id": item.child_intent_id,
                    "kind": "purchase_product",
                }),
            }
            for item in parent.items
        ],
    }
    gateway.vault.ensure_safe(payload, rule="PII-OUT")
    directory = gateway.evidence_dir.parent / "allocations"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{parent.id}.json"
    data = jcs_bytes(payload)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError("AUD-CHAIN")
        return
    with path.open("xb") as stream:
        if stream.write(data) != len(data):
            raise OSError("AUD-WRITE")


def register_allocation(
    gateway: "Gateway",
    draft: AllocationDraft,
    *,
    selection: UserInput | None,
    inputs: Sequence[UserInput],
    authorizations: Sequence[OperationAuthorization],
) -> "GatewayResult":
    """Validate the entire signed bundle before adding any child authority."""
    from corridor.gateway.service import _LOCK, GatewayResult

    with _LOCK:
        parent = draft.parent
        if selection is None:
            return GatewayResult("draft", details=draft.overview)
        try:
            state = gateway.store.snapshot()
            if gateway._write_failed or not gateway.audit.verify():
                return gateway._failure(parent.principal, "AUD-CHAIN")
            existing = state.allocation_plans.get(parent.id)
            if existing is not None:
                if existing != parent or _control(state, parent.id) != "ready":
                    return gateway._failure(parent.principal, "APR-VOID")
                expected_inputs = {ref for item in parent.items for ref in item.input_refs}
                expected_auths = {item.authorization_ref for item in parent.items}
                if (
                    selection != state.user_inputs.get(parent.selection_input_ref or "")
                    or len(inputs) != len(expected_inputs)
                    or {value.id for value in inputs} != expected_inputs
                    or any(value != state.user_inputs.get(value.id) for value in inputs)
                    or len(authorizations) != len(expected_auths)
                    or {value.id for value in authorizations} != expected_auths
                    or any(auth != state.authorizations.get(auth.id) for auth in authorizations)
                ):
                    return gateway._failure(parent.principal, "PLAN-SCOPE")
                inspection = inspect_allocation_plan(parent.id, state)
                if inspection.errors:
                    return gateway._failure(parent.principal, inspection.errors[0])
                return GatewayResult("ready", details=allocation_snapshot(gateway, parent.id))
            canonical = draft_allocation(
                gateway, parent.principal, parent.parent_intent_id, parent.request_ref
            )
            if (
                parent != canonical.parent
                or draft.children != canonical.children
                or draft.biac != canonical.biac
                or draft.overview != canonical.overview
            ):
                return gateway._failure(parent.principal, "PLAN-SCOPE")
            selection = UserInput.model_validate(selection.model_dump(mode="python"))
            signed_inputs = [
                UserInput.model_validate(value.model_dump(mode="python")) for value in inputs
            ]
            signed_auths = [
                OperationAuthorization.model_validate(value.model_dump(mode="python"))
                for value in authorizations
            ]
            expected_refs = {ref for item in parent.items for ref in item.input_refs}
            if (
                len(signed_inputs) != len(expected_refs)
                or {value.id for value in signed_inputs} != expected_refs
                or len(signed_auths) != len(parent.items)
                or {value.id for value in signed_auths}
                != {item.authorization_ref for item in parent.items}
                or selection.id != parent.selection_input_ref
            ):
                return gateway._failure(parent.principal, "PLAN-SCOPE")
            customer = state.customers[parent.principal]
            for value in [selection, *signed_inputs]:
                if (
                    value.principal != parent.principal
                    or value.submitted_at > state.now
                    or not verify(customer.device_pubkey, INPUT, value, value.sig)
                    or value.id in state.user_inputs
                    and state.user_inputs[value.id] != value
                ):
                    return gateway._failure(parent.principal, "AUTH-SIG")
            for auth in signed_auths:
                if (
                    auth.principal != parent.principal
                    or not verify(customer.device_pubkey, CONTROL, auth, auth.sig)
                    or auth.id in state.authorizations
                    and state.authorizations[auth.id] != auth
                ):
                    return gateway._failure(parent.principal, "AUTH-SIG")
            gateway.vault.ensure_safe((
                parent,
                selection,
                signed_inputs,
                signed_auths,
                draft.children,
            ))
            candidate = BankState.model_validate({
                **state.model_dump(mode="python"),
                "allocation_plans": {**state.allocation_plans, parent.id: parent},
                "user_inputs": {
                    **state.user_inputs,
                    selection.id: selection,
                    **{value.id: value for value in signed_inputs},
                },
                "authorizations": {
                    **state.authorizations,
                    **{auth.id: auth for auth in signed_auths},
                },
            })
            inspection = inspect_allocation_plan(parent.id, candidate, require_ready=False)
            if inspection.errors:
                return gateway._failure(parent.principal, inspection.errors[0])
            for child in draft.children:
                rule = validate_plan(child, candidate)
                if rule:
                    return gateway._failure(parent.principal, rule)
                if child.plan_id in gateway._plans and gateway._plans[child.plan_id] != child:
                    return gateway._failure(parent.principal, "PLAN-SCOPE")
            gateway.store.update(
                allocation_plans=candidate.allocation_plans,
                user_inputs=candidate.user_inputs,
                authorizations=candidate.authorizations,
            )
            for old in state.allocation_plans.values():
                if (
                    old.principal == parent.principal
                    and old.parent_intent_id == parent.parent_intent_id
                ):
                    mark_allocation(gateway, old, "stopped")
            for child in draft.children:
                result = gateway.submit_plan(child)
                if result.status != "registered":
                    mark_allocation(gateway, parent, "failed")
                    return result
            gateway._audit(
                "allocation_registered",
                parent.principal,
                {
                    "allocation_ref": parent.id,
                    "plan_hash": parent.plan_hash,
                    "biac_hash": parent.biac_hash,
                    "selection_hash": H(selection),
                    "child_plan_hashes": [item.child_plan_hash for item in parent.items],
                },
            )
            _write_manifest(gateway, parent)
            mark_allocation(gateway, parent, "ready")
            return GatewayResult("ready", details=allocation_snapshot(gateway, parent.id))
        except OSError:
            gateway._write_failed = True
            return gateway._failure(parent.principal, "AUD-WRITE")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            rule = (
                str(exc)
                if str(exc) in {"APR-LOCK", "AUTH-CONSUMED", "AUD-CHAIN", "PII-OUT", "PII-CTX"}
                else "PLAN-SCOPE"
            )
            return gateway._failure(parent.principal, rule)


def allocation_snapshot(gateway: "Gateway", parent_id: str) -> dict[str, Any]:
    from corridor.gateway.service import _LOCK

    with _LOCK:
        state = gateway.store.snapshot()
        parent = state.allocation_plans[parent_id]
        inspection = inspect_allocation_plan(parent_id, state, require_ready=False)
        control = _control(state, parent_id)
        settled = set(inspection.settled_item_refs)
        events = latest_events(state)
        rows: list[dict[str, Any]] = []
        for item in parent.items:
            key = H({
                "principal": parent.principal,
                "intent_id": item.child_intent_id,
                "kind": "purchase_product",
            })
            event = events.get(key)
            rows.append({
                "item_ref": item.item_ref,
                "product_ref": item.product_ref,
                "principal": f"{item.principal.numerator}/{item.principal.denominator}",
                "fee_buy": f"{item.fee_buy.numerator}/{item.fee_buy.denominator}",
                "status": "settled"
                if item.item_ref in settled
                else "unknown"
                if event and event.event == "settled"
                else event.event
                if event
                else "pending",
                "receipt_ref": event.bank_receipt_id if event else None,
                "decision_key": key,
                "child_plan_id": item.child_plan_id,
            })
        unknown = any(row["status"] in {"unknown", "reserved"} for row in rows)
        terminal = control in {"stopped", "handoff", "failed", "unknown"}
        if unknown:
            status = "unknown"
        elif len(settled) == len(parent.items):
            status = "completed"
        elif terminal or inspection.errors:
            status = (
                "partially_executed"
                if settled
                else "cancelled"
                if control in {"stopped", "handoff"}
                else "failed"
            )
        else:
            status = "executing" if settled else "ready" if control == "ready" else "draft"
        return {
            "allocation_ref": parent.id,
            "plan_hash": parent.plan_hash,
            "biac_hash": parent.biac_hash,
            "status": status,
            "control_status": control,
            "items": rows,
            "settled_principal": fraction_string(
                sum(
                    (item.principal for item in parent.items if item.item_ref in settled),
                    Fraction(),
                )
            ),
            "rule_ids": list(inspection.errors),
            "audit_checkpoint": gateway.audit.checkpoint(),
            "resume_notice": tr(
                "Stopped, failed, handed-off and unknown plans do not resume automatically."
            ),
        }


def advance_allocation(gateway: "Gateway", parent_id: str) -> "GatewayResult":
    from corridor.gateway.service import _LOCK, GatewayResult

    with _LOCK:
        state = gateway.store.snapshot()
        parent = state.allocation_plans[parent_id]
        inspection = inspect_allocation_plan(parent_id, state)
        if inspection.errors:
            return gateway._failure(parent.principal, inspection.errors[0])
        if not inspection.remaining_item_refs:
            return GatewayResult("completed", details=allocation_snapshot(gateway, parent_id))
        item = next(
            item for item in parent.items if item.item_ref == inspection.remaining_item_refs[0]
        )
        results = gateway.advance_plan(item.child_plan_id)
        if not results:
            return GatewayResult(
                "waiting_input", ["PLAN-SCOPE"], details=allocation_snapshot(gateway, parent_id)
            )
        result = results[0]
        if result.status in {"failed", "rejected", "unknown"}:
            mark_allocation(gateway, parent, "unknown" if result.status == "unknown" else "failed")
        result.details["allocation_ref"] = parent_id
        result.details["allocation_item_ref"] = item.item_ref
        return result


def stop_allocation(
    gateway: "Gateway", parent_id: str, *, handoff: bool = False
) -> "GatewayResult":
    from corridor.gateway.service import _LOCK, GatewayResult

    with _LOCK:
        parent = gateway.store.snapshot().allocation_plans.get(parent_id)
        if parent is None:
            return GatewayResult("rejected", ["PLAN-SCHEMA"])
        try:
            if allocation_snapshot(gateway, parent_id)["status"] == "completed":
                return GatewayResult("completed", details=allocation_snapshot(gateway, parent_id))
            mark_allocation(gateway, parent, "handoff" if handoff else "stopped")
            for item in parent.items:
                if item.child_plan_id in gateway._plans:
                    gateway._blocked_plans.add(item.child_plan_id)
                    gateway.audit.append(
                        "plan_interrupted",
                        now=gateway.store.snapshot().now,
                        principal_token=parent.principal,
                        plan_id=item.child_plan_id,
                        payload={"plan_hash": item.child_plan_hash, "ownership_epoch": 0},
                    )
            snapshot = allocation_snapshot(gateway, parent_id)
            return GatewayResult(snapshot["status"], details=snapshot)
        except (OSError, ValueError):
            gateway._write_failed = True
            return gateway._failure(parent.principal, "AUD-WRITE")
