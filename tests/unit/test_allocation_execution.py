"""Independent signed-parent and receipt-budget tests for allocation dispatch."""

from fractions import Fraction
from uuid import NAMESPACE_URL, uuid5

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT, RECEIPT
from corridor.kernel.allocation import build_allocation
from corridor.kernel.allocation_execution import (
    allocation_child_intent,
    allocation_dependency_projection,
    allocation_item_id,
    allocation_plan_hash,
    allocation_purchase_errors,
    inspect_allocation_plan,
)
from corridor.schemas.allocation import AllocationPlan, AllocationPlanItem
from corridor.schemas.bank import (
    AccountMovement,
    BankAction,
    BankCertificate,
    BankEffect,
    BankOrder,
    BankReceipt,
    BusinessEvent,
    InputTerm,
    OperationAuthorization,
)
from corridor.schemas.domain import Position
from corridor.sim.device import Device
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.stores.bank import add_seconds
from tests.bank_cases import signed


def execution_case(*, fee=Fraction()):
    state = make_wealth_state()
    device = Device()
    request = device.confirm_input(
        intent_id="PARENT",
        slot="allocation",
        value=allocation_request().model_dump(mode="json"),
        now=state.now,
    )
    state = state.model_copy(update={"user_inputs": {request.id: request}})
    biac = build_allocation("C_DEMO", "PARENT", request.id, state)
    amounts = [
        device.confirm_input(
            intent_id=allocation_child_intent("PARENT", row.product_id),
            slot="amount",
            value={"amount": str(row.principal), "ccy": "CNY"},
            now=state.now,
        )
        for row in biac.allocation
    ]
    links = [
        device.confirm_input(
            intent_id=amount.scope_id, slot="allocation_binding", value={}, now=state.now, step=2
        )
        for amount in amounts
    ]
    items = [
        AllocationPlanItem(
            item_ref=allocation_item_id("PARENT", row.product_id),
            product_ref=row.product_id,
            principal=row.principal,
            fee_buy=row.fee_buy,
            child_intent_id=amounts[i].scope_id,
            input_refs=[amounts[i].id, links[i].id],
            authorization_ref=f"AUTH_{i}",
            child_plan_id=f"PLAN_{i}",
            child_plan_hash=H({"child": i}),
            child_node_id="BUY",
        )
        for i, row in enumerate(biac.allocation)
    ]
    selection = device.confirm_input(
        intent_id="PARENT", slot="allocation_selection", value={}, now=state.now, step=2
    )
    parent = AllocationPlan(
        id="ALLOCATION_PARENT",
        principal="C_DEMO",
        parent_intent_id="PARENT",
        request_ref=request.id,
        biac_hash=H(biac),
        policy_hash=biac.policy_hash,
        catalog_hash=biac.catalog_hash,
        risk_assessment_hash=biac.risk_assessment_hash,
        initial_budget=Fraction(12000),
        items=items,
        plan_hash="0" * 64,
        selection_input_ref=selection.id,
    )
    parent = parent.model_copy(update={"plan_hash": allocation_plan_hash(parent)})
    selection = signed(
        selection.model_copy(
            update={
                "value": {
                    "parent_id": parent.id,
                    "plan_hash": parent.plan_hash,
                    "biac_hash": parent.biac_hash,
                    "request_ref": request.id,
                    "selected_items": sorted(item.item_ref for item in items),
                }
            }
        ),
        INPUT,
    )
    actions, certs, auths = [], [], []
    for i, item in enumerate(items):
        links[i] = signed(
            links[i].model_copy(
                update={
                    "value": {
                        "allocation_ref": parent.id,
                        "allocation_item_ref": item.item_ref,
                        "parent_intent_id": parent.parent_intent_id,
                        "request_hash": biac.request_hash,
                        "biac_hash": parent.biac_hash,
                        "product_ref": item.product_ref,
                        "principal": str(item.principal),
                        "fee_buy": str(item.fee_buy),
                        "parent_plan_hash": parent.plan_hash,
                    }
                }
            ),
            INPUT,
        )
        auth = signed(
            OperationAuthorization(
                id=item.authorization_ref,
                principal="C_DEMO",
                intent_id=item.child_intent_id,
                allowed_kind="purchase_product",
                object_refs=["A_CURRENT", item.product_ref, parent.id],
                amount_bound=item.principal + item.fee_buy + fee,
                expires_at=add_seconds(state.now, 300),
                input_hashes=[H(amounts[i]), H(links[i])],
                sig="0" * 128,
            ),
            CONTROL,
        )
        action = BankAction(
            action_id=f"ACTION_{i}",
            intent_id=item.child_intent_id,
            principal="C_DEMO",
            device_session_id="SESSION",
            plan_id=item.child_plan_id,
            plan_hash=item.child_plan_hash,
            node_id=item.child_node_id,
            kind="purchase_product",
            args={
                "source_ref": "A_CURRENT",
                "product_ref": item.product_ref,
                "amount_ref": amounts[i].id,
                "allocation_ref": parent.id,
                "allocation_item_ref": item.item_ref,
            },
        )
        cert = BankCertificate(
            action_hash=H(action),
            authorization_ref=auth.id,
            allocation=biac,
            dependency_hashes={},
            derivations={
                "args.amount_ref": InputTerm(input_ref=amounts[i].id, slot="amount"),
                "args.allocation_ref": InputTerm(input_ref=links[i].id, slot="allocation_binding"),
                "args.allocation_item_ref": InputTerm(
                    input_ref=links[i].id, slot="allocation_binding"
                ),
            },
        )
        actions.append(action)
        certs.append(cert)
        auths.append(auth)
    state = state.model_copy(
        update={
            "allocation_plans": {parent.id: parent},
            "user_inputs": {value.id: value for value in [request, selection, *amounts, *links]},
            "authorizations": {auth.id: auth for auth in auths},
            "security": state.security.model_copy(
                update={"active_device_sessions": {"C_DEMO": "SESSION"}}
            ),
        }
    )
    return parent, actions, certs, control(state, parent, "ready")


def control(state, parent, status):
    event = BusinessEvent(
        id=f"CONTROL_{len(state.ledger)}",
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
    return state.model_copy(update={"ledger": [*state.ledger, event]})


def settled(state, action, cert, *, receipt_update=None, event_update=None):
    item = next(
        item
        for item in state.allocation_plans[action.args.allocation_ref].items
        if item.item_ref == action.args.allocation_item_ref
    )
    key = H({"principal": action.principal, "intent_id": action.intent_id, "kind": action.kind})
    order = BankOrder(
        intent_key=key,
        action_id=action.action_id,
        principal=action.principal,
        kind="purchase_product",
        requested_at=state.now,
        args={
            "source_ref": "A_CURRENT",
            "product_ref": item.product_ref,
            "amount": item.principal,
            "fee_buy": item.fee_buy,
        },
    )
    lot_id = str(uuid5(uuid5(NAMESPACE_URL, "corridor-demo-v0"), f"{key}:0:position"))
    position = Position(
        id=lot_id,
        owner=action.principal,
        product_ref=item.product_ref,
        principal_amount=item.principal,
        units=item.principal,
        reserved_units=Fraction(),
        nav=Fraction(1),
        acquired_at=state.now,
        redeemable_at=add_seconds(state.now, 30 * 86400),
        status="active",
    )
    receipt = signed(
        BankReceipt(
            receipt_id=f"RECEIPT_{item.product_ref}",
            intent_key=key,
            kind="purchase_product",
            status="settled",
            executed_at=state.now,
            sig="0" * 128,
            exact_effects=[
                BankEffect(
                    effect_type="debit",
                    object_ref="A_CURRENT",
                    account_ref="A_CURRENT",
                    counterparty_ref=item.product_ref,
                    amount=item.principal + item.fee_buy,
                    field="balance",
                    before="12000/1",
                    after=str(Fraction(12000) - item.principal - item.fee_buy),
                ),
                BankEffect(
                    effect_type="position",
                    object_ref=lot_id,
                    field="position",
                    after=position.model_dump(mode="json"),
                ),
            ],
        ),
        RECEIPT,
        "bank",
    )
    if receipt_update:
        receipt = receipt.model_copy(update=receipt_update)
    event = BusinessEvent(
        id=f"SETTLED_{item.product_ref}",
        intent_key=key,
        event="settled",
        kind="purchase_product",
        principal=action.principal,
        ts=state.now,
        bank_receipt_id=receipt.id,
        debit=AccountMovement(account_ref="A_CURRENT", amount=item.principal + item.fee_buy),
        object_delta={
            "action": action.model_dump(mode="json"),
            "cert": cert.model_dump(mode="json"),
            "order": order.model_dump(mode="json"),
        },
    )
    if event_update:
        event = event.model_copy(update=event_update)
    return state.model_copy(
        update={
            "ledger": [*state.ledger, event],
            "receipts": {receipt.id: receipt},
            "positions": {position.id: position},
        }
    )


def test_default_parent_authorizes_only_next_exact_child():
    parent, actions, certs, state = execution_case()
    result = inspect_allocation_plan(parent.id, state)
    assert (
        result.errors == () and result.current_budget == 12000 and result.remaining_debit == 10000
    )
    assert allocation_purchase_errors(actions[0], certs[0], state) == []
    assert "PLAN-SCOPE" in allocation_purchase_errors(actions[1], certs[1], state)


def test_only_verified_own_settled_debit_restores_original_budget():
    parent, actions, certs, state = execution_case()
    state = settled(state, actions[0], certs[0])
    result = inspect_allocation_plan(parent.id, state)
    assert result.errors == () and result.current_budget == 7000 and result.settled_debit == 5000
    assert result.remaining_debit == 5000 and result.certificate == certs[1].allocation
    assert allocation_purchase_errors(actions[1], certs[1], state) == []
    assert "AUTH-CONSUMED" in allocation_purchase_errors(actions[0], certs[0], state)


@pytest.mark.parametrize("status", ["stopped", "handoff", "failed", "unknown"])
def test_control_marker_blocks_direct_child_and_enters_approval_dependencies(status):
    parent, actions, certs, state = execution_case()
    before = allocation_dependency_projection(actions[0], state)
    state = control(state, parent, status)
    assert allocation_purchase_errors(actions[0], certs[0], state)
    assert allocation_dependency_projection(actions[0], state) != before
    assert inspect_allocation_plan(parent.id, state, require_ready=False).control_status == status


@pytest.mark.parametrize("fault", ["signature", "debit", "order", "pending", "unknown"])
def test_foreign_or_unverified_effects_are_never_added_back(fault):
    parent, actions, certs, state = execution_case()
    receipt_update = {"sig": "0" * 128} if fault == "signature" else None
    event_update = (
        {"event": "reserved" if fault == "pending" else "unknown"}
        if fault in {"pending", "unknown"}
        else None
    )
    if fault == "debit":
        event_update = {"debit": AccountMovement(account_ref="A_CURRENT", amount=Fraction(4000))}
    state = settled(
        state, actions[0], certs[0], receipt_update=receipt_update, event_update=event_update
    )
    if fault == "order":
        event = state.ledger[-1]
        order = {**event.object_delta["order"], "principal": "OTHER"}
        event = event.model_copy(update={"object_delta": {**event.object_delta, "order": order}})
        state = state.model_copy(update={"ledger": [*state.ledger[:-1], event]})
    result = inspect_allocation_plan(parent.id, state)
    assert result.errors and result.settled_debit == 0
    assert allocation_purchase_errors(actions[1], certs[1], state)


def test_external_budget_change_cannot_be_added_back():
    parent, actions, certs, state = execution_case()
    state = settled(state, actions[0], certs[0])
    other = BusinessEvent(
        id="OTHER_DEBIT",
        intent_key=H("OTHER"),
        event="settled",
        kind="transfer",
        principal="C_DEMO",
        ts=state.now,
        debit=AccountMovement(account_ref="A_CURRENT", amount=Fraction(1)),
    )
    state = state.model_copy(update={"ledger": [*state.ledger, other]})
    assert "APR-DRIFT" in inspect_allocation_plan(parent.id, state).errors


@pytest.mark.parametrize(
    "field,value",
    [
        ("intent_id", "OTHER"),
        ("plan_id", "OTHER"),
        ("plan_hash", "0" * 64),
        ("node_id", "OTHER"),
        ("device_session_id", "OTHER"),
    ],
)
def test_child_mapping_and_session_cannot_be_rewrapped(field, value):
    _, actions, certs, state = execution_case()
    action = actions[0].model_copy(update={field: value})
    assert allocation_purchase_errors(
        action, certs[0].model_copy(update={"action_hash": H(action)}), state
    )


def test_child_authorization_exactly_binds_total_debit():
    _, actions, certs, state = execution_case(fee=Fraction(1, 100))
    assert "AUTH-SCOPE" in allocation_purchase_errors(actions[0], certs[0], state)


def test_parent_selection_is_all_items_and_input_scope_is_parent():
    parent, actions, certs, state = execution_case()
    old = state.user_inputs[parent.selection_input_ref]
    changed = signed(
        old.model_copy(
            update={"value": {**old.value, "selected_items": [parent.items[0].item_ref]}}
        ),
        INPUT,
    )
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, old.id: changed}})
    assert "PLAN-SCOPE" in allocation_purchase_errors(actions[0], certs[0], state)


def test_parent_plan_hash_and_child_signed_bindings_are_checked_independently():
    parent, actions, certs, state = execution_case()
    bad = parent.model_copy(update={"initial_budget": Fraction(99999)})
    state = state.model_copy(update={"allocation_plans": {parent.id: bad}})
    assert "PLAN-SCOPE" in inspect_allocation_plan(parent.id, state).errors


def test_missing_request_account_fails_with_a_rule_instead_of_exception():
    parent, _, _, state = execution_case()
    state = state.model_copy(update={"accounts": {}})
    assert inspect_allocation_plan(parent.id, state).errors


@pytest.mark.parametrize("fault", ["signature", "scope", "batch", "parent_hash", "amount"])
def test_signed_child_binding_and_amount_are_not_free_form_authority(fault):
    parent, actions, certs, state = execution_case()
    item = parent.items[0]
    ref = next(
        ref for ref in item.input_refs if state.user_inputs[ref].slot == "allocation_binding"
    )
    value = state.user_inputs[ref]
    change = {
        "signature": {"sig": "0" * 128},
        "scope": {"scope_id": "OTHER"},
        "batch": {"batch_id": "OTHER"},
        "parent_hash": {"value": {**value.value, "parent_plan_hash": "0" * 64}},
        "amount": {"value": {**value.value, "principal": "5001/1"}},
    }[fault]
    value = value.model_copy(update=change)
    if fault != "signature":
        value = signed(value, INPUT)
    # Updating the independently signed operation scope cannot cure a bad parent binding.
    auth = state.authorizations[item.authorization_ref]
    hashes = [H(value) if raw == H(state.user_inputs[ref]) else raw for raw in auth.input_hashes]
    auth = signed(auth.model_copy(update={"input_hashes": hashes}), CONTROL)
    state = state.model_copy(
        update={
            "user_inputs": {**state.user_inputs, ref: value},
            "authorizations": {**state.authorizations, auth.id: auth},
        }
    )
    assert allocation_purchase_errors(actions[0], certs[0], state)


def test_stripping_allocation_fields_cannot_reuse_registered_child_as_legacy():
    from corridor.kernel.allocation import allocation_errors

    _, actions, certs, state = execution_case()
    args = actions[0].args.model_dump(mode="json")
    args.pop("allocation_ref")
    args.pop("allocation_item_ref")
    args["preference_ref"] = "LEGACY_PREF"
    action = BankAction.model_validate({**actions[0].model_dump(mode="json"), "args": args})
    assert allocation_errors(action, certs[0].model_copy(update={"allocation": None}), state) == [
        "PLAN-SCOPE"
    ]


@pytest.mark.parametrize("slot", ["allocation", "allocation_selection"])
def test_superseded_parent_inputs_preserve_receipted_partial_projection(slot):
    parent, actions, certs, state = execution_case()
    state = settled(state, actions[0], certs[0])
    old_ref = parent.request_ref if slot == "allocation" else parent.selection_input_ref
    old = state.user_inputs[old_ref]
    new = Device().confirm_input(
        intent_id="PARENT", slot=slot, value=old.value, now=state.now, step=3, supersedes=old.id
    )
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, new.id: new}})
    result = inspect_allocation_plan(parent.id, state, require_ready=False)
    assert result.errors and result.settled_item_refs == (parent.items[0].item_ref,)
    assert result.settled_debit == 5000 and result.current_budget == 7000
    assert allocation_purchase_errors(actions[1], certs[1], state)


def test_catalogue_drift_cannot_erase_already_signed_bank_position():
    from corridor.crypto.sign import CATALOG

    parent, actions, certs, state = execution_case()
    state = settled(state, actions[0], certs[0])
    products = [
        p.model_copy(update={"min_hold_days": 31}) if p.id == "P_A" else p
        for p in state.catalog.products
    ]
    catalog = signed(state.catalog.model_copy(update={"products": products}), CATALOG, "bank")
    state = state.model_copy(update={"catalog": catalog})
    result = inspect_allocation_plan(parent.id, state, require_ready=False)
    assert "BIC-CATALOG" in result.errors
    assert result.settled_item_refs == (parent.items[0].item_ref,) and result.settled_debit == 5000
