"""Independent exact investment receipt checks, including signed malicious effects."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, sign
from corridor.eval.mockbank.exec import MockBank
from corridor.gateway.bank_adapter import (
    compile_order,
    movements,
    receipt_updates,
    reservation_updates,
    validate_receipt,
)
from corridor.schemas.bank import BankAction, BankOrder, BusinessEvent
from corridor.schemas.domain import Position
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import available
from tests.bank_cases import transfer_case


def _order(kind, args, state, *, label="investment"):
    return BankOrder.model_validate({
        "intent_key": H({"kind": kind, "label": label}),
        "action_id": "ACTION_INVESTMENT",
        "principal": "C_DEMO",
        "kind": kind,
        "requested_at": state.now,
        "args": args,
    })


def _purchase():
    state = make_state()
    order = _order(
        "purchase_product",
        {
            "source_ref": "A_CURRENT",
            "product_ref": "P_B",
            "amount": "10001/100",
            "fee_buy": "101/100",
        },
        state,
    )
    bank = MockBank(state, signing_key("bank"))
    return order, bank.execute(order), state


def _redemption(*, delay=0, amount=Fraction(100), label="investment"):
    state = make_state()
    product = state.catalog.products[0].model_copy(
        update={
            "annual_fee_rate": Fraction(365, 10000),
            "redemption_fee_rate": Fraction(1, 1000),
            "redeem_delay_days": delay,
        }
    )
    position = Position(
        id="POSITION_TEST",
        owner="C_DEMO",
        product_ref=product.id,
        principal_amount=Fraction(1000),
        units=Fraction(1000),
        reserved_units=Fraction(0),
        nav=Fraction(1),
        acquired_at="2026-09-16T02:00:00Z",
        redeemable_at=state.now,
        status="active",
    )
    state = state.model_copy(
        update={
            "catalog": state.catalog.model_copy(update={"products": [product]}),
            "positions": {position.id: position},
            "subscriptions": {},
        }
    )
    order = _order(
        "redeem_product", {"position_ref": position.id, "amount": amount}, state, label=label
    )
    return order, state, MockBank(state, signing_key("bank"))


def _reserved(order, state):
    debit, credit = movements(order, state)
    original = state.positions[order.args.position_ref]
    event = BusinessEvent(
        id=f"RESERVE_{order.intent_key}",
        intent_key=order.intent_key,
        event="reserved",
        kind=order.kind,
        principal=order.principal,
        debit=debit,
        credit=credit,
        object_delta={
            "order": order.model_dump(mode="json"),
            "original_position": original.model_dump(mode="json"),
        },
        ts=state.now,
    )
    return state.model_copy(
        update={"ledger": [*state.ledger, event], **reservation_updates(order, state)}
    )


def _signed(receipt):
    return receipt.model_copy(update={"sig": sign(signing_key("bank"), RECEIPT, receipt)})


def test_compile_purchase_uses_exact_rounded_fee_and_no_preference_on_bank_wire():
    action, cert, state = transfer_case(Fraction(10001, 100))
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "purchase_product",
        "args": {
            "source_ref": "A_CURRENT",
            "product_ref": "P_B",
            "amount_ref": action.args.amount_ref,
            "preference_ref": "PREFERENCE",
        },
    })
    order = compile_order(action, cert, state)
    assert order.args.amount == Fraction(10001, 100)
    assert order.args.fee_buy == Fraction(101, 100)
    assert "preference_ref" not in order.args.model_dump()


def test_purchase_debits_fee_and_projects_exact_new_lot():
    order, receipt, state = _purchase()
    assert validate_receipt(order, receipt, state)
    debit, credit = movements(order, state)
    assert debit.account_ref == "A_CURRENT" and debit.amount == Fraction(5051, 50)
    assert credit is None
    updates = receipt_updates(order, receipt, state)
    position = next(iter(updates["positions"].values()))
    assert position.principal_amount == position.units == Fraction(10001, 100)
    assert position.reserved_units == 0 and position.version == 1
    assert position.acquired_at == state.now and position.redeemable_at == "2026-10-26T02:00:00Z"
    assert state.positions == {}


@pytest.mark.parametrize(
    "mutation", ["fee", "amount", "owner", "product", "hold", "extra", "id", "before"]
)
def test_signed_purchase_receipt_cannot_change_charge_or_lot(mutation):
    order, receipt, state = _purchase()
    effects = list(receipt.exact_effects)
    if mutation == "fee":
        effects[0] = effects[0].model_copy(update={"amount": Fraction(10001, 100)})
    elif mutation == "extra":
        effects.append(effects[1])
    else:
        after = dict(effects[1].after)
        field, value = {
            "amount": ("principal_amount", "100/1"),
            "owner": ("owner", "OTHER"),
            "product": ("product_ref", "P_A"),
            "hold": ("redeemable_at", state.now),
            "id": ("id", "UNRELATED_POSITION"),
            "before": ("version", 1),
        }[mutation]
        after[field] = value
        changes = {"after": after}
        if mutation == "before":
            changes["before"] = after
        effects[1] = effects[1].model_copy(update=changes)
    changed = _signed(receipt.model_copy(update={"exact_effects": effects}))
    assert not validate_receipt(order, changed, state)
    with pytest.raises(ValueError, match="BANK-RECEIPT"):
        receipt_updates(order, changed, state)


def test_immediate_redemption_charges_actual_held_days_and_preserves_acquisition():
    order, original, bank = _redemption()
    state = _reserved(order, original)
    assert state.positions["POSITION_TEST"].reserved_units == 100
    assert available(state, "A_CURRENT") == 10000
    receipt = bank.execute(order)
    assert receipt.status == "settled" and validate_receipt(order, receipt, state)
    debit, credit = movements(order, original)
    assert debit is None and credit.amount == Fraction(498, 5)
    assert credit.account_ref == "A_CURRENT"
    position = receipt_updates(order, receipt, state)["positions"]["POSITION_TEST"]
    assert position.units == position.principal_amount == 900
    assert position.reserved_units == 0 and position.version == 3
    assert position.acquired_at == original.positions[position.id].acquired_at
    assert receipt.exact_effects[0].after == "50498/5"


def test_pending_reserves_once_and_never_credits_until_verified_settlement():
    order, original, bank = _redemption(delay=2)
    state = _reserved(order, original)
    pending = bank.execute(order)
    assert pending.status == "pending" and pending.settle_at == "2026-10-18T02:00:00Z"
    assert validate_receipt(order, pending, state)
    state = state.model_copy(update=receipt_updates(order, pending, state))
    assert state.positions["POSITION_TEST"].reserved_units == 100
    assert state.positions["POSITION_TEST"].version == 2
    assert receipt_updates(order, pending, state)["positions"] == state.positions
    assert available(state, "A_CURRENT") == 10000
    assert bank.advance_clock("2026-10-18T01:59:59Z") == []
    assert bank.final_state()["balances"]["A_CURRENT"] == "10000/1"
    [settled] = bank.advance_clock("2026-10-18T02:00:00Z")
    assert not validate_receipt(order, settled, state)
    state = state.model_copy(update={"now": settled.settle_at})
    assert validate_receipt(order, settled, state)
    updates = receipt_updates(order, settled, state)
    position = updates["positions"]["POSITION_TEST"]
    assert position.units == 900 and position.reserved_units == 0 and position.version == 3
    assert position.acquired_at == original.positions[position.id].acquired_at


@pytest.mark.parametrize("pending", [False, True])
@pytest.mark.parametrize("mutation", ["amount", "acquired", "reserved", "time", "extra"])
def test_signed_redemption_receipt_requires_exact_units_fees_and_timing(pending, mutation):
    order, original, bank = _redemption(delay=2 if pending else 0)
    state = _reserved(order, original)
    receipt = bank.execute(order)
    effects = list(receipt.exact_effects)
    position_index = 0 if pending else 1
    after = dict(effects[position_index].after)
    if mutation == "amount":
        after["principal_amount"] = "999/1"
    elif mutation == "acquired":
        after["acquired_at"] = state.now
    elif mutation == "reserved":
        after["reserved_units"] = "99/1" if pending else "1/1"
    elif mutation == "extra":
        effects.append(effects[0])
    effects[position_index] = effects[position_index].model_copy(update={"after": after})
    changed = receipt.model_copy(update={"exact_effects": effects})
    if mutation == "time":
        changed = changed.model_copy(update={"settle_at": "2026-10-19T02:00:00Z"})
    assert not validate_receipt(order, _signed(changed), state)


def test_failed_redemption_releases_local_reservation_without_changing_lot():
    order, original, bank = _redemption(delay=2)
    state = _reserved(order, original)
    bank.faults[order.intent_key] = "failed"
    receipt = bank.execute(order)
    assert validate_receipt(order, receipt, state)
    updates = receipt_updates(order, receipt, state)
    assert updates["positions"] == original.positions
    assert available(state, "A_CURRENT") == 10000


def test_unknown_redemption_holds_units_until_lookup_recovery():
    order, original, bank = _redemption(delay=2)
    state = _reserved(order, original)
    bank.faults[order.intent_key] = "response_loss"
    with pytest.raises(TimeoutError):
        bank.execute(order)
    assert state.positions["POSITION_TEST"].reserved_units == 100
    assert available(state, "A_CURRENT") == 10000
    receipt = bank.lookup(order.intent_key)
    assert receipt.status == "pending" and validate_receipt(order, receipt, state)


def test_two_pending_redemptions_share_lot_without_double_releasing_units():
    first, original, bank = _redemption(delay=2)
    state = _reserved(first, original)
    pending_first = bank.execute(first)
    state = state.model_copy(update=receipt_updates(first, pending_first, state))
    second = _order(
        "redeem_product",
        {"position_ref": "POSITION_TEST", "amount": "200/1"},
        state,
        label="second",
    )
    state = _reserved(second, state)
    pending_second = bank.execute(second)
    state = state.model_copy(update=receipt_updates(second, pending_second, state))
    assert state.positions["POSITION_TEST"].reserved_units == 300
    settled = bank.advance_clock("2026-10-18T02:00:00Z")
    state = state.model_copy(update={"now": "2026-10-18T02:00:00Z"})
    orders = {first.intent_key: first, second.intent_key: second}
    for receipt in settled:
        order = orders[receipt.intent_key]
        assert validate_receipt(order, receipt, state)
        updates = receipt_updates(order, receipt, state)
        event = next(value for value in state.ledger if value.intent_key == order.intent_key)
        final = event.model_copy(update={"id": "SETTLED_" + order.intent_key, "event": "settled"})
        state = state.model_copy(update={**updates, "ledger": [*state.ledger, final]})
    assert state.positions["POSITION_TEST"].units == 700
    assert state.positions["POSITION_TEST"].reserved_units == 0
    assert available(state, "A_CURRENT") == Fraction(51494, 5)
