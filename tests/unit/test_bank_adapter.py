"""Gateway validates signed bank effects, including malicious but valid signatures."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, sign
from corridor.eval.mockbank.exec import MockBank
from corridor.gateway.bank_adapter import (
    compile_order,
    movements,
    receipt_updates,
    validate_receipt,
)
from corridor.schemas.bank import BankOrder, BusinessEvent
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from tests.bank_cases import transfer_case


def executed(contact="CONTACT_CHEN"):
    action, cert, state = transfer_case(contact_ref=contact)
    order = compile_order(action, cert, state)
    receipt = MockBank(state, signing_key("bank")).execute(order)
    return order, receipt, state


def signed(receipt):
    return receipt.model_copy(update={"sig": sign(signing_key("bank"), RECEIPT, receipt)})


def test_real_transfer_and_recovery_reservation_match_exact_effects():
    order, receipt, state = executed()
    assert validate_receipt(order, receipt, state)
    debit, credit = movements(order, state)
    assert debit.amount == Fraction(200)
    assert credit is None
    event = BusinessEvent(
        id="RESERVE",
        intent_key=order.intent_key,
        event="unknown",
        kind="transfer",
        principal=order.principal,
        debit=debit,
        ts=state.now,
    )
    recovery_state = state.model_copy(update={"ledger": [event]})
    assert validate_receipt(order, receipt, recovery_state)


@pytest.mark.parametrize(
    "mutation", ["amount", "destination", "extra", "balance", "status", "intent", "signature"]
)
def test_signed_scope_changes_are_rejected(mutation):
    order, receipt, state = executed()
    effects = list(receipt.exact_effects)
    if mutation == "amount":
        effects[0] = effects[0].model_copy(update={"amount": Fraction(201)})
    elif mutation == "destination":
        effects[0] = effects[0].model_copy(update={"counterparty_ref": "DEST_CONTACT_NEW"})
    elif mutation == "extra":
        effects.append(effects[0])
    elif mutation == "balance":
        effects[0] = effects[0].model_copy(update={"after": "9000/1"})
    changed = receipt.model_copy(update={"exact_effects": effects})
    if mutation == "status":
        changed = changed.model_copy(update={"status": "failed"})
    if mutation == "intent":
        changed = changed.model_copy(update={"intent_key": "0" * 64})
    changed = signed(changed)
    if mutation == "signature":
        changed = changed.model_copy(update={"sig": "0" * 128})
    assert not validate_receipt(order, changed, state)


def test_new_payee_projection_changes_only_after_valid_receipt():
    order, receipt, state = executed("CONTACT_NEW")
    assert validate_receipt(order, receipt, state)
    changes = receipt_updates(order, receipt, state)
    assert changes["contacts"]["CONTACT_NEW"].is_new is False
    assert changes["contacts"]["CONTACT_NEW"].version == state.contacts["CONTACT_NEW"].version + 1
    assert state.contacts["CONTACT_NEW"].is_new is True


def test_failed_receipt_has_no_effects_and_no_projection():
    action, cert, state = transfer_case()
    order = compile_order(action, cert, state)
    bank = MockBank(state, signing_key("bank"))
    bank.faults[order.intent_key] = "failed"
    receipt = bank.execute(order)
    assert receipt.status == "failed"
    assert validate_receipt(order, receipt, state)
    assert set(receipt_updates(order, receipt, state)) == {"receipts"}


@pytest.mark.parametrize(
    "kind,args",
    [
        ("balance_query", {"account_ref": "A_CURRENT"}),
        ("transactions_query", {"account_ref": "A_CURRENT", "period": "2026-10"}),
        ("subscription_query", {"account_ref": "A_CURRENT", "period": "2026-10"}),
        ("subscription_reminders", {"account_ref": "A_CURRENT", "period": "2026-10"}),
        ("cancel_subscription", {"authorization_ref": "SUB_AUTH"}),
        (
            "lock_funds",
            {
                "source_ref": "A_CURRENT",
                "locked_ref": "A_LOCKED",
                "amount": "200/1",
                "purpose_ref": "BIRTHDAY",
            },
        ),
        (
            "merchant_order",
            {
                "source_ref": "A_CURRENT",
                "merchant_ref": "FLOWERS",
                "offer_ref": "O_FLOWERS",
                "destination_ref": "DEST_FLOWERS",
                "amount": "300/1",
            },
        ),
    ],
)
def test_supported_bank_effects_are_fully_reconciled(kind, args):
    state = make_state()
    # Refer to fixture identities, without taking expected effects from the bank.
    if kind == "cancel_subscription":
        args = {"authorization_ref": next(iter(state.subscriptions))}
    if kind == "merchant_order":
        merchant = next(
            value
            for value in state.merchants.values()
            if value.offers and value.offers[0].amount == 300
        )
        args = {
            **args,
            "merchant_ref": merchant.id,
            "offer_ref": merchant.offers[0].id,
            "destination_ref": merchant.destination_ref,
        }
    order = BankOrder.model_validate({
        "intent_key": H({"kind": kind}),
        "action_id": "ACTION",
        "principal": "C_DEMO",
        "kind": kind,
        "requested_at": state.now,
        "args": args,
    })
    receipt = MockBank(state, signing_key("bank")).execute(order)
    assert receipt.status == "settled"
    assert validate_receipt(order, receipt, state)
    projected = state.model_copy(update=receipt_updates(order, receipt, state))
    assert receipt.id in projected.receipts
