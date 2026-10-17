"""Automatic bank events never become planner tools."""

import pytest

from corridor.schemas.bank import BankAction, BankOrder, BankReceipt


def test_subscription_debit_is_receipt_only():
    receipt = BankReceipt.model_validate({
        "receipt_id": "automatic",
        "intent_key": "a" * 64,
        "kind": "subscription_debit",
        "status": "settled",
        "exact_effects": [],
        "executed_at": "2026-10-16T02:00:00Z",
        "sig": "0" * 128,
    })
    assert receipt.kind == "subscription_debit"
    for model in (BankAction, BankOrder):
        with pytest.raises(ValueError):
            model.model_validate({"kind": "subscription_debit", "args": {}})
