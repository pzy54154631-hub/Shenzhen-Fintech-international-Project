"""Clock-generated bank mandates are verified before ledger projection."""

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, sign
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import available


def _case():
    return BankCase(make_state(), task_id="B8-CLOCK", subcase_id="mandate")


def test_clock_projects_real_mandates_once_and_continues_serving():
    case = _case()
    sub = next(iter(case.state.subscriptions.values()))
    before = available(case.state, sub.source_account_ref)
    results = case.gateway.advance_clock(sub.next_due)
    assert len(results) == 1 and results[0].status == "settled"
    assert available(case.state, sub.source_account_ref) == before - sub.amount
    digest = H(case.state)
    assert case.gateway.advance_clock(sub.next_due) == []
    assert H(case.state) == digest


@pytest.mark.parametrize(
    "mutation", ["counterparty", "credit_arithmetic", "next_due", "executed_at"]
)
def test_signed_but_out_of_scope_mandate_receipt_cannot_change_trusted_state(mutation):
    case = _case()
    sub = next(iter(case.state.subscriptions.values()))
    receipt = case.gateway.bank.advance_clock(sub.next_due)[0]
    case.gateway.store.update(now=sub.next_due)
    effects = list(receipt.exact_effects)
    if mutation == "counterparty":
        effects[0] = effects[0].model_copy(update={"counterparty_ref": "WRONG"})
    elif mutation == "credit_arithmetic":
        effects[1] = effects[1].model_copy(update={"after": "9999/1"})
    elif mutation == "next_due":
        effects[-1] = effects[-1].model_copy(update={"after": "2099-01-01T00:00:00Z"})
    receipt = receipt.model_copy(update={"exact_effects": effects})
    if mutation == "executed_at":
        receipt = receipt.model_copy(update={"executed_at": "2026-01-01T00:00:00Z"})
    receipt = receipt.model_copy(update={"sig": sign(signing_key("bank"), RECEIPT, receipt)})
    ledger = H(case.state.ledger)
    result = case.gateway._subscription_event(receipt)
    assert result.rule_ids == ["BANK-RECEIPT"]
    assert H(case.state.ledger) == ledger
