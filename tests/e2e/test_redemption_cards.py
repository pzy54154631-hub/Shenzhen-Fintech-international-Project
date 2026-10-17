"""Redemption approval facts agree with exact charges and actual bank settlement."""

from fractions import Fraction

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.bench.investment_runner import _position_state, prepare_redemption
from corridor.crypto.jcs import H
from corridor.crypto.sign import CATALOG, sign
from corridor.gateway.bank_adapter import compile_order, movements
from corridor.kernel.binding import binding
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds, available


def _case(*, delay=0, now="2026-10-16T02:00:00Z", held_seconds=30 * 86400):
    state = _position_state().model_copy(update={"now": now, "subscriptions": {}})
    product = state.catalog.products[0].model_copy(
        update={
            "annual_fee_rate": Fraction(365, 10000),
            "redemption_fee_rate": Fraction(1, 1000),
            "redeem_delay_days": delay,
        }
    )
    catalog = state.catalog.model_copy(update={"products": [product]})
    catalog = catalog.model_copy(update={"sig": sign(signing_key("bank"), CATALOG, catalog)})
    position = state.positions["POS_A"].model_copy(
        update={
            "acquired_at": add_seconds(now, -held_seconds),
            "redeemable_at": now,
        }
    )
    state = state.model_copy(update={"catalog": catalog, "positions": {position.id: position}})
    return BankCase(state, task_id="F2-BIC-5", subcase_id=f"redemption-{delay}-{now}")


@pytest.mark.parametrize("delay", [0, 2])
@pytest.mark.parametrize("now", ["2026-10-16T02:00:00Z", "2026-10-16T18:00:00Z"])
def test_redemption_card_discloses_exact_partial_fees_account_and_settlement(delay, now):
    case = _case(delay=delay, now=now)
    prepared = prepare_redemption(case, "10001/100")
    assert prepared.proposal.verdict.outcome == "Accept"
    card = prepared.proposal.card
    assert card["amount"] == "10001/100"
    # Each contractual fee rounds upward independently: .30003 -> .31 and .10001 -> .11.
    assert card["fees"] == "21/50"
    assert card["fee_breakdown"] == {"fee_hold": "31/100", "fee_sell": "11/100"}
    assert card["net_proceeds"] == "9959/100"
    assert card["return_account_ref"] == "A_CURRENT"
    local_day = 17 if now.endswith("18:00:00Z") else 16
    assert card["settlement_date"] == f"2026-10-{local_day + delay:02}"
    order = compile_order(prepared.action, prepared.cert, case.state)
    debit, credit = movements(order, case.state)
    assert debit is None
    assert credit.account_ref == card["return_account_ref"]
    assert credit.amount == Fraction(card["net_proceeds"])
    outcome = case.dispatch(prepared)
    if delay:
        assert outcome.status == "pending"
        assert available(case.state, "A_CURRENT") == 9000
        due = add_seconds(now, delay * 86400)
        assert outcome.receipt.settle_at == due
        [receipt] = case.gateway.bank.advance_clock(due)
        case.gateway.store.update(now=due)
        outcome = case.gateway.reconcile(receipt.intent_key)
    assert outcome.status == "settled"
    [credit_effect] = [
        effect for effect in outcome.receipt.exact_effects if effect.effect_type == "credit"
    ]
    assert credit_effect.account_ref == card["return_account_ref"]
    assert credit_effect.amount == Fraction(card["net_proceeds"])
    assert available(case.state, "A_CURRENT") == Fraction(9000) + Fraction(card["net_proceeds"])
    assert case.state.positions["POS_A"].units == Fraction(89999, 100)


def test_redemption_approval_date_does_not_drift_within_the_same_day():
    case = _case(delay=2)
    prepared = prepare_redemption(case, "10001/100")
    token = case.device.approve(
        prepared.action, prepared.cert, prepared.proposal.card, now=case.state.now
    )
    now = add_seconds(case.state.now, 60)
    case.gateway.bank.advance_clock(now)
    case.gateway.store.update(now=now)
    assert H(binding(prepared.action, prepared.cert, case.state).card_core) == H(
        prepared.proposal.card
    )
    assert case.gateway.dispatch(prepared.action, prepared.cert, token).status == "pending"


def test_redemption_fee_day_boundary_invalidates_previous_approval():
    case = _case(delay=2, held_seconds=31 * 86400 - 1)
    prepared = prepare_redemption(case, "1000/1")
    assert prepared.proposal.card["fees"] == "4/1"
    token = case.device.approve(
        prepared.action, prepared.cert, prepared.proposal.card, now=case.state.now
    )
    case.gateway.store.update(now=add_seconds(case.state.now, 1))
    current = binding(prepared.action, prepared.cert, case.state).card_core
    assert current["fees"] == "41/10"
    assert H(current) != H(prepared.proposal.card)
    assert case.gateway.dispatch(prepared.action, prepared.cert, token).status == "rejected"
    assert case.gateway.bank.execute_count == 0


def test_redemption_cannot_display_or_dispatch_an_ambiguous_return_account():
    case = _case()
    second = case.state.accounts["A_CURRENT"].model_copy(update={"id": "A_SECOND"})
    case.gateway.store.update(accounts={**case.state.accounts, second.id: second})
    prepared = prepare_redemption(case)
    assert prepared.proposal.verdict.outcome == "Reject"
    assert "DOMAIN-STATE" in prepared.proposal.verdict.rule_ids
    assert not prepared.proposal.card
    assert case.gateway.bank.execute_count == 0


def test_redemption_return_account_version_is_bound_to_approval():
    case = _case()
    prepared = prepare_redemption(case)
    token = case.device.approve(
        prepared.action, prepared.cert, prepared.proposal.card, now=case.state.now
    )
    account = case.state.accounts["A_CURRENT"]
    updated = account.model_copy(update={"version": account.version + 1})
    case.gateway.store.update(accounts={**case.state.accounts, updated.id: updated})
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status == "rejected" and result.rule_ids == ["APR-DRIFT"]
    assert case.gateway.bank.execute_count == 0
