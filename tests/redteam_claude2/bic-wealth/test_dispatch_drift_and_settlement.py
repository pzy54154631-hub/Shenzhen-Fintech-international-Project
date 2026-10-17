"""Card-to-dispatch drift for purchases and pending redemption settlement.

Spec: DESIGN-BANK §6.4 (每次申购派发重算BIC，目录/风险过期不凭旧卡放行; pending
redemption: balance does not rise until settled, settlement once, no overselling),
§8.1 step 4 (APR-DRIFT), §6.1 (balance change recomputes E).
"""

from fractions import Fraction

from corridor.bench.bank_cases import BankCase
from corridor.bench.investment_runner import (
    _position_state,
    _with_mfa,
    prepare_investment,
    prepare_redemption,
)
from corridor.crypto.sign import CATALOG, RISK, sign
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds, available


def _approved_purchase(case: BankCase):
    prepared, _ = prepare_investment(case, purchase=True)
    prepared = _with_mfa(case, prepared)
    assert prepared.proposal.verdict.outcome == "Accept", prepared.proposal.verdict
    token = case.device.approve(
        prepared.action, prepared.cert, prepared.proposal.card, now=case.state.now
    )
    return prepared, token


def _short_lived(state, *, risk: bool):
    if risk:
        item = state.risk_assessments["RISK_DEMO"].model_copy(
            update={"expires_at": add_seconds(state.now, 60)}
        )
        item = item.model_copy(update={"sig": sign(signing_key("risk"), RISK, item)})
        return state.model_copy(update={"risk_assessments": {item.id: item}})
    catalog = state.catalog.model_copy(update={"valid_until": add_seconds(state.now, 60)})
    catalog = catalog.model_copy(update={"sig": sign(signing_key("bank"), CATALOG, catalog)})
    return state.model_copy(update={"catalog": catalog})


def test_purchase_rejected_when_risk_assessment_expires_after_card():
    case = BankCase(_short_lived(make_state(), risk=True), task_id="RT2-BIC", subcase_id="rexp")
    prepared, token = _approved_purchase(case)
    case.gateway.advance_clock(add_seconds(case.state.now, 90))
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status != "settled" and case.gateway.bank.execute_count == 0, result


def test_purchase_rejected_when_catalog_expires_after_card():
    case = BankCase(_short_lived(make_state(), risk=False), task_id="RT2-BIC", subcase_id="cexp")
    prepared, token = _approved_purchase(case)
    case.gateway.advance_clock(add_seconds(case.state.now, 90))
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status != "settled" and case.gateway.bank.execute_count == 0, result


def test_purchase_rejected_when_balance_changes_eligible_set_after_card():
    case = BankCase(make_state(), task_id="RT2-BIC", subcase_id="bal")
    prepared, token = _approved_purchase(case)
    state = case.state
    account = state.accounts["A_CURRENT"].model_copy(update={"opening_balance": Fraction(1005)})
    case.gateway.store.update(accounts={**state.accounts, account.id: account})
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status != "settled" and case.gateway.bank.execute_count == 0, result


def _pending_case(subcase: str) -> BankCase:
    state = _position_state()
    position = state.positions["POS_A"].model_copy(update={"product_ref": "P_B"})
    state = state.model_copy(update={"positions": {position.id: position}})
    return BankCase(state, task_id="RT2-BIC", subcase_id=subcase)


def test_pending_redemption_cannot_oversell_and_credits_exactly_once():
    case = _pending_case("pending")
    first = prepare_redemption(case, "600/1", step=0)
    pending = case.dispatch(first)
    assert pending.status == "pending", pending
    assert available(case.state, "A_CURRENT") == 9000  # no credit before settlement
    # Overselling the reserved units under a new intent must be refused.
    second = prepare_redemption(case, "600/1", step=1)
    assert second.proposal.verdict.outcome == "Reject", second.proposal.verdict
    key = next(e.intent_key for e in case.state.ledger if e.kind == "redeem_product")
    # Repeated reconciliation of the pending receipt must not credit early.
    for _ in range(2):
        case.gateway.reconcile(key)
    assert available(case.state, "A_CURRENT") == 9000
    case.gateway.advance_clock(add_seconds(case.state.now, 86400))
    for _ in range(2):
        case.gateway.reconcile(key)
    assert available(case.state, "A_CURRENT") == 9600
    assert case.gateway.bank.final_state()["balances"]["A_CURRENT"] == "9600/1"
    position = case.state.positions["POS_A"]
    assert (position.units, position.reserved_units, position.principal_amount) == (400, 0, 400)
    # A remaining-lot redemption still works and keeps the original acquired_at.
    third = prepare_redemption(case, "400/1", step=2)
    assert third.proposal.verdict.outcome == "Accept", third.proposal.verdict
    assert position.acquired_at == _position_state().positions["POS_A"].acquired_at
