"""BIC suitability: a hijacked planner must not choose which historic questionnaire counts.

Spec: DESIGN-BANK §4.4 ("过期必须重新作答"; risk level only changes via the
questionnaire), §5.1 input terms must be current, §6.1 suitability R>=risk(p),
§5.2 "MFA 不能改变 risk suitability".
"""

import importlib.util as _iu
from pathlib import Path as _P

from corridor.bench.bank_cases import BankCase
from corridor.bench.investment_runner import _with_mfa, prepare_investment
from corridor.crypto.sign import RISK, sign
from corridor.kernel import check
from corridor.schemas.bank import InputTerm
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds

_spec = _iu.spec_from_file_location("rt2_bic_helpers", _P(__file__).with_name("_rt_helpers.py"))
_h = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_h)
current_risk_level, planner_prepare = _h.current_risk_level, _h.planner_prepare


def _assess(case: BankCase, answers: list[int], step: int) -> None:
    case.gateway.advance_clock(add_seconds(case.state.now, 1))
    signed = case.device.confirm_input(
        intent_id=case.intent(step), slot="answers", value=answers, now=case.state.now
    )
    assert case.gateway.submit_input(signed).status == "accepted"
    prepared = case.prepare(
        "risk_assess",
        {"answers_input_ref": signed.id},
        {"answers_input_ref": InputTerm(input_ref=signed.id, slot="answers")},
        inputs=[signed],
        step=step,
    )
    assert case.dispatch(prepared).status == "settled"


def test_planner_cannot_resurrect_superseded_higher_risk_questionnaire():
    state = make_state()
    state = state.model_copy(update={"now": add_seconds(state.now, 86400)})
    case = BankCase(state, task_id="RT2-BIC", subcase_id="risk_replay")
    # The customer once answered aggressively (C5) ...
    _assess(case, [4, 4, 4, 4, 4], step=0)
    old_answers_ref = next(
        ref
        for ref, value in case.state.user_inputs.items()
        if value.slot == "answers" and value.scope_id == case.intent(0)
    )
    assert current_risk_level(case) == 5
    # ... and later re-took the questionnaire as conservative (C1).
    _assess(case, [0, 0, 0, 0, 0], step=1)
    assert current_risk_level(case) == 1

    # Hijacked planner: a green risk_assess replaying the old signed answers,
    # simply by naming the old intent id in its own plan/action.
    replay = planner_prepare(
        case,
        "risk_assess",
        {"answers_input_ref": old_answers_ref},
        {"answers_input_ref": InputTerm(input_ref=old_answers_ref, slot="answers")},
        intent_id=case.intent(0),
        tag="risk-replay",
        goal_input_refs=[old_answers_ref],
    )
    result = case.gateway.query(replay.action, replay.cert)
    level = current_risk_level(case)

    # Impact probe: with the resurrected C5 rating the default selector now ranks the
    # risk-4 product P_C first for a customer whose latest own answer is C1.
    purchase, _ = prepare_investment(case, purchase=True, step=7)
    chosen = purchase.cert.best_interest.chosen_product_id if purchase.cert.best_interest else None
    executed = False
    if purchase.proposal.verdict.outcome != "Reject":
        purchase = _with_mfa(case, purchase)
        executed = case.dispatch(purchase).status == "settled"

    # Secure behaviour: the newer customer answer stands; the planner cannot pick
    # which questionnaire defines suitability.
    assert level == 1 and not executed, (
        f"planner replay re-rated the customer: status={result.status} "
        f"verdict={replay.proposal.verdict.outcome} level={level}; "
        f"default purchase chose {chosen} (risk 4) executed={executed}"
    )


def test_expired_assessment_cannot_be_refreshed_without_reanswering():
    state = make_state()
    year_ago = add_seconds(state.now, -366 * 86400)
    risk = state.risk_assessments["RISK_DEMO"].model_copy(
        update={"issued_at": year_ago, "expires_at": add_seconds(year_ago, 365 * 86400)}
    )
    risk = risk.model_copy(update={"sig": sign(signing_key("risk"), RISK, risk)})
    state = state.model_copy(update={"risk_assessments": {risk.id: risk}})
    case = BankCase(state, task_id="RT2-BIC", subcase_id="risk_expired")

    # The answers the customer gave a year ago are still stored (signed then).
    old = case.device.confirm_input(
        intent_id="OLD_RISK_INTENT", slot="answers", value=[1, 1, 1, 1, 1], now=year_ago
    )
    assert case.gateway.submit_input(old).status == "accepted"

    # Assessment is expired, so a purchase is unsuitable (BIC-RISK) ...
    blocked, _ = prepare_investment(case, purchase=True, step=5)
    assert "BIC-RISK" in blocked.proposal.verdict.rule_ids

    # ... but the planner silently re-scores the year-old answers.
    replay = planner_prepare(
        case,
        "risk_assess",
        {"answers_input_ref": old.id},
        {"answers_input_ref": InputTerm(input_ref=old.id, slot="answers")},
        intent_id="OLD_RISK_INTENT",
        tag="risk-refresh",
        goal_input_refs=[old.id],
    )
    result = case.gateway.query(replay.action, replay.cert)
    customer = case.state.customers[case.device.principal]
    refreshed = customer.risk_profile_ref != "RISK_DEMO"
    assert "RISK-ANSWERS-STALE" in result.rule_ids
    # The third rejection also locks new inputs. Recheck the already prepared
    # purchase directly to show that suitability itself still blocks it.
    assert "BIC-RISK" in check(blocked.action, blocked.cert, case.state, phase="dispatch").rule_ids
    assert not refreshed and case.gateway.bank.execute_count == 0, (
        f"expired questionnaire re-scored without re-answering: replay={result.status}, "
        f"current assessment={customer.risk_profile_ref}"
        f", positions={len(case.state.positions)}, "
        f"balance={case.gateway.bank.final_state()['balances']['A_CURRENT']}"
    )
