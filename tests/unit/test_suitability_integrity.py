"""Retake ceilings and conservative effective suitability preserve signed raw scores."""

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.crypto.jcs import H
from corridor.crypto.sign import ALLOCATION_POLICY, RISK
from corridor.gateway.investments import build_risk_assessment
from corridor.kernel import check
from corridor.kernel.allocation import evaluate_allocation
from corridor.kernel.binding import binding, dependency_hashes
from corridor.kernel.investment import (
    effective_risk_level,
    evaluate_investment,
    risk_retake_errors,
    risk_score,
    risk_session_cap,
)
from corridor.schemas.allocation import RiskRetakeLimits
from corridor.schemas.bank import BusinessEvent
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.stores.bank import add_seconds
from tests.bank_cases import signed
from tests.investment_cases import investment_case, preference
from tests.unit.test_allocation_selector import case as allocation_case
from tests.unit.test_risk_answer_lifecycle import _prepare


def _case():
    state = make_state()
    state = state.model_copy(update={"now": add_seconds(state.now, 86400)})
    return BankCase(state, task_id="M5-INTEGRITY", subcase_id="retake")


def _history(state, dates, *, principal="C_DEMO", event="settled"):
    events = [
        BusinessEvent(
            id=f"M5_HISTORY_{index}",
            intent_key=H(["M5", principal, index]),
            kind="risk_assess",
            event=event,
            principal=principal,
            object_delta={"answers_input_ref": f"M5_ANSWERS_{index}"},
            ts=ts,
        )
        for index, ts in enumerate(dates)
    ]
    return state.model_copy(update={"ledger": [*state.ledger, *events]})


@pytest.mark.rule("RISK-RETAKE-LIMIT")
def test_third_same_day_retake_exact_rule_and_second_attempt_benign_twin():
    case = _case()
    for step in range(2):
        _, prepared = _prepare(case, step=step)
        assert prepared.proposal.verdict.outcome == "Accept"
        assert case.dispatch(prepared).status == "settled"
        case.gateway.advance_clock(add_seconds(case.state.now, 1))
    before = H(case.state.risk_assessments)
    _, third = _prepare(case, step=2)
    assert third.proposal.verdict.outcome == "Reject"
    assert third.proposal.verdict.rule_ids == ["RISK-RETAKE-LIMIT"]
    assert check(third.action, third.cert, case.state, phase="dispatch").rule_ids == [
        "RISK-RETAKE-LIMIT"
    ]
    with pytest.raises(ValueError, match="^RISK-RETAKE-LIMIT$"):
        build_risk_assessment(third.action, case.state, signing_key("risk"))
    assert case.dispatch(third).status == "rejected"
    assert H(case.state.risk_assessments) == before
    assert case.gateway.bank.execute_count == 0


@pytest.mark.rule("RISK-RETAKE-LIMIT")
def test_eighth_trailing_year_assessment_allowed_ninth_rejected():
    case = _case()
    _, prepared = _prepare(case)
    dates = [f"2026-{month:02d}-10T02:00:00Z" for month in range(1, 9)]
    for count, expected in ((6, "Accept"), (7, "Reject")):
        state = _history(case.state, dates[:count])
        cert = prepared.cert.model_copy(
            update={"dependency_hashes": dependency_hashes(prepared.action, prepared.cert, state)}
        )
        verdict = check(prepared.action, cert, state, phase="dispatch")
        assert verdict.outcome == expected
        if count == 7:
            assert verdict.rule_ids == ["RISK-RETAKE-LIMIT"]


def test_retake_business_date_uses_utc_plus_eight():
    case = _case()
    _, prepared = _prepare(case)
    dates = ["2026-10-16T16:00:00Z", "2026-10-17T01:00:00Z"]
    state = _history(case.state, dates)
    with pytest.raises(ValueError, match="^RISK-RETAKE-LIMIT$"):
        build_risk_assessment(prepared.action, state, signing_key("risk"))
    state = _history(case.state, ["2026-10-16T15:59:59Z", dates[1]])
    assert build_risk_assessment(prepared.action, state, signing_key("risk")).level == 2


@pytest.mark.parametrize("event", ["failed", "settled"])
def test_failed_and_other_customer_attempts_do_not_use_customer_budget(event):
    case = _case()
    _, prepared = _prepare(case)
    principal = case.device.principal if event == "failed" else "OTHER"
    state = _history(case.state, [case.state.now] * 2, principal=principal, event=event)
    assert build_risk_assessment(prepared.action, state, signing_key("risk")).level == 2


def _signal(state, session, cap, *, signal="cannot_accept_loss", principal="C_DEMO"):
    event = BusinessEvent(
        id=f"M5_SIGNAL_{len(state.ledger)}",
        intent_key=H(["signal", len(state.ledger)]),
        event="settled",
        kind="allocation_compare",
        principal=principal,
        object_delta={
            "device_session_id": session,
            "effective_level_cap": cap,
            "suitability_signal": signal,
        },
        ts=state.now,
    )
    return state.model_copy(update={"ledger": [*state.ledger, event]})


def _profile(state, answers):
    old = state.risk_assessments["RISK_DEMO"]
    score, level = risk_score(answers, state)
    risk = signed(
        old.model_copy(
            update={"answers": answers, "answers_hash": H(answers), "score": score, "level": level}
        ),
        RISK,
        "risk",
    )
    return state.model_copy(update={"risk_assessments": {risk.id: risk}})


@pytest.mark.rule("RISK-UPGRADE-REVIEW")
def test_upgrade_after_refused_purchase_escalates_and_benign_same_level_passes():
    for answers, expected in (([1] * 5, "Accept"), ([3] * 5, "Escalate")):
        case = _case()
        state = _signal(case.state, case.session, 2, signal="purchase_refused")
        case.gateway.store.update(ledger=state.ledger)
        _, prepared = _prepare(case, answers=answers)
        verdict = check(prepared.action, prepared.cert, case.state, phase="dispatch")
        assert verdict.outcome == expected
        if expected == "Escalate":
            assert verdict.rule_ids == ["RISK-UPGRADE-REVIEW"]
            with pytest.raises(ValueError, match="^RISK-UPGRADE-REVIEW$"):
                build_risk_assessment(prepared.action, case.state, signing_key("risk"))
        else:
            assert (
                build_risk_assessment(prepared.action, case.state, signing_key("risk")).level == 2
            )
        assert case.gateway.bank.execute_count == 0


def test_signed_answer_conflict_lowers_effective_level_without_altering_raw_signature():
    state = _profile(make_state(), [4, 0, 4, 4, 4])
    action, _, state = investment_case(state=state)
    evaluation = evaluate_investment(action, state)
    assert "risk" in evaluation.exclusions["P_A"]
    assert effective_risk_level(action.principal, state) == 1
    assert state.risk_assessments["RISK_DEMO"].level == 4
    assert risk_score(state.risk_assessments["RISK_DEMO"].answers, state) == (16, 4)
    twin = _profile(state, [3] * 5)
    assert "P_A" not in evaluate_investment(action, twin).exclusions
    assert effective_risk_level(action.principal, twin) == 4


def test_signed_short_horizon_growth_goal_uses_c2_policy_and_session_cap_lowers_both_paths():
    state = _profile(make_wealth_state(), [3] * 5)
    ref, state = allocation_case(allocation_request(horizon_days=364), state)
    result = evaluate_allocation("C_DEMO", "WEALTH_SELECTOR", ref, state)
    assert result.certificate is not None and result.errors == ()
    risks = {product.id: product.risk_level for product in state.catalog.products}
    assert all(risks[ref] <= 2 for ref in result.certificate.candidate_ids)
    assert effective_risk_level("C_DEMO", state, horizon_days=364, objective="net_return") == 2
    assert effective_risk_level("C_DEMO", state, horizon_days=365, objective="net_return") == 4
    state = state.model_copy(
        update={
            "security": state.security.model_copy(
                update={"active_device_sessions": {"C_DEMO": "S"}}
            )
        }
    )
    state = _signal(state, "S", 1)
    result = evaluate_allocation("C_DEMO", "WEALTH_SELECTOR", ref, state)
    assert result.certificate is not None
    assert all(risks[ref] == 1 for ref in result.certificate.candidate_ids)
    action, _, state = investment_case(state=state, pref=preference(horizon_days=364))
    state = _signal(state, action.device_session_id, 1)
    investment = evaluate_investment(action, state)
    assert all(
        "risk" in reasons for ref, reasons in investment.exclusions.items() if risks[ref] > 1
    )


def test_session_candidate_minimum_never_upgrades_or_crosses_session_or_customer():
    case = _case()
    state = _signal(case.state, case.session, 1)
    state = _signal(state, case.session, 5)
    assert risk_session_cap(case.device.principal, state) == 1
    assert risk_session_cap(case.device.principal, state, device_session_id="OTHER_SESSION") == 5
    assert risk_session_cap("OTHER_CUSTOMER", state, device_session_id=case.session) == 5


def test_changed_effective_level_changes_card_dependency_even_if_product_stays_eligible():
    action, cert, state = investment_case(kind="purchase_product")
    state = _profile(state, [3] * 5)
    before = binding(action, cert, state)
    changed = _signal(state, action.device_session_id, 3)
    after = binding(action, cert, changed)
    assert before.card_core["risk"]["raw_level"] == 4
    assert after.card_core["risk"]["effective_level"] == 3
    assert dependency_hashes(action, cert, state) != dependency_hashes(action, cert, changed)
    assert before.card_core != after.card_core


def test_calendar_year_boundary_is_inclusive_and_leap_day_is_clamped():
    for now, anniversary, before in (
        ("2026-10-16T02:00:00Z", "2025-10-15T16:00:00Z", "2025-10-15T15:59:59Z"),
        ("2028-02-29T02:00:00Z", "2027-02-27T16:00:00Z", "2027-02-27T15:59:59Z"),
    ):
        state = make_state().model_copy(update={"now": now})
        year = int(now[:4]) - 1
        count = 6 if year == 2025 else 7
        dates = [f"{year}-12-{day:02d}T02:00:00Z" for day in range(1, count + 1)]
        assert risk_retake_errors("C_DEMO", _history(state, [*dates, anniversary])) == [
            "RISK-RETAKE-LIMIT"
        ]
        assert risk_retake_errors("C_DEMO", _history(state, [*dates, before])) == []


def test_signed_policy_can_only_tighten_hard_limits_and_legacy_policy_signatures_survive():
    state = make_wealth_state()
    policy = next(iter(state.allocation_policies.values()))
    assert "risk_retake_limits" not in policy.model_dump(mode="json")
    assert risk_retake_errors("C_DEMO", state) == []
    policy = signed(
        policy.model_copy(update={"risk_retake_limits": RiskRetakeLimits(daily=1)}),
        ALLOCATION_POLICY,
        "bank",
    )
    state = state.model_copy(update={"allocation_policies": {policy.id: policy}})
    state = _history(state, [state.now])
    assert risk_retake_errors("C_DEMO", state) == ["RISK-RETAKE-LIMIT"]
    with pytest.raises(ValueError):
        RiskRetakeLimits(daily=3, trailing_twelve_months=9)
    unsigned = policy.model_copy(update={"sig": "0" * 128})
    state = state.model_copy(update={"allocation_policies": {unsigned.id: unsigned}})
    assert risk_retake_errors("C_DEMO", state) == ["ALLOC-POLICY"]


def test_signed_bootstrap_assessment_counts_without_a_ledger_event():
    state = make_state()
    assert risk_retake_errors("C_DEMO", state) == []
    original = state.risk_assessments["RISK_DEMO"]
    second = signed(original.model_copy(update={"id": "RISK_BOOTSTRAP_2"}), RISK, "risk")
    state = state.model_copy(
        update={"risk_assessments": {**state.risk_assessments, second.id: second}}
    )
    assert risk_retake_errors("C_DEMO", state) == ["RISK-RETAKE-LIMIT"]


def test_failed_retries_and_assessment_receipt_links_are_not_double_counted():
    case = _case()
    _, prepared = _prepare(case)
    assert case.dispatch(prepared).status == "settled"
    # Legacy events predate the explicit risk_assessment_ref but link the signed receipt.
    event = case.state.ledger[-1]
    legacy_delta = {k: v for k, v in event.object_delta.items() if k != "risk_assessment_ref"}
    legacy = event.model_copy(update={"object_delta": legacy_delta})
    state = case.state.model_copy(update={"ledger": [*case.state.ledger[:-1], legacy]})
    assert risk_retake_errors(case.device.principal, state) == []
    duplicate = legacy.model_copy(update={"id": "M5_DUPLICATE"})
    state = state.model_copy(update={"ledger": [*state.ledger, duplicate]})
    assert risk_retake_errors(case.device.principal, state) == []


def test_retakes_preserve_consumed_and_stale_rule_priority():
    case = _case()
    _, first = _prepare(case)
    assert case.dispatch(first).status == "settled"
    case.gateway.advance_clock(add_seconds(case.state.now, 1))
    _, second = _prepare(case, step=1)
    assert case.dispatch(second).status == "settled"
    with pytest.raises(ValueError, match="^RISK-ANSWERS-CONSUMED$"):
        build_risk_assessment(first.action, case.state, signing_key("risk"))
    _, fresh = _prepare(case, step=2)
    with pytest.raises(ValueError, match="^RISK-ANSWERS-STALE$"):
        build_risk_assessment(fresh.action, case.state, signing_key("risk"))
