"""Fresh device questionnaires are consumed atomically with their assessments."""

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.crypto.jcs import H
from corridor.gateway.investments import build_risk_assessment
from corridor.kernel import check
from corridor.kernel.binding import dependency_hashes
from corridor.schemas.bank import InputTerm
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds


def _case(*, ttl=1800):
    state = make_state()
    state = state.model_copy(
        update={
            "now": add_seconds(state.now, 86400),
            "policy": state.policy.model_copy(update={"risk_answers_ttl_seconds": ttl}),
        }
    )
    return BankCase(state, task_id="F2-RISK", subcase_id="lifecycle")


def _prepare(case, *, step=0, submitted_at=None, answers=None):
    item = case.device.confirm_input(
        intent_id=case.intent(step),
        slot="answers",
        value=[1] * 5 if answers is None else answers,
        now=submitted_at or case.state.now,
    )
    assert case.gateway.submit_input(item).status == "accepted"
    prepared = case.prepare(
        "risk_assess",
        {"answers_input_ref": item.id},
        {"answers_input_ref": InputTerm(input_ref=item.id, slot="answers")},
        inputs=[item],
        step=step,
    )
    return item, prepared


@pytest.mark.rule("RISK-ANSWERS-CONSUMED")
def test_answer_consumption_survives_recertification_and_later_assessment():
    case = _case()
    item, old = _prepare(case, answers=[4] * 5)
    assert case.dispatch(old).status == "settled"
    assert case.state.ledger[-1].object_delta["answers_input_ref"] == item.id
    case.gateway.advance_clock(add_seconds(case.state.now, 1))
    _, newer = _prepare(case, step=1, answers=[0] * 5)
    assert case.dispatch(newer).status == "settled"
    before = H(case.state.risk_assessments)
    cert = old.cert.model_copy(
        update={
            "dependency_hashes": dependency_hashes(old.action, old.cert, case.state),
        }
    )
    result = check(old.action, cert, case.state, phase="dispatch")
    assert "RISK-ANSWERS-CONSUMED" in result.rule_ids
    with pytest.raises(ValueError, match="RISK-ANSWERS-CONSUMED"):
        build_risk_assessment(old.action, case.state, signing_key("risk"))
    assert case.gateway.query(old.action, cert).status == "rejected"
    assert H(case.state.risk_assessments) == before
    customer = case.state.customers[case.device.principal]
    assert case.state.risk_assessments[customer.risk_profile_ref].level == 1


@pytest.mark.rule("RISK-ANSWERS-STALE")
@pytest.mark.parametrize("age", [1801, 366 * 86400])
def test_unused_old_answers_are_rejected_at_dispatch(age):
    case = _case()
    _, prepared = _prepare(case)
    case.gateway.advance_clock(add_seconds(case.state.now, age))
    result = check(prepared.action, prepared.cert, case.state, phase="dispatch")
    assert "RISK-ANSWERS-STALE" in result.rule_ids
    with pytest.raises(ValueError, match="RISK-ANSWERS-STALE"):
        build_risk_assessment(prepared.action, case.state, signing_key("risk"))
    assert case.gateway.query(prepared.action, prepared.cert).status == "rejected"
    assert case.state.customers[case.device.principal].risk_profile_ref == "RISK_DEMO"


@pytest.mark.rule("RISK-ANSWERS-STALE")
@pytest.mark.parametrize("offset", [-1, 0])
def test_answers_must_be_strictly_newer_than_current_assessment(offset):
    case = _case()
    current = case.state.risk_assessments["RISK_DEMO"]
    _, prepared = _prepare(case, submitted_at=add_seconds(current.issued_at, offset))
    assert "RISK-ANSWERS-STALE" in prepared.proposal.verdict.rule_ids
    assert case.dispatch(prepared).status == "rejected"


@pytest.mark.parametrize("ttl", [60, 1800])
def test_answers_at_policy_ttl_boundary_are_accepted_and_same_answers_can_be_resubmitted(ttl):
    case = _case(ttl=ttl)
    _, prepared = _prepare(case)
    case.gateway.advance_clock(add_seconds(case.state.now, ttl))
    assert case.dispatch(prepared).status == "settled"
    case.gateway.advance_clock(add_seconds(case.state.now, 1))
    _, fresh = _prepare(case, step=1)
    assert case.dispatch(fresh).status == "settled"


@pytest.mark.rule("RISK-ANSWERS-STALE")
def test_custom_answer_ttl_is_enforced_at_dispatch():
    case = _case(ttl=60)
    _, prepared = _prepare(case)
    assert prepared.proposal.verdict.outcome == "Accept"
    case.gateway.advance_clock(add_seconds(case.state.now, 61))
    result = case.dispatch(prepared)
    assert "RISK-ANSWERS-STALE" in result.rule_ids
    assert case.state.customers[case.device.principal].risk_profile_ref == "RISK_DEMO"


def test_expired_assessment_can_be_replaced_with_newly_submitted_answers():
    state = make_state()
    state = state.model_copy(update={"now": add_seconds(state.now, 366 * 86400)})
    case = BankCase(state, task_id="F2-RISK", subcase_id="fresh_renewal")
    _, prepared = _prepare(case)
    assert case.dispatch(prepared).status == "settled"
    ref = case.state.customers[case.device.principal].risk_profile_ref
    assert ref != "RISK_DEMO"
    assert case.state.risk_assessments[ref].issued_at == case.state.now


@pytest.mark.rule("APR-LOCK")
def test_risk_assessment_is_a_write_for_proposal_dispatch_and_plan_registration():
    case = _case()
    _, prepared = _prepare(case)
    assert prepared.proposal.verdict.outcome == "Accept"
    case.gateway.lock(case.device.principal, "test")
    before = H(case.state.risk_assessments)
    assert "APR-LOCK" in case.gateway.propose(prepared.action, prepared.cert).verdict.rule_ids
    assert "APR-LOCK" in case.gateway.query(prepared.action, prepared.cert).rule_ids
    assert "APR-LOCK" in case.gateway.submit_plan(prepared.plan).rule_ids
    assert H(case.state.risk_assessments) == before
    assert case.gateway.bank.execute_count == 0
