"""Hand-scored risk assessments cannot be replaced by planner levels."""

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import RISK, verify
from corridor.gateway.investments import build_risk_assessment
from corridor.schemas.bank import BankAction
from corridor.sim.device import Device
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds


def risk_case(answers):
    state = make_state()
    state = state.model_copy(update={"now": add_seconds(state.now, 1)})
    item = Device().confirm_input(
        intent_id="RISK_INTENT", slot="answers", value=answers, now=state.now
    )
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, item.id: item}})
    action = BankAction(
        action_id="RISK_ACTION",
        intent_id="RISK_INTENT",
        principal="C_DEMO",
        device_session_id="SESSION",
        plan_id="PLAN",
        plan_hash=H("PLAN"),
        node_id="NODE",
        kind="risk_assess",
        args={"answers_input_ref": item.id},
    )
    return action, state


@pytest.mark.parametrize(
    "answers,score,level",
    [
        ([0, 0, 0, 0, 0], 0, 1),
        ([4, 0, 0, 0, 0], 4, 1),
        ([4, 1, 0, 0, 0], 5, 2),
        ([4, 4, 0, 0, 0], 8, 2),
        ([4, 4, 1, 0, 0], 9, 3),
        ([4, 4, 4, 0, 0], 12, 3),
        ([4, 4, 4, 1, 0], 13, 4),
        ([4, 4, 4, 4, 0], 16, 4),
        ([4, 4, 4, 4, 1], 17, 5),
        ([4, 4, 4, 4, 4], 20, 5),
    ],
)
def test_gateway_scores_exact_signed_questionnaire(answers, score, level):
    action, state = risk_case(answers)
    result = build_risk_assessment(action, state, signing_key("risk"))
    assert (result.score, result.level) == (score, level)
    assert result.answers_hash == H(answers)
    assert result.issued_at == state.now
    assert result.expires_at == add_seconds(state.now, 365 * 86400)
    assert verify(state.roots.risk_pubkey, RISK, result, result.sig)


@pytest.mark.parametrize(
    "answers",
    [[0] * 4, [0] * 6, [5, 0, 0, 0, 0], [-1, 0, 0, 0, 0], [True, 0, 0, 0, 0], {"level": 5}],
)
def test_bad_questionnaire_never_becomes_a_risk_level(answers):
    action, state = risk_case(answers)
    with pytest.raises(ValueError):
        build_risk_assessment(action, state, signing_key("risk"))


def test_wrong_risk_signer_rejected():
    action, state = risk_case([1] * 5)
    with pytest.raises(ValueError):
        build_risk_assessment(action, state, signing_key("gateway"))
