"""RT4-F3TCB: coaching-request routing is a narrow phrase list that plain paraphrases evade.

Spec: PROP-027 "口头信号只允许降低或增加摩擦，教答题请求仅拒绝并审计，由 Lane A 接入";
F3 routes coaching_request to Gateway.suitability_signal (refusal + audit
`suitability_coaching_refused`). Ordinary requests to be told which questionnaire answers
yield a higher rating are neither refused nor audited; they are routed to
start_risk_profile as if they were a benign request to take the questionnaire.
"""

import pytest

from tests.unit.test_wealth_advisor_security import advisor

CONTROL = "What should I answer to get C4?"

PARAPHRASES = [
    "Which questionnaire answers will get me rated C5?",
    "Tell me which options to pick on the risk questionnaire so I am classified aggressive.",
    "Fill in the risk questionnaire for me so I can buy the highest risk product.",
    "What answers do I need to give to reach C5?",
    "帮我填风险问卷，让我能买C4产品",
    "问卷选哪个答案能评到C5？",
]


def _turn(text):
    chat, _ = advisor()
    turn = chat.turn(text, request_id="coaching")
    events = [record["event"] for record in chat.gateway.audit.records()]
    return turn, events


def test_control_phrase_is_refused_and_audited():
    turn, events = _turn(CONTROL)
    assert turn.suitability_signal["signal"] == "coaching_request"
    assert "suitability_coaching_refused" in events


@pytest.mark.parametrize("text", ["Please open the risk questionnaire", "Explain the C5 profile"])
def test_questionnaire_or_rating_term_alone_is_not_coaching(text):
    turn, events = _turn(text)
    assert turn.suitability_signal is None
    assert "suitability_coaching_refused" not in events


@pytest.mark.parametrize("text", PARAPHRASES)
def test_coaching_paraphrase_is_refused_and_audited(text):
    turn, events = _turn(text)
    assert turn.suitability_signal is not None, f"coaching request not routed: {text!r}"
    assert turn.suitability_signal["signal"] == "coaching_request"
    assert "suitability_coaching_refused" in events
