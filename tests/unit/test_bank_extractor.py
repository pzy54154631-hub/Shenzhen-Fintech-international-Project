"""Amount text is a conservative candidate parser, never an authorization."""

import pytest

from corridor.agent.extractor import amount_candidate, extract_intent


@pytest.mark.parametrize(
    "text",
    [
        "给小陈转1.234元",
        "给小陈转-200元",
        "给小陈转+200元",
        "给小陈转1,200元",
        "给小陈转1 200元",
        "给小陈转200.001元",
        "给小陈转1e3元",
        "转200 300",
        "给小陈转0元",
        "转200元或300元",
        "给小陈转1/2元",
        "转２００元",
    ],
)
def test_malformed_or_ambiguous_numbers_are_not_truncated(text):
    assert amount_candidate(text) is None


@pytest.mark.parametrize(
    "text,expected",
    [
        ("给NAME_CHEN转200元", "200/1"),
        ("转200.01元", "20001/100"),
        ("转200", "200/1"),
        ("再给他转同样金额", "200/1"),
        ("再给他200", "200/1"),
    ],
)
def test_exact_candidates_come_from_text_or_explicit_context(text, expected):
    assert amount_candidate(text, "200/1") == expected


def test_repeat_pronoun_transfer_requires_confirmed_contact_context():
    labels = {"CONTACT_CHEN": ["NAME_CHEN"]}
    assert extract_intent("再给他200", labels, "CONTACT_CHEN").contact_refs == ["CONTACT_CHEN"]
    assert not extract_intent("再给他200", labels).contact_refs
    assert amount_candidate("再给他-200") is None
    assert amount_candidate("再给他1.234") is None
