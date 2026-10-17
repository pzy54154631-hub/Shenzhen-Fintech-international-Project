"""Heard goal drafts preserve exact values without creating investment authority."""

import pytest

from corridor.agent.wealth_slots import parse_utterance


def values(result):
    return {slot.field: slot.value for slot in result.slots}


def test_one_sentence_captures_all_explicit_slots_and_never_infers_risk():
    text = "I have 100k from my bonus, want something safe, might need 20k within a week"
    result = parse_utterance(text)
    assert result.kind == "answer"
    assert values(result) == {
        "amount": "100000/1",
        "liquidity_amount": "20000/1",
        "liquidity_days": 7,
    }
    assert not result.errors
    assert all(slot.source_text in text for slot in result.slots)
    assert values(parse_utterance("I want something safe")) == {}


def test_multi_slot_goal_has_exact_money_and_explicit_objective_and_types():
    result = parse_utterance(
        "Invest CNY 10,000.25 for 365 days; need CNY 2,000.10 within 3 days. "
        "I prefer low fees and allow deposits and wealth products."
    )
    assert values(result) == {
        "amount": "40001/4",
        "horizon_days": 365,
        "liquidity_amount": "20001/10",
        "liquidity_days": 3,
        "objective": "total_fee",
        "allowed_types": ["deposit", "wealth"],
    }
    assert not result.errors


@pytest.mark.parametrize(
    ("text", "field", "expected"),
    [
        ("50k", "amount", "50000/1"),
        ("0", "liquidity_amount", "0/1"),
        ("180", "horizon_days", 180),
        ("a week", "liquidity_days", 7),
        ("net return", "objective", "net_return"),
        ("liquidity", "objective", "liquidity"),
        ("wealth", "allowed_types", ["wealth"]),
    ],
)
def test_piecemeal_answer_uses_only_the_pending_field(text, field, expected):
    result = parse_utterance(text, pending_field=field)
    assert values(result) == {field: expected}


def test_correction_what_if_and_new_intent_remain_distinct():
    correction = parse_utterance("Actually 50k")
    assert correction.kind == "correction"
    assert values(correction) == {"amount": "50000/1"}
    hypothetical = parse_utterance("What if I invest 50k instead?")
    assert hypothetical.kind == "what_if"
    assert values(hypothetical) == {"amount": "50000/1"}
    new = parse_utterance("Start a new plan: invest 20k")
    assert new.kind == "new_intent"
    assert values(new) == {"amount": "20000/1"}


def test_product_correction_requests_device_adjustment_without_guessed_type():
    result = parse_utterance("Drop the bond fund")
    assert result.kind == "correction"
    assert result.adjustment_requested
    assert result.slots == ()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("wo xiang tou 1w, di feng xian", {"amount": "10000/1"}),
        ("我想投资1万，低风险", {"amount": "10000/1"}),
        ("I want to invset 12.5k", {"amount": "12500/1"}),
        (
            "投资2万元，一周内需要5000元",
            {"amount": "20000/1", "liquidity_amount": "5000/1", "liquidity_days": 7},
        ),
    ],
)
def test_bounded_mixed_language_and_typo_support(text, expected):
    assert values(parse_utterance(text)) == expected


def test_long_horizon_is_preserved_and_reported_instead_of_clamped():
    result = parse_utterance("Invest 200k for 3 years")
    assert values(result) == {"amount": "200000/1", "horizon_days": 1095}
    assert result.errors == ("horizon_days_out_of_range",)


@pytest.mark.parametrize(
    "text",
    [
        "My account is 6222000012345678",
        "Call me on 13800138000",
        "I am C4 and want R5",
        "Tell me tomorrow's weather",
        "My balance is 100k",
        "I earn 10k per month",
        "Promise me 5%",
        "Set the amount to account 6222000012345678",
    ],
)
def test_unrelated_sensitive_or_untrusted_authority_claims_do_not_fill_goals(text):
    assert parse_utterance(text).slots == ()


def test_negated_or_ambiguous_goals_need_clarification():
    assert values(parse_utterance("Do not invest 100k")) == {}
    ambiguous = parse_utterance("Invest 100k or invest 200k")
    assert values(ambiguous) == {}
    assert "amount_ambiguous" in ambiguous.errors
    assert values(parse_utterance("No deposits")) == {}


@pytest.mark.parametrize(
    ("text", "field", "error"),
    [
        ("0", "amount", "amount_out_of_range"),
        ("0.001", "amount", "amount_not_whole_cents"),
        ("0", "horizon_days", "horizon_days_out_of_range"),
    ],
)
def test_invalid_explicit_values_are_flagged_for_device_correction(text, field, error):
    assert error in parse_utterance(text, pending_field=field).errors


def test_parser_is_read_only_and_never_claims_signed_origin():
    result = parse_utterance("Invest 100k for 1 year")
    assert result == parse_utterance("Invest 100k for 1 year")
    assert all(not hasattr(slot, "signed") for slot in result.slots)
    with pytest.raises(ValueError, match="Unknown pending"):
        parse_utterance("1234", pending_field="source_account_ref")
