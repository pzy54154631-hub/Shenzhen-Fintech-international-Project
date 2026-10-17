"""Red-team (claude2): P1 card controls, DESIGN-BANK 4.4 / PROP-020."""

from fractions import Fraction

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.bench.card_runner import _token, card_state, prepare_card
from corridor.gateway.bank_adapter import card_authorize


def _case(name, **kwargs):
    return BankCase(card_state(**kwargs), task_id="J24", subcase_id=name)


@pytest.mark.parametrize(
    "category",
    ["Online", "ONLINE", " online", "online ", "online\t", "ｏｎｌｉｎｅ"],
)
def test_card_probe_uses_exact_category_identifiers_without_payment_effects(category):
    """CARD-CAT-1 was rejected: this read-only test probe uses exact identifiers.

    DESIGN-BANK 4.4 does not require normalization of probe input. Preserve the
    original six spellings, canonical restriction check, and no-payment invariant.
    """
    case = _case("rt_category", restrictions=["online"])
    bank = case.gateway.bank
    before = bank.final_state()
    state_before = case.state.model_dump(mode="json")
    assert not card_authorize(bank, "CARD_DEMO", Fraction(1), "online")
    assert card_authorize(bank, "CARD_DEMO", Fraction(1), category), category
    assert bank.final_state() == before
    assert case.state.model_dump(mode="json") == state_before
    assert bank.execute_count == 0


@pytest.mark.parametrize("status", ["frozen", "lost"])
def test_card_authorize_refuses_frozen_and_lost(status):
    case = _case(f"rt_status_{status}", status=status)
    assert not card_authorize(case.gateway.bank, "CARD_DEMO", Fraction(1), "dining")


def test_lost_card_cannot_be_unfrozen_directly_even_with_token():
    case = _case("rt_lost_unfreeze", status="lost")
    prepared = prepare_card(case, "unfreeze_card", change={"status": "active"})
    assert prepared.proposal.verdict.outcome == "Reject"
    result = case.gateway.dispatch(prepared.action, prepared.cert, _token(case, prepared))
    assert result.status == "rejected"
    assert case.state.cards["CARD_DEMO"].status == "lost"
    assert case.gateway.bank.execute_count == 0


@pytest.mark.parametrize(
    "kind,change",
    [("raise_card_limit", {"limit": "5000/1"}), ("relax_card_restriction", {"restrictions": []})],
)
def test_red_card_changes_need_mfa_at_dispatch(kind, change):
    case = _case(f"rt_red_{kind}", restrictions=["online"])
    prepared = prepare_card(case, kind, change=change)
    assert prepared.proposal.verdict.tier == "red"
    result = case.gateway.dispatch(prepared.action, prepared.cert, _token(case, prepared))
    assert "TIER-MFA-REQUIRED" in result.rule_ids
    assert case.gateway.bank.execute_count == 0
