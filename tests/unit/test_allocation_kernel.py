"""Allocation comparison retains the normal kernel authorization and source gates."""

from corridor.kernel import check
from corridor.kernel.binding import binding
from tests.bank_cases import recertify
from tests.wealth_cases import allocation_case


def test_signed_allocation_comparison_is_green_and_has_recomputed_facts():
    action, cert, state = allocation_case()
    result = check(action, cert, state, phase="propose")
    assert result.outcome == "Accept"
    assert result.tier == "green"
    card = binding(action, cert, state).card_core
    assert card["allocation"]["totals"]["principal"] == "10000/1"
    assert card["allocation"]["totals"]["projected_net"] == "350/1"
    assert card["available"] == "12000/1"


def test_allocation_comparison_requires_its_signed_session_permission():
    action, cert, state = allocation_case()
    state = state.model_copy(update={"authorizations": {}})
    action, cert, state = recertify(action, cert, state)
    result = check(action, cert, state, phase="propose")
    assert result.outcome == "Reject"
    assert "AUTH-SCOPE" in result.rule_ids


def test_allocation_witness_cannot_replace_legacy_purchase_witness():
    from tests.investment_cases import investment_case

    _, wealth_cert, _ = allocation_case()
    action, cert, state = investment_case(kind="purchase_product")
    cert = cert.model_copy(update={"allocation": wealth_cert.allocation})
    action, cert, state = recertify(action, cert, state)
    result = check(action, cert, state, phase="propose")
    assert result.outcome == "Reject"
