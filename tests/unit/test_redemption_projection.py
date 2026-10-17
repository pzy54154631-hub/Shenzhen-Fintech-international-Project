"""Shared redemption guards use registered rule identifiers for all callers."""

from fractions import Fraction

import pytest

from corridor.kernel.investment import price_redemption, resolve_redemption_account
from corridor.stores.bank import add_seconds
from tests.investment_cases import redemption_case


@pytest.mark.parametrize("invalid", ["future_acquisition", "zero_amount", "excessive_fees"])
def test_shared_redemption_price_guards_use_registered_domain_rule(invalid):
    _, _, state = redemption_case()
    position = state.positions["LOT_A"]
    product = state.catalog.products[0]
    amount = Fraction(1000)
    if invalid == "future_acquisition":
        position = position.model_copy(update={"acquired_at": add_seconds(state.now, 1)})
    elif invalid == "zero_amount":
        amount = Fraction(0)
    else:
        product = product.model_copy(update={"redemption_fee_rate": Fraction(2)})
    with pytest.raises(ValueError, match="^DOMAIN-STATE$"):
        price_redemption(product, position, amount, state.now)


@pytest.mark.parametrize("invalid", ["ambiguous", "no_active_account", "wrong_owner"])
def test_shared_redemption_account_guards_use_registered_domain_rule(invalid):
    _, _, state = redemption_case()
    position = state.positions["LOT_A"]
    account = state.accounts["A_CURRENT"]
    principal = position.owner
    if invalid == "ambiguous":
        second = account.model_copy(update={"id": "A_SECOND"})
        state = state.model_copy(update={"accounts": {**state.accounts, second.id: second}})
    elif invalid == "no_active_account":
        closed = account.model_copy(update={"status": "closed"})
        state = state.model_copy(update={"accounts": {**state.accounts, closed.id: closed}})
    else:
        principal = "OTHER"
    with pytest.raises(ValueError, match="^DOMAIN-STATE$"):
        resolve_redemption_account(position, principal, state)
