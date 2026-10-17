"""Whole-vector exact-money properties with independently recomputed bounds."""

from fractions import Fraction

from hypothesis import given
from hypothesis import strategies as st

from corridor.crypto.jcs import jcs_bytes
from corridor.crypto.sign import CATALOG
from corridor.kernel import check
from corridor.schemas.models import Accept, Reject
from corridor.sim.wealth import allocation_request
from tests.bank_cases import signed
from tests.wealth_cases import allocation_case


@given(half_amount=st.integers(min_value=100, max_value=6000), liquid_halves=st.integers(0, 2))
def test_every_constructed_default_conserves_cents_cap_bands_and_net_liquidity(
    half_amount, liquid_halves
):
    principal = Fraction(2 * half_amount)
    needed = Fraction(liquid_halves * half_amount)
    request = allocation_request(amount=str(principal), liquidity_amount=str(needed))
    action, cert, state = allocation_case(request=request)
    assert isinstance(check(action, cert, state, phase="propose"), Accept)
    rows = cert.allocation.allocation
    products = {product.product_id: product for product in state.catalog.products}
    assert sum((row.principal for row in rows), Fraction()) == principal
    assert len({row.product_id for row in rows}) == len(rows)
    assert all((row.principal * 100).denominator == 1 for row in rows)
    assert all(Fraction(100) <= row.principal <= principal / 2 for row in rows)
    by_risk = {
        risk: sum(
            (row.principal for row in rows if products[row.product_id].risk_level == risk),
            Fraction(),
        )
        for risk in range(1, 6)
    }
    assert by_risk[1] == by_risk[2] == principal / 2
    assert by_risk[3] == by_risk[4] == by_risk[5] == 0
    assert Fraction(2, 5) <= by_risk[1] / principal <= Fraction(3, 5)
    liquid = sum(
        (
            row.principal
            for row in rows
            if products[row.product_id].min_hold_days + products[row.product_id].redeem_delay_days
            <= 3
        ),
        Fraction(),
    )
    expected = sum(
        (row.principal * products[row.product_id].expected_annual_rate for row in rows),
        Fraction(),
    )
    assert liquid >= needed
    assert cert.allocation.totals.liquid_net_principal == liquid
    assert cert.allocation.totals.projected_net == expected
    assert cert.allocation.totals.total_debit == principal
    assert jcs_bytes(cert.allocation) == jcs_bytes(allocation_case(request=request)[1].allocation)


@given(cents=st.integers(min_value=1, max_value=9999))
def test_no_positive_cent_tolerance_in_certificate_principal_conservation(cents):
    action, cert, state = allocation_case()
    assert isinstance(check(action, cert, state, phase="propose"), Accept)
    biac = cert.allocation
    totals = biac.totals.model_copy(update={"principal": Fraction(10000) + Fraction(cents, 100)})
    forged = cert.model_copy(update={"allocation": biac.model_copy(update={"totals": totals})})
    verdict = check(action, forged, state, phase="propose")
    assert isinstance(verdict, Reject)
    assert "ALLOC-SUM" in verdict.rule_ids


def _ceil_cent(value):
    scaled = value * 100
    return Fraction(-(-scaled.numerator // scaled.denominator), 100)


@given(
    half_cents=st.integers(min_value=10000, max_value=500000),
    purchase_bps=st.integers(min_value=1, max_value=99),
    redemption_bps=st.integers(min_value=1, max_value=99),
)
def test_net_liquidity_and_debit_round_each_product_fee_up_before_summing(
    half_cents, purchase_bps, redemption_bps
):
    half = Fraction(half_cents, 100)
    principal = 2 * half
    buy_rate = Fraction(purchase_bps, 10000)
    sell_rate = Fraction(redemption_bps, 10000)
    buy_per_item = _ceil_cent(half * buy_rate)
    sell_per_item = _ceil_cent(half * sell_rate)
    needed = principal - 2 * sell_per_item
    _, _, state = allocation_case()
    products = [
        product.model_copy(update={"purchase_fee_rate": buy_rate, "redemption_fee_rate": sell_rate})
        for product in state.catalog.products
    ]
    catalog = signed(state.catalog.model_copy(update={"products": products}), CATALOG, "bank")
    request = allocation_request(amount=str(principal), liquidity_amount=str(needed))
    action, cert, state = allocation_case(
        request=request, state=state.model_copy(update={"catalog": catalog})
    )
    assert isinstance(check(action, cert, state, phase="propose"), Accept)
    assert {row.product_id for row in cert.allocation.allocation} == {"P_B", "P_D"}
    assert cert.allocation.totals.liquid_net_principal == needed
    assert cert.allocation.totals.fee_buy == 2 * buy_per_item
    assert cert.allocation.totals.total_debit == principal + 2 * buy_per_item
    for row in cert.allocation.allocation:
        assert row.principal == half
        assert row.fee_buy == buy_per_item
        assert row.fee_sell == sell_per_item
        assert row.liquid_net_principal == half - sell_per_item
