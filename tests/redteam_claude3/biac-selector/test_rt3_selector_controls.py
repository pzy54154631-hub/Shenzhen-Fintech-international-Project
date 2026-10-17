"""Red-team round 3 controls that HELD: selector invariants, twin and adjustment guards."""

import importlib.util as _iu
from fractions import Fraction
from pathlib import Path as _P

import pytest

from corridor.crypto.jcs import H
from corridor.kernel.allocation import verify_allocation
from corridor.schemas.allocation import AllocationRequestItem
from corridor.sim.wealth import allocation_request

_spec = _iu.spec_from_file_location("rt3_biac", _P(__file__).with_name("_biac.py"))
B = _iu.module_from_spec(_spec)
_spec.loader.exec_module(B)


def test_rank_swap_and_reason_forgery_rejected():
    ref, state = B.sign_request()
    ev = B.evaluate(ref, state)
    cert = ev.certificate
    r1 = cert.sleeves[0]
    swapped = r1.model_copy(update={"ranking_rows": list(reversed(r1.ranking_rows))})
    forged = cert.model_copy(update={"sleeves": [swapped, *cert.sleeves[1:]]})
    assert "BIC-SCORE" in verify_allocation(forged, ev, state)
    item = cert.allocation[0].model_copy(update={"selection_reason": "liquidity_requirement"})
    forged = cert.model_copy(update={"allocation": [item, *cert.allocation[1:]]})
    assert "ALLOC-SELECT" in verify_allocation(forged, ev, state)


def test_explicit_items_above_risk_or_out_of_band_by_one_cent_rejected():
    ref, state = B.sign_request()
    default = B.evaluate(ref, state).certificate

    def items(pairs):
        return allocation_request(
            selection_mode="explicit_items",
            items=[AllocationRequestItem(product_id=p, principal=Fraction(a)) for p, a in pairs],
            model_biac_hash=H(default),
            reason_code="product_preference",
        )

    bad, st = B.sign_request(
        items([("P_A", "6000.01"), ("P_B", "0.99"), ("P_C", 3999)]), state, step=2, supersedes=ref
    )
    assert "ALLOC-BAND" in B.evaluate(bad, st).errors
    bad, st = B.sign_request(items([("P_A", 5000), ("P_X", 5000)]), state, step=2, supersedes=ref)
    assert {"BIC-COMPLETE", "BIC-RISK"} <= set(B.evaluate(bad, st).errors)


@pytest.mark.parametrize("liquidity", ["0", "5000", "9950"])
def test_liquidity_is_net_of_fees_and_hold_plus_delay(liquidity):
    state = B.with_products(
        B.sign_request()[1],
        {
            "P_D": {
                "redemption_fee_rate": Fraction(1, 100),
                "expected_annual_rate": Fraction(4, 100),
            }
        },
    )
    ref, state = B.sign_request(allocation_request(liquidity_amount=Fraction(liquidity)), state)
    cert = B.evaluate(ref, state).certificate
    assert cert is not None
    assert cert.totals.liquid_net_principal >= Fraction(liquidity)
    assert all(i.product_id != "P_A" or i.liquid_net_principal == 0 for i in cert.allocation)


def test_greedy_failure_is_not_reported_as_empty_eligible_set():
    state = B.with_products(B.sign_request()[1], only={"P_A", "P_C", "P_X", "P_Y"})
    ref, state = B.sign_request(allocation_request(liquidity_amount=Fraction(1)), state)
    ev = B.evaluate(ref, state)
    assert ev.certificate is None and "BIC-NOFEASIBLE" not in ev.errors
    assert "ALLOC-SELECT" in ev.errors
