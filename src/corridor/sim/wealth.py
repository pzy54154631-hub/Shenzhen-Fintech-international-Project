"""Synthetic Topic B fixtures and deterministically signed allocation policies."""

from fractions import Fraction
from pathlib import Path
from typing import Any

from corridor.crypto.sign import ALLOCATION_POLICY, CATALOG, sign
from corridor.schemas.allocation import AllocationPolicy, AllocationRequest
from corridor.schemas.base import loads_exact
from corridor.schemas.domain import Product, ProductCatalog
from corridor.schemas.state import BankState
from corridor.sim.fixtures import END, NOW, PRINCIPAL, make_state
from corridor.sim.keys import signing_key


def allocation_request(**changes: Any) -> AllocationRequest:
    """Return the public hand-calculated request, before the device signs it."""
    return AllocationRequest.model_validate({
        "id": "ALLOCATION_REQUEST",
        "version": 1,
        "source_account_ref": "A_CURRENT",
        "amount": "10000/1",
        "horizon_days": 365,
        "liquidity_days": 3,
        "liquidity_amount": "0/1",
        "allowed_types": ["wealth"],
        "objective": "net_return",
        "allocation_policy_ref": "ALLOCATION_POLICY",
        "selection_mode": "default",
        **changes,
    })


def signed_allocation_policy(**changes: Any) -> AllocationPolicy:
    path = Path(__file__).resolve().parents[3] / "data" / "wealth" / "allocation-policy-v1.json"
    body = loads_exact(path.read_bytes())
    policy = AllocationPolicy.model_validate({**body, **changes, "sig": "0" * 128})
    return policy.model_copy(update={"sig": sign(signing_key("bank"), ALLOCATION_POLICY, policy)})


def make_wealth_state() -> BankState:
    """C2, CNY 12,000 available, and the six-product W03-W10 public catalogue."""
    state = make_state()
    products = [
        Product.model_validate({
            "product_id": product_id,
            "type": "wealth",
            "risk_level": risk,
            "min_amount": "20000/1" if product_id == "P_Y" else "100/1",
            "purchase_open": True,
            "eligible_customers": [PRINCIPAL],
            "min_hold_days": hold,
            "redeem_delay_days": delay,
            "expected_annual_rate": rate,
            "purchase_fee_rate": "0/1",
            "annual_fee_rate": "0/1",
            "redemption_fee_rate": "0/1",
            "pricing_model": "simple_365_v1",
        })
        for product_id, risk, hold, delay, rate in (
            ("P_A", 1, 30, 0, "3/100"),
            ("P_B", 1, 0, 1, "1/50"),
            ("P_C", 2, 30, 0, "1/25"),
            ("P_D", 2, 0, 1, "3/100"),
            ("P_X", 3, 0, 0, "9/100"),
            ("P_Y", 1, 0, 0, "1/100"),
        )
    ]
    catalog = ProductCatalog(
        id="CATALOG", version=1, issued_at=NOW, valid_until=END, products=products, sig="0" * 128
    )
    catalog = catalog.model_copy(update={"sig": sign(signing_key("bank"), CATALOG, catalog)})
    policy = signed_allocation_policy()
    account = state.accounts["A_CURRENT"].model_copy(update={"opening_balance": Fraction(12000)})
    return BankState.model_validate({
        **state.model_dump(mode="python"),
        "catalog": catalog,
        "policy": state.policy.model_copy(
            update={"tool_whitelist": [*state.policy.tool_whitelist, "allocation_compare"]}
        ),
        "accounts": {**state.accounts, account.id: account},
        "allocation_policies": {policy.id: policy},
    })
