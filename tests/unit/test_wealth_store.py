"""An allocation's immutable parent manifest survives later state updates."""

import pytest

from corridor.schemas.allocation import AllocationPlan
from corridor.sim.wealth import make_wealth_state
from corridor.stores.bank import BankStore


def test_parent_manifest_is_append_only():
    parent = AllocationPlan(
        id="PARENT",
        principal="C_DEMO",
        parent_intent_id="INTENT",
        request_ref="REQUEST",
        biac_hash="a" * 64,
        policy_hash="b" * 64,
        catalog_hash="c" * 64,
        risk_assessment_hash="d" * 64,
        initial_budget="12000/1",
        items=[
            {
                "item_ref": "ITEM",
                "product_ref": "P_A",
                "principal": "5000/1",
                "fee_buy": "0/1",
                "child_intent_id": "CHILD",
                "input_refs": ["INPUT"],
                "authorization_ref": "AUTH",
                "child_plan_id": "PLAN",
                "child_plan_hash": "e" * 64,
                "child_node_id": "NODE",
            }
        ],
        plan_hash="f" * 64,
    )
    store = BankStore(make_wealth_state())
    store.update(allocation_plans={parent.id: parent})
    for entries in ({}, {parent.id: parent.model_copy(update={"initial_budget": "13000/1"})}):
        with pytest.raises(ValueError, match="Append-only allocation_plans"):
            store.update(allocation_plans=entries)
    assert store.snapshot().allocation_plans[parent.id] == parent
