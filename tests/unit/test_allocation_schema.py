"""Strict, bounded public wealth schemas and deterministic synthetic fixtures."""

from fractions import Fraction

import pytest
from pydantic import ValidationError

from corridor.crypto.jcs import H
from corridor.crypto.sign import ALLOCATION_POLICY, CATALOG, verify
from corridor.schemas.allocation import (
    AllocationFailure,
    AllocationPlan,
    AllocationPolicy,
    AllocationRequest,
)
from corridor.schemas.bank import BankCertificate, PurchaseArgs
from corridor.schemas.state import BankState
from corridor.sim.wealth import allocation_request, make_wealth_state, signed_allocation_policy


def test_default_request_roundtrips_with_exact_rationals():
    request = allocation_request()
    assert request.amount == 10000
    assert request.horizon_days == 365
    assert request.selection_mode == "default"
    assert AllocationRequest.model_validate_json(request.model_dump_json()) == request
    assert request.model_dump(mode="json")["amount"] == "10000/1"


@pytest.mark.parametrize(
    "changes",
    [
        {"amount": "0/1"},
        {"amount": "100000000001/100"},
        {"amount": "1/1000"},
        {"horizon_days": 366},
        {"liquidity_days": 366},
        {"liquidity_amount": "10001/1"},
        {"allowed_types": ["wealth", "wealth"]},
        {"amount": "1" * 200},
        {"amount": "1/" + str(2**128)},
        {"source_account_ref": "A" * 129},
        {"id": "A" * 129},
        {"sponsored": True},
        {"selection_mode": "explicit_weights"},
        {"selection_mode": "explicit_items"},
        {"target_weights": {"R1": "1/1"}},
    ],
)
def test_allocation_request_rejects_invalid_or_unbounded_values(changes):
    with pytest.raises(ValidationError):
        allocation_request(**changes)


def test_explicit_request_requires_complete_weights_and_bound_model_reference():
    request = allocation_request(
        selection_mode="explicit_weights",
        target_weights={"R1": "3/5", "R2": "2/5", "R3": "0/1", "R4": "0/1", "R5": "0/1"},
        model_biac_hash="a" * 64,
        reason_code="user_adjustment",
    )
    assert request.target_weights["R1"] == Fraction(3, 5)
    assert AllocationRequest.model_validate_json(request.model_dump_json()) == request
    with pytest.raises(ValidationError):
        allocation_request(
            selection_mode="explicit_items",
            items=[{"product_id": "P_A", "principal": "5000/1"}] * 2,
            model_biac_hash="a" * 64,
            reason_code="user_adjustment",
        )


def test_policy_accepts_signed_non_midpoint_weights_within_bands():
    policy = signed_allocation_policy()
    raw = policy.model_dump(mode="json")
    raw["profiles"]["C2"]["model_weights"]["R1"] = "3/5"
    raw["profiles"]["C2"]["model_weights"]["R2"] = "2/5"
    changed = AllocationPolicy.model_validate(raw)
    assert changed.profiles["C2"].model_weights["R1"] == Fraction(3, 5)


def test_policy_rejects_incomplete_or_unsuitable_profiles():
    raw = signed_allocation_policy().model_dump(mode="json")
    raw["profiles"]["C2"]["model_weights"]["R3"] = "1/10"
    with pytest.raises(ValidationError):
        AllocationPolicy.model_validate(raw)
    raw = signed_allocation_policy().model_dump(mode="json")
    del raw["profiles"]["C5"]
    with pytest.raises(ValidationError):
        AllocationPolicy.model_validate(raw)
    raw = signed_allocation_policy().model_dump(mode="json")
    raw["profiles"]["C2"]["bands"][2]["upper"] = "3/10"
    with pytest.raises(ValidationError):
        AllocationPolicy.model_validate(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"max_products": 13},
        {"concentration_cap": "3/5"},
        {"valid_until": "2026-10-16T02:00:00Z"},
        {"ranking_basis": "allocated_principal"},
        {"selector_version": "unbounded_solver"},
    ],
)
def test_policy_rejects_unapproved_scope_and_resource_bounds(changes):
    with pytest.raises(ValidationError):
        signed_allocation_policy(**changes)


def test_explicit_product_list_is_resource_bounded():
    with pytest.raises(ValidationError):
        allocation_request(
            selection_mode="explicit_items",
            items=[{"product_id": f"P_{index}", "principal": "100/1"} for index in range(13)],
            model_biac_hash="a" * 64,
            reason_code="user_adjustment",
        )


def test_request_json_rejects_float_and_duplicate_fields():
    payload = allocation_request().model_dump_json()
    with pytest.raises(ValueError):
        AllocationRequest.model_validate_json(payload.replace('"10000/1"', "10000.0"))
    with pytest.raises(ValueError):
        AllocationRequest.model_validate_json('{"amount":"1/1",' + payload[1:])


def test_failure_trace_is_bounded_and_does_not_claim_infeasibility():
    body = {
        "input_hashes": {},
        "candidate_ids": ["P_A"],
        "exclusions": [],
        "stage": "fill",
        "reason_codes": ["capacity_shortfall"],
        "residual_cents": 100,
        "unmet_constraints": [],
        "trace": [
            {
                "product_id": "P_A",
                "stage": "fill",
                "allocated_cents": 0,
                "skipped_reason": "sleeve_capacity",
            }
        ],
    }
    failure = AllocationFailure.model_validate(body)
    assert failure.trace[0].allocated_cents == 0
    with pytest.raises(ValidationError):
        AllocationFailure.model_validate({**body, "trace": body["trace"] * 25})
    with pytest.raises(ValidationError):
        AllocationFailure.model_validate({**body, "reason_codes": ["proven_infeasible"]})


def test_allocation_plan_uses_published_risk_hash_name_and_bounds_inherited_ids():
    body = {
        "id": "ALLOCATION_PLAN",
        "principal": "C_DEMO",
        "parent_intent_id": "PARENT",
        "request_ref": "ALLOCATION_INPUT",
        "biac_hash": "a" * 64,
        "policy_hash": "b" * 64,
        "catalog_hash": "c" * 64,
        "risk_assessment_hash": "d" * 64,
        "initial_budget": "12000/1",
        "items": [
            {
                "item_ref": "ITEM_A",
                "product_ref": "P_A",
                "principal": "5000/1",
                "fee_buy": "0/1",
                "child_intent_id": "CHILD_A",
                "input_refs": ["AMOUNT_A"],
                "authorization_ref": "AUTH_A",
                "child_plan_id": "PLAN_A",
                "child_plan_hash": "e" * 64,
                "child_node_id": "NODE_A",
            }
        ],
        "plan_hash": "f" * 64,
    }
    plan = AllocationPlan.model_validate(body)
    assert plan.risk_assessment_hash == "d" * 64
    assert AllocationPlan.model_validate_json(plan.model_dump_json()) == plan
    with pytest.raises(ValidationError):
        AllocationPlan.model_validate({**body, "risk_hash": "d" * 64})
    with pytest.raises(ValidationError):
        AllocationPlan.model_validate({**body, "id": "A" * 129})
    with pytest.raises(ValidationError):
        signed_allocation_policy(id="A" * 129)


def test_purchase_has_exactly_one_legacy_or_allocation_branch():
    common = {"source_ref": "A_CURRENT", "product_ref": "P_A", "amount_ref": "INPUT_AMOUNT"}
    legacy = PurchaseArgs.model_validate({**common, "preference_ref": "INPUT_PREFERENCE"})
    assert legacy.model_dump(mode="json") == {**common, "preference_ref": "INPUT_PREFERENCE"}
    allocation = PurchaseArgs.model_validate({
        **common,
        "allocation_ref": "ALLOCATION_PLAN",
        "allocation_item_ref": "ITEM_A",
    })
    assert allocation.preference_ref is None
    for partial in ({}, {"allocation_ref": "ALLOCATION_PLAN"}, {"allocation_item_ref": "ITEM_A"}):
        with pytest.raises(ValidationError):
            PurchaseArgs.model_validate({**common, **partial})
    with pytest.raises(ValidationError):
        PurchaseArgs.model_validate({
            **allocation.model_dump(mode="json"),
            "preference_ref": "INPUT_PREFERENCE",
        })


def test_legacy_certificate_and_empty_state_do_not_add_allocation_wire_fields():
    certificate = BankCertificate(
        action_hash="a" * 64,
        authorization_ref="AUTH",
        derivations={},
        dependency_hashes={},
    )
    assert "allocation" not in certificate.model_dump(mode="json")
    state = make_wealth_state()
    empty = state.model_copy(update={"allocation_policies": {}, "allocation_plans": {}})
    assert "allocation_policies" not in empty.model_dump(mode="json")
    assert "allocation_plans" not in empty.model_dump(mode="json")


def test_wealth_fixture_matches_public_hand_calculation_and_has_valid_signatures():
    state = make_wealth_state()
    assert H(state) == H(make_wealth_state())
    assert state.accounts["A_CURRENT"].opening_balance == 12000
    assert state.risk_assessments["RISK_DEMO"].level == 2
    assert [product.id for product in state.catalog.products] == [
        "P_A",
        "P_B",
        "P_C",
        "P_D",
        "P_X",
        "P_Y",
    ]
    assert [product.risk_level for product in state.catalog.products] == [1, 1, 2, 2, 3, 1]
    assert verify(state.roots.bank_pubkey, CATALOG, state.catalog, state.catalog.sig)
    policy = state.allocation_policies["ALLOCATION_POLICY"]
    assert verify(state.roots.bank_pubkey, ALLOCATION_POLICY, policy, policy.sig)
    assert BankState.model_validate_json(state.model_dump_json()) == state
