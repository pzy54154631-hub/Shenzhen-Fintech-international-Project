"""Independent whole-allocation witness and signed-state fault injection."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import CATALOG, INPUT, RISK
from corridor.kernel import check
from corridor.schemas.allocation import AllocationGroupBound
from corridor.schemas.models import Accept, Reject
from corridor.sim.wealth import allocation_request
from tests.bank_cases import recertify, signed
from tests.wealth_cases import allocation_case

POLICY_CONTEXT = "corridor/bank/allocation-policy/v1"


def _accepted(case):
    verdict = check(*case, phase="propose")
    assert isinstance(verdict, Accept), verdict
    return case


def _rejected(case):
    verdict = check(*case, phase="propose")
    assert isinstance(verdict, Reject), verdict
    return verdict


def _ceil_cent(value):
    scaled = value * 100
    return Fraction(-(-scaled.numerator // scaled.denominator), 100)


def _replace_vector(cert, state, amounts, *, horizon=365, liquidity_days=3):
    """Forge a fully priced vector without calling the trusted pricing/selector."""
    biac = cert.allocation
    prototype = biac.allocation[0]
    products = {item.product_id: item for item in state.catalog.products}
    rows = []
    total = sum(amounts.values(), Fraction())
    for product_id, principal in sorted(amounts.items()):
        product = products[product_id]
        buy = _ceil_cent(principal * product.purchase_fee_rate)
        hold = _ceil_cent(principal * product.annual_fee_rate * Fraction(horizon, 365))
        sell = _ceil_cent(principal * product.redemption_fee_rate)
        access = product.min_hold_days + product.redeem_delay_days
        liquid = (
            principal
            - _ceil_cent(principal * product.annual_fee_rate * Fraction(product.min_hold_days, 365))
            - sell
            if access <= liquidity_days
            else Fraction()
        )
        rows.append(
            prototype.model_copy(
                update={
                    "product_id": product_id,
                    "sleeve": f"R{product.risk_level}",
                    "principal": principal,
                    "weight": principal / total,
                    "fee_buy": buy,
                    "fee_hold": hold,
                    "fee_sell": sell,
                    "expected_net": principal
                    * product.expected_annual_rate
                    * Fraction(horizon, 365)
                    - buy
                    - hold
                    - sell,
                    "access_days": access,
                    "liquid_net_principal": liquid,
                }
            )
        )
    totals = biac.totals.model_copy(
        update={
            "principal": total,
            "fee_buy": sum((row.fee_buy for row in rows), Fraction()),
            "total_debit": total + sum((row.fee_buy for row in rows), Fraction()),
            "projected_fees": sum(
                (row.fee_buy + row.fee_hold + row.fee_sell for row in rows), Fraction()
            ),
            "projected_net": sum((row.expected_net for row in rows), Fraction()),
            "liquid_net_principal": sum((row.liquid_net_principal for row in rows), Fraction()),
        }
    )
    sleeves = [
        sleeve.model_copy(
            update={
                "actual_cents": int(
                    sum(
                        (row.principal for row in rows if row.sleeve == sleeve.sleeve),
                        Fraction(),
                    )
                    * 100
                )
            }
        )
        for sleeve in biac.sleeves
    ]
    return cert.model_copy(
        update={
            "allocation": biac.model_copy(
                update={"allocation": rows, "totals": totals, "sleeves": sleeves}
            )
        }
    )


def _policy_state(state, **changes):
    policy = next(iter(state.allocation_policies.values()))
    changed = policy.model_copy(update=changes)
    if "sig" not in changes:
        changed = signed(changed, POLICY_CONTEXT, "bank")
    return state.model_copy(update={"allocation_policies": {changed.id: changed}})


def test_hand_calculated_default_is_accepted_without_model_or_mfa():
    action, cert, state = _accepted(allocation_case())
    assert action.kind == "allocation_compare"
    assert cert.allocation.candidate_ids == ["P_A", "P_B", "P_C", "P_D"]
    assert {row.product_id: row.principal for row in cert.allocation.allocation} == {
        "P_A": Fraction(5000),
        "P_C": Fraction(5000),
    }
    assert cert.allocation.totals.projected_net == 350
    assert cert.allocation.totals.total_debit == 10000
    assert cert.allocation.totals.liquid_net_principal == 0
    assert check(action, cert, state, phase="dispatch").tier == "green"


@pytest.mark.rule("ALLOC-POLICY")
@pytest.mark.parametrize(
    "change",
    [
        {"sig": "0" * 128},
        {"catalog_id": "OTHER_CATALOG"},
        {"catalog_version": 2},
        {"issued_at": "2026-10-15T02:00:00Z", "valid_until": "2026-10-16T02:00:00Z"},
        {"issued_at": "2026-10-16T02:00:01Z"},
    ],
)
def test_policy_authenticity_catalog_binding_and_validity_are_required(change):
    action, cert, state = _accepted(allocation_case())
    changed = _policy_state(state, **change)
    verdict = _rejected(recertify(action, cert, changed))
    assert "ALLOC-POLICY" in verdict.rule_ids


def test_old_certificate_cannot_follow_policy_revision_without_recomputation():
    action, cert, state = _accepted(allocation_case())
    changed = _policy_state(state, version=2)
    verdict = _rejected(recertify(action, cert, changed))
    assert "ALLOC-POLICY" in verdict.rule_ids
    _, fresh, _ = _accepted(allocation_case(state=changed))
    assert fresh.allocation.policy_hash != cert.allocation.policy_hash


def test_multiple_policy_entries_cannot_offer_planner_choice_of_old_policy():
    action, cert, state = _accepted(allocation_case())
    policy = next(iter(state.allocation_policies.values()))
    other = signed(policy.model_copy(update={"id": "OLD_POLICY"}), POLICY_CONTEXT, "bank")
    changed = state.model_copy(
        update={"allocation_policies": {**state.allocation_policies, other.id: other}}
    )
    verdict = _rejected(recertify(action, cert, changed))
    assert "ALLOC-POLICY" in verdict.rule_ids


@pytest.mark.rule("ALLOC-BAND")
def test_fully_priced_vector_outside_sleeve_band_is_rejected():
    action, cert, state = _accepted(allocation_case())
    forged = _replace_vector(
        cert, state, {"P_A": Fraction(3500), "P_B": Fraction(3500), "P_C": Fraction(3000)}
    )
    verdict = _rejected((action, forged, state))
    assert "ALLOC-BAND" in verdict.rule_ids


@pytest.mark.rule("ALLOC-CONC")
def test_band_valid_fully_priced_vector_cannot_exceed_one_product_cap():
    action, cert, state = _accepted(allocation_case())
    forged = _replace_vector(cert, state, {"P_A": Fraction(6000), "P_C": Fraction(4000)})
    verdict = _rejected((action, forged, state))
    assert "ALLOC-CONC" in verdict.rule_ids


@pytest.mark.rule("ALLOC-LIQ")
def test_full_vector_cannot_substitute_illiquid_product_for_signed_need():
    action, cert, state = _accepted(
        allocation_case(request=allocation_request(liquidity_amount="5000/1"))
    )
    assert {row.product_id for row in cert.allocation.allocation} == {"P_A", "P_D"}
    assert cert.allocation.totals.liquid_net_principal == 5000
    forged = _replace_vector(cert, state, {"P_A": Fraction(5000), "P_C": Fraction(5000)})
    verdict = _rejected((action, forged, state))
    assert "ALLOC-LIQ" in verdict.rule_ids


@pytest.mark.rule("ALLOC-SUM")
@pytest.mark.parametrize("field", ["principal", "total_debit", "fee_buy"])
def test_one_cent_forgery_in_aggregate_cash_facts_is_rejected(field):
    action, cert, state = _accepted(allocation_case())
    biac = cert.allocation
    totals = biac.totals.model_copy(update={field: getattr(biac.totals, field) + Fraction(1, 100)})
    cert = cert.model_copy(update={"allocation": biac.model_copy(update={"totals": totals})})
    verdict = _rejected((action, cert, state))
    assert "ALLOC-SUM" in verdict.rule_ids


@pytest.mark.rule("ALLOC-SELECT")
def test_feasible_lower_ranked_vector_needs_explicit_device_adjustment():
    action, cert, state = _accepted(allocation_case())
    forged = _replace_vector(cert, state, {"P_B": Fraction(5000), "P_C": Fraction(5000)})
    verdict = _rejected((action, forged, state))
    assert "ALLOC-SELECT" in verdict.rule_ids


@pytest.mark.parametrize(
    "candidates",
    [
        ["P_B", "P_C", "P_D"],
        ["P_A", "P_B", "P_B", "P_C", "P_D"],
        ["P_A", "P_B", "P_C", "P_D", "P_X"],
        ["P_D", "P_C", "P_B", "P_A"],
    ],
)
def test_eligible_set_omission_duplicate_unsuitable_addition_and_order_fail(candidates):
    action, cert, state = _accepted(allocation_case())
    cert = cert.model_copy(
        update={"allocation": cert.allocation.model_copy(update={"candidate_ids": candidates})}
    )
    verdict = _rejected((action, cert, state))
    assert "BIC-COMPLETE" in verdict.rule_ids


@pytest.mark.parametrize("field", ["expected_net", "fee_buy", "gap"])
def test_comparison_score_forgery_does_not_become_verified_fact(field):
    action, cert, state = _accepted(allocation_case())
    sleeves = list(cert.allocation.sleeves)
    sleeve = sleeves[0]
    rows = list(sleeve.ranking_rows)
    rows[0] = rows[0].model_copy(update={field: getattr(rows[0], field) + Fraction(1, 100)})
    sleeves[0] = sleeve.model_copy(update={"ranking_rows": rows})
    cert = cert.model_copy(
        update={"allocation": cert.allocation.model_copy(update={"sleeves": sleeves})}
    )
    verdict = _rejected((action, cert, state))
    assert "BIC-SCORE" in verdict.rule_ids


def test_c2_cannot_accept_r3_even_inside_a_claimed_whole_allocation():
    action, cert, state = _accepted(allocation_case())
    forged = _replace_vector(cert, state, {"P_A": Fraction(5000), "P_X": Fraction(5000)})
    verdict = _rejected((action, forged, state))
    assert "BIC-RISK" in verdict.rule_ids


@pytest.mark.parametrize(
    "change,resign",
    [
        ({"sig": "0" * 128}, False),
        ({"scope_id": "OTHER_PARENT"}, True),
        ({"principal": "OTHER_CUSTOMER"}, True),
        ({"submitted_at": "2026-10-16T02:00:01Z"}, True),
    ],
)
def test_goal_requires_correct_signature_principal_parent_and_time(change, resign):
    action, cert, state = _accepted(allocation_case())
    request = state.user_inputs[action.args.request_ref].model_copy(update=change)
    if resign:
        request = signed(request, INPUT)
    changed = state.model_copy(update={"user_inputs": {**state.user_inputs, request.id: request}})
    verdict = _rejected(recertify(action, cert, changed))
    assert "BIC-PREFERENCE" in verdict.rule_ids


def test_superseded_parent_input_cannot_keep_old_allocation_alive():
    action, cert, state = _accepted(allocation_case())
    old = state.user_inputs[action.args.request_ref]
    replacement = signed(
        old.model_copy(update={"id": "NEW_ALLOCATION_INPUT", "supersedes": old.id}), INPUT
    )
    state = state.model_copy(
        update={"user_inputs": {**state.user_inputs, replacement.id: replacement}}
    )
    verdict = _rejected(recertify(action, cert, state))
    assert "BIC-PREFERENCE" in verdict.rule_ids


def test_unsigned_catalog_edit_is_rejected_while_resigned_order_preserves_economics():
    action, cert, state = _accepted(allocation_case())
    reverse = state.catalog.model_copy(update={"products": list(reversed(state.catalog.products))})
    changed = state.model_copy(update={"catalog": reverse})
    verdict = _rejected(recertify(action, cert, changed))
    assert "BIC-CATALOG" in verdict.rule_ids
    changed = state.model_copy(update={"catalog": signed(reverse, CATALOG, "bank")})
    _, reordered, _ = _accepted(allocation_case(state=changed))
    assert H(reordered.allocation) != H(cert.allocation)
    assert reordered.allocation.candidate_ids == cert.allocation.candidate_ids
    assert reordered.allocation.allocation == cert.allocation.allocation
    assert reordered.allocation.totals == cert.allocation.totals


def test_current_risk_assessment_expiry_cannot_be_covered_by_old_biac():
    action, cert, state = _accepted(allocation_case())
    risk = state.risk_assessments["RISK_DEMO"]
    risk = signed(
        risk.model_copy(update={"issued_at": "2026-10-15T02:00:00Z", "expires_at": state.now}),
        RISK,
        "risk",
    )
    changed = state.model_copy(update={"risk_assessments": {risk.id: risk}})
    verdict = _rejected(recertify(action, cert, changed))
    assert "BIC-RISK" in verdict.rule_ids


def test_candidate_amount_cap_below_total_still_belongs_to_complete_set():
    _, _, state = allocation_case()
    products = [
        product.model_copy(update={"max_amount": Fraction(5000)})
        if product.product_id == "P_A"
        else product
        for product in state.catalog.products
    ]
    catalog = signed(state.catalog.model_copy(update={"products": products}), CATALOG, "bank")
    _, cert, _ = _accepted(allocation_case(state=state.model_copy(update={"catalog": catalog})))
    assert "P_A" in cert.allocation.candidate_ids
    assert {row.product_id: row.principal for row in cert.allocation.allocation}["P_A"] == 5000


def test_signed_model_weights_are_authoritative_without_midpoint_equality():
    _, _, state = allocation_case()
    policy = next(iter(state.allocation_policies.values()))
    profiles = dict(policy.profiles)
    profiles["C2"] = profiles["C2"].model_copy(
        update={
            "model_weights": {
                "R1": Fraction(3, 5),
                "R2": Fraction(2, 5),
                "R3": Fraction(),
                "R4": Fraction(),
                "R5": Fraction(),
            }
        }
    )
    state = _policy_state(state, profiles=profiles)
    _, cert, _ = _accepted(allocation_case(state=state))
    assert {row.product_id: row.principal for row in cert.allocation.allocation} == {
        "P_A": Fraction(5000),
        "P_B": Fraction(1000),
        "P_C": Fraction(4000),
    }
    assert cert.allocation.totals.projected_net == 330


def test_group_upper_bound_is_checked_independently_of_each_sleeve_band():
    _, _, state = allocation_case()
    policy = next(iter(state.allocation_policies.values()))
    profiles = dict(policy.profiles)
    profiles["C2"] = profiles["C2"].model_copy(
        update={
            "group_bounds": [
                AllocationGroupBound(sleeves=["R1"], lower=Fraction(2, 5), upper=Fraction(1, 2))
            ]
        }
    )
    state = _policy_state(state, profiles=profiles)
    action, cert, state = _accepted(allocation_case(state=state))
    forged = _replace_vector(
        cert, state, {"P_A": Fraction(3000), "P_B": Fraction(3000), "P_C": Fraction(4000)}
    )
    verdict = _rejected((action, forged, state))
    assert "ALLOC-BAND" in verdict.rule_ids


def _explicit_case(*, mode, changes=None, intent="WEALTH_TEST", build=True):
    action, cert, state = _accepted(allocation_case())
    extra = (
        {"target_weights": {"R1": "3/5", "R2": "2/5", "R3": "0/1", "R4": "0/1", "R5": "0/1"}}
        if mode == "explicit_weights"
        else {
            "items": [
                {"product_id": "P_B", "principal": "5000/1"},
                {"product_id": "P_C", "principal": "5000/1"},
            ]
        }
    )
    request = allocation_request(
        selection_mode=mode,
        model_biac_hash=H(cert.allocation),
        reason_code="user_adjustment",
        **{**extra, **(changes or {})},
    )
    return allocation_case(
        request=request,
        state=state,
        intent=intent,
        step=2,
        supersedes=action.args.request_ref,
        build=build,
    )


@pytest.mark.parametrize(
    "mode,amounts,delta",
    [
        ("explicit_weights", {"P_A": 5000, "P_B": 1000, "P_C": 4000}, -20),
        ("explicit_items", {"P_B": 5000, "P_C": 5000}, -50),
    ],
)
def test_signed_adjustments_accept_valid_vector_and_preserve_exact_deviation(mode, amounts, delta):
    _, cert, _ = _accepted(_explicit_case(mode=mode))
    assert {row.product_id: row.principal for row in cert.allocation.allocation} == amounts
    assert cert.allocation.selection_mode == mode
    assert cert.allocation.deviations.projected_net_delta == delta
    assert cert.allocation.model_biac_hash is not None
    if mode == "explicit_weights":
        deltas = {item.sleeve: item.weight_delta for item in cert.allocation.deviations.sleeves}
        assert deltas["R1"] == Fraction(1, 10)
        assert deltas["R2"] == Fraction(-1, 10)


@pytest.mark.parametrize("mode", ["explicit_weights", "explicit_items"])
def test_device_signed_adjustment_cannot_reuse_default_hash_after_horizon_changes(mode):
    verdict = _rejected(_explicit_case(mode=mode, changes={"horizon_days": 364}, build=False))
    assert "ALLOC-SELECT" in verdict.rule_ids


@pytest.mark.parametrize("mode", ["explicit_weights", "explicit_items"])
def test_default_reference_from_another_parent_cannot_authorize_adjustment(mode):
    verdict = _rejected(_explicit_case(mode=mode, intent="OTHER_PARENT", build=False))
    assert "ALLOC-SELECT" in verdict.rule_ids


def test_signed_seventy_thirty_weights_cannot_override_policy_bands():
    verdict = _rejected(
        _explicit_case(
            mode="explicit_weights",
            changes={
                "target_weights": {
                    "R1": "7/10",
                    "R2": "3/10",
                    "R3": "0/1",
                    "R4": "0/1",
                    "R5": "0/1",
                }
            },
            build=False,
        )
    )
    assert "ALLOC-BAND" in verdict.rule_ids


def test_signed_explicit_product_table_still_cannot_include_r3_for_c2():
    verdict = _rejected(
        _explicit_case(
            mode="explicit_items",
            changes={
                "items": [
                    {"product_id": "P_A", "principal": "5000/1"},
                    {"product_id": "P_X", "principal": "5000/1"},
                ]
            },
            build=False,
        )
    )
    assert "BIC-RISK" in verdict.rule_ids
