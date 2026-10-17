"""Unsigned deterministic alternatives must become ordinary signed kernel inputs."""

from fractions import Fraction

import pytest
from hypothesis import given
from hypothesis import strategies as st

from corridor.crypto.jcs import H, jcs_bytes
from corridor.eval.mockbank.exec import MockBank
from corridor.gateway.service import Gateway
from corridor.kernel import check
from corridor.kernel.allocation import evaluate_allocation
from corridor.kernel.allocation_fallback import (
    compare_allocation_requests,
    preview_allocation_alternatives,
)
from corridor.schemas.allocation import AllocationGroupBound, BestInterestAllocationCertificate
from corridor.schemas.allocation_fallback import AllocationCorrectionDiff, AllocationFallbackPreview
from corridor.schemas.models import Accept, Reject
from corridor.sim.device import Device
from corridor.sim.keys import signing_key
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.stores.bank import BankStore, add_seconds
from tests.unit.test_allocation_selector import (
    INTENT,
    case,
    explicit_case,
    policy,
    products,
    weights,
)
from tests.wealth_cases import allocation_case


def preview(ref, state):
    return preview_allocation_alternatives("C_DEMO", INTENT, ref, state)


def confirm(alternative, ref, state):
    action, cert, confirmed = allocation_case(
        request=alternative.proposed_request,
        state=state,
        intent=INTENT,
        step=3,
        supersedes=ref,
    )
    assert isinstance(check(action, cert, confirmed, phase="propose"), Accept)
    assert cert.allocation.allocation == alternative.projection.allocation
    assert cert.allocation.totals == alternative.projection.totals
    assert all(item.satisfied for item in cert.allocation.checks)
    return cert.allocation


@pytest.mark.rule("ALLOC-BAND")
def test_w08_signed_rejection_and_clipped_alternative_pass_the_real_kernel():
    ref, state, model = explicit_case(changes={"target_weights": weights("7/10", "3/10")})
    request = evaluate_allocation("C_DEMO", INTENT, ref, state).request
    action, cert, rejected = allocation_case(
        request=request, state=state, intent=INTENT, build=False, step=3, supersedes=ref
    )
    verdict = check(action, cert, rejected, phase="propose")
    assert isinstance(verdict, Reject) and "ALLOC-BAND" in verdict.rule_ids
    before = jcs_bytes(state)
    result = preview(ref, state)
    assert result.requires_confirmation and result.status == "unsigned_preview"
    assert len(result.alternatives) == 1
    alternative = result.alternatives[0]
    assert alternative.kind == "weights_clipped"
    assert alternative.proposed_request.target_weights == weights("3/5", "2/5")
    assert alternative.proposed_request.model_biac_hash == H(model)
    assert alternative.diff.basis == "historical_default_baseline"
    assert alternative.diff.products[0].principal_delta == 0
    assert alternative.diff.benchmark_net_delta == -20
    assert alternative.diff.requested_weights[0].percentage_points_delta == -10
    assert jcs_bytes(state) == before
    assert "certificate" not in result.model_dump()
    confirm(alternative, ref, state)


@pytest.mark.rule("ALLOC-LIQ")
def test_liquidity_fallback_uses_largest_constructor_threshold_and_net_fees():
    state = products(
        make_wealth_state(),
        {"P_D": {"redemption_fee_rate": Fraction(1, 100)}},
    )
    request = allocation_request(liquidity_amount="10000/1")
    action, cert, signed_state = allocation_case(
        request=request, state=state, intent=INTENT, build=False
    )
    verdict = check(action, cert, signed_state, phase="propose")
    assert isinstance(verdict, Reject) and "ALLOC-LIQ" in verdict.rule_ids
    ref = action.args.request_ref
    result = preview(ref, signed_state)
    alternative = result.alternatives[0]
    assert alternative.kind == "lower_liquidity"
    assert alternative.proposed_request.liquidity_amount == 9950
    assert alternative.diff.basis == "no_constructed_baseline"
    assert alternative.diff.products == []
    assert alternative.changes[0].delta == -50
    confirm(alternative, ref, signed_state)


@pytest.mark.rule("ALLOC-SELECT")
def test_capacity_failure_offers_smaller_amount_and_rechecks_concentration():
    state = products(
        make_wealth_state(), {"P_A": {"max_amount": Fraction(4000)}}, only={"P_A", "P_C"}
    )
    ref, state = case(state=state)
    assert "ALLOC-SELECT" in evaluate_allocation("C_DEMO", INTENT, ref, state).errors
    result = preview(ref, state)
    alternative = next(item for item in result.alternatives if item.kind == "lower_amount")
    assert alternative.proposed_request.amount == 8000
    assert alternative.changes[0].delta == -2000
    confirm(alternative, ref, state)


@pytest.mark.parametrize("fault", ["signature", "scope", "superseded", "policy"])
def test_untrusted_or_stale_original_never_receives_relaxed_previews(fault):
    ref, state = case(allocation_request(liquidity_amount="10000/1"))
    if fault == "policy":
        value = next(iter(state.allocation_policies.values()))
        state = state.model_copy(
            update={"allocation_policies": {value.id: value.model_copy(update={"sig": "0" * 128})}}
        )
    elif fault == "superseded":
        _, state = case(state=state, step=2, supersedes=ref)
    else:
        value = state.user_inputs[ref].model_copy(
            update={"sig": "0" * 128} if fault == "signature" else {"scope_id": "OTHER"}
        )
        state = state.model_copy(update={"user_inputs": {**state.user_inputs, ref: value}})
    assert preview(ref, state).alternatives == []


@given(r1=st.integers(min_value=61, max_value=100))
def test_every_weight_fallback_stays_in_band_and_eligible_set(r1):
    ref, state, _ = explicit_case(
        changes={"target_weights": weights(Fraction(r1, 100), Fraction(100 - r1, 100))}
    )
    result = preview(ref, state)
    assert len(result.alternatives) == 1
    alternative = result.alternatives[0]
    assert all(item.satisfied for item in alternative.projection.checks)
    assert {item.product_id for item in alternative.projection.allocation} <= set(
        alternative.projection.candidate_ids
    )
    assert all(
        Fraction(2, 5) <= alternative.proposed_request.target_weights[s] <= Fraction(3, 5)
        for s in ("R1", "R2")
    )
    confirm(alternative, ref, state)


def test_horizon_and_deposit_are_explicit_separate_changes_checked_after_signing():
    state = products(make_wealth_state(), only={"P_A", "P_C"})
    ref, state = case(allocation_request(horizon_days=10), state)
    alternative = preview(ref, state).alternatives[0]
    assert alternative.kind == "extend_horizon"
    assert alternative.proposed_request.horizon_days == 30
    assert alternative.changes[0].delta == 20
    confirm(alternative, ref, state)
    state = products(make_wealth_state(), {"P_B": {"type": "deposit"}, "P_D": {"type": "deposit"}})
    ref, state = case(allocation_request(liquidity_amount="10000/1"), state)
    result = preview(ref, state)
    assert [item.kind for item in result.alternatives] == ["lower_liquidity", "allow_deposit"]
    alternative = result.alternatives[1]
    assert alternative.proposed_request.allowed_types == ["deposit", "wealth"]
    assert alternative.proposed_request.liquidity_amount == 10000
    confirm(alternative, ref, state)


def test_three_alternative_bound_and_fixed_menu_order():
    state = products(
        make_wealth_state(),
        {
            "P_A": {"min_hold_days": 0, "max_amount": Fraction(4000)},
            "P_B": {"type": "deposit"},
            "P_C": {"min_hold_days": 0},
            "P_D": {"risk_level": 1, "min_hold_days": 30},
        },
    )
    ref, state = case(allocation_request(horizon_days=10), state)
    result = preview(ref, state)
    assert [item.kind for item in result.alternatives] == [
        "extend_horizon",
        "allow_deposit",
        "lower_amount",
    ]
    assert jcs_bytes(result) == jcs_bytes(preview(ref, state))
    for alternative in result.alternatives:
        confirm(alternative, ref, state)


def test_clipping_removes_excess_requested_risk_but_never_changes_risk_assessment():
    targets = {**weights("2/5", "2/5"), "R3": Fraction(1, 5)}
    ref, state, _ = explicit_case(changes={"target_weights": targets})
    assert "BIC-RISK" in evaluate_allocation("C_DEMO", INTENT, ref, state).errors
    alternative = preview(ref, state).alternatives[0]
    assert alternative.proposed_request.target_weights == weights("3/5", "2/5")
    assert all(row.sleeve in {"R1", "R2"} for row in alternative.projection.allocation)
    confirm(alternative, ref, state)


def test_group_bound_can_refuse_a_clipped_vector_instead_of_weakening_it():
    state = policy(
        make_wealth_state(),
        groups=[AllocationGroupBound(sleeves=["R1"], lower=Fraction(2, 5), upper=Fraction(11, 20))],
    )
    ref, state = case(state=state)
    model = evaluate_allocation("C_DEMO", INTENT, ref, state).certificate
    request = allocation_request(
        selection_mode="explicit_weights",
        target_weights=weights("7/10", "3/10"),
        model_biac_hash=H(model),
        reason_code="user_adjustment",
    )
    ref, state = case(request, state, step=2, supersedes=ref)
    result = preview(ref, state)
    assert result.alternatives == []
    assert result.binding_constraints


def test_preview_never_substitutes_for_a_new_device_signature():
    ref, state, _ = explicit_case(changes={"target_weights": weights("7/10", "3/10")})
    alternative = preview(ref, state).alternatives[0]
    with pytest.raises(ValueError):
        BestInterestAllocationCertificate.model_validate(
            alternative.projection.model_dump(mode="python")
        )
    value = state.user_inputs[ref].model_copy(
        update={"value": alternative.proposed_request.model_dump(mode="json")}
    )
    forged = state.model_copy(update={"user_inputs": {**state.user_inputs, ref: value}})
    assert evaluate_allocation("C_DEMO", INTENT, ref, forged).errors == ("BIC-PREFERENCE",)
    assert preview(ref, forged).alternatives == []
    confirm(alternative, ref, state)


def test_exact_product_diffs_include_independently_calculated_fees_and_net_liquidity():
    state = products(
        make_wealth_state(),
        {
            "P_B": {
                "purchase_fee_rate": Fraction(1, 100),
                "annual_fee_rate": Fraction(3, 1000),
                "redemption_fee_rate": Fraction(1, 100),
            }
        },
    )
    ref, state = case(state=state)
    model = evaluate_allocation("C_DEMO", INTENT, ref, state).certificate
    request = allocation_request(
        selection_mode="explicit_weights",
        target_weights=weights("7/10", "3/10"),
        model_biac_hash=H(model),
        reason_code="user_adjustment",
    )
    ref, state = case(request, state, step=2, supersedes=ref)
    alternative = preview(ref, state).alternatives[0]
    diffs = {row.product_id: row for row in alternative.diff.products}
    added = diffs["P_B"]
    assert (added.principal_delta, added.percentage_points_delta) == (1000, 10)
    assert (added.fee_buy_delta, added.fee_hold_delta, added.fee_sell_delta) == (10, 3, 10)
    assert added.benchmark_net_delta == 20 - 10 - 3 - 10
    assert added.liquid_net_principal_delta == 1000 - 10
    assert diffs["P_C"].benchmark_net_delta == -40
    assert alternative.diff.projected_fees_delta == 23
    assert alternative.diff.benchmark_net_delta == -43
    assert alternative.diff.total_debit_delta == 10
    assert alternative.diff.liquid_net_principal_delta == 990
    confirm(alternative, ref, state)


def test_successful_request_has_truthful_empty_fallback():
    ref, state = case()
    result = preview(ref, state)
    assert result.alternatives == [] and result.source_errors == []
    assert "already constructs" in result.notice
    assert "No allocation" not in result.notice


def test_gateway_preview_is_read_only_and_preserves_unsigned_contract():
    ref, state, _ = explicit_case(changes={"target_weights": weights("7/10", "3/10")})
    service = Gateway(BankStore(state), MockBank(state, signing_key("bank")))
    service.login(Device().login(session_id="SESSION", expires_at=add_seconds(state.now, 3600)))
    before = jcs_bytes(service.store.snapshot())
    result = AllocationFallbackPreview.model_validate(
        service.allocation_alternatives("C_DEMO", INTENT, ref)
    )
    assert len(result.alternatives) == 1 and result.requires_confirmation
    assert jcs_bytes(service.store.snapshot()) == before


def test_signed_correction_diff_recomputes_fees_horizon_amount_and_liquid_day():
    state = products(make_wealth_state(), {"P_C": {"purchase_fee_rate": Fraction(1, 100)}})
    before_ref, state = case(state=state)
    request = allocation_request(
        amount="8000/1", horizon_days=180, liquidity_days=1, liquidity_amount="4000/1"
    )
    after_ref, state = case(request, state, step=2, supersedes=before_ref)
    before_state = jcs_bytes(state)
    result = compare_allocation_requests("C_DEMO", before_ref, after_ref, state)
    assert result.before_request.amount == 10000 and result.after_request.amount == 8000
    assert (result.before_request.horizon_days, result.after_request.horizon_days) == (365, 180)
    assert (result.before_request.liquidity_days, result.after_request.liquidity_days) == (3, 1)
    deltas = {row.product_id: row for row in result.products}
    assert deltas["P_A"].principal_delta == -1000
    assert deltas["P_C"].principal_delta == -5000
    assert deltas["P_C"].fee_buy_delta == -50
    assert deltas["P_D"].principal_delta == 4000
    assert result.principal_delta == -2000
    assert result.fee_buy_delta == result.projected_fees_delta == -50
    assert result.total_debit_delta == -2050
    assert result.liquid_net_principal_delta == 4000
    assert result.benchmark_net_delta == Fraction(240 * 180, 365) - 300
    assert evaluate_allocation("C_DEMO", INTENT, before_ref, state).errors == ("BIC-PREFERENCE",)
    assert evaluate_allocation("C_DEMO", INTENT, after_ref, state).errors == ()
    assert jcs_bytes(state) == before_state


@pytest.mark.parametrize("fault", ["old_signature", "new_signature", "old_scope", "new_superseded"])
def test_correction_diff_rejects_unverified_pair_or_noncurrent_replacement(fault):
    before_ref, state = case()
    after_ref, state = case(
        allocation_request(amount="8000/1"), state, step=2, supersedes=before_ref
    )
    if fault == "new_superseded":
        _, state = case(state=state, step=3, supersedes=after_ref)
    else:
        ref = after_ref if fault == "new_signature" else before_ref
        value = state.user_inputs[ref].model_copy(
            update={"scope_id": "OTHER"} if fault == "old_scope" else {"sig": "0" * 128}
        )
        state = state.model_copy(update={"user_inputs": {**state.user_inputs, ref: value}})
    with pytest.raises(ValueError, match="BIC-PREFERENCE"):
        compare_allocation_requests("C_DEMO", before_ref, after_ref, state)


def test_gateway_correction_diff_is_read_only_and_matches_pure_comparison():
    before_ref, state = case()
    after_ref, state = case(
        allocation_request(amount="8000/1", liquidity_amount="4000/1"),
        state,
        step=2,
        supersedes=before_ref,
    )
    service = Gateway(BankStore(state), MockBank(state, signing_key("bank")))
    service.login(Device().login(session_id="SESSION", expires_at=add_seconds(state.now, 3600)))
    snapshot = service.store.snapshot()
    before_state = jcs_bytes(snapshot)
    result = AllocationCorrectionDiff.model_validate(
        service.allocation_correction_diff("C_DEMO", before_ref, after_ref)
    )
    assert result == compare_allocation_requests("C_DEMO", before_ref, after_ref, snapshot)
    assert result.principal_delta == -2000 and result.liquid_net_principal_delta == 4000
    assert jcs_bytes(service.store.snapshot()) == before_state
