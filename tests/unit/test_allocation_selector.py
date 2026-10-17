"""Hand-computed W03-W10 allocation construction and refusal boundaries."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import ALLOCATION_POLICY, CATALOG, INPUT
from corridor.kernel.allocation import build_allocation, evaluate_allocation, verify_allocation
from corridor.schemas.allocation import AllocationRequestItem
from corridor.schemas.domain import MarketingMetadata
from corridor.sim.device import Device
from corridor.sim.wealth import allocation_request, make_wealth_state
from tests.bank_cases import signed

INTENT = "WEALTH_SELECTOR"


def case(request=None, state=None, *, step=1, supersedes=None):
    state = state or make_wealth_state()
    request = request or allocation_request()
    value = Device().confirm_input(
        intent_id=INTENT,
        slot="allocation",
        value=request.model_dump(mode="json"),
        now=state.now,
        step=step,
        supersedes=supersedes,
    )
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, value.id: value}})
    return value.id, state


def run(request=None, state=None):
    ref, state = case(request, state)
    return evaluate_allocation("C_DEMO", INTENT, ref, state)


def products(state, changes=None, *, only=None, reverse=False):
    values = [
        p.model_copy(update=(changes or {}).get(p.id, {}))
        for p in state.catalog.products
        if only is None or p.id in only
    ]
    if reverse:
        values.reverse()
    catalog = signed(state.catalog.model_copy(update={"products": values}), CATALOG, "bank")
    return state.model_copy(update={"catalog": catalog})


def vector(certificate):
    return {item.product_id: item.principal for item in certificate.allocation}


def policy(state, *, weights=None, bands=None, groups=None, changes=None):
    value = next(iter(state.allocation_policies.values()))
    profile = value.profiles["C2"]
    update = {}
    if weights is not None:
        update["model_weights"] = weights
    if bands is not None:
        update["bands"] = [
            band.model_copy(
                update={
                    "lower": Fraction(bands.get(band.sleeve, (band.lower, band.upper))[0]),
                    "upper": Fraction(bands.get(band.sleeve, (band.lower, band.upper))[1]),
                }
            )
            for band in profile.bands
        ]
    if groups is not None:
        update["group_bounds"] = groups
    value = signed(
        value.model_copy(
            update={
                "profiles": {**value.profiles, "C2": profile.model_copy(update=update)},
                **(changes or {}),
            }
        ),
        ALLOCATION_POLICY,
        "bank",
    )
    return state.model_copy(update={"allocation_policies": {value.id: value}})


def weights(r1, r2):
    return {
        "R1": Fraction(r1),
        "R2": Fraction(r2),
        "R3": Fraction(),
        "R4": Fraction(),
        "R5": Fraction(),
    }


def test_w04_default_complete_hand_calculation():
    evaluation = run()
    assert evaluation.errors == () and evaluation.failure is None
    cert = evaluation.certificate
    assert cert.candidate_ids == ["P_A", "P_B", "P_C", "P_D"]
    assert vector(cert) == {"P_A": 5000, "P_C": 5000}
    assert cert.totals.projected_net == 350
    assert cert.totals.principal == cert.totals.total_debit == 10000
    assert cert.totals.liquid_net_principal == 0
    assert all(check.satisfied for check in cert.checks)
    assert {item.product_id for item in cert.exclusions} == {"P_X", "P_Y"}
    assert "risk" in cert.exclusions[0].reason_codes


@pytest.mark.parametrize(
    "objective,r1,r2",
    [
        ("net_return", ["P_A", "P_B"], ["P_C", "P_D"]),
        ("total_fee", ["P_A", "P_B"], ["P_C", "P_D"]),
        ("liquidity", ["P_B", "P_A"], ["P_D", "P_C"]),
    ],
)
def test_w03_rank_at_common_reference_and_objective(objective, r1, r2):
    cert = run(allocation_request(objective=objective)).certificate
    for sleeve, expected in zip(cert.sleeves[:2], (r1, r2), strict=True):
        assert [row.product_id for row in sleeve.ranking_rows] == expected
        assert all(
            row.reference_amount == 10000 and row.comparison_only for row in sleeve.ranking_rows
        )
        assert sleeve.ranking_rows[0].gap == 0
    if objective == "net_return":
        assert cert.sleeves[0].ranking_rows[1].gap == 100


def test_w03_buy_fee_exact_tie_and_actual_fees():
    state = products(make_wealth_state(), {"P_C": {"purchase_fee_rate": Fraction(1, 100)}})
    cert = run(state=state).certificate
    rows = cert.sleeves[1].ranking_rows
    assert [row.product_id for row in rows] == ["P_C", "P_D"]
    assert rows[0].expected_net == rows[1].expected_net == 300
    assert rows[0].gap == rows[1].gap == 0
    assert cert.allocation[1].fee_buy == 50
    assert cert.totals.total_debit == 10050


def test_w03_interval_eligibility_includes_product_capped_below_total():
    state = products(make_wealth_state(), {"P_A": {"max_amount": Fraction(4000)}})
    cert = run(state=state).certificate
    assert "P_A" in cert.candidate_ids
    assert vector(cert) == {"P_A": 4000, "P_B": 1000, "P_C": 5000}


@pytest.mark.parametrize(
    "change",
    [
        {"sig": "0" * 128},
        {"catalog_version": 2},
        {"version": 0},
        {"valid_until": "2026-10-16T02:00:00Z"},
        {"issued_at": "2027-10-16T02:00:00Z"},
    ],
)
def test_w04_invalid_policy_refused(change):
    state = make_wealth_state()
    value = next(iter(state.allocation_policies.values()))
    if "sig" in change:
        value = value.model_copy(update=change)
    else:
        value = signed(value.model_copy(update=change), ALLOCATION_POLICY, "bank")
    state = state.model_copy(update={"allocation_policies": {value.id: value}})
    result = run(state=state)
    assert result.certificate is None and "ALLOC-POLICY" in result.errors


def test_w04_explicit_signed_policy_weights_need_not_equal_band_midpoints():
    state = policy(make_wealth_state(), weights=weights("3/5", "2/5"))
    cert = run(state=state).certificate
    assert vector(cert) == {"P_A": 5000, "P_B": 1000, "P_C": 4000}
    assert cert.totals.projected_net == 330


def test_w04_conflicting_model_or_high_risk_weights_refused():
    for model in [
        weights("7/10", "3/10"),
        weights("1/2", "1/3"),
        {**weights("1/2", "2/5"), "R3": Fraction(1, 10)},
    ]:
        result = run(state=policy(make_wealth_state(), weights=model))
        assert result.certificate is None and "ALLOC-POLICY" in result.errors


def test_w04_capacity_failure_does_not_claim_infeasibility():
    state = products(
        make_wealth_state(), {"P_A": {"max_amount": Fraction(4000)}}, only={"P_A", "P_C"}
    )
    result = run(state=state)
    assert result.certificate is None and "ALLOC-SELECT" in result.errors
    assert result.failure.residual_cents == 100000


def test_w04_greedy_failure_retains_real_feasible_witness():
    state = make_wealth_state()
    state = policy(state, weights=weights(1, 0), bands={"R1": (1, 1), "R2": (0, 0)})
    template = state.catalog.products[0]
    candidates = [
        template.model_copy(
            update={
                "product_id": name,
                "min_amount": Fraction(minimum),
                "max_amount": Fraction(maximum),
                "expected_annual_rate": Fraction(rate, 100),
            }
        )
        for name, minimum, maximum, rate in [
            ("P_A", 40, 40, 3),
            ("P_B", 30, 35, 2),
            ("P_C", 30, 50, 1),
        ]
    ]
    state = state.model_copy(
        update={
            "catalog": signed(
                state.catalog.model_copy(update={"products": candidates}), CATALOG, "bank"
            )
        }
    )
    result = run(allocation_request(amount="100/1"), state)
    assert result.certificate is None and "ALLOC-SELECT" in result.errors
    assert result.failure.residual_cents == 2500
    assert [
        (step.product_id, step.allocated_cents, step.skipped_reason)
        for step in result.failure.trace
    ] == [("P_A", 4000, None), ("P_B", 3500, None), ("P_C", 0, "minimum_amount")]
    feasible_witness = {"P_A": 40, "P_B": 30, "P_C": 30}
    assert sum(feasible_witness.values()) == 100
    assert all(p.min_amount <= feasible_witness[p.id] <= min(p.max_amount, 50) for p in candidates)


@pytest.mark.parametrize(
    "required,expected,net",
    [
        (5000, {"P_A": 5000, "P_D": 5000}, 300),
        (10000, {"P_B": 5000, "P_D": 5000}, 250),
    ],
)
def test_w05_liquidity_first_occupies_sleeve_budget(required, expected, net):
    cert = run(allocation_request(liquidity_amount=f"{required}/1")).certificate
    assert vector(cert) == expected
    assert cert.totals.liquid_net_principal >= required
    assert cert.totals.projected_net == net


def test_w05_liquidity_uses_net_principal_and_holding_plus_delay():
    state = products(
        make_wealth_state(),
        {
            "P_D": {
                "expected_annual_rate": Fraction(1, 25),
                "redemption_fee_rate": Fraction(1, 100),
            }
        },
    )
    cert = run(allocation_request(liquidity_amount="5000/1"), state).certificate
    assert vector(cert) == {"P_B": 5000, "P_D": 5000}
    assert cert.totals.liquid_net_principal == 9950
    assert cert.totals.projected_net == 250
    result = run(allocation_request(liquidity_amount="10000/1"), state)
    assert result.certificate is None and "ALLOC-LIQ" in result.errors


def test_w06_same_sleeve_fill_at_concentration_boundary():
    state = policy(
        make_wealth_state(),
        weights=weights("3/5", "2/5"),
        bands={"R1": (Fraction(1, 2), Fraction(7, 10)), "R2": (Fraction(3, 10), Fraction(1, 2))},
    )
    assert vector(run(state=state).certificate) == {"P_A": 5000, "P_B": 1000, "P_C": 4000}
    result = run(state=products(state, only={"P_A", "P_C", "P_D"}))
    assert result.certificate is None and "ALLOC-SELECT" in result.errors


def explicit_case(*, model=None, changes=None):
    ref, state = case()
    default = build_allocation("C_DEMO", INTENT, ref, state)
    request = allocation_request(
        selection_mode="explicit_weights",
        target_weights=weights("3/5", "2/5"),
        model_biac_hash=model or H(default),
        reason_code="user_adjustment",
    )
    if changes:
        request = request.model_copy(update=changes)
    new_ref, state = case(request, state, step=2, supersedes=ref)
    return new_ref, state, default


def test_w07_signed_explicit_weights_reconstruct_superseded_default():
    ref, state, default = explicit_case()
    cert = build_allocation("C_DEMO", INTENT, ref, state)
    assert cert.base_context_hash == default.base_context_hash
    assert cert.request_hash != default.request_hash
    assert cert.model_biac_hash == H(default)
    assert vector(cert) == {"P_A": 5000, "P_B": 1000, "P_C": 4000}
    assert cert.deviations.projected_net_delta == -20
    assert cert.deviations.sleeves[0].weight_delta == Fraction(1, 10)


def test_w07_signed_items_can_choose_eligible_runner_up():
    ref, state, _ = explicit_case(
        changes={
            "selection_mode": "explicit_items",
            "target_weights": None,
            "items": [
                AllocationRequestItem(product_id="P_B", principal=Fraction(5000)),
                AllocationRequestItem(product_id="P_C", principal=Fraction(5000)),
            ],
        }
    )
    cert = build_allocation("C_DEMO", INTENT, ref, state)
    assert vector(cert) == {"P_B": 5000, "P_C": 5000}
    assert cert.deviations.projected_net_delta == -50


@pytest.mark.parametrize("fault", ["signature", "scope", "model", "context"])
def test_w07_explicit_requires_signature_scope_current_model_context(fault):
    ref, state, _ = explicit_case(
        model="0" * 64 if fault == "model" else None,
        changes={"horizon_days": 364} if fault == "context" else None,
    )
    if fault in {"signature", "scope"}:
        value = state.user_inputs[ref].model_copy(
            update={"sig": "0" * 128} if fault == "signature" else {"scope_id": "OTHER"}
        )
        if fault == "scope":
            value = signed(value, INPUT)
        state = state.model_copy(update={"user_inputs": {**state.user_inputs, ref: value}})
    result = evaluate_allocation("C_DEMO", INTENT, ref, state)
    assert result.certificate is None
    assert "BIC-PREFERENCE" in result.errors or "ALLOC-SELECT" in result.errors


def test_w08_signed_out_of_band_and_unsuitable_items_are_rejected():
    ref, state, _ = explicit_case(changes={"target_weights": weights("7/10", "3/10")})
    assert "ALLOC-BAND" in evaluate_allocation("C_DEMO", INTENT, ref, state).errors
    ref, state, _ = explicit_case(
        changes={
            "selection_mode": "explicit_items",
            "target_weights": None,
            "items": [
                AllocationRequestItem(product_id="P_A", principal=Fraction(5000)),
                AllocationRequestItem(product_id="P_X", principal=Fraction(5000)),
            ],
        }
    )
    assert "BIC-RISK" in evaluate_allocation("C_DEMO", INTENT, ref, state).errors


def test_w09_marketing_and_catalog_order_invariance_and_economic_sensitivity():
    ref, state = case()
    original = build_allocation("C_DEMO", INTENT, ref, state)
    MarketingMetadata(product_id="P_X", sponsored=True, campaign_text_handle="INJECTION")
    assert H(build_allocation("C_DEMO", INTENT, ref, state)) == H(original)
    reordered = build_allocation("C_DEMO", INTENT, ref, products(state, reverse=True))
    assert vector(reordered) == vector(original)
    assert reordered.sleeves == original.sleeves
    assert reordered.catalog_hash != original.catalog_hash
    changed = build_allocation(
        "C_DEMO", INTENT, ref, products(state, {"P_B": {"expected_annual_rate": Fraction(1, 10)}})
    )
    assert vector(changed) != vector(original)


def test_w10_pure_verifier_detects_candidates_ranking_and_wrong_default():
    ref, state = case()
    evaluation = evaluate_allocation("C_DEMO", INTENT, ref, state)
    cert = evaluation.certificate
    assert verify_allocation(cert, evaluation, state) == []
    assert "BIC-COMPLETE" in verify_allocation(
        cert.model_copy(update={"candidate_ids": ["P_B"]}), evaluation, state
    )
    sleeve = cert.sleeves[0]
    rows = [sleeve.ranking_rows[0].model_copy(update={"gap": Fraction(1)}), sleeve.ranking_rows[1]]
    altered = cert.model_copy(
        update={"sleeves": [sleeve.model_copy(update={"ranking_rows": rows}), *cert.sleeves[1:]]}
    )
    assert "BIC-SCORE" in verify_allocation(altered, evaluation, state)


def test_w04_cent_remainders_obey_bands_and_concentration_without_tolerance():
    state = products(
        make_wealth_state(),
        {name: {"min_amount": Fraction(1, 100)} for name in ("P_A", "P_B", "P_C", "P_D")},
    )
    cert = run(allocation_request(amount="5/100"), state).certificate
    assert vector(cert) == {
        "P_A": Fraction(2, 100),
        "P_B": Fraction(1, 100),
        "P_C": Fraction(2, 100),
    }
    result = run(allocation_request(amount="3/100"), state)
    assert result.certificate is None and result.errors == ("ALLOC-SELECT",)
    assert result.failure.reason_codes == ["target_rounding_conflict"]


def test_w03_fee_rounding_is_per_product_and_per_charge_and_budget_is_exact():
    state = products(
        make_wealth_state(),
        {
            name: {
                "min_amount": Fraction(1, 100),
                "min_hold_days": 0,
                "purchase_fee_rate": Fraction(1, 300),
                "annual_fee_rate": Fraction(1, 300),
                "redemption_fee_rate": Fraction(1, 300),
            }
            for name in ("P_A", "P_C")
        },
        only={"P_A", "P_C"},
    )
    account = state.accounts["A_CURRENT"].model_copy(update={"opening_balance": Fraction(6, 100)})
    state = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
    request = allocation_request(amount="4/100", liquidity_amount="2/100")
    result = run(request, state)
    assert result.errors == ()
    cert = result.certificate
    assert cert.totals.total_debit == Fraction(6, 100)
    assert cert.totals.projected_fees == Fraction(6, 100)
    assert cert.totals.liquid_net_principal == Fraction(2, 100)
    assert all(
        (row.fee_buy, row.fee_hold, row.fee_sell) == (Fraction(1, 100),) * 3
        for row in cert.allocation
    )
    account = account.model_copy(update={"opening_balance": Fraction(5, 100)})
    state = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
    result = run(request, state)
    assert result.certificate is None and "ALLOC-SELECT" in result.errors
    assert len(result.failure.trace) <= 2 * len(state.catalog.products)


@pytest.mark.parametrize("field", ["purchase_fee_rate", "expected_annual_rate", "min_amount"])
def test_unbounded_catalogue_numbers_are_controlled_refusals(field):
    state = products(make_wealth_state(), {"P_A": {field: Fraction(2**128)}})
    assert run(state=state).errors == ("BIC-CATALOG",)


def test_bounded_inputs_whose_projection_exceeds_output_limit_fail_controlled():
    state = products(make_wealth_state(), {"P_A": {"expected_annual_rate": Fraction(2**126)}})
    result = run(state=state)
    assert result.certificate is None and result.errors == ("ALLOC-SUM",)


def test_unbounded_available_budget_is_a_controlled_refusal():
    state = make_wealth_state()
    account = state.accounts["A_CURRENT"].model_copy(update={"opening_balance": Fraction(2**128)})
    state = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
    assert run(state=state).errors == ("BAL-AVAILABLE",)


def test_w10_omitted_ranking_member_and_out_of_band_target_have_precise_rules():
    ref, state = case()
    evaluation = evaluate_allocation("C_DEMO", INTENT, ref, state)
    cert = evaluation.certificate
    r1 = cert.sleeves[0]
    altered = cert.model_copy(
        update={
            "sleeves": [
                r1.model_copy(update={"ranking_rows": r1.ranking_rows[1:]}),
                *cert.sleeves[1:],
            ]
        }
    )
    assert "BIC-COMPLETE" in verify_allocation(altered, evaluation, state)
    altered = cert.model_copy(
        update={"sleeves": [r1.model_copy(update={"target_cents": 700000}), *cert.sleeves[1:]]}
    )
    assert "ALLOC-BAND" in verify_allocation(altered, evaluation, state)
