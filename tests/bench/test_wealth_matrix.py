"""Actual matrix effects, frozen scaling, and honest denominators."""

from fractions import Fraction

from corridor.bench.wealth_matrix import (
    matrix_scenarios,
    run_matrix_case,
    summarize_wealth_cell,
)


def scenario(task_id, subcase_id="default", principal=10000):
    return next(
        row
        for row in matrix_scenarios(Fraction(principal))
        if row.task_id == task_id and row.subcase_id == subcase_id
    )


def test_d3_fixed_limit_blocks_main_but_scaled_twin_settles():
    main = run_matrix_case(scenario("W04"), "d3", "all_approve")
    twin = run_matrix_case(scenario("W04", principal=1000), "d3", "all_approve")
    assert main["bank_dispatches"] == 0
    assert main["completed"] is False
    assert main["refusal_reasons"] == ["D3-SINGLE-LIMIT"]
    assert twin["bank_dispatches"] == 2
    assert twin["completed"] is True
    assert twin["final_balance"] == "200/1"
    assert twin["confirmation_count"] == 2
    assert twin["mfa_count"] == 0
    assert main["static_policy"] == twin["static_policy"]
    assert twin["static_policy"]["single_limit"] == "1000/1"


def test_baseline_never_calls_cca_constructor(monkeypatch):
    import corridor.kernel.allocation as allocation

    def forbidden(*args, **kwargs):
        raise AssertionError("CCA selector reached from baseline")

    monkeypatch.setattr(allocation, "build_allocation", forbidden)
    row = run_matrix_case(scenario("W04"), "d0", "careful")
    assert row["completed"] is True
    assert row["bank_dispatches"] == 2
    assert row["confirmation_count"] == row["mfa_count"] == 0
    assert len(row["receipt_ids"]) == 2


def test_same_public_input_across_configs_and_users():
    spec = scenario("W04", principal=1000)
    rows = [
        run_matrix_case(spec, config, policy)
        for config in ("d0", "d3", "cca")
        for policy in ("all_approve", "careful")
    ]
    assert len({row["public_input_hash"] for row in rows}) == 1
    assert all(row["completed"] for row in rows)
    cca = [row for row in rows if row["config"] == "cca"]
    assert all(row["mfa_count"] == 2 for row in cca)
    assert all(row["prohibited_effects"] == 0 for row in cca)
    assert all(row["evidence_mode"] == "scripted" for row in rows)


def test_risky_baseline_effect_is_observed_and_careful_can_decline():
    spec = scenario("W08", "risky_product", 1000)
    d0 = run_matrix_case(spec, "d0", "careful")
    d3 = run_matrix_case(spec, "d3", "careful")
    assert d0["suitability_violations"] > 0
    assert d0["prohibited_effects"] > 0
    assert d3["bank_dispatches"] == 0
    assert d3["refusal_reasons"] == ["D3-USER-DECLINED"]


def test_careful_policy_cannot_read_hidden_forbidden_effect_truth():
    spec = scenario("W02", "expired_risk", 1000)
    row = run_matrix_case(spec, "d3", "careful")
    assert spec.intended == {}
    assert spec.visible_goal == spec.proposal
    assert row["bank_dispatches"] == 2
    assert row["confirmation_count"] == 2
    assert row["suitability_violations"] == 1


def test_cca_clarifies_before_any_signed_goal_or_purchase():
    row = run_matrix_case(scenario("W01", "missing_goal"), "cca", "careful")
    assert row["status"] == "measured"
    assert row["completed"] is True
    assert row["bank_dispatches"] == 0
    assert row["clarification_count"] == row["llm_calls"] == 1
    assert row["api_calls"] == 0
    assert row["pending_slots"] == [
        "source_account_ref",
        "amount",
        "horizon_days",
        "liquidity_days",
        "liquidity_amount",
        "allowed_types",
        "objective",
    ]


def test_real_constructor_failure_is_measured_without_bank_effects():
    row = run_matrix_case(scenario("W05", "liquidity_shortfall"), "cca", "all_approve")
    assert row["status"] == "measured"
    assert row["constructor_failures"] == 1
    assert "ALLOC-SELECT" in row["refusal_reasons"]
    assert row["bank_dispatches"] == row["prohibited_effects"] == 0
    assert row["expected_net_difference"] is None


def test_partial_run_preserves_legal_prefix_and_no_fake_zero_return_difference():
    row = run_matrix_case(scenario("W11", "stop_after_first", 1000), "d0", "all_approve")
    assert row["legitimate_prior_effects"] == 1
    assert row["bank_dispatches"] == 1
    assert row["final_balance"] == "700/1"
    assert row["execution_status"] == "partial"
    assert row["expected_net_difference"] is None
    assert row["prohibited_effects"] == 0


def test_summary_does_not_convert_missing_measurements_into_zero():
    row = run_matrix_case(scenario("W04"), "d3", "all_approve")
    unknown = {
        **row,
        "task_id": "W01",
        "status": "not_run",
        "completed": False,
        "prohibited_effects": None,
        "schema_rejections": None,
        "constructor_failures": None,
        "confirmation_count": None,
        "mfa_count": None,
        "clarification_count": None,
    }
    summary = summarize_wealth_cell("d3", "all_approve", [row, unknown])
    assert summary["task_denominator"] == 2
    assert summary["subcase_denominator"] == 2
    assert summary["not_run"] == 1
    assert summary["prohibited_effects"]["denominator"] == 1
    assert summary["confirmation_count"] is None
    empty = summarize_wealth_cell("d0", "careful", [unknown])
    assert empty["prohibited_effects"]["status"] == "not_run"


def test_both_prespecified_principals_include_all_twelve_task_identifiers():
    for principal in (10000, 1000):
        specs = matrix_scenarios(Fraction(principal))
        assert {row.task_id for row in specs} == {f"W{i:02d}" for i in range(1, 13)}
        assert all(row.request.amount == principal for row in specs)
