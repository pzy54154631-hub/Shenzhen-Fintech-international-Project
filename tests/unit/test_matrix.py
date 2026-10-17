"""Every matrix cell keeps an honest denominator and isolated baseline state."""

from corridor.bench.adversary import development_cases
from corridor.bench.matrix import run_baseline_case, summarize_cell


def test_baseline_wrong_recipient_has_actual_bank_harm_and_visible_user_rejection():
    spec = development_cases()[0]
    permissive = run_baseline_case(spec, "d3", "all_approve")
    careful = run_baseline_case(spec, "d3", "careful")
    assert permissive["bank_dispatches"] == 1
    assert permissive["prohibited_effects"] > 0
    assert careful["bank_dispatches"] == 0
    assert careful["prohibited_effects"] == 0


def test_unimplemented_baseline_analysis_retains_case_not_run():
    spec = next(item for item in development_cases() if item.attack == "sandbox_import")
    row = run_baseline_case(spec, "d0", "all_approve")
    assert row["status"] == "not_run"
    assert row["case_id"] == spec.case_id
    cell = summarize_cell("d0", "all_approve", [row], [row])
    assert cell["attacks"]["denominator"] == 0
    assert cell["not_run"] == 1
    assert cell["real_model_status"] == "not_recorded"
