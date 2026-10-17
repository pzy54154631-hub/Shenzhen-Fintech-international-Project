"""B9 judge checks real restricted execution and preserves bank authority."""

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.sandbox_runner import prepare_sandbox, run_sandbox, sandbox_case
from corridor.schemas.base import loads_exact


def test_sandbox_judge_real_execution_and_evidence(tmp_path):
    result = run_sandbox(client=LLMClient(mode="scripted"), evidence_dir=tmp_path)
    assert result["passed"], result
    assert result["financial_writes"] == 0
    assert result["real_model_evaluation"] == "not_run"
    for check in (
        "weekday_weekend_exact",
        "category_totals_exact",
        "rational_average_exact",
        "empty_exact",
        "row_boundary_exact",
        "timeout_reclaimed_and_query_alive",
        "exploratory_amount_rejected",
    ):
        assert result["checks"][check], check
    manifest = loads_exact((tmp_path / "manifest.json").read_bytes())
    assert manifest["passed"]
    assert set(manifest["sources"]) == {"scripted"}
    assert list(tmp_path.glob("*/audit.jsonl"))


def test_sandbox_strict_has_no_scripted_substitution(tmp_path):
    with pytest.raises(RuntimeError, match="task_id=J08"):
        run_sandbox(client=LLMClient(mode="strict", replay_dir=tmp_path))


@pytest.mark.parametrize(
    ("program", "expected"),
    [
        ("result = {'answer': count(filter_rows(dataset, 'category', '==', 'dining'))}", "6/1"),
        (
            "result = {'answer': sum_money(filter_rows(dataset, 'category', '==', 'shopping'))}",
            "99/1",
        ),
    ],
)
def test_program_changes_are_really_interpreted(program, expected):
    case = sandbox_case("custom")
    prepared = prepare_sandbox(case, program)
    result = case.dispatch(prepared)
    assert result.status == "settled", result
    assert result.analysis_receipt.results["answer"].value == expected
    assert result.analysis_receipt.trust == "exploratory"
    assert case.gateway.bank.execute_count == 0


def test_sandbox_judge_rejects_unknown_task():
    with pytest.raises(ValueError, match="not_implemented"):
        run_sandbox("J99")
