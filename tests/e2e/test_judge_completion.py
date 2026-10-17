"""Every B10 missing judge task requires all named, machine-readable checks."""

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.judge_runner import run_completion
from corridor.schemas.base import loads_exact


@pytest.mark.parametrize(
    "task,minimum", [("J02", 5), ("J03", 8), ("J04", 7), ("J05", 12), ("J09", 6)]
)
def test_remaining_judges_check_all_subcases_and_export_evidence(tmp_path, task, minimum):
    result = run_completion(task, client=LLMClient(mode="scripted"), evidence_dir=tmp_path)
    assert result["passed"], result["checks"]
    assert len(result["checks"]) >= minimum
    assert all(value is True for value in result["checks"].values())
    assert result["real_model_evaluation"] == "not_run"
    assert result["llm_calls"]
    if task == "J05":
        assert result["checks"]["late_schedule:due_waits_for_mfa"]
        assert result["checks"]["late_schedule:old_scope_invalid_next_day"]
        assert result["checks"]["late_schedule:late_schedule_counted_today_once"]
    manifest = loads_exact((tmp_path / "manifest.json").read_bytes())
    assert manifest["planner_mode"] == "scripted"
    assert manifest["expected_hash"]
    for name in result["subcases"]:
        root = tmp_path / name
        for filename in (
            "transcript.md",
            "plan.json",
            "verdict.json",
            "audit.jsonl",
            "decisions.json",
            "mockbank_final.json",
            "oracle.json",
            "manifest.json",
        ):
            assert (root / filename).is_file(), (name, filename)


def test_unknown_judge_never_passes():
    with pytest.raises(ValueError, match="Unsupported"):
        run_completion("J99", client=LLMClient(mode="scripted"))
