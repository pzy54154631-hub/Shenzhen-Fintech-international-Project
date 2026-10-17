"""B8 judge tasks exercise persistent authorization and real plan execution."""

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.planning_runner import run_planning
from corridor.schemas.base import loads_exact


@pytest.mark.parametrize("task", ["J06", "J19", "J20"])
def test_planning_judge_real_execution_and_evidence(task, tmp_path):
    result = run_planning(task, client=LLMClient(mode="scripted"), evidence_dir=tmp_path)
    assert result["passed"], result
    assert result["checks"] and all(result["checks"].values())
    assert result["real_model_evaluation"] == "not_run"
    manifest = loads_exact((tmp_path / "manifest.json").read_bytes())
    assert manifest["passed"]
    assert manifest["sources"] and set(manifest["sources"]) == {"scripted"}
    assert list(tmp_path.glob("*/audit.jsonl"))


@pytest.mark.parametrize("task", ["J06", "J19", "J20"])
def test_planning_strict_has_no_scripted_substitution(task, tmp_path):
    with pytest.raises(RuntimeError, match=f"task_id={task}"):
        run_planning(task, client=LLMClient(mode="strict", replay_dir=tmp_path))
