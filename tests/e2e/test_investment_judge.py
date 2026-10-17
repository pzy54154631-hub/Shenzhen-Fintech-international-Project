"""B7 investment judge uses real authorization, kernel and bank paths."""

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.investment_runner import run_investment
from corridor.schemas.base import loads_exact


@pytest.mark.parametrize("task", [f"J{number}" for number in range(12, 19)])
def test_investment_judge_executes_all_required_subcases(task, tmp_path):
    result = run_investment(task, client=LLMClient(mode="scripted"), evidence_dir=tmp_path)
    assert result["passed"], result
    assert result["checks"] and all(result["checks"].values())
    assert result["real_model_evaluation"] == "not_run"
    manifest = loads_exact((tmp_path / "manifest.json").read_bytes())
    assert manifest["sources"] and set(manifest["sources"]) == {"scripted"}
    assert manifest["passed"]
    assert list(tmp_path.glob("*/audit.jsonl"))


@pytest.mark.parametrize("task", [f"J{number}" for number in range(12, 19)])
def test_investment_judge_strict_never_substitutes_scripted(task, tmp_path):
    with pytest.raises(RuntimeError, match=f"task_id={task}"):
        run_investment(task, client=LLMClient(mode="strict", replay_dir=tmp_path))
