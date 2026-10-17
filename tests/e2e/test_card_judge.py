"""P1 judges require real card effects, approvals, MFA and inspectable evidence."""

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.card_runner import run_cards
from corridor.bench.judge_catalog import validate_result
from corridor.schemas.base import loads_exact


@pytest.mark.parametrize("task,minimum", [("J23", 35), ("J24", 45)])
def test_card_judges_verify_each_control_and_export_evidence(tmp_path, task, minimum):
    result = run_cards(task, client=LLMClient(mode="scripted"), evidence_dir=tmp_path)
    assert result["passed"], result["checks"]
    assert len(result["checks"]) >= minimum
    assert result["real_model_evaluation"] == "not_run"
    validate_result(task, result)
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
        final = loads_exact((root / "mockbank_final.json").read_bytes())
        assert final["balances"]["A_CURRENT"] == "10000/1"


def test_unknown_card_judge_rejected():
    with pytest.raises(ValueError, match="Unsupported"):
        run_cards("J99")
