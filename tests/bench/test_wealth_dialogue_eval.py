"""Task-specific wealth dialogue evidence never replaces scripted mutation probes."""

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.wealth_dialogue_eval import run_dialogue_task


@pytest.mark.parametrize("task_id", [f"W{i:02}" for i in range(1, 13)])
def test_every_wealth_task_has_checked_dialogue_workflows(task_id):
    client = LLMClient(mode="scripted", api="responses", env_file=None)
    result = run_dialogue_task(task_id, client)
    assert result["passed"], result
    assert result["status"] == "complete_task_workflows"
    assert result["workflow_total"] > 0
    assert result["workflow_passed"] == result["workflow_total"]
    assert result["covered_subcases"] == []
    assert result["mechanism_mutation_scope"] == "scripted_separately"
    assert client.calls
    assert all(row["assertions"] for row in result["workflows"])
    assert all(row["source"] == "scripted" for row in result["workflows"])
    labels = [item["assertion"] for row in result["workflows"] for item in row["assertions"]]
    assert "no_allocation_constructed" not in labels
    assert "remaining_work_stopped" not in labels
    if task_id in {"W04", "W05", "W06", "W08"}:
        assert "honest_constructor_language" in labels
    for row in result["workflows"]:
        for assertion in row["assertions"]:
            if assertion["assertion"] == "partial_state_disclosed":
                assert assertion["expected"] is True and assertion["observed"] is True


def test_malformed_model_response_cannot_count_as_workflow_success(monkeypatch):
    from corridor.agent.llm import LLMResult

    client = LLMClient(mode="scripted", api="responses", env_file=None)
    monkeypatch.setattr(client, "complete", lambda **_: LLMResult({}, "scripted", "invalid"))
    result = run_dialogue_task("W04", client)
    assert not result["passed"]
    assert result["status"] == "failed_task_workflows"


def test_recorded_execution_workflows_reproduce_with_network_disabled(tmp_path, monkeypatch):
    from corridor.bench.recording import network_disabled, observation_hash, replay_client

    client = LLMClient(
        mode="record",
        model="gpt-6.1-sol",
        api="responses",
        api_key="synthetic-placeholder",
        env_file=None,
        max_calls=100,
        max_usd="10",
        replay_dir=tmp_path / "replay",
    )

    def fake_live(prompt, state, trace):
        trace.update(
            cost_usd="0/1", input_tokens=10, output_tokens=10, reasoning_tokens=0, total_tokens=20
        )
        client.api_calls += 1
        return {
            "tool": state["required_tool"],
            "arguments": {"refs": state["permitted_refs"], "note": ""},
        }

    monkeypatch.setattr(client, "_live", fake_live)
    recorded = run_dialogue_task("W11", client, tmp_path / "live")
    assert recorded["passed"], recorded
    with network_disabled():
        repeated = run_dialogue_task("W11", replay_client(client), tmp_path / "strict")
    assert repeated["passed"], repeated
    assert observation_hash(recorded) == observation_hash(repeated)
    assert all(row["source"] == "live-recorded" for row in recorded["workflows"])
    assert all(row["source"] == "strict-replay" for row in repeated["workflows"])


def test_m2_m4_recording_uses_persistent_shared_budget_and_replays(tmp_path, monkeypatch):
    from corridor.bench import recording
    from corridor.cli.record import _record_dialogue_validation
    from corridor.schemas.base import loads_exact

    original = recording.LaneRecordingClient
    monkeypatch.setattr(
        recording,
        "LaneRecordingClient",
        lambda **options: original(**options, api_key="synthetic-placeholder", env_file=None),
    )

    def fake_live(self, prompt, state, trace):
        trace.update(
            cost_usd="0/1", input_tokens=10, output_tokens=10, reasoning_tokens=0, total_tokens=20
        )
        self.api_calls += 1
        if "required_tool" in state:
            return {
                "tool": state["required_tool"],
                "arguments": {"refs": state["permitted_refs"], "note": ""},
            }
        return {"note": "Returns are a performance benchmark (not guaranteed)."}

    monkeypatch.setattr(LLMClient, "_live", fake_live)
    output = tmp_path / "evidence"
    journal = tmp_path / "shared-budget.json"
    _record_dialogue_validation(
        "gpt-6.1-sol", "main", 60, "10", tmp_path / "replay", output, journal, True
    )
    result = loads_exact((output / "dialogue-recording.json").read_bytes())
    assert result["passed"] and result["strict_replay"] == "PASS"
    assert result["M2_passed"] == result["M2_total"] == 26
    assert result["M4_passed"] == result["M4_total"] == 10
    budget = loads_exact(journal.read_bytes())
    assert budget["attempts"] == budget["groups"]["dialogue"] == result["api_calls"] == 55


def test_missing_purchase_receipts_cannot_pass_execution_workflows(monkeypatch):
    from unittest.mock import patch

    from corridor.bench.wealth_dialogue_eval import Workflow
    from corridor.schemas.bank import BankReceipt

    finish = Workflow.finish

    def erased_receipts(self, *args, **kwargs):
        current = self.state
        erased = current.model_copy(
            update={
                "receipts": {
                    key: receipt
                    for key, receipt in current.receipts.items()
                    if not isinstance(receipt, BankReceipt) or receipt.kind != "purchase_product"
                }
            }
        )
        with patch.object(self.gateway.store, "snapshot", return_value=erased):
            return finish(self, *args, **kwargs)

    monkeypatch.setattr(Workflow, "finish", erased_receipts)
    result = run_dialogue_task("W11", LLMClient(mode="scripted", api="responses", env_file=None))
    assert not result["passed"]
    assert len(result["workflows"]) == 5
    assert all(not row["passed"] for row in result["workflows"])
    assert all(row["settled_purchases"] == 0 for row in result["workflows"])


def test_completed_workflows_require_independent_execution_completion(monkeypatch):
    from dataclasses import replace

    from corridor.bench import wealth_dialogue_eval

    verify = wealth_dialogue_eval.verify_execution

    def incomplete(*args, **kwargs):
        return replace(verify(*args, **kwargs), completed=False)

    monkeypatch.setattr(wealth_dialogue_eval, "verify_execution", incomplete)
    result = run_dialogue_task("W11", LLMClient(mode="scripted", api="responses", env_file=None))
    assert not result["passed"]
    rows = {row["id"]: row for row in result["workflows"]}
    assert rows["complete"]["passed"] is False
    assert rows["unknown"]["passed"] is False
    assert all(rows[name]["passed"] for name in ("stop", "handoff", "failed"))
