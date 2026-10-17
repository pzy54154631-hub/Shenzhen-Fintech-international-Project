"""The record command requires explicit live credentials and budgets."""

import pytest
from typer.testing import CliRunner

from corridor.agent.llm import LLMClient, LLMConfigurationError
from corridor.cli import app
from corridor.cli.record import _replay_instructions, record_requests
from corridor.crypto.jcs import jcs_bytes
from tests.unit.test_llm import _sdk


@pytest.mark.parametrize("stage", ["main", "contrast", "standalone"])
def test_replay_instructions_preserve_weak_model_profile_and_valid_source_paths(tmp_path, stage):
    profile = {
        "model": "gpt-5.4-mini",
        "api": "responses",
        "reasoning_effort": "low",
        "max_output_tokens": 512,
    }
    source = tmp_path / "final release"
    output = source / stage / profile["model"] if stage != "standalone" else source
    instructions = _replay_instructions(output, profile)
    assert '"api":"responses"' in instructions
    assert '"max_output_tokens":512' in instructions
    assert "corridor judge" not in instructions
    if stage == "standalone":
        assert "do not pass this standalone folder" in instructions
        assert "--source" not in instructions
    else:
        assert f'--source "{source.as_posix()}"' in instructions
        assert f'--output "{source.as_posix()}-offline-replay"' in instructions
        assert f"--stages {stage}" in instructions
        if stage == "contrast":
            assert "all three declared model tiers" in instructions


def test_record_without_credentials_refuses_instead_of_creating_fake_replay(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for key in ("LLM_API_KEY", "LLM_MODEL", "LLM_MAX_CALLS", "LLM_MAX_USD"):
        monkeypatch.delenv(key, raising=False)
    result = CliRunner().invoke(app, ["record", "--tasks", "J01"])
    assert result.exit_code != 0
    assert "credential" in result.output.lower() or "key" in result.output.lower()
    assert not list(tmp_path.rglob("*.json"))


def test_record_without_budget_refuses_before_importing_runner(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLM_API_KEY", "test-credential")
    monkeypatch.setenv("LLM_MODEL", "openai/fixed-model-v1")
    monkeypatch.delenv("LLM_MAX_CALLS", raising=False)
    monkeypatch.delenv("LLM_MAX_USD", raising=False)
    result = CliRunner().invoke(app, ["record", "--tasks", "J01"])
    assert result.exit_code != 0
    assert "budget" in result.output.lower()


def test_record_unknown_task_never_claims_supported_judge_suite(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLM_API_KEY", "test-credential")
    monkeypatch.setenv("LLM_MODEL", "openai/fixed-model-v1")
    monkeypatch.setenv("LLM_MAX_CALLS", "1")
    monkeypatch.setenv("LLM_MAX_USD", "1")
    result = CliRunner().invoke(app, ["record", "--tasks", "J22"])
    assert result.exit_code != 0
    assert "not_implemented" in result.output


def test_generic_record_interface_requires_actual_api_response(monkeypatch, tmp_path):
    _, calls = _sdk(monkeypatch)
    requests = [{"task_id": "J01", "step": "planner", "prompt": {"handles": []}, "tool_state": {}}]
    with pytest.raises(LLMConfigurationError):
        record_requests(LLMClient(mode="scripted", replay_dir=tmp_path), requests)
    client = LLMClient(
        mode="record",
        replay_dir=tmp_path,
        model="openai/fixed-model-v1",
        api_key="test-credential",
        max_calls=1,
        max_usd="1",
        env_file=None,
    )
    results = record_requests(client, requests)
    assert results[0]["source"] == "live-recorded"
    assert len(calls) == 1


def test_requests_cli_records_only_explicit_live_response(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _sdk(monkeypatch)
    monkeypatch.setenv("LLM_API_KEY", "test-credential")
    monkeypatch.setenv("LLM_MODEL", "openai/fixed-model-v1")
    request_path = tmp_path / "requests.jsonl"
    request_path.write_bytes(
        jcs_bytes({
            "task_id": "J01",
            "step": "planner",
            "prompt": {"handles": []},
            "tool_state": {},
        })
        + b"\n"
    )
    result = CliRunner().invoke(
        app,
        [
            "record",
            "--requests",
            str(request_path),
            "--max-calls",
            "1",
            "--max-usd",
            "1",
            "--replay-dir",
            str(tmp_path / "replay"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "live-recorded" in result.output
    assert "test-credential" not in result.output
    assert len(list((tmp_path / "replay").rglob("*.json"))) == 1


def test_recorded_response_does_not_turn_failed_j01_into_a_pass(monkeypatch, tmp_path):
    from corridor.bench import transfer_runner

    monkeypatch.chdir(tmp_path)
    _sdk(monkeypatch)
    monkeypatch.setenv("LLM_API_KEY", "test-credential")
    monkeypatch.setenv("LLM_MODEL", "openai/fixed-model-v1")

    def failed_runner(client):
        client.complete(
            task_id="J01", step="planner", prompt={}, tool_state={}, scripted=lambda: {}
        )
        return {"passed": False}

    monkeypatch.setattr(transfer_runner, "run_j01", failed_runner)
    result = CliRunner().invoke(
        app, ["record", "--tasks", "J01", "--max-calls", "1", "--max-usd", "1"]
    )
    assert result.exit_code != 0
    assert "development scope" in result.output.lower()
    assert "J01 did not pass" in result.output
