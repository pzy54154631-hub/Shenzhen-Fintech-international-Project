"""M2 evidence runner uses synthetic tasks and honest mode-specific outcomes."""

import builtins
import os
from fractions import Fraction

import httpx
import pytest

from corridor.agent.llm import LLMClient, ReplayMiss
from corridor.agent.wealth_validation import CASES, main, run_validation
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("LLM_"):
            monkeypatch.delenv(name)


def _client(tmp_path, mode="scripted", **changes):
    options = {
        "mode": mode,
        "model": "gpt-6.1-sol",
        "api": "responses",
        "reasoning_effort": "low",
        "max_output_tokens": 1024,
        "replay_dir": tmp_path / "replay",
        "env_file": None,
    }
    if mode == "record":
        options.update(api_key="synthetic-validation-credential", max_calls=60, max_usd="20")
    return LLMClient(**{**options, **changes})


def _local_provider(monkeypatch):
    sends = []

    def send(self, request):
        body = loads_exact(request.content)
        state = loads_exact(body["input"][1]["content"])["tool_state"]
        sends.append(body)
        response = {
            "id": "resp_synthetic",
            "object": "response",
            "created_at": 1,
            "model": body["model"],
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_synthetic",
                    "name": state["required_tool"],
                    "arguments": jcs_bytes({"refs": state["permitted_refs"], "note": ""}).decode(
                        "utf-8"
                    ),
                    "status": "completed",
                }
            ],
            "usage": {
                "input_tokens": 30,
                "output_tokens": 8,
                "total_tokens": 38,
                "output_tokens_details": {"reasoning_tokens": 2},
            },
        }
        return httpx.Response(200, json=response)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", send)
    return sends


def test_fixed_dataset_contains_forty_utterances_and_required_categories():
    assert sum(len(case.turns) for case in CASES) == 40
    assert len({case.task_id for case in CASES}) == len(CASES)
    assert {
        "one-shot",
        "piecemeal",
        "vague",
        "typo",
        "mixed-language",
        "off-topic",
        "correction",
        "what-if",
        "new-intent",
        "partial-interruption",
    } <= {case.category for case in CASES}


def test_scripted_dataset_and_w04_w07_smokes_report_exact_metrics(tmp_path):
    client = _client(tmp_path)
    summary = run_validation(client, tmp_path / "evidence")
    assert summary["passed"], summary["runs"]
    assert summary["dataset_utterances"] == 40
    assert summary["api_calls"] == summary["input_tokens"] == summary["output_tokens"] == 0
    assert summary["attempted_model_calls"] <= 50
    assert summary["evidence_mode"] == "scripted"
    runs = {row["task_id"]: row for row in summary["runs"]}
    assert runs["M2-bonus"]["turns_to_signed_goals"] == 3
    assert runs["M2-bonus"]["clarification_count"] == 2
    assert runs["M2-correction-amount"]["correction_count"] == 1
    assert runs["M2-partial"]["execution_status"] == "partially_executed"
    assert runs["M2-partial"]["purchase_dispatches"] == 1
    assert runs["W04"]["allocation"] == {"P_A": "5000/1", "P_C": "5000/1"}
    assert runs["W07"]["allocation"] == {"P_A": "5000/1", "P_B": "1000/1", "P_C": "4000/1"}
    assert runs["W07"]["projected_net_delta"] == "-20/1"
    assert all(row["sources"] == ["scripted"] for row in summary["runs"])
    assert (tmp_path / "evidence/scripted/summary.json").is_file()
    assert (tmp_path / "evidence/scripted/summary.md").is_file()


def test_mock_recording_and_strict_replay_share_identity_but_are_test_artifacts(
    tmp_path, monkeypatch
):
    sends = _local_provider(monkeypatch)
    recorded = run_validation(_client(tmp_path, "record"), tmp_path / "evidence")
    assert recorded["passed"], recorded["runs"]
    assert 40 <= len(sends) <= 50
    assert recorded["api_calls"] == len(sends)
    assert recorded["input_tokens"] == 30 * len(sends)
    assert recorded["output_tokens"] == 8 * len(sends)
    original = builtins.__import__

    def offline(name, *args, **kwargs):
        if name.split(".")[0] in {"openai", "httpx", "litellm"}:
            pytest.fail("Strict validation imported a provider SDK")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", offline)
    replayed = run_validation(_client(tmp_path, "strict"), tmp_path / "evidence")
    assert replayed["passed"]
    assert replayed["evidence_mode"] == "strict-replay"
    assert replayed["api_calls"] == replayed["input_tokens"] == replayed["output_tokens"] == 0
    assert len(sends) == recorded["api_calls"]
    assert recorded["dataset_hash"] == replayed["dataset_hash"]
    assert recorded["replay_keys"] == replayed["replay_keys"]


def test_strict_miss_is_fatal_and_never_calls_provider(tmp_path, monkeypatch):
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", lambda *_: pytest.fail("network"))
    with pytest.raises(ReplayMiss):
        run_validation(_client(tmp_path, "strict"), tmp_path / "evidence")
    assert not (tmp_path / "evidence/strict/summary.json").exists()


def test_failure_is_sanitized_and_one_attempt_per_utterance(tmp_path, monkeypatch):
    attempts = []

    def failure(self, request):
        attempts.append(request)
        raise httpx.ConnectError("private-validation-sentinel")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", failure)
    result = run_validation(_client(tmp_path, "record", max_calls=1), tmp_path / "evidence")
    assert not result["passed"]
    assert len(attempts) == 1
    assert result["api_calls"] == 1
    assert "private-validation-sentinel" not in str(result)
    assert all(row["status"] in {"failed", "not_run_budget"} for row in result["runs"])


def test_cli_missing_key_reports_not_run_without_reading_environment_file(tmp_path, monkeypatch):
    def no_text(*args, **kwargs):
        pytest.fail("The validation CLI read an environment file")

    monkeypatch.setattr(type(tmp_path), "read_text", no_text)
    code = main([
        "--mode",
        "record",
        "--no-env-file",
        "--output",
        str(tmp_path / "evidence"),
        "--replay-dir",
        str(tmp_path / "replay"),
    ])
    assert code != 0
    summary = loads_exact((tmp_path / "evidence/record/summary.json").read_bytes())
    assert summary["status"] == "not_run"
    assert summary["reason"] == "missing_credential"
    assert summary["api_calls"] == 0


def test_default_credential_file_is_only_passed_to_the_existing_loader(tmp_path, monkeypatch):
    from pathlib import Path

    from corridor.agent import wealth_validation
    from corridor.agent.llm import LLMConfigurationError

    seen = []

    def loader(**options):
        seen.append(options)
        raise LLMConfigurationError("Live/record requires an API key credential")

    monkeypatch.setattr(wealth_validation, "LLMClient", loader)
    assert main(["--mode", "record", "--output", str(tmp_path)]) == 2
    assert seen[0]["env_file"] == Path(".env")
    assert seen[0]["max_calls"] == 60


def test_additional_checks_share_client_without_changing_dataset(tmp_path):
    client = _client(tmp_path)
    seen = []

    def extension(shared):
        seen.append(shared)
        return [{"task_id": "extension-test", "passed": True, "status": "scripted"}]

    report = run_validation(client, tmp_path / "evidence", additional_checks=extension)
    assert seen == [client]
    assert report["extensions"] == [
        {"task_id": "extension-test", "passed": True, "status": "scripted"}
    ]
    assert report["dataset_utterances"] == 40


def test_computed_fraction_costs_pass_privacy_scan_and_keep_exact_wire(tmp_path, monkeypatch):
    from corridor.agent import wealth_validation

    monkeypatch.setattr(wealth_validation, "CASES", ())
    _local_provider(monkeypatch)
    client = _client(tmp_path, "record", assumed_price_in="10001/1000")
    result = run_validation(client, tmp_path / "evidence")
    assert result["passed"]
    assert isinstance(result["assumed_cost_usd"], Fraction)
    assert all(isinstance(call["cost_usd"], Fraction) for call in result["calls"])
    wire = loads_exact((tmp_path / "evidence/record/summary.json").read_bytes())
    assert wire["calls"][0]["cost_usd"] == "62003/100000000"
    assert Fraction(wire["assumed_cost_usd"]) == client.spent_usd


def test_report_still_rejects_raw_phone_text(tmp_path, monkeypatch):
    from corridor.agent import wealth_validation

    monkeypatch.setattr(wealth_validation, "CASES", ())
    with pytest.raises(ValueError):
        run_validation(
            _client(tmp_path),
            tmp_path / "evidence",
            additional_checks=lambda _: [{"passed": True, "note": "13900139000"}],
        )
    assert not (tmp_path / "evidence/scripted/summary.json").exists()


def test_smokes_only_uses_five_calls_and_keeps_dataset_denominator_separate(tmp_path):
    client = _client(tmp_path)
    result = run_validation(client, tmp_path / "smokes", smokes_only=True)
    assert result["passed"]
    assert result["dataset_utterances"] == result["dataset_tasks"] == 0
    assert result["attempted_model_calls"] == 5
    assert [row["task_id"] for row in result["runs"]] == ["W04", "W07"]
