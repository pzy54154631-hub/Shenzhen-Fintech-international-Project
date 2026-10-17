"""The standalone verifier uses recorded profiles without modifying or contacting sources."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from corridor.bench.evidence_bundle import seal_bundle
from corridor.bench.recording import observation_hash
from corridor.crypto.jcs import jcs_bytes


@pytest.fixture
def replay_script():
    path = Path(__file__).resolve().parents[2] / "scripts" / "replay_final.py"
    spec = importlib.util.spec_from_file_location("replay_final_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _recording(source, model="gpt-5.4-mini"):
    profile = {
        "model": model,
        "api": "responses",
        "reasoning_effort": "low",
        "max_output_tokens": 512,
    }
    directory = source / "contrast" / model
    rows = []
    for task in ("J02", "W04"):
        result = {
            "task_id": task,
            "passed": True,
            "facts": ["1000/1"],
            "llm_calls": [{"source": "live-recorded", "config": "cca", **profile}],
        }
        if task.startswith("W"):
            result["live_passed"] = True
        row = {
            "task_id": task,
            "source": "live-recorded",
            "passed": True,
            "observation_hash": observation_hash(result),
            "model_profile": profile,
        }
        folder = directory / "live-recorded" / model / task
        folder.mkdir(parents=True)
        (folder / "result.json").write_bytes(jcs_bytes(result))
        (folder / "record-result.json").write_bytes(jcs_bytes(row))
        seal_bundle(folder, {"source": "live-recorded", "task_id": task, **profile})
        rows.append(row)
    (directory / f"recording-{model}.json").write_bytes(
        jcs_bytes({"model_profile": profile, "results": rows, "evidence_mode": "live-recorded"})
    )
    return directory


def _fake_client(options):
    return SimpleNamespace(calls=[], api_calls=0, **options)


def _result(task, client, destination):
    import socket

    with pytest.raises(RuntimeError, match="Network is disabled"):
        socket.create_connection(("invalid.example", 443))
    client.calls.append({"source": "replay"})
    result = {"task_id": task, "passed": True, "facts": ["1000/1"], "llm_calls": client.calls[:1]}
    if task.startswith("W"):
        result["live_passed"] = True
    return result


def test_weak_model_replay_uses_saved_responses_profile_and_preserves_source(
    replay_script, tmp_path, monkeypatch
):
    source, output = tmp_path / "source", tmp_path / "new-replay"
    _recording(source)
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    options = []

    def client(**kwargs):
        options.append(kwargs)
        return _fake_client(kwargs)

    monkeypatch.setattr(replay_script, "LLMClient", client)
    monkeypatch.setattr(replay_script, "run_task", _result)
    with replay_script.network_disabled():
        result = replay_script.replay_recording(source, output, "contrast", "gpt-5.4-mini")
    assert result["identical"] and result["matched"] == result["total"] == 2
    assert options[0]["model"] == "gpt-5.4-mini"
    assert options[0]["api"] == "responses"
    assert options[0]["reasoning_effort"] == "low"
    assert options[0]["max_output_tokens"] == 512
    assert options[0]["mode"] == "strict" and options[0]["env_file"] is None
    assert {
        p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()
    } == before


@pytest.mark.parametrize("failure", ["changed_output", "cache_miss", "tampered_bundle"])
def test_replay_failures_never_become_identical_success(
    replay_script, tmp_path, monkeypatch, failure
):
    source, output = tmp_path / "source", tmp_path / "new-replay"
    directory = _recording(source)
    monkeypatch.setattr(replay_script, "LLMClient", lambda **kw: _fake_client(kw))

    def changed(task, client, destination):
        if failure == "cache_miss":
            raise RuntimeError("Synthetic missing cache; never fall back")
        result = _result(task, client, destination)
        result["facts"] = ["2000/1"]
        return result

    monkeypatch.setattr(replay_script, "run_task", changed)
    if failure == "tampered_bundle":
        path = directory / "live-recorded" / "gpt-5.4-mini" / "J02" / "result.json"
        path.write_bytes(b"{}")
    with replay_script.network_disabled():
        result = replay_script.replay_recording(source, output, "contrast", "gpt-5.4-mini")
    assert not result["identical"]
    assert result["matched"] == 0
    assert result["total"] == 2


@pytest.mark.parametrize("output", ["source", "source/nested", "."])
def test_replay_output_cannot_overlap_recorded_source(replay_script, tmp_path, output):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="separate|overlap|exist"):
        replay_script.validate_paths(source, tmp_path / output)


def test_dialogue_profile_keeps_recorded_token_limit(replay_script):
    profile = replay_script.profile({
        "model": "gpt-6.1-sol",
        "api": "responses",
        "reasoning_effort": "low",
        "max_output_tokens": 1024,
    })
    assert profile["max_output_tokens"] == 1024
    assert profile["api"] == "responses"


def test_missing_actual_strict_cache_never_reads_environment_or_calls_live(
    replay_script, tmp_path, monkeypatch
):
    from corridor.agent import llm

    source, output = tmp_path / "source", tmp_path / "new-replay"
    _recording(source)

    def forbidden(*args, **kwargs):
        pytest.fail("Strict replay attempted environment or live access")

    monkeypatch.setattr(llm, "_environment", forbidden)
    monkeypatch.setattr(llm.LLMClient, "_live", forbidden)

    def missing(task, client, destination):
        client.complete(task_id=task, step="absent", prompt={}, tool_state={}, scripted=forbidden)

    monkeypatch.setattr(replay_script, "run_task", missing)
    with replay_script.network_disabled():
        result = replay_script.replay_recording(source, output, "contrast", "gpt-5.4-mini")
    assert not result["identical"]
    assert result["api_calls"] == 0
    assert [row["error_type"] for row in result["tasks"]] == ["ReplayMiss", "ReplayMiss"]


def test_dialogue_replays_recorded_profile_and_compares_both_datasets(
    replay_script, tmp_path, monkeypatch
):
    from corridor.agent import wealth_validation

    source, output = tmp_path / "source", tmp_path / "new-replay"
    original = source / "dialogue" / "record"
    original.mkdir(parents=True)
    saved_profile = {
        "model": "gpt-6.1-sol",
        "api": "responses",
        "reasoning_effort": "low",
        "max_output_tokens": 1024,
    }
    saved = {
        **saved_profile,
        "requested_mode": "record",
        "evidence_mode": "live-recorded",
        "dataset_hash": "fixed-dataset",
        "runs": [{"task_id": "M2", "passed": True, "sources": ["live-recorded"]}],
        "extensions": [{"task_id": "M4", "passed": False, "sources": ["live-recorded"]}],
        "passed": False,
        "calls": [{"source": "live-recorded", **saved_profile}],
    }
    (original / "summary.json").write_bytes(jcs_bytes(saved))
    seal_bundle(original, {"source": "live-recorded", "model": "gpt-6.1-sol"})
    options = []

    def client(**kwargs):
        options.append(kwargs)
        return _fake_client(kwargs)

    def validation(client, output, *, additional_checks):
        client.calls.append({"source": "replay"})
        return {**saved, "requested_mode": "strict", "evidence_mode": "strict-replay"}

    monkeypatch.setattr(replay_script, "LLMClient", client)
    monkeypatch.setattr(wealth_validation, "run_validation", validation)
    with replay_script.network_disabled():
        result = replay_script.replay_dialogue(source, output)
    assert result["identical"] and result["matched"] == result["total"] == 2
    assert result["recorded_passed"] is False and result["replay_task_passed"] is False
    assert options[0]["max_output_tokens"] == 1024
    assert options[0]["env_file"] is None and options[0]["mode"] == "strict"


def test_blind_replay_compares_every_expected_case_without_touching_frozen_input(
    replay_script, tmp_path, monkeypatch
):
    from corridor.bench import blind_nl

    source, output = tmp_path / "source", tmp_path / "new-replay"
    original = source / "blind" / "live-recorded"
    saved_profile = {
        "model": "gpt-6.1-sol",
        "api": "responses",
        "reasoning_effort": "low",
        "max_output_tokens": 512,
    }
    cases = [SimpleNamespace(case_id=f"case-{number:02d}") for number in range(1, 17)]
    for case in cases:
        folder = original / case.case_id
        folder.mkdir(parents=True)
        (folder / "nl-result.json").write_bytes(
            jcs_bytes({
                "case_id": case.case_id,
                "source": "live-recorded",
                "sources": ["live-recorded"],
                "llm_calls": [{"source": "live-recorded", **saved_profile}],
                "receipts": [{"amount": "1000/1"}],
            })
        )
    seal_bundle(original, {"source": "live-recorded", "model": "gpt-6.1-sol"})
    monkeypatch.setattr(blind_nl, "load_frozen_cases", lambda path: (cases, {}))
    monkeypatch.setattr(replay_script, "LLMClient", lambda **kw: _fake_client(kw))

    def replay(cases_path, output, client):
        for case in cases:
            saved = replay_script.read(original / case.case_id / "nl-result.json")
            saved.update(source="strict-replay", sources=["replay"])
            if case.case_id == "case-16":
                saved["receipts"] = [{"amount": "2000/1"}]
            replay_script.write(output / "strict-replay" / case.case_id / "nl-result.json", saved)

    monkeypatch.setattr(blind_nl, "run_natural_blind_suite", replay)
    with replay_script.network_disabled():
        result = replay_script.replay_nl(source, output, "blind", tmp_path / "frozen")
    assert result["total"] == 16 and result["matched"] == 15
    assert not result["identical"]


def test_cli_runs_all_contrast_models_inside_disabled_network(replay_script, tmp_path, monkeypatch):
    import socket

    source, output = tmp_path / "source", tmp_path / "new-replay"
    source.mkdir()
    models = []

    def replay(source, output, stage, model):
        with pytest.raises(RuntimeError, match="Network is disabled"):
            socket.create_connection(("invalid.example", 443))
        models.append(model)
        return {"stage": stage, "model": model, "identical": True, "api_calls": 0}

    monkeypatch.setattr(replay_script, "replay_recording", replay)
    assert (
        replay_script.main([
            "--source",
            str(source),
            "--output",
            str(output),
            "--stages",
            "contrast",
        ])
        == 0
    )
    assert models == ["gpt-6.1-sol", "gpt-6-luna", "gpt-5.4-mini"]
    saved = replay_script.read(output / "replay-summary.json")
    assert saved["identical"] and saved["api_calls"] == 0
    assert saved["schema_version"] == "final-offline-replay-v1"
