"""The formal wealth judge exercises every required case through real mechanisms."""

from pathlib import Path
from shutil import rmtree

import pytest

from corridor.agent.llm import LLMClient, ReplayMiss
from corridor.bench import wealth_runner
from corridor.bench.wealth_runner import (
    WEALTH_TASK_IDS,
    run_wealth_case,
    run_wealth_suite,
    verify_wealth_evidence,
)


@pytest.fixture
def evidence_path():
    # Windows sandbox directories need inherited ACLs, not tempfile's mode 0700.
    root = Path(__file__).resolve().parents[2] / ".tmp"
    root.mkdir(exist_ok=True)
    index = 0
    while (root / f"wealth-runner-test-{index}").exists():
        index += 1
    path = root / f"wealth-runner-test-{index}"
    path.mkdir()
    yield path
    assert path.resolve().parent == root.resolve()
    rmtree(path)


@pytest.mark.parametrize("task_id", WEALTH_TASK_IDS)
def test_formal_wealth_case_has_executable_assertions(task_id):
    result = run_wealth_case(task_id)
    assert result["passed"], result
    assert result["source"] == "scripted"
    assert result["subcases"]
    assert result["assertions"]
    assert all(row["passed"] for row in result["assertions"])
    assert all(row["source"] == "scripted" for row in result["subcases"])


def test_unknown_wealth_case_is_not_silently_counted():
    with pytest.raises(ValueError, match="Unknown wealth"):
        run_wealth_case("W13")


def test_wealth_suite_reports_a_separate_denominator():
    result = run_wealth_suite(task_ids=["W03", "W04"])
    assert result["suite"] == "wealth"
    assert result["passed"] == result["total"] == 2
    assert [row["task_id"] for row in result["cases"]] == ["W03", "W04"]


def test_empty_probe_cannot_claim_success(monkeypatch):
    monkeypatch.setitem(wealth_runner._CASES, "W04", lambda judge: judge.run("empty", lambda: None))
    result = run_wealth_case("W04")
    assert not result["passed"]
    assert result["assertions"][0]["assertion"] == "has_executable_assertions"


def test_evidence_manifest_detects_changed_truncated_and_removed_artifacts(evidence_path):
    result = run_wealth_case("W04", evidence_dir=evidence_path)
    assert result["passed"]
    assert verify_wealth_evidence(evidence_path)
    artifact = evidence_path / "scripted/default_hand_calculation/comparison_0.json"
    original = artifact.read_bytes()
    for changed in (original[:-1], original.replace(b"5000/1", b"5001/1", 1)):
        artifact.write_bytes(changed)
        assert not verify_wealth_evidence(evidence_path)
    artifact.write_bytes(original)
    assert verify_wealth_evidence(evidence_path)
    artifact.unlink()
    assert not verify_wealth_evidence(evidence_path)


def test_model_coverage_never_relabels_scripted_mechanisms():
    client = LLMClient(mode="scripted", env_file=None)
    result = run_wealth_case("W05", client=client)
    assert result["passed"]
    assert result["source"] == "scripted"
    assert result["dialogue"]["covered_subcases"] == []
    assert result["dialogue"]["workflow_passed"] == 3
    assert result["dialogue"]["mechanism_mutation_scope"] == "scripted_separately"
    assert result["live_status"] == "complete_task_workflows"
    assert not result["live_passed"]
    assert len(client.calls) == 6
    assert all(row["source"] == "scripted" for row in result["subcases"])


def test_w12_model_path_checks_documents_and_red_lock_not_generic_w04_success():
    client = LLMClient(mode="scripted", env_file=None)
    result = run_wealth_case("W12", client=client)
    assert result["passed"]
    assert result["live_status"] == "complete_task_workflows"
    assert not result["live_passed"]
    assert client.calls
    workflows = result["dialogue"]["workflows"]
    assert [row["id"] for row in workflows] == [
        "benign_brochure",
        "malicious_brochure_and_red_lock",
    ]
    assert all(row["bank_dispatches"] == 0 for row in workflows)
    assert all(row["source"] == "scripted" for row in result["subcases"])


def test_strict_missing_wealth_cache_fails_without_network(evidence_path, monkeypatch):
    client = LLMClient(mode="strict", api="responses", replay_dir=evidence_path, env_file=None)
    monkeypatch.setattr(client, "_live", lambda *_: pytest.fail("Network path invoked"))
    with pytest.raises(ReplayMiss):
        run_wealth_case("W04", client=client)
    assert client.api_calls == 0
