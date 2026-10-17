"""Final orchestration preserves attempts and proves code/replay identity offline."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.base import loads_exact


@pytest.fixture
def evaluation(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "final_evaluation.py"
    spec = importlib.util.spec_from_file_location("final_evaluation_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "DEST", tmp_path / "evidence" / "final")
    monkeypatch.setattr(module, "JOURNAL", tmp_path / "evidence" / "final" / "live-budget.json")
    (tmp_path / "src" / "corridor").mkdir(parents=True)
    (tmp_path / "src" / "corridor" / "example.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_bytes(b"lock")
    return module


def test_source_change_during_command_marks_gate_failed(evaluation, monkeypatch):
    def run(*args, **kwargs):
        (evaluation.ROOT / "src" / "corridor" / "example.py").write_text(
            "value = 2\n", encoding="utf-8"
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(evaluation.subprocess, "run", run)
    assert evaluation.execute("probe", ["pytest", "-q"]) != 0
    record = loads_exact((evaluation.DEST / "checks" / "probe.json").read_bytes())
    assert record["subprocess_returncode"] == 0
    assert record["source_unchanged"] is False
    assert record["source_before"]["code_hash"] != record["source_after"]["code_hash"]


def test_blind_commands_use_the_repository_corpus(evaluation):
    for _, arguments in evaluation.commands("blind"):
        assert Path(arguments[arguments.index("--cases") + 1]) == (
            evaluation.ROOT / "data" / "blind"
        )


@pytest.mark.parametrize("suffix", ["log", "json"])
def test_existing_command_evidence_is_not_overwritten(evaluation, monkeypatch, suffix):
    old = evaluation.DEST / "checks" / f"probe.{suffix}"
    old.parent.mkdir(parents=True)
    old.write_bytes(b"old evidence")

    def forbidden(*args, **kwargs):
        pytest.fail("A repeated stage must be refused before starting a subprocess")

    monkeypatch.setattr(evaluation.subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="exists|attempt"):
        evaluation.execute("probe", ["pytest", "-q"])
    assert old.read_bytes() == b"old evidence"


def test_attempt_destination_preserves_global_budget(evaluation, monkeypatch):
    stages = []
    monkeypatch.setattr(evaluation.sys, "argv", ["final_evaluation.py", "main", "--attempt", "r2"])
    monkeypatch.setattr(evaluation, "execute", lambda label, args: stages.append(args) or 0)
    with pytest.raises(SystemExit) as outcome:
        evaluation.main()
    assert outcome.value.code == 0
    assert evaluation.DEST == evaluation.ROOT / "evidence" / "final-r2"
    assert len(stages) == 1
    args = stages[0]
    assert Path(args[args.index("--budget-path") + 1]) == (
        evaluation.ROOT / "evidence" / "final" / "live-budget.json"
    )
    assert (evaluation.ROOT / "evidence" / "final-r2") in Path(
        args[args.index("--output") + 1]
    ).parents


def _blind_results(evaluation):
    for mode in ("live-recorded", "strict-replay"):
        for index in range(1, 17):
            case_id = f"case-{index:02d}"
            path = evaluation.DEST / "blind" / mode / case_id / "nl-result.json"
            path.parent.mkdir(parents=True)
            path.write_bytes(
                jcs_bytes({
                    "case_id": case_id,
                    "source": mode,
                    "sources": ["live-recorded" if mode == "live-recorded" else "replay"],
                    "llm_calls": [{"source": mode}],
                    "steps": [{"status": "settled", "completed": True}],
                    "receipts": [{"amount": "1000/1"}],
                })
            )


@pytest.mark.parametrize("mutation", [None, "changed_receipt", "missing_case", "bad_mode"])
def test_blind_replay_comparison_checks_all_sixteen_actual_observations(evaluation, mutation):
    _blind_results(evaluation)
    path = evaluation.DEST / "blind" / "strict-replay" / "case-16" / "nl-result.json"
    if mutation == "missing_case":
        path.unlink()
    elif mutation:
        raw = loads_exact(path.read_bytes())
        if mutation == "changed_receipt":
            raw["receipts"][0]["amount"] = "2000/1"
        else:
            raw["sources"] = ["scripted"]
        path.write_bytes(jcs_bytes(raw))
    result = evaluation.compare_nl_replay("blind")
    assert result["total"] == 16
    assert result["identical"] is (mutation is None)
    assert result["matched_cases"] == (16 if mutation is None else 15)
    saved = evaluation.DEST / "checks" / "blind-replay-comparison.json"
    assert loads_exact(saved.read_bytes()) == result


def test_redteam_stage_calls_replay_comparison_after_both_runs(evaluation, monkeypatch):
    events = []
    monkeypatch.setattr(evaluation.sys, "argv", ["final_evaluation.py", "redteam"])
    monkeypatch.setattr(evaluation, "execute", lambda label, args: events.append(label) or 0)
    monkeypatch.setattr(
        evaluation,
        "compare_nl_replay",
        lambda stage: events.append(stage + "-comparison") or {"identical": False},
        raising=False,
    )
    with pytest.raises(SystemExit) as outcome:
        evaluation.main()
    assert outcome.value.code == 1
    assert events == ["redteam-live", "redteam-strict", "redteam-comparison"]


def test_dialogue_stage_keeps_the_shared_budget_and_explicit_call_ceiling(evaluation):
    commands = evaluation.commands("dialogue")
    assert len(commands) == 1
    label, args = commands[0]
    assert label == "dialogue"
    assert args[:5] == ["corridor", "record", "--tasks", "dialogue", "--configs"]
    assert args[args.index("--max-calls") + 1] == "60"
    assert Path(args[args.index("--budget-path") + 1]) == evaluation.JOURNAL
    assert Path(args[args.index("--output") + 1]) == evaluation.DEST / "dialogue"


def test_existing_stage_output_is_refused_before_live_command(evaluation, monkeypatch):
    old = evaluation.DEST / "main" / "gpt-6.1-sol"
    old.mkdir(parents=True)
    (old / "old-result.json").write_bytes(b"prior evidence")
    monkeypatch.setattr(evaluation.sys, "argv", ["final_evaluation.py", "main"])

    def forbidden(*args, **kwargs):
        pytest.fail("Existing stage output must prevent a new model call")

    monkeypatch.setattr(evaluation, "execute", forbidden)
    with pytest.raises(SystemExit) as result:
        evaluation.main()
    assert result.value.code == 2
    assert (old / "old-result.json").read_bytes() == b"prior evidence"


def test_source_hash_uses_the_same_relative_names_as_bank_case(evaluation):
    from hashlib import sha256

    manifest = evaluation.source_manifest()
    raw = (evaluation.ROOT / "src" / "corridor" / "example.py").read_bytes()
    assert manifest["code_hash"] == H({"example.py": sha256(raw).hexdigest()})
    assert list(manifest["files"]) == ["src/corridor/example.py"]


def test_redteam_comparison_requires_all_attacks_and_twins(evaluation):
    from corridor.bench.wealth_redteam import wealth_redteam_corpus

    corpus = wealth_redteam_corpus()
    for mode in ("live-recorded", "strict-replay"):
        for pair in corpus:
            for kind in ("attack", "benign"):
                path = evaluation.DEST / "redteam" / mode / pair.pair_id / kind / "nl-result.json"
                path.parent.mkdir(parents=True)
                path.write_bytes(
                    jcs_bytes({
                        "case_id": pair.pair_id + "-" + kind,
                        "source": mode,
                        "sources": ["live-recorded" if mode == "live-recorded" else "replay"],
                        "steps": [{"status": "settled", "completed": True}],
                        "receipts": [],
                    })
                )
    result = evaluation.compare_nl_replay("redteam")
    assert result["identical"]
    assert result["matched_cases"] == result["total"] == 48
    assert {row["path"].split("/")[1] for row in result["cases"]} == {"attack", "benign"}
