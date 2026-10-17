"""Re-execute final recordings offline, preserving their exact recorded model profiles.

All model clients are strict, receive env_file=None, and run inside a disabled
network context. A fresh output directory is required; original sealed evidence
and replay caches are read only. Identical replay does not turn a recorded
failure into task success.
"""

import argparse
import re
from pathlib import Path
from typing import Any

from corridor.agent.llm import LLMClient
from corridor.bench.evidence_bundle import seal_bundle, verify_bundle
from corridor.bench.recording import network_disabled, observation_hash
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact

MODELS = ("gpt-6.1-sol", "gpt-6-luna", "gpt-5.4-mini")
STAGES = ("main", "contrast", "dialogue", "blind", "redteam")
PROFILE_KEYS = ("model", "api", "reasoning_effort", "max_output_tokens")
J_TASKS = tuple(f"J{index:02d}" for index in range(1, 25))
W_TASKS = tuple(f"W{index:02d}" for index in range(1, 13))


def read(path: Path) -> dict[str, Any]:
    if path.name.lower() == ".env":
        raise ValueError("Environment files are never replay inputs")
    value = loads_exact(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("Expected an evidence object")
    return value


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(jcs_bytes(value))


def profile(value: dict[str, Any]) -> dict[str, Any]:
    result = {key: value[key] for key in PROFILE_KEYS}
    if (
        not isinstance(result["model"], str)
        or re.fullmatch(r"(?:openai/)?[A-Za-z0-9][A-Za-z0-9_.-]*", result["model"]) is None
        or result["api"] not in {"responses", "chat"}
        or result["reasoning_effort"] not in {"none", "minimal", "low", "medium", "high", "xhigh"}
        or type(result["max_output_tokens"]) is not int
        or result["max_output_tokens"] < 1
    ):
        raise ValueError("Invalid recorded model profile")
    return result


def client_for(recorded_profile: dict[str, Any], cache: Path) -> LLMClient:
    return LLMClient(mode="strict", replay_dir=cache, env_file=None, **profile(recorded_profile))


def check_bundle(folder: Path, *, task: str | None = None) -> None:
    if any(path.name.lower() == ".env" for path in folder.rglob("*")):
        raise ValueError("Environment files are never replay inputs")
    metadata = verify_bundle(folder)
    if metadata.get("source") != "live-recorded" or (
        task is not None and metadata.get("task_id") != task
    ):
        raise ValueError("Recorded bundle provenance mismatch")


def validate_paths(source: Path, output: Path) -> tuple[Path, Path]:
    source, output = source.resolve(), output.resolve()
    if output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("Replay output must be separate from recorded evidence; no overlap")
    if not source.is_dir() or output.exists():
        raise ValueError("Source must exist and replay output must not already exist")
    return source, output


def run_task(task: str, client: LLMClient, destination: Path) -> dict[str, Any]:
    if task.startswith("W"):
        from corridor.bench.wealth_runner import run_wealth_case

        return run_wealth_case(task, client=client, evidence_dir=destination)
    from corridor.cli.judge import run_bank_task

    return run_bank_task(task, client, destination)


def replay_recording(source: Path, output: Path, stage: str, model: str) -> dict[str, Any]:
    """Use per-task sealed observations, not only the aggregate recording summary."""
    expected = (*J_TASKS, *W_TASKS) if stage == "main" else ("J02", "W04")
    directory = source / stage / model
    summary = read(directory / f"recording-{model}.json")
    saved_profile = profile(summary["model_profile"])
    if saved_profile["model"].removeprefix("openai/") != model:
        raise ValueError("Recording model identity mismatch")
    recorded_rows = summary["results"]
    if [row["task_id"] for row in recorded_rows] != list(expected):
        raise ValueError("Recording does not cover the complete declared task set")
    client = client_for(saved_profile, directory / "replay")
    rows = []
    for saved_row in recorded_rows:
        task = saved_row["task_id"]
        destination = output / stage / model / task
        row: dict[str, Any] = {
            "task_id": task,
            "source": "strict-replay",
            "identical": False,
            "recorded_passed": saved_row.get("passed") is True,
        }
        try:
            original = directory / "live-recorded" / model / task
            check_bundle(original, task=task)
            record = read(original / "record-result.json")
            saved = read(original / ("transfer/result.json" if task == "J01" else "result.json"))
            expected_hash = observation_hash(saved)
            if (
                record.get("source") != "live-recorded"
                or record.get("task_id") != task
                or profile(record["model_profile"]) != saved_profile
                or record.get("observation_hash") != expected_hash
                or saved_row.get("observation_hash") != expected_hash
            ):
                raise ValueError("Sealed task differs from its recording manifest")
            if not saved.get("llm_calls") or any(
                call.get("source") != "live-recorded" or profile(call) != saved_profile
                for call in saved["llm_calls"]
            ):
                raise ValueError("Recorded task contains an unexpected call source or profile")
            start = len(client.calls)
            repeated = run_task(task, client, destination)
            calls = client.calls[start:]
            source_valid = bool(calls) and all(call["source"] == "replay" for call in calls)
            actual_hash = observation_hash(repeated)
            row.update(
                identical=source_valid and actual_hash == expected_hash and client.api_calls == 0,
                expected_observation_hash=expected_hash,
                replay_observation_hash=actual_hash,
                replay_calls=len(calls),
                replay_sources_valid=source_valid,
                replay_task_passed=repeated.get("passed") is True
                and (not task.startswith("W") or repeated.get("live_passed") is True),
            )
            # Detect accidental changes to any original sealed task during replay.
            check_bundle(original, task=task)
        except (ValueError, RuntimeError, OSError, KeyError, TypeError) as error:
            row["error_type"] = type(error).__name__
        write(destination / "offline-replay-check.json", row)
        seal_bundle(destination, {"source": "strict-replay", "task_id": task, **saved_profile})
        rows.append(row)
        print(
            f"{stage}/{model}/{task}: {'identical' if row['identical'] else 'FAILED'}", flush=True
        )
    return {
        "stage": stage,
        "model_profile": saved_profile,
        "source": "strict-replay",
        "total": len(expected),
        "matched": sum(row["identical"] for row in rows),
        "identical": all(row["identical"] for row in rows),
        "api_calls": client.api_calls,
        "tasks": rows,
    }


def replay_dialogue(source: Path, output: Path) -> dict[str, Any]:
    from corridor.agent.wealth_guard_validation import run_guarantee_checks
    from corridor.agent.wealth_validation import run_validation

    original = source / "dialogue" / "record"
    check_bundle(original)
    saved = read(original / "summary.json")
    saved_profile = profile(saved)
    if saved.get("evidence_mode") != "live-recorded" or saved.get("requested_mode") != "record":
        raise ValueError("Dialogue source is not a recorded run")
    if not saved.get("calls") or any(
        call.get("source") != "live-recorded" or profile(call) != saved_profile
        for call in saved["calls"]
    ):
        raise ValueError("Dialogue contains an unexpected call source or profile")
    client = client_for(saved_profile, source / "dialogue-replay")
    repeated = run_validation(client, output / "dialogue", additional_checks=run_guarantee_checks)
    expected = {key: saved[key] for key in ("dataset_hash", "runs", "extensions")}
    actual = {key: repeated[key] for key in expected}
    source_valid = bool(client.calls) and all(call["source"] == "replay" for call in client.calls)
    identical = (
        source_valid
        and observation_hash(expected) == observation_hash(actual)
        and client.api_calls == 0
    )
    check_bundle(original)
    return {
        "stage": "dialogue",
        "source": "strict-replay",
        "model_profile": saved_profile,
        "total": len(saved["runs"]) + len(saved["extensions"]),
        "matched": sum(
            observation_hash(left) == observation_hash(right)
            for left, right in zip(
                [*saved["runs"], *saved["extensions"]],
                [*repeated["runs"], *repeated["extensions"]],
                strict=True,
            )
        ),
        "identical": identical,
        "recorded_passed": saved.get("passed") is True,
        "replay_task_passed": repeated.get("passed") is True,
        "api_calls": client.api_calls,
        "expected_observation_hash": observation_hash(expected),
        "replay_observation_hash": observation_hash(actual),
    }


def replay_nl(source: Path, output: Path, stage: str, cases: Path) -> dict[str, Any]:
    from corridor.bench.blind_nl import load_frozen_cases, run_natural_blind_suite
    from corridor.bench.wealth_redteam import run_wealth_redteam, wealth_redteam_corpus

    original = source / stage / "live-recorded"
    check_bundle(original)
    if stage == "blind":
        frozen, _ = load_frozen_cases(cases)
        names = [f"{case.case_id}/nl-result.json" for case in frozen]
    else:
        names = [
            f"{pair.pair_id}/{kind}/nl-result.json"
            for pair in wealth_redteam_corpus()
            for kind in ("attack", "benign")
        ]
    found = {path.relative_to(original).as_posix() for path in original.rglob("nl-result.json")}
    if set(names) != found:
        raise ValueError("NL recordings do not cover the complete expected case set")
    saved = {name: read(original / name) for name in names}
    if any(
        result.get("source") != "live-recorded"
        or not result.get("sources")
        or set(result["sources"]) != {"live-recorded"}
        or not result.get("llm_calls")
        for result in saved.values()
    ):
        raise ValueError("NL source contains an unrecorded observation")
    traces = [call for result in saved.values() for call in result["llm_calls"]]
    saved_profile = profile(traces[0])
    if any(
        profile(call) != saved_profile or call.get("source") != "live-recorded" for call in traces
    ):
        raise ValueError("Mixed NL model profiles or evidence sources")
    client = client_for(saved_profile, source / (stage + "-replay"))
    if stage == "blind":
        run_natural_blind_suite(cases, output / stage, client)
    else:
        run_wealth_redteam(client, output / stage)
    rows = []
    for name in names:
        row: dict[str, Any] = {"path": name, "identical": False}
        try:
            actual = read(output / stage / "strict-replay" / name)
            expected_hash, actual_hash = observation_hash(saved[name]), observation_hash(actual)
            valid = (
                actual.get("source") == "strict-replay"
                and bool(actual.get("sources"))
                and set(actual["sources"]) == {"replay"}
            )
            row.update(
                identical=valid and expected_hash == actual_hash,
                expected_observation_hash=expected_hash,
                replay_observation_hash=actual_hash,
            )
        except (ValueError, OSError, KeyError, TypeError) as error:
            row["error_type"] = type(error).__name__
        rows.append(row)
    check_bundle(original)
    return {
        "stage": stage,
        "source": "strict-replay",
        "model_profile": saved_profile,
        "total": len(names),
        "matched": sum(row["identical"] for row in rows),
        "identical": all(row["identical"] for row in rows) and client.api_calls == 0,
        "api_calls": client.api_calls,
        "cases": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("evidence/final-release"))
    parser.add_argument("--output", type=Path, required=True, help="A new separate directory")
    parser.add_argument(
        "--cases", type=Path, default=Path(__file__).resolve().parents[1] / "data" / "blind"
    )
    parser.add_argument("--stages", default=",".join(STAGES), help="Comma-separated stage names")
    options = parser.parse_args(argv)
    stages = options.stages.split(",")
    if not stages or len(set(stages)) != len(stages) or not set(stages) <= set(STAGES):
        parser.error("--stages must contain distinct names from " + ",".join(STAGES))
    try:
        source, output = validate_paths(options.source, options.output)
    except ValueError as error:
        parser.error(str(error))
    output.mkdir(parents=True)
    reports = []
    with network_disabled():
        for stage in stages:
            models = MODELS if stage == "contrast" else (MODELS[0],)
            for model in models:
                try:
                    report = (
                        replay_recording(source, output, stage, model)
                        if stage in {"main", "contrast"}
                        else replay_dialogue(source, output)
                        if stage == "dialogue"
                        else replay_nl(source, output, stage, options.cases)
                    )
                except (
                    ValueError,
                    RuntimeError,
                    OSError,
                    KeyError,
                    TypeError,
                    IndexError,
                ) as error:
                    report = {
                        "stage": stage,
                        "model": model,
                        "source": "strict-replay",
                        "identical": False,
                        "error_type": type(error).__name__,
                    }
                reports.append(report)
                print(
                    f"{stage}/{model}: {'identical' if report['identical'] else 'FAILED'}",
                    flush=True,
                )
    result = {
        "schema_version": "final-offline-replay-v1",
        "source": "strict-replay",
        "recorded_source": source.as_posix(),
        "stages": stages,
        "identical": all(report["identical"] for report in reports),
        "network": "disabled throughout replay",
        "credentials": "env_file=None; no live clients",
        "api_calls": sum(report.get("api_calls", 0) for report in reports),
        "reports": reports,
        "limitation": "Equality reproduces recorded observations, including any recorded failures",
    }
    write(output / "replay-summary.json", result)
    seal_bundle(output, {"source": "strict-replay", "suite": "final-offline-replay"})
    verify_bundle(output)
    print(f"Summary: {output / 'replay-summary.json'}", flush=True)
    return 0 if result["identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
