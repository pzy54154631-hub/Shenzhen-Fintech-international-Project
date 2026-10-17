"""Explicit real-model recording; scripted development never manufactures replay."""

from pathlib import Path
from typing import Any

import typer

from corridor.agent.llm import LLMClient, LLMConfigurationError
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact


def record_requests(client: LLMClient, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if client.mode != "record":
        raise LLMConfigurationError("Recording requires explicit record mode")
    results = []
    for request in requests:
        if (
            not isinstance(request, dict)
            or set(request) - {"task_id", "step", "prompt", "tool_state", "sample_idx"}
            or not {"task_id", "step", "prompt", "tool_state"} <= set(request)
        ):
            raise LLMConfigurationError("Invalid recording request fields")
        result = client.complete(**request, scripted=lambda: {"status": "not_recorded"})
        if result.source != "live-recorded":
            raise LLMConfigurationError("Model did not return a recordable real response")
        results.append({"source": result.source, "replay_key": result.replay_key})
    return results


def _replay_instructions(output: Path, profile: dict[str, Any]) -> str:
    """Document the saved profile without relying on model-name API defaults."""
    text = (
        "# Offline replay\n\nThe recording manifest preserves the exact model, API, reasoning "
        "effort and output-token limit. Strict replay requires that complete profile, disables "
        "network and requires no credentials.\n\nSaved profile:\n\n```json\n"
        + jcs_bytes(profile).decode("utf-8")
        + "\n```\n\n"
    )
    stage = output.parent.name
    if stage in {"main", "contrast"} and output.name == profile["model"].removeprefix("openai/"):
        source = output.parent.parent
        destination = source.with_name(source.name + "-offline-replay")
        text += (
            "For this final-driver recording, run from the repository root with a new output "
            "directory:\n\n"
            f'`uv run python scripts/replay_final.py --source "{source.as_posix()}" '
            f'--output "{destination.as_posix()}" --stages {stage}`\n\n'
        )
        if stage == "contrast":
            text += "The contrast stage requires recordings for all three declared model tiers.\n\n"
    else:
        text += (
            "This is a standalone recording directory. The final verifier "
            "`scripts/replay_final.py` expects a final-driver source tree containing "
            "`main/<model>/` and/or all three `contrast/<model>/` directories; do not pass "
            "this standalone folder as its source. For a custom runner, construct a strict "
            "`LLMClient` from the saved profile with `env_file=None`, use the recorded replay "
            "directory, and run it inside `network_disabled()`.\n\n"
        )
    return text + (
        "Missing or corrupt cache entries fail; scripted responses are never substituted. "
        "Identical replay reproduces recorded failures as well as successes. "
        "bundle.sha256 detects accidental manifest changes; it is not an external trust anchor.\n"
    )


def run(
    tasks: str = typer.Option("J01", "--tasks"),
    model: str = typer.Option("scripted-bank-v1", "--model"),
    max_calls: int | None = typer.Option(None, "--max-calls"),
    max_usd: str | None = typer.Option(None, "--max-usd"),
    replay_dir: Path = typer.Option(Path("data/replay/bank"), "--replay-dir"),
    requests: Path | None = typer.Option(None, "--requests"),
    configs: str = typer.Option("", "--configs"),
    model_tier: str = typer.Option("main", "--model-tier"),
    output: Path = typer.Option(Path("evidence/wealth"), "--output"),
    budget_path: Path = typer.Option(Path("evidence/wealth/live-budget.json"), "--budget-path"),
    verify_replay: bool = typer.Option(True, "--verify-replay/--no-verify-replay"),
) -> None:
    try:
        if configs:
            if configs != "cca" or requests is not None:
                raise LLMConfigurationError(
                    "Suite recording requires --configs cca without --requests"
                )
            _record_suites(
                tasks,
                model,
                model_tier,
                max_calls,
                max_usd,
                replay_dir,
                output,
                budget_path,
                verify_replay,
            )
            return
        from corridor.bench.recording import LaneRecordingClient

        client = LaneRecordingClient(
            mode="record",
            model=model,
            replay_dir=replay_dir,
            max_calls=max_calls,
            max_usd=max_usd,
            budget_path=budget_path,
        )
        if requests is not None:
            try:
                rows = [
                    loads_exact(line) for line in requests.read_bytes().splitlines() if line.strip()
                ]
            except ValueError:
                raise LLMConfigurationError("Invalid recording request JSON") from None
            result: Any = record_requests(client, rows)
        elif tasks.upper() in {"J01", "JUDGE"}:
            from corridor.bench.transfer_runner import run_j01

            typer.echo("Development scope: J01 only; J02-J22 not_implemented.", err=True)
            result = run_j01(client)
            if not client.calls or any(call["source"] != "live-recorded" for call in client.calls):
                raise LLMConfigurationError("Runner did not produce only real model recordings")
            if result.get("passed") is not True:
                raise LLMConfigurationError(
                    "J01 did not pass; recordings do not imply task success"
                )
        else:
            raise LLMConfigurationError("Requested task is not_implemented; supported: J01")
        typer.echo(jcs_bytes({"recorded": result, "calls": client.calls}).decode("utf-8"))
    except typer.Exit:
        raise
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        typer.echo(f"record refused: {exc}", err=True)
        raise typer.Exit(2) from None


def _record_suites(
    tasks: str,
    model: str,
    model_tier: str,
    max_calls: int | None,
    max_usd: str | None,
    replay_dir: Path,
    output: Path,
    budget_path: Path,
    verify_replay: bool,
) -> None:
    from corridor.bench.bank_cases import write_json
    from corridor.bench.evidence_bundle import seal_bundle, verify_bundle
    from corridor.bench.recording import (
        LaneRecordingClient,
        network_disabled,
        observation_hash,
        replay_client,
    )
    from corridor.cli.judge import IMPLEMENTED, run_bank_task

    if tasks.strip().lower() == "dialogue":
        _record_dialogue_validation(
            model, model_tier, max_calls, max_usd, replay_dir, output, budget_path, verify_replay
        )
        return

    selected = []
    for item in tasks.split(","):
        name = item.strip().upper()
        selected.extend(
            IMPLEMENTED
            if name == "JUDGE"
            else [f"W{number:02d}" for number in range(1, 13)]
            if name == "WEALTH"
            else [name]
        )
    allowed = {*IMPLEMENTED, *(f"W{number:02d}" for number in range(1, 13))}
    if not selected or len(set(selected)) != len(selected) or not set(selected) <= allowed:
        raise LLMConfigurationError("Unknown or duplicate recording task")
    client = LaneRecordingClient(
        mode="record",
        model=model,
        model_tier=model_tier,
        replay_dir=replay_dir,
        max_calls=min(max_calls, 1200) if max_calls is not None else 1200,
        max_usd=max_usd,
        budget_path=budget_path,
        api="responses",
        reasoning_effort="low",
    )
    replay = replay_client(client)
    rows = []
    profile = {
        "model": client.model,
        "api": client.api,
        "reasoning_effort": client.reasoning_effort,
        "max_output_tokens": client.max_output_tokens,
    }
    slug = client.model.removeprefix("openai/")
    for task in selected:
        start = len(client.calls)
        destination = output / "live-recorded" / slug / task
        replay_destination = output / "strict-replay" / slug / task
        result: dict[str, Any] = {}
        row: dict[str, Any] = {
            "task_id": task,
            "source": "not_run",
            "passed": False,
            "strict_replay": "not_run",
            "model_profile": profile,
        }
        try:
            if task.startswith("W"):
                from corridor.bench.wealth_runner import run_wealth_case

                result = run_wealth_case(task, client=client, evidence_dir=destination)
            else:
                result = run_bank_task(task, client, destination)
            calls = client.calls[start:]
            all_live = bool(calls) and all(call["source"] == "live-recorded" for call in calls)
            row.update(
                source="live-recorded" if all_live else "not_run",
                passed=result.get("passed") is True
                and all_live
                and (not task.startswith("W") or result.get("live_passed") is True),
                observation_hash=observation_hash(result),
                llm_calls=calls,
            )
            if task.startswith("W"):
                row["live_status"] = result.get("live_status", "not_run")
                row["live_scope"] = result.get("live_scope", "See the task evidence")
                row["scripted_passed"] = result.get("passed") is True
                row["workflow_passed"] = result["dialogue"]["workflow_passed"]
                row["workflow_total"] = result["dialogue"]["workflow_total"]
                row["formal_mutation_subcases"] = len(result["subcases"])
                row["formal_live_coverage"] = result["formal_live_coverage"]
            if verify_replay and all_live:
                with network_disabled():
                    if task.startswith("W"):
                        repeated = run_wealth_case(
                            task, client=replay, evidence_dir=replay_destination
                        )
                    else:
                        repeated = run_bank_task(task, replay, replay_destination)
                same = observation_hash(repeated) == row["observation_hash"]
                row["strict_replay"] = "PASS" if same else "FAIL"
                row["passed"] &= same
                write_json(
                    replay_destination / "replay-result.json",
                    {
                        "source": "strict-replay",
                        "task_id": task,
                        "identical": same,
                        "observation_hash": observation_hash(repeated),
                        "model_profile": profile,
                    },
                )
                seal_bundle(
                    replay_destination, {"source": "strict-replay", "task_id": task, **profile}
                )
                verify_bundle(replay_destination)
        except (ValueError, RuntimeError, OSError, ImportError) as exc:
            # Provider exceptions have already been sanitized by llm.py. Only the
            # exception class is persisted here; no request/header/key is exported.
            calls = client.calls[start:]
            row.update(
                error_type=type(exc).__name__,
                passed=False,
                llm_calls=calls,
                source="live-recorded"
                if calls and all(call["source"] == "live-recorded" for call in calls)
                else "not_run",
            )
        write_json(destination / "record-result.json", row)
        seal_bundle(destination, {"source": row["source"], "task_id": task, **profile})
        verify_bundle(destination)
        rows.append(row)
        typer.echo(
            f"{task}: {'PASS' if row['passed'] else 'FAIL'}; "
            f"source={row['source']}; strict-replay={row['strict_replay']}"
        )
    summary = {
        "model_profile": profile,
        "results": rows,
        "api_calls": client.api_calls,
        "assumed_cost_usd": str(client.spent_usd),
        "evidence_mode": "live-recorded",
        "J": {
            "passed": sum(row["passed"] for row in rows if row["task_id"].startswith("J")),
            "total": sum(row["task_id"].startswith("J") for row in rows),
        },
        "W": {
            "passed": sum(row["passed"] for row in rows if row["task_id"].startswith("W")),
            "total": sum(row["task_id"].startswith("W") for row in rows),
            "scope": (
                "Integrated task-specific advisor workflows; formal mutation probes remain scripted"
            ),
            "workflow_passed": sum(row.get("workflow_passed", 0) for row in rows),
            "workflow_total": sum(row.get("workflow_total", 0) for row in rows),
            "formal_mutation_subcases_scripted": sum(
                row.get("formal_mutation_subcases", 0) for row in rows
            ),
            "formal_mutation_subcases_live": 0,
        },
    }
    write_json(output / f"recording-{slug}.json", summary)
    (output / "REPRODUCE.md").write_text(
        _replay_instructions(output, profile),
        encoding="utf-8",
    )
    (output / f"SUMMARY-{slug}.md").write_text(
        "# Model recording and offline replay\n\n"
        "| Task | Scripted | Live-recorded | Strict-replay |\n|---|---|---|---|\n"
        + "\n".join(
            f"| {row['task_id']} | separate judge | "
            f"{'PASS' if row['passed'] else 'FAIL / ' + row['source']} | "
            f"{row['strict_replay']} |"
            for row in rows
        )
        + f"\n\nModel: {client.model}. J and W denominators are separate. "
        "Scenario-selection calls are mechanism evidence, not unrestricted dialogue competence.\n",
        encoding="utf-8",
    )
    if not all(row["passed"] for row in rows):
        raise typer.Exit(1)


def _record_dialogue_validation(
    model, model_tier, max_calls, max_usd, replay_dir, output, budget_path, verify_replay
):
    """M2/M4 share the same persistent ceiling as every other final recording."""
    from corridor.agent.wealth_guard_validation import run_guarantee_checks
    from corridor.agent.wealth_validation import run_validation
    from corridor.bench.bank_cases import write_json
    from corridor.bench.evidence_bundle import seal_bundle, verify_bundle
    from corridor.bench.recording import (
        LaneRecordingClient,
        network_disabled,
        observation_hash,
        replay_client,
    )

    client = LaneRecordingClient(
        mode="record",
        model=model,
        model_tier=model_tier,
        replay_dir=replay_dir,
        max_calls=min(max_calls, 60) if max_calls is not None else 60,
        max_usd=max_usd,
        budget_path=budget_path,
        budget_group="dialogue",
        api="responses",
        reasoning_effort="low",
        max_output_tokens=1024,
    )
    result = run_validation(client, output, additional_checks=run_guarantee_checks)
    replay = replay_client(client)
    identical = False
    if verify_replay:
        with network_disabled():
            repeated = run_validation(replay, output, additional_checks=run_guarantee_checks)
        observed = {key: result[key] for key in ("dataset_hash", "runs", "extensions")}
        reproduced = {key: repeated[key] for key in ("dataset_hash", "runs", "extensions")}
        identical = observation_hash(observed) == observation_hash(reproduced)
        seal_bundle(output / "strict", {"source": "strict-replay", "model": client.model})
        verify_bundle(output / "strict")
    seal_bundle(output / "record", {"source": "live-recorded", "model": client.model})
    verify_bundle(output / "record")
    summary = {
        "source": "live-recorded",
        "model": client.model,
        "passed": result["passed"] and (identical or not verify_replay),
        "M2_passed": result["completed_expected_outcomes"],
        "M2_total": result["expected_outcome_denominator"],
        "M4_passed": sum(row["passed"] for row in result["extensions"]),
        "M4_total": len(result["extensions"]),
        "api_calls": client.api_calls,
        "strict_replay": "PASS" if identical else "FAIL" if verify_replay else "not_run",
        "scope": "M2 fixed utterance dataset plus two comparison smokes; M4 guarded prose",
    }
    write_json(output / "dialogue-recording.json", summary)
    typer.echo(jcs_bytes(summary).decode("utf-8"))
    if not summary["passed"]:
        raise typer.Exit(1)


def register(app: typer.Typer) -> None:
    app.command("record")(run)
