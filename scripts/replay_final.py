"""Re-execute final recordings offline, preserving their exact recorded model profiles.

All model clients are strict, receive env_file=None, and run inside a disabled
network context. A fresh output directory is required; original sealed evidence
and replay caches are read only. Identical replay does not turn a recorded
failure into task success.
"""

import argparse
import re
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any

from corridor.agent.llm import LLMClient
from corridor.bench.evidence_bundle import seal_bundle, verify_bundle
from corridor.bench.recording import network_disabled, observation_hash
from corridor.crypto.jcs import H, jcs_bytes
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
    if task == "J01":
        from corridor.bench.judge_catalog import validate_result
        from corridor.bench.transfer_runner import run_j01
        from corridor.i18n import get_locale

        witnesses = []
        result = run_j01(
            client, evidence_dir=destination / "transfer", narrative_observer=witnesses.append
        )
        validate_result(task, result)
        if len(witnesses) != 1:
            raise ValueError("J01 requires exactly one authenticated narrative witness")
        # Written after the unchanged runner measurements, and included in the replay seal.
        write(
            destination / "narrative-facts.json",
            {
                "schema": "authenticated-gateway-narrative-v1",
                "locale": get_locale(),
                "rendered": witnesses[0],
            },
        )
        return result
    if task.startswith("W"):
        from corridor.bench.wealth_runner import run_wealth_case

        return run_wealth_case(task, client=client, evidence_dir=destination)
    from corridor.cli.judge import run_bank_task

    return run_bank_task(task, client, destination)


def verify_j01_fact_hash_migration(
    original: Path, destination: Path, saved: dict[str, Any], repeated: dict[str, Any]
) -> dict[str, Any]:
    """Prove only the final J01 fact-hash schema changed; never replace raw equality.

    Both raw bundles, complete audit chains, retained checkpoints, signed receipts,
    exact English display facts, and all other business observations remain required.
    This is deliberately specific to the one historical transfer narrative shape.
    """
    from corridor.crypto.sign import RECEIPT, verify
    from corridor.gateway.audit import AuditLog
    from corridor.schemas.bank import BankReceipt
    from corridor.schemas.money import fraction_string
    from corridor.schemas.narrative import NarrativeResult
    from corridor.sim.fixtures import make_state

    def require(condition: bool, reason: str) -> None:
        if not condition:
            raise ValueError("J01 fact-hash migration rejected: " + reason)

    check_bundle(original, task="J01")
    metadata = verify_bundle(destination)
    require(
        metadata.get("source") == "strict-replay" and metadata.get("task_id") == "J01",
        "replay seal",
    )
    require(saved == read(original / "transfer/result.json"), "source result anchor")
    require(repeated == read(destination / "transfer/result.json"), "replay result anchor")
    require(saved.get("task_id") == repeated.get("task_id") == "J01", "task scope")
    require(
        read(original / "record-result.json").get("observation_hash") == observation_hash(saved),
        "recorded observation anchor",
    )
    audits = []
    checkpoints = []
    for folder, result in ((original, saved), (destination, repeated)):
        audit = AuditLog(folder / "transfer/audit.jsonl", folder / "transfer/audit.checkpoint.json")
        require(
            audit.verify(result.get("audit_checkpoint")),
            "complete audit chain and result checkpoint",
        )
        checkpoint = audit.checkpoint()
        require(result.get("audit_checkpoint") == checkpoint, "explicit result checkpoint anchor")
        require(
            read(folder / "transfer/manifest.json").get("audit_checkpoint") == checkpoint,
            "manifest checkpoint anchor",
        )
        audits.append(audit.records())
        checkpoints.append(checkpoint)
    old, current = audits
    require(len(old) == len(current) == 19, "exact historical audit length")
    prefix = (original / "transfer/audit.jsonl").read_bytes().splitlines(keepends=True)[:-1]
    require(
        prefix
        == (destination / "transfer/audit.jsonl").read_bytes().splitlines(keepends=True)[:-1],
        "all preceding audit bytes",
    )
    require(
        sum(event["event"] == "narrative_rendered" for event in old) == 1, "unique narrative event"
    )
    require(
        current[-1]["event"] == old[-1]["event"] == "narrative_rendered", "final narrative event"
    )
    require(
        set(old[-1]["payload"]) == set(current[-1]["payload"]) == {"fact_hash", "rule_ids"},
        "exact narrative payload fields",
    )
    require(
        old[-1]["payload"]["rule_ids"] == current[-1]["payload"]["rule_ids"] == [],
        "narrative rules",
    )

    witness = read(destination / "narrative-facts.json")
    require(set(witness) == {"schema", "locale", "rendered"}, "witness shape")
    require(
        witness["schema"] == "authenticated-gateway-narrative-v1" and witness["locale"] == "en",
        "English gateway witness",
    )
    rendered = NarrativeResult.model_validate(witness["rendered"])
    require(
        rendered.status == "rendered" and not rendered.rule_ids and not rendered.note,
        "successful fact-only narrative",
    )
    require(
        [fact.field for fact in rendered.facts] == ["status", "amount", "balance_after"],
        "exact historical fact sequence",
    )
    require(
        rendered.text
        == saved.get("narrative")
        == repeated.get("narrative")
        == "\n".join(fact.text for fact in rendered.facts),
        "all narrative display text",
    )
    full_hash = H(rendered.facts)
    exact_hash = H([
        fact.model_dump(include={"receipt_ref", "field", "exact_value"}) for fact in rendered.facts
    ])
    require(full_hash == old[-1]["payload"]["fact_hash"], "legacy full fact hash")
    require(
        exact_hash == current[-1]["payload"]["fact_hash"] and full_hash != exact_hash,
        "new exact fact hash",
    )

    # Recheck the synthetic bank signature and values, independently of the observer.
    final = read(destination / "transfer/mockbank_final.json")
    refs = {fact.receipt_ref for fact in rendered.facts}
    require(len(refs) == 1, "one transfer receipt")
    receipt = BankReceipt.model_validate(final["receipts"][next(iter(refs))])
    require(receipt.id == next(iter(refs)), "receipt identity binding")
    require(
        verify(make_state().roots.bank_pubkey, RECEIPT, receipt, receipt.sig), "receipt signature"
    )
    require(receipt.kind == "transfer" and receipt.status == "settled", "settled transfer receipt")
    debits = [
        effect
        for effect in receipt.exact_effects
        if effect.effect_type == "debit" and effect.account_ref == "A_CURRENT"
    ]
    require(len(debits) == 1, "unique authorized source debit")
    require(
        [fact.exact_value for fact in rendered.facts]
        == [receipt.status, fraction_string(debits[0].amount), debits[0].after],
        "receipt-backed exact values",
    )

    # No non-audit business artifact can change. These are the whole historical set.
    exceptions = {
        "audit.jsonl",
        "audit.checkpoint.json",
        "manifest.json",
        "result.json",
        "transcript.md",
    }
    inventories = []
    for folder in (original, destination):
        inventories.append({
            path.relative_to(folder / "transfer").as_posix(): path.read_bytes()
            for path in (folder / "transfer").rglob("*")
            if path.is_file()
        })
    require(set(inventories[0]) == set(inventories[1]), "transfer artifact inventory")
    artifacts = sorted(set(inventories[0]) - exceptions)
    require(
        all(inventories[0][name] == inventories[1][name] for name in artifacts),
        "all other business artifact bytes",
    )
    old_manifest = read(original / "transfer/manifest.json")
    new_manifest = read(destination / "transfer/manifest.json")
    new_manifest["audit_checkpoint"] = checkpoints[0]
    require(
        observation_hash(old_manifest) == observation_hash(new_manifest),
        "all other manifest observations",
    )
    old_transcript, new_transcript = [item["transcript.md"] for item in inventories]
    require(old_transcript.startswith(b"Planner: record\r\n"), "historical transcript provenance")
    expected_transcript = b"Planner: strict" + old_transcript.removeprefix(b"Planner: record")
    require(
        new_transcript in {expected_transcript, expected_transcript.replace(b"\r\n", b"\n")},
        "all transcript content (only recorded mode header and platform CRLF-to-LF allowed)",
    )
    transcript_line_endings = "unchanged" if new_transcript == expected_transcript else "CRLF-to-LF"

    projected_event = deepcopy(current[-1])
    projected_event["payload"]["fact_hash"] = full_hash
    projected_event["payload_hash"] = H(projected_event["payload"])
    projected_event["record_hash"] = H({
        key: value for key, value in projected_event.items() if key != "record_hash"
    })
    require(
        jcs_bytes(projected_event) == jcs_bytes(old[-1]),
        "complete reconstructed legacy final event",
    )
    require(
        checkpoints[0] == {"seq": 19, "head": projected_event["record_hash"]},
        "reconstructed legacy checkpoint",
    )
    projected_result = deepcopy(repeated)
    projected_result["audit_checkpoint"] = checkpoints[0]
    require(
        observation_hash(projected_result) == observation_hash(saved),
        "every other business and security observation",
    )
    check_bundle(original, task="J01")
    verify_bundle(destination)
    return {
        "schema": "j01-rendered-fact-hash-v1-to-v2",
        "basis": (
            "Authenticated English RenderedFact list versus receipt_ref/field/exact_value "
            "tuples; only the final audit fact hash and its derived checkpoint differ"
        ),
        "old_fact_hash": full_hash,
        "new_fact_hash": exact_hash,
        "source_checkpoint": checkpoints[0],
        "replay_checkpoint": checkpoints[1],
        "unchanged_audit_prefix_records": 18,
        "unchanged_audit_prefix_sha256": sha256(b"".join(prefix)).hexdigest(),
        "witness_sha256": sha256((destination / "narrative-facts.json").read_bytes()).hexdigest(),
        "unchanged_business_artifacts": artifacts,
        "receipt_signatures_valid": True,
        "transcript_line_endings": transcript_line_endings,
        "source_bundle_sha256": sha256((original / "bundle.json").read_bytes()).hexdigest(),
        "expected_observation_hash": observation_hash(saved),
        "replay_observation_hash": observation_hash(repeated),
        "legacy_projected_observation_hash": observation_hash(projected_result),
    }


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
            "verified": False,
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
                verified=source_valid and actual_hash == expected_hash and client.api_calls == 0,
                expected_observation_hash=expected_hash,
                replay_observation_hash=actual_hash,
                replay_calls=len(calls),
                replay_sources_valid=source_valid,
                replay_task_passed=repeated.get("passed") is True
                and (not task.startswith("W") or repeated.get("live_passed") is True),
            )
            if task == "J01" and not row["identical"] and source_valid and client.api_calls == 0:
                seal_bundle(
                    destination, {"source": "strict-replay", "task_id": task, **saved_profile}
                )
                proof = verify_j01_fact_hash_migration(original, destination, saved, repeated)
                write(destination / "fact-hash-migration.json", proof)
                row.update(verified=True, schema_migration=proof)
            # Detect accidental changes to any original sealed task during replay.
            check_bundle(original, task=task)
        except (ValueError, RuntimeError, OSError, KeyError, TypeError) as error:
            row.update(identical=False, verified=False)
            row["error_type"] = type(error).__name__
        write(destination / "offline-replay-check.json", row)
        seal_bundle(destination, {"source": "strict-replay", "task_id": task, **saved_profile})
        verify_bundle(destination)
        rows.append(row)
        print(f"{stage}/{model}/{task}: {verification_label(row)}", flush=True)
    return {
        "stage": stage,
        "model_profile": saved_profile,
        "source": "strict-replay",
        "total": len(expected),
        "matched": sum(row["identical"] for row in rows),
        "raw_identical_count": sum(row["identical"] for row in rows),
        "verified_count": sum(row["verified"] for row in rows),
        "schema_migrations": sum(row["verified"] and "schema_migration" in row for row in rows),
        "identical": all(row["identical"] for row in rows),
        "verified": all(row["verified"] for row in rows) and client.api_calls == 0,
        "api_calls": client.api_calls,
        "tasks": rows,
    }


def verification_label(row: dict[str, Any]) -> str:
    if row["identical"]:
        return "identical"
    return "verified schema migration (raw unequal)" if row.get("verified") else "FAILED"


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
    matched = (
        sum(
            observation_hash(left) == observation_hash(right)
            for left, right in zip(
                [*saved["runs"], *saved["extensions"]],
                [*repeated["runs"], *repeated["extensions"]],
                strict=True,
            )
        )
        if source_valid and client.api_calls == 0
        else 0
    )
    return {
        "stage": "dialogue",
        "source": "strict-replay",
        "model_profile": saved_profile,
        "total": len(saved["runs"]) + len(saved["extensions"]),
        "matched": matched,
        "raw_identical_count": matched,
        "verified_count": matched,
        "schema_migrations": 0,
        "identical": identical,
        "verified": identical,
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
        row: dict[str, Any] = {"path": name, "identical": False, "verified": False}
        try:
            actual = read(output / stage / "strict-replay" / name)
            expected_hash, actual_hash = observation_hash(saved[name]), observation_hash(actual)
            valid = (
                actual.get("source") == "strict-replay"
                and bool(actual.get("sources"))
                and set(actual["sources"]) == {"replay"}
            )
            row.update(
                identical=valid and expected_hash == actual_hash and client.api_calls == 0,
                verified=valid and expected_hash == actual_hash and client.api_calls == 0,
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
        "raw_identical_count": sum(row["identical"] for row in rows),
        "verified_count": sum(row["verified"] for row in rows),
        "schema_migrations": 0,
        "identical": all(row["identical"] for row in rows) and client.api_calls == 0,
        "verified": all(row["verified"] for row in rows) and client.api_calls == 0,
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
                        "verified": False,
                        "error_type": type(error).__name__,
                    }
                reports.append(report)
                print(
                    f"{stage}/{model}: {verification_label(report)}",
                    flush=True,
                )
    result = {
        "schema_version": "final-offline-replay-v2",
        "source": "strict-replay",
        "recorded_source": source.as_posix(),
        "stages": stages,
        "identical": all(report["identical"] for report in reports),
        "verified": all(
            report.get("verified", report["identical"]) and report.get("api_calls", 0) == 0
            for report in reports
        ),
        "total": sum(report.get("total", 0) for report in reports),
        "raw_identical_count": sum(report.get("raw_identical_count", 0) for report in reports),
        "verified_count": sum(report.get("verified_count", 0) for report in reports),
        "schema_migrations": sum(report.get("schema_migrations", 0) for report in reports),
        "network": "disabled throughout replay",
        "credentials": "env_file=None; no live clients",
        "api_calls": sum(report.get("api_calls", 0) for report in reports),
        "reports": reports,
        "limitation": (
            "Raw equality and verified schema migration are reported separately; "
            "neither changes recorded task failures into success"
        ),
    }
    write(output / "replay-summary.json", result)
    seal_bundle(output, {"source": "strict-replay", "suite": "final-offline-replay"})
    verify_bundle(output)
    print(f"Summary: {output / 'replay-summary.json'}", flush=True)
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
