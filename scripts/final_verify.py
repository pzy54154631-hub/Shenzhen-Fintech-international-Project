"""Verify final manifests and retain a compact, explicitly labelled evidence index."""

from hashlib import sha256
from pathlib import Path
from shutil import copyfile

from corridor.bench.evidence_bundle import verify_bundle
from corridor.bench.wealth_runner import verify_wealth_evidence
from corridor.cli.evidence import inventory
from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.base import loads_exact

ROOT = Path(__file__).resolve().parents[1]
FINAL = ROOT / "evidence" / "final-f5"
COMPACT = ROOT / "evidence" / "final-summary"
J_TASKS = tuple(f"J{number:02d}" for number in range(1, 25))
W_TASKS = tuple(f"W{number:02d}" for number in range(1, 13))
MODELS = ("gpt-6.1-sol", "gpt-6-luna", "gpt-5.4-mini")
STAGES = ("main", "contrast", "dialogue", "blind", "redteam")
EXPECTED_RUNS = (
    ("main", MODELS[0]),
    *(("contrast", model) for model in MODELS),
    *((stage, MODELS[0]) for stage in ("dialogue", "blind", "redteam")),
)
COMMAND_LABELS = (
    "test",
    "rules",
    "ruff",
    "format",
    "mypy",
    "imports",
    "judge-scripted",
    "wealth-scripted",
    "adversary",
    "matrix",
    "main-gpt-6.1-sol",
    "blind-live",
    "blind-strict",
    "redteam-live",
    "redteam-strict",
    "contrast-gpt-6.1-sol",
    "contrast-gpt-6-luna",
    "contrast-gpt-5.4-mini",
    "dialogue",
)


def exact_ids(rows, key, expected, label):
    observed = [row[key] for row in rows]
    if len(observed) != len(set(observed)) or set(observed) != set(expected):
        raise ValueError(f"Incomplete or repeated {label} coverage")


def dialogue_ids():
    from corridor.agent.wealth_guard_validation import GUARANTEE_PROMPTS
    from corridor.agent.wealth_validation import CASES

    return (
        {case.task_id for case in CASES} | {"W04", "W07"},
        {case.task_id for case in GUARANTEE_PROMPTS},
    )


def expected_nl_paths(stage):
    if stage == "blind":
        return {f"case-{number:02d}/nl-result.json" for number in range(1, 17)}
    if stage == "redteam":
        from corridor.bench.wealth_redteam import wealth_redteam_corpus

        return {
            f"{pair.pair_id}/{kind}/nl-result.json"
            for pair in wealth_redteam_corpus()
            for kind in ("attack", "benign")
        }
    raise ValueError("Unknown NL replay stage")


def validate_commands(commands):
    labels = [row["label"] for row in commands]
    if len(labels) != len(set(labels)) or not set(COMMAND_LABELS) <= set(labels):
        raise ValueError("Required final command coverage is missing or repeated")


def formal_wealth_manifests(root):
    manifests = sorted(root.rglob("wealth-manifest.json"))
    exact_ids([{"task": path.parent.name} for path in manifests], "task", W_TASKS, "W manifest")
    for path in manifests:
        body = loads_exact(path.read_bytes())
        result = loads_exact((path.parent / "result.json").read_bytes())
        if (
            path.parent.parent != root
            or body["task_id"] != path.parent.name
            or result["task_id"] != path.parent.name
            or result["source"] != "scripted"
        ):
            raise ValueError("Wealth manifest identity or evidence source mismatch")
    return len(manifests)


def validate_offline(replay, final):
    """An identical subset is insufficient for the final all-stage replay claim."""
    if (
        replay.get("schema_version") != "final-offline-replay-v1"
        or replay.get("source") != "strict-replay"
        or replay.get("identical") is not True
        or replay.get("api_calls") != 0
        or Path(replay["recorded_source"]).resolve() != final.resolve()
        or len(replay["stages"]) != len(STAGES)
        or set(replay["stages"]) != set(STAGES)
    ):
        raise ValueError("Final independent replay source, mode or stage coverage mismatch")
    reports = replay["reports"]
    keys = [
        (
            row["stage"],
            row.get("model_profile", {}).get("model", row.get("model", "")).removeprefix("openai/"),
        )
        for row in reports
    ]
    if len(keys) != len(set(keys)) or set(keys) != set(EXPECTED_RUNS):
        raise ValueError("Final offline replay model coverage mismatch")
    for row in reports:
        stage = row["stage"]
        if stage in {"main", "contrast"}:
            expected = J_TASKS + W_TASKS if stage == "main" else ("J02", "W04")
            observations = row["tasks"]
            exact_ids(observations, "task_id", expected, "offline task")
            if any(item["source"] != "strict-replay" for item in observations):
                raise ValueError("Offline task evidence mode mismatch")
        elif stage in {"blind", "redteam"}:
            expected = expected_nl_paths(stage)
            observations = row["cases"]
            exact_ids(observations, "path", expected, "offline NL case")
        else:
            expected = set.union(*dialogue_ids())
            observations = []
        if (
            row.get("source") != "strict-replay"
            or row.get("identical") is not True
            or row.get("api_calls") != 0
            or row.get("total") != len(expected)
            or row.get("matched") != len(expected)
            or any(item.get("identical") is not True for item in observations)
        ):
            raise ValueError("Final independent replay contains missing or unequal observations")


def validate_dialogue_coverage(body):
    m2, m4 = dialogue_ids()
    exact_ids(body["runs"], "task_id", m2, "M2 dialogue")
    exact_ids(body["extensions"], "task_id", m4, "M4 output guard")


def copy_final_ui(root, compact):
    """Validate current browser captures and preserve their declared evidence modes."""
    snapshots = root / "evidence" / "ui" / "wealth" / "f5"
    manifest = snapshots / "screenshots.json"
    body = loads_exact(manifest.read_bytes())
    if body["schema_version"] != "f5-browser-ui-evidence-v1":
        raise ValueError("Unknown final UI manifest")
    for row in body["source_files"]:
        source = root / row["path"]
        if not source.resolve().is_relative_to((root / "src").resolve()):
            raise ValueError("Final UI source path escapes source directory")
        if sha256(source.read_bytes()).hexdigest() != row["sha256"]:
            raise ValueError("Final UI source digest mismatch")
    assets = []
    for row in body["files"]:
        source = snapshots / row["path"]
        if source.parent != snapshots or source.name == "screenshots.json":
            raise ValueError("Final UI asset path is outside capture directory")
        payload = source.read_bytes()
        if len(payload) != row["bytes"] or sha256(payload).hexdigest() != row["sha256"]:
            raise ValueError("Final UI asset digest or size mismatch")
        assets.append({
            "file": "f5-" + source.name,
            "source": source.relative_to(root).as_posix(),
            "mode": body["evidence_mode"],
            "provenance": "Final F5 browser capture; source and asset hashes verified",
            "sha256": row["sha256"],
            "bytes": row["bytes"],
        })
    if len({row["file"] for row in assets}) != len(assets):
        raise ValueError("Duplicate final UI asset paths")
    for row in assets:
        copyfile(root / row["source"], compact / row["file"])
    copyfile(manifest, compact / "f5-screenshots.json")
    return {
        "manifest": "f5-screenshots.json",
        "mode": body["evidence_mode"],
        "live_recorded": body["live_recorded"],
        "strict_replay": body["strict_replay"],
        "assets": assets,
    }


def main() -> None:
    COMPACT.mkdir(parents=True, exist_ok=True)
    bundles = []
    for seal in sorted(FINAL.rglob("bundle.json")):
        metadata = verify_bundle(seal.parent)
        bundles.append({
            "path": seal.parent.relative_to(ROOT).as_posix(),
            "metadata": metadata,
            "manifest_sha256": sha256(seal.read_bytes()).hexdigest(),
        })
    wealth_root = FINAL / "judge" / "wealth" / "scripted"
    wealth_count = formal_wealth_manifests(wealth_root)
    if not verify_wealth_evidence(wealth_root):
        raise ValueError("Formal scripted wealth evidence verification failed")
    source = ROOT / "src" / "corridor"
    current = H({
        path.relative_to(source).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted(source.rglob("*.py"))
    })
    source_manifests = []
    for path in sorted(FINAL.rglob("manifest.json")):
        body = loads_exact(path.read_bytes())
        if body.get("schema_version") == "bank-v1":
            if body["code_hash"] != current:
                raise ValueError("Evidence does not match final integrated source")
            source_manifests.append(path.relative_to(ROOT).as_posix())
    commands = []
    for path in sorted((FINAL / "checks").glob("*.json")):
        body = loads_exact(path.read_bytes())
        if "command" not in body:
            continue
        if (
            body["source_before"]["code_hash"] != current
            or body["source_after"]["code_hash"] != current
            or not body["source_unchanged"]
        ):
            raise ValueError("Final command ran against different source bytes")
        if sha256((ROOT / body["log"]).read_bytes()).hexdigest() != body["log_sha256"]:
            raise ValueError("Final command log digest mismatch")
        commands.append({"label": body["label"], "returncode": body["returncode"]})
    validate_commands(commands)
    offline = ROOT / "evidence" / "final-f5-offline"
    verify_bundle(offline)
    replay = loads_exact((offline / "replay-summary.json").read_bytes())
    validate_offline(replay, FINAL)
    for path in (
        FINAL / "dialogue" / "record" / "summary.json",
        offline / "dialogue" / "strict" / "summary.json",
    ):
        validate_dialogue_coverage(loads_exact(path.read_bytes()))
    files, _ = inventory(ROOT / "evidence")
    replay_scans = {}
    for folder in (ROOT / "data" / "replay", ROOT / "docs" / "status" / "lane-a-replay"):
        if folder.is_dir() and any(path.is_file() for path in folder.rglob("*")):
            replay_files, _ = inventory(folder)
            replay_scans[folder.relative_to(ROOT).as_posix()] = len(replay_files)
    scan = {
        "files_scanned": len(files),
        "additional_replay_roots": replay_scans,
        "credential_pattern_findings": 0,
        "method": "credential-patterns-v1; .env is never opened",
        "limitation": "Pattern scanning cannot establish absence of every possible secret encoding",
    }
    snapshots = ROOT / "evidence" / "ui" / "wealth" / "f3"
    original = loads_exact((snapshots / "screenshots.json").read_bytes())
    screenshots = []
    for name in ("03-allocation-receipt.jpg", "06-completed.jpg", "07-audit.jpg"):
        source_path = snapshots / name
        digest = sha256(source_path.read_bytes()).hexdigest()
        if digest != original[name]:
            raise ValueError("Historical UI screenshot digest mismatch")
        target = COMPACT / ("f3-" + name)
        copyfile(source_path, target)
        screenshots.append({
            "file": target.name,
            "source": source_path.relative_to(ROOT).as_posix(),
            "mode": "scripted",
            "provenance": "Historical F3 browser capture; not a final live-model UI run",
            "sha256": digest,
        })
    final_ui = copy_final_ui(ROOT, COMPACT)
    screenshots.extend(row for row in final_ui["assets"] if row["file"].endswith(".jpg"))
    verification = {
        "schema_version": "f5-verification-v1",
        "code_hash": current,
        "verified_bundles": len(bundles),
        "matching_bank_source_manifests": len(source_manifests),
        "wealth_formal_manifests": wealth_count,
        "final_commands": commands,
        "independent_offline_replay": {
            "path": offline.relative_to(ROOT).as_posix(),
            "identical": replay["identical"],
            "api_calls": replay["api_calls"],
        },
        "credential_scan": scan,
        "bundles": bundles,
        "screenshots": screenshots,
        "final_ui": final_ui,
    }
    (COMPACT / "verification.json").write_bytes(jcs_bytes(verification))
    (COMPACT / "credential-scan.json").write_bytes(jcs_bytes(scan))
    index = {
        path.relative_to(COMPACT).as_posix(): {
            "sha256": sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }
        for path in sorted(COMPACT.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }
    (COMPACT / "manifest.json").write_bytes(
        jcs_bytes({
            "schema_version": "f5-compact-evidence-v1",
            "code_hash": current,
            "files": index,
            "raw_evidence": "evidence/final-f5; regenerate with scripts/final_evaluation.py",
            "integrity": "SHA-256 inventory, not an externally anchored signature",
        })
    )
    print({
        "verified_bundles": len(bundles),
        "source_manifests": len(source_manifests),
        "credential_findings": 0,
        "files_scanned": len(files),
    })


if __name__ == "__main__":
    main()
