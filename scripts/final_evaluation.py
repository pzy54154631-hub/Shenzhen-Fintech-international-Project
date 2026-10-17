"""Reproduce the final gates and recordings without inspecting credentials.

Live stages run sequentially against one persistent conservative call journal.
The ordinary LLMClient additionally enforces its configured call/USD ceilings.
"""

import argparse
import re
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.base import loads_exact

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "evidence" / "final"
JOURNAL = DEST / "live-budget.json"


def source_manifest() -> dict:
    files = {
        path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / "src").rglob("*.py"))
    }
    return {
        "code_hash": H({
            name.removeprefix("src/corridor/"): value
            for name, value in files.items()
            if name.startswith("src/corridor/")
        }),
        "files": files,
        "uv_lock_sha256": sha256((ROOT / "uv.lock").read_bytes()).hexdigest(),
        "scope": "Final integrated source bytes; working tree may be uncommitted",
    }


def execute(label: str, arguments: list[str]) -> int:
    logs = DEST / "checks"
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / f"{label}.log"
    record_path = logs / f"{label}.json"
    if log.exists() or record_path.exists():
        raise ValueError(f"Evidence already exists for {label}; use a new --attempt")
    before = source_manifest()
    if arguments[0] == "corridor":
        command = [sys.executable, "-c", "from corridor.cli import app; app()", *arguments[1:]]
    elif arguments[0] == "importlinter.cli":
        command = [
            sys.executable,
            "-c",
            "from importlinter.cli import lint_imports; lint_imports()",
        ]
    else:
        command = [sys.executable, "-m", *arguments]
    print(f"START {label}", flush=True)
    with log.open("x", encoding="utf-8", newline="\n") as output:
        outcome = subprocess.run(
            command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=False
        )
    after = source_manifest()
    unchanged = before == after
    returncode = outcome.returncode if unchanged else 1
    with record_path.open("xb") as record:
        record.write(
            jcs_bytes({
                "label": label,
                "command": arguments,
                "returncode": returncode,
                "subprocess_returncode": outcome.returncode,
                "log": log.relative_to(ROOT).as_posix(),
                "log_sha256": sha256(log.read_bytes()).hexdigest(),
                "source": after,
                "source_before": before,
                "source_after": after,
                "source_unchanged": unchanged,
            })
        )
    print(f"END {label}: exit {returncode}; {log.relative_to(ROOT)}", flush=True)
    return returncode


def compare_nl_replay(stage: str) -> dict:
    """Require every expected NL observation to match its transport-disabled replay."""
    from corridor.bench.recording import observation_hash

    if stage == "blind":
        expected = {f"case-{index:02d}/nl-result.json" for index in range(1, 17)}
    elif stage == "redteam":
        from corridor.bench.wealth_redteam import wealth_redteam_corpus

        expected = {
            f"{pair.pair_id}/{kind}/nl-result.json"
            for pair in wealth_redteam_corpus()
            for kind in ("attack", "benign")
        }
    else:
        raise ValueError("Replay comparison requires blind or redteam")
    root = DEST / stage
    roots = {mode: root / mode for mode in ("live-recorded", "strict-replay")}
    found = {
        mode: {path.relative_to(folder).as_posix() for path in folder.rglob("nl-result.json")}
        for mode, folder in roots.items()
    }
    rows = []
    for name in sorted(expected):
        row = {"path": name, "identical": False}
        for mode, folder in roots.items():
            path = folder / name
            if name not in found[mode]:
                row[mode] = {"status": "missing"}
                continue
            try:
                raw_bytes = path.read_bytes()
                raw = loads_exact(raw_bytes)
                required_source = "live-recorded" if mode == "live-recorded" else "replay"
                valid_mode = (
                    raw.get("source") == mode
                    and bool(raw.get("sources"))
                    and set(raw["sources"]) == {required_source}
                )
                row[mode] = {
                    "status": "observed" if valid_mode else "invalid_evidence_mode",
                    "observation_hash": observation_hash(raw),
                    "file_sha256": sha256(raw_bytes).hexdigest(),
                }
            except (ValueError, OSError, TypeError, AttributeError):
                row[mode] = {"status": "invalid"}
        live, replay = row["live-recorded"], row["strict-replay"]
        row["identical"] = (
            live["status"] == replay["status"] == "observed"
            and live["observation_hash"] == replay["observation_hash"]
        )
        rows.append(row)
    result = {
        "schema_version": "final-nl-replay-comparison-v1",
        "stage": stage,
        "source": "strict-replay",
        "total": len(expected),
        "matched_cases": sum(row["identical"] for row in rows),
        "identical": all(row["identical"] for row in rows)
        and all(paths == expected for paths in found.values()),
        "unexpected_paths": {mode: sorted(paths - expected) for mode, paths in found.items()},
        "cases": rows,
    }
    destination = DEST / "checks" / f"{stage}-replay-comparison.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(jcs_bytes(result))
    return result


def cli(*args: str) -> list[str]:
    return ["corridor", *args]


def commands(stage: str) -> list[tuple[str, list[str]]]:
    if stage == "gates":
        return [
            ("test", cli("test")),
            ("rules", ["pytest", "-q", "-m", "rule", "--rules-coverage"]),
            ("ruff", ["ruff", "check", "."]),
            ("format", ["ruff", "format", "--check", "."]),
            ("mypy", ["mypy"]),
            ("imports", ["importlinter.cli"]),
        ]
    if stage == "scripted":
        return [
            (
                "judge-scripted",
                cli(
                    "judge",
                    "--planner",
                    "scripted",
                    "--suite",
                    "all",
                    "--output",
                    str(DEST / "judge"),
                ),
            ),
            (
                "wealth-scripted",
                cli(
                    "judge",
                    "--planner",
                    "scripted",
                    "--suite",
                    "wealth",
                    "--output",
                    str(DEST / "judge"),
                ),
            ),
            (
                "adversary",
                cli(
                    "adversary",
                    "--output",
                    str(DEST / "adversary"),
                    "--results",
                    str(DEST / "adversary-results"),
                ),
            ),
            (
                "matrix",
                cli(
                    "bench",
                    "--suite",
                    "wealth",
                    "--output",
                    str(DEST / "bench"),
                    "--table",
                    str(ROOT / "results" / "final-wealth-table.md"),
                ),
            ),
        ]
    if stage in {"main", "contrast"}:
        models = (
            ("gpt-6.1-sol",) if stage == "main" else ("gpt-6.1-sol", "gpt-6-luna", "gpt-5.4-mini")
        )
        return [
            (
                stage + "-" + model,
                cli(
                    "record",
                    "--tasks",
                    "judge,wealth" if stage == "main" else "J02,W04",
                    "--configs",
                    "cca",
                    "--model",
                    model,
                    "--replay-dir",
                    str(DEST / stage / model / "replay"),
                    "--output",
                    str(DEST / stage / model),
                    "--max-calls",
                    "500",
                    "--budget-path",
                    str(JOURNAL),
                ),
            )
            for model in models
        ]
    if stage == "dialogue":
        return [
            (
                "dialogue",
                cli(
                    "record",
                    "--tasks",
                    "dialogue",
                    "--configs",
                    "cca",
                    "--model",
                    "gpt-6.1-sol",
                    "--max-calls",
                    "60",
                    "--output",
                    str(DEST / "dialogue"),
                    "--replay-dir",
                    str(DEST / "dialogue-replay"),
                    "--budget-path",
                    str(JOURNAL),
                ),
            ),
        ]
    if stage in {"blind", "redteam"}:
        common = [
            "redteam",
            "--suite",
            "blind-nl" if stage == "blind" else "wealth",
            "--model",
            "gpt-6.1-sol",
            "--output",
            str(DEST / stage),
            "--replay-dir",
            str(DEST / (stage + "-replay")),
            "--budget-path",
            str(JOURNAL),
        ]
        if stage == "blind":
            common += ["--cases", str(ROOT / "data" / "blind")]
        return [
            (stage + "-live", cli(*common, "--planner", "record")),
            (stage + "-strict", cli(*common, "--planner", "strict")),
        ]
    raise ValueError("Unknown stage")


def main() -> None:
    global DEST
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "stage", choices=["gates", "scripted", "main", "blind", "redteam", "contrast", "dialogue"]
    )
    parser.add_argument(
        "--attempt",
        help="Preserve a retry under evidence/final-<attempt>; the shared budget never resets",
    )
    options = parser.parse_args()
    if options.attempt is not None:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", options.attempt) is None:
            parser.error("--attempt must be 1-64 ASCII letters, digits, underscores or hyphens")
        DEST = ROOT / "evidence" / ("final-" + options.attempt)
    DEST.mkdir(parents=True, exist_ok=True)
    selected = commands(options.stage)
    try:
        # Check the entire stage before any model call. Shared live/strict paths
        # are expected within this stage, but never reused across attempts.
        targets = {
            DEST / "checks" / f"{label}.{suffix}"
            for label, _ in selected
            for suffix in ("log", "json")
        }
        for _, arguments in selected:
            for option in ("--output", "--replay-dir"):
                if option in arguments:
                    targets.add(Path(arguments[arguments.index(option) + 1]))
        if options.stage in {"blind", "redteam"}:
            targets.add(DEST / "checks" / f"{options.stage}-replay-comparison.json")
        if any(path.exists() for path in targets):
            raise ValueError("Stage evidence already exists; use a new --attempt")
        results = [execute(label, args) for label, args in selected]
        if options.stage in {"blind", "redteam"}:
            comparison = compare_nl_replay(options.stage)
            results.append(0 if comparison["identical"] else 1)
    except (ValueError, OSError) as exc:
        print(
            str(exc) if isinstance(exc, ValueError) else "Final evaluation filesystem failure",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    raise SystemExit(0 if all(code == 0 for code in results) else 1)


if __name__ == "__main__":
    main()
