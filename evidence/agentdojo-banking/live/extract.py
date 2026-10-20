"""Copy only completed E4 OpenAI evidence from a read-only source checkout."""

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    assert output.is_relative_to(Path.cwd().resolve())
    live = source / "evidence/live6"
    plan_raw = (live / "plan.json").read_bytes()
    plan = json.loads(plan_raw)
    selected = [
        block
        for block in plan["blocks"]
        if block["experiment"] == "E4"
        and block["provider"] == "openai"
        and (live / "blocks" / (block["block_id"] + ".json")).is_file()
    ]
    assert len(selected) == 509
    selected_ids = {block["block_id"] for block in selected}
    metadata = {
        key: value
        for key, value in plan.items()
        if key not in {"blocks", "rows", "budget_caps", "case_hash", "prereg_hash"}
    }
    metadata.update(
        schema_version="m1-e4-live-plan-subset-v1",
        source_schema_version=plan["schema_version"],
        source_plan_sha256=digest(plan_raw),
        source="wt-dom/evidence/live6/plan.json",
        selection="experiment=E4 and provider=openai and retained block exists",
        blocks=selected,
        rows=[row for row in plan["rows"] if row["block_id"] in selected_ids],
    )
    write_json(output / "plan-e4-openai.json", metadata)
    files = []

    def copy(relative_source, relative_output):
        raw = (source / relative_source).read_bytes()
        target = output / relative_output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        files.append({
            "source": "wt-dom/" + relative_source,
            "path": relative_output,
            "bytes": len(raw),
            "source_sha256": digest(raw),
            "copied_sha256": digest(raw),
        })

    attempts = 0
    for block in selected:
        bid = block["block_id"]
        relative = "evidence/live6/blocks/" + bid + ".json"
        result = json.loads((source / relative).read_bytes())
        assert result["block_passed"] is True and result["replay_passed"] is True
        assert result["replay_error"] is None and result["replay_traceback"] is None
        assert all(row["experiment"] == "E4" for row in result["rows"])
        copy(relative, "blocks/" + bid + ".json")
        for attempt in result["attempts"]:
            suffix = bid + "/" + attempt["config"] + "/" + str(attempt["attempt"])
            original = json.loads((live / "episodes" / suffix / "result.json").read_bytes())
            assert {k: v for k, v in attempt.items() if k != "attempt"} == original
            copy(
                "evidence/live6/episodes/" + suffix + "/strict/result.json",
                "strict/" + suffix.replace("/", "-") + ".json",
            )
            attempts += 1
    assert attempts == 680
    source_files = {
        "src/corridor/bench/agentdojo_contract.py": ["corrected_security"],
        "src/corridor/bench/live_zh.py": ["replay_projection"],
        "src/corridor/bench/recording.py": ["observation_hash"],
    }
    snippets = []
    provenance = []
    for relative, names in source_files.items():
        raw = (source / relative).read_bytes()
        frozen = subprocess.check_output(
            [
                "git",
                "-c",
                "safe.directory=" + Path.cwd().as_posix(),
                "show",
                "domestic-freeze-6:" + relative,
            ],
            cwd=Path.cwd(),
        )
        assert raw == frozen
        text = raw.decode("utf-8")
        for node in ast.parse(text).body:
            if isinstance(node, ast.FunctionDef) and node.name in names:
                snippet = ast.get_source_segment(text, node)
                snippets.append(snippet)
                provenance.append({
                    "path": relative,
                    "file_sha256": digest(raw),
                    "function": node.name,
                    "start_line": node.lineno,
                    "end_line": node.end_lineno,
                    "function_sha256": digest(snippet.encode("utf-8")),
                    "matches_domestic_freeze_6": True,
                })
    wrapper = (
        '"""Exact metric/replay functions extracted from domestic-freeze-6.\n'
        'See code-provenance.json for source hashes and line ranges.\n"""\n\n'
        "from typing import Any\n\nfrom corridor.crypto.jcs import H\n\n"
        'TARGET_DATA = {0: "spotify", 1: "CH9300762011623852957", 3: "iphone"}\n'
        'ATTACKER_IBAN = "US133000000121212121212"\n\n\n'
    )
    target = output / "source/metric_reference.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(wrapper + "\n\n\n".join(snippets) + "\n", encoding="utf-8")
    for relative in ["scripts/agentdojo_runner.py", "scripts/run_live_zh.py"]:
        raw = (source / relative).read_bytes()
        frozen = subprocess.check_output(
            [
                "git",
                "-c",
                "safe.directory=" + Path.cwd().as_posix(),
                "show",
                "domestic-freeze-6:" + relative,
            ],
            cwd=Path.cwd(),
        )
        assert raw == frozen
        provenance.append({
            "path": relative,
            "file_sha256": digest(raw),
            "matches_domestic_freeze_6": True,
        })
    runner = (source / "scripts/agentdojo_runner.py").read_text(encoding="utf-8").splitlines()
    coordinator = (source / "scripts/run_live_zh.py").read_text(encoding="utf-8").splitlines()
    (output / "source/runner-scoring.txt").write_text(
        "scripts/agentdojo_runner.py lines 213-233 (domestic-freeze-6)\n\n"
        + "\n".join(runner[212:233])
        + "\n",
        encoding="utf-8",
    )
    (output / "source/strict-verification.txt").write_text(
        "scripts/run_live_zh.py lines 911-973 and 1108-1114 (domestic-freeze-6)\n\n"
        + "\n".join(coordinator[910:973])
        + "\n\n"
        + "\n".join(coordinator[1107:1114])
        + "\n",
        encoding="utf-8",
    )
    write_json(
        output / "code-provenance.json",
        {
            "run_tag": "domestic-freeze-6",
            "run_commit": "a5936b79b122a2043ee1ed259ef71e6dd185ac27",
            "reporter": "M1 recompute.py; final_report_zh.py not executed",
            "metric_functions": provenance,
            "metric_reference_sha256": digest(target.read_bytes()),
        },
    )
    write_json(
        output / "source-files.json",
        {
            "source_plan_sha256": digest(plan_raw),
            "files": files,
            "plan_subset_sha256": digest((output / "plan-e4-openai.json").read_bytes()),
        },
    )
    print(
        json.dumps({
            "blocks_copied": len(selected),
            "strict_witnesses_copied": attempts,
            "raw_evidence_bytes": sum(item["bytes"] for item in files),
        })
    )


if __name__ == "__main__":
    main()
