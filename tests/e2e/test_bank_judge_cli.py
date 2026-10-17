"""CLI evidence distinguishes development success from missing real replay."""

import os
import subprocess
import sys

from typer.testing import CliRunner

from corridor.cli import app
from corridor.schemas.base import loads_exact


def test_scripted_judge_exports_verifiable_sources_and_real_effects(tmp_path):
    result = CliRunner().invoke(
        app, ["judge", "--planner", "scripted", "--tasks", "J01", "--output", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    summary = loads_exact((tmp_path / "scripted/judge.json").read_bytes())
    assert summary["passed"] == summary["total"] == 1
    assert summary["results"][0]["real_model_evaluation"] == "not_run"
    directory = tmp_path / "scripted/cca/careful/J01/transfer"
    manifest = loads_exact((directory / "manifest.json").read_bytes())
    assert manifest["sources"] == ["scripted", "scripted", "scripted"]
    final = loads_exact((directory / "mockbank_final.json").read_bytes())
    assert final["balances"]["A_CURRENT"] == "9800/1"
    checked = CliRunner().invoke(
        app,
        [
            "verify-log",
            "--log",
            str(directory / "audit.jsonl"),
            "--checkpoint",
            str(directory / "audit.checkpoint.json"),
        ],
    )
    assert checked.exit_code == 0, checked.output


def test_default_strict_judge_fails_without_sdk_import_or_network(tmp_path):
    script = r"""
import builtins, socket, sys
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.')[0] in {'litellm', 'openai', 'httpx'}:
        raise AssertionError('Forbidden SDK import: ' + name)
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
def blocked(*args, **kwargs):
    raise AssertionError('Forbidden network access')
socket.create_connection = blocked
socket.socket.connect = blocked
from typer.testing import CliRunner
from corridor.cli import app
from corridor.schemas.base import loads_exact
from pathlib import Path
result = CliRunner().invoke(app, ['judge', '--replay-dir', sys.argv[1], '--output', sys.argv[1]])
assert result.exit_code == 1, result.output
summary = loads_exact((Path(sys.argv[1]) / 'strict/judge.json').read_bytes())
assert summary['passed'] == 0
first = summary['results'][0]
assert first['task_id'] == 'J01' and first['passed'] is False
assert first['error_type'] == 'ReplayMiss'
assert 'litellm' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        env={**os.environ, "LLM_API_KEY": "unused-test-only"},
    )
    assert result.returncode == 0, result.stderr


def test_judge_does_not_silently_fallback_or_claim_unimplemented_tasks():
    for arguments in (["judge", "--planner", "fallback"], ["judge", "--tasks", "J99"]):
        result = CliRunner().invoke(app, arguments)
        assert result.exit_code == 2


def test_card_judge_cli_reports_p1_separately(tmp_path):
    result = CliRunner().invoke(
        app, ["judge", "--planner", "scripted", "--tasks", "J23,J24", "--output", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    summary = loads_exact((tmp_path / "scripted/judge.json").read_bytes())
    assert summary["passed"] == summary["total"] == 2
    assert {row["task_id"] for row in summary["results"]} == {"J23", "J24"}
    assert all(row["passed"] for row in summary["results"])
