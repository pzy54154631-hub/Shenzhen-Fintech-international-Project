"""The worker boundary limits resources and never forwards untrusted diagnostics."""

import json
import os
import subprocess
import sys
from pathlib import Path
from time import perf_counter

import pytest

from corridor.gateway import sandbox_monitor as monitor


def _worker(tmp_path, monkeypatch, source):
    path = tmp_path / "trusted_worker.py"
    path.write_text(source, encoding="utf-8")
    monkeypatch.setattr(monitor, "_worker_command", lambda: [sys.executable, "-I", str(path)])


def _reply(tmp_path, monkeypatch, response):
    raw = json.dumps(response, separators=(",", ":")).encode("utf-8")
    _worker(tmp_path, monkeypatch, f"import sys\nsys.stdout.buffer.write({raw!r})\n")


def test_real_interpreter_returns_exact_rationals_without_financial_capability():
    result = monitor.run_sandbox(
        'result = {"total": sum_money(dataset, "net_amount"), "rows": count(dataset)}',
        [{"net_amount": "1/3"}, {"net_amount": "2/3"}],
    )
    assert result.status == "ok" and result.rule_ids == []
    assert result.results == {"total": "1/1", "rows": "2/1"}
    assert result.reason is None


def test_worker_command_is_fixed_isolated_python_script():
    command = monitor._worker_command()
    assert command[:2] == [sys.executable, "-I"]
    assert len(command) == 3
    assert Path(command[2]).is_absolute()
    assert Path(command[2]).name == "sandbox_interpreter.py"


def test_no_parent_environment_credentials_files_or_console_are_inherited(tmp_path, monkeypatch):
    monkeypatch.setenv("CORRIDOR_TEST_SECRET", "private-synthetic-marker")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    _worker(
        tmp_path,
        monkeypatch,
        """import json, os, sys
result = {
    "secret_absent": "1/1" if "CORRIDOR_TEST_SECRET" not in os.environ else "0/1",
    "path_absent": "1/1" if "PYTHONPATH" not in os.environ else "0/1",
    "empty_cwd": "1/1" if not os.listdir() else "0/1",
    "isolated": "1/1" if sys.flags.isolated else "0/1",
}
sys.stdout.write(json.dumps({"status": "ok", "results": result}))
""",
    )
    captured = {}
    popen = subprocess.Popen

    def inspect(*args, **kwargs):
        captured.update(kwargs)
        return popen(*args, **kwargs)

    monkeypatch.setattr(monitor.subprocess, "Popen", inspect)
    result = monitor.run_sandbox("result = {}", [])
    assert result.status == "ok"
    assert set(result.results.values()) == {"1/1"}
    assert set(captured["env"]) <= {"SystemRoot"}
    assert captured["close_fds"] is True
    assert captured["stderr"] == subprocess.DEVNULL
    assert not Path(captured["cwd"]).exists()
    if os.name == "nt":
        assert captured["creationflags"] & subprocess.CREATE_NO_WINDOW


@pytest.mark.rule("SBX-TIMEOUT")
def test_deadline_kills_and_reaps_worker_even_when_stdin_is_not_read(tmp_path, monkeypatch):
    _worker(tmp_path, monkeypatch, "import time\ntime.sleep(30)\n")
    processes = []
    popen = subprocess.Popen

    def capture(*args, **kwargs):
        process = popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(monitor.subprocess, "Popen", capture)
    dataset = [{"category": "x" * 200, "amount": "1/1"} for _ in range(1000)]
    started = perf_counter()
    result = monitor.run_sandbox("result = {}", dataset)
    elapsed = perf_counter() - started
    assert elapsed <= 4
    assert result.status == "rejected" and result.rule_ids == ["SBX-TIMEOUT"]
    assert result.results == {} and result.reason == "deadline"
    assert processes[0].poll() is not None
    _reply(tmp_path, monkeypatch, {"status": "ok", "results": {"alive": "1/1"}})
    assert monitor.run_sandbox("result = {}", []).results == {"alive": "1/1"}


@pytest.mark.rule("SBX-LIMIT")
def test_output_overflow_terminates_worker_before_deadline(tmp_path, monkeypatch):
    _worker(
        tmp_path,
        monkeypatch,
        """import sys, time
sys.stdout.buffer.write(b"x" * 32769)
sys.stdout.buffer.flush()
time.sleep(30)
""",
    )
    started = perf_counter()
    result = monitor.run_sandbox("result = {}", [])
    assert perf_counter() - started < 2
    assert result.rule_ids == ["SBX-LIMIT"] and result.reason == "output_bytes"
    assert result.results == {}


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "other", "results": {}},
        {"status": "ok", "results": {}, "unexpected": "ignored"},
        {"status": "ok", "results": ["1/1"]},
        {"status": "ok", "results": {"value": 1}},
        {"status": "ok", "results": {"value": True}},
        {"status": "ok", "results": {"value": None}},
        {"status": "ok", "results": {"value": 1.5}},
        {"status": "ok", "results": {"value": "hello"}},
        {"status": "ok", "results": {"value": "2/2"}},
        {"status": "ok", "results": {"value": "1/0"}},
        {"status": "ok", "results": {"value": f"{2**128}/1"}},
        {"status": "ok", "results": {"<|endoftext|>": "1/1"}},
        {"status": "ok", "results": {"__class__": "1/1"}},
        {"status": "ok", "results": {"PII_deadbeef": "1/1"}},
        {"status": "ok", "results": {"13800138000": "1/1"}},
        {"status": "rejected", "rule": "OTHER", "reason": "untrusted"},
    ],
)
def test_malformed_unknown_or_escaping_output_is_rejected(tmp_path, monkeypatch, payload):
    _reply(tmp_path, monkeypatch, payload)
    result = monitor.run_sandbox("result = {}", [])
    assert result.status == "rejected"
    assert result.rule_ids[0] in {"SBX-SYNTAX", "SBX-LIMIT"}
    assert result.results == {}


@pytest.mark.parametrize(
    "raw", [b"not json", b"\xff", b'{"status":"ok","status":"ok","results":{}}']
)
def test_non_json_invalid_utf8_and_duplicate_keys_fail_closed(tmp_path, monkeypatch, raw):
    _worker(tmp_path, monkeypatch, f"import sys\nsys.stdout.buffer.write({raw!r})\n")
    result = monitor.run_sandbox("result = {}", [])
    assert result.status == "rejected" and result.results == {}


def test_known_rejection_preserves_rule_but_never_worker_source_or_diagnostics(
    tmp_path, monkeypatch
):
    secret = "worker stderr contains raw source and private-synthetic-marker"
    _reply(tmp_path, monkeypatch, {"status": "rejected", "rule": "SBX-SYNTAX", "reason": secret})
    result = monitor.run_sandbox("result = {}", [])
    assert result.rule_ids == ["SBX-SYNTAX"] and result.results == {}
    assert secret not in repr(result) and "private-synthetic-marker" not in repr(result)


def test_bounded_nested_numeric_output_and_large_rational_are_accepted(tmp_path, monkeypatch):
    output = {"groups": {"0": ["-1/3", "0/1"], "weekend": f"{2**127}/1"}}
    _reply(tmp_path, monkeypatch, {"status": "ok", "results": output})
    result = monitor.run_sandbox("result = {}", [])
    assert result.status == "ok" and result.results == output


@pytest.mark.parametrize("case", ["source", "source_utf8", "rows", "bytes", "pii", "float"])
def test_invalid_input_rejects_before_worker_launch(monkeypatch, case):
    def forbidden():
        raise AssertionError("The worker must not start")

    monkeypatch.setattr(monitor, "_worker_command", forbidden)
    program, dataset = "result = {}", []
    if case == "source":
        program = "#" * 8193
    elif case == "source_utf8":
        program = "#" + "界" * 2731
    elif case == "rows":
        dataset = [{}] * 1001
    elif case == "bytes":
        dataset = [{"category": "x" * 200, "merchant_ref": "y" * 100} for _ in range(1000)]
    elif case == "pii":
        program = 'result = {"13800138000": 1}'
    else:
        dataset = [{"amount": 1.5}]
    result = monitor.run_sandbox(program, dataset)
    assert result.status == "rejected" and result.results == {}


def test_exact_source_and_row_boundaries_are_permitted():
    program = 'result = {"rows": count(dataset)}\n#'
    program += "x" * (8192 - len(program))
    dataset = [{"category": "x" * 246} for _ in range(1000)]
    encoded_size = len(json.dumps(dataset, separators=(",", ":")).encode("utf-8"))
    assert 250 * 1024 < encoded_size <= 256 * 1024
    result = monitor.run_sandbox(program, dataset)
    assert result.status == "ok" and result.results == {"rows": "1000/1"}


def test_transport_setup_failure_also_terminates_and_reaps_child(tmp_path, monkeypatch):
    _worker(tmp_path, monkeypatch, "import time\ntime.sleep(30)\n")
    processes = []
    popen = subprocess.Popen

    def capture(*args, **kwargs):
        process = popen(*args, **kwargs)
        processes.append(process)
        return process

    def unavailable(_):
        raise RuntimeError("Synthetic transport setup failure")

    monkeypatch.setattr(monitor.subprocess, "Popen", capture)
    monkeypatch.setattr(monitor.Thread, "start", unavailable)
    result = monitor.run_sandbox("result = {}", [])
    assert result.status == "rejected" and result.reason == "worker_start"
    assert processes[0].poll() is not None


@pytest.mark.parametrize("shape", ["scalars", "depth"])
def test_output_structure_limits_are_rechecked_by_parent(tmp_path, monkeypatch, shape):
    value = {"items": ["0/1"] * 1001}
    if shape == "depth":
        value = {"value": "0/1"}
        for _ in range(21):
            value = {"nested": value}
    _reply(tmp_path, monkeypatch, {"status": "ok", "results": value})
    assert monitor.run_sandbox("result = {}", []).rule_ids == ["SBX-LIMIT"]


def test_worker_crash_and_stderr_do_not_escape(tmp_path, monkeypatch):
    _worker(
        tmp_path,
        monkeypatch,
        'import sys\nsys.stderr.write("private-synthetic-marker")\nsys.exit(5)\n',
    )
    result = monitor.run_sandbox("result = {}", [])
    assert result.status == "rejected" and result.results == {}
    assert "private-synthetic-marker" not in repr(result)
