"""Bounded subprocess transport for the fixed restricted-analysis interpreter.

The interpreter's language restrictions provide file and network isolation.
This process boundary supplies resource control, not an operating-system sandbox.
"""

import json
import os
import re
import subprocess
import sys
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from secrets import token_hex
from tempfile import gettempdir
from threading import Event, Thread
from typing import Any, BinaryIO, Literal

from corridor.gateway.privacy import PIIVault
from corridor.schemas.models import JsonValue

_MAX_SOURCE = 8 * 1024
_MAX_INPUT = 256 * 1024
_MAX_WIRE = _MAX_INPUT + _MAX_SOURCE + 1024
_MAX_OUTPUT = 32 * 1024
_MAX_ROWS = 1000
_MAX_SCALARS = 1000
_MAX_DEPTH = 20
_MAX_BITS = 128
_DEADLINE = 3
_KEY = re.compile(r"[A-Za-z0-9_]{1,64}")
_RATIONAL = re.compile(r"-?(?:0|[1-9][0-9]*)/[1-9][0-9]*")


@dataclass(frozen=True)
class SandboxRun:
    status: Literal["ok", "rejected"]
    rule_ids: list[str] = field(default_factory=list)
    results: dict[str, JsonValue] = field(default_factory=dict)
    reason: str | None = None


class _Rejected(ValueError):
    def __init__(self, rule: str, reason: str) -> None:
        self.rule, self.reason = rule, reason
        super().__init__(reason)


def _reject(rule: str, reason: str) -> SandboxRun:
    return SandboxRun("rejected", [rule], reason=reason)


def _worker_command() -> list[str]:
    return [sys.executable, "-I", str(Path(__file__).with_name("sandbox_interpreter.py").resolve())]


@contextmanager
def _working_directory() -> Generator[str, None, None]:
    # Inherit the temp parent's Windows ACL: tempfile's owner-only mode is not
    # usable under restricted Windows tokens. No business files are copied here.
    directory = Path(gettempdir()) / ("corridor-analysis-" + token_hex(16))
    directory.mkdir()
    try:
        yield str(directory)
    finally:
        directory.rmdir()


def _input_value(value: object, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise _Rejected("SBX-LIMIT", "input_depth")
    if isinstance(value, str):
        if len(value) > 256:
            raise _Rejected("SBX-LIMIT", "input_string")
    elif value is None or type(value) is bool:
        return
    elif type(value) is int:
        if value.bit_length() > _MAX_BITS:
            raise _Rejected("SBX-LIMIT", "input_integer")
    elif isinstance(value, list):
        for item in value:
            _input_value(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _Rejected("SBX-SYNTAX", "input_shape")
            _input_value(key, depth + 1)
            _input_value(item, depth + 1)
    else:
        raise _Rejected("SBX-SYNTAX", "input_shape")


def _payload(program: str, dataset: list[dict[str, JsonValue]]) -> bytes:
    if not isinstance(program, str) or not isinstance(dataset, list):
        raise _Rejected("SBX-SYNTAX", "input_shape")
    if len(program.encode("utf-8")) > _MAX_SOURCE:
        raise _Rejected("SBX-LIMIT", "source_bytes")
    if len(dataset) > _MAX_ROWS:
        raise _Rejected("SBX-LIMIT", "input_rows")
    if any(not isinstance(row, dict) for row in dataset):
        raise _Rejected("SBX-SYNTAX", "input_shape")
    _input_value(dataset)
    try:
        PIIVault().ensure_safe((program, dataset))
    except ValueError as exc:
        raise _Rejected("SBX-SYNTAX", "private_input") from exc
    data_bytes = json.dumps(
        dataset,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(data_bytes) > _MAX_INPUT:
        raise _Rejected("SBX-LIMIT", "input_bytes")
    code_bytes = json.dumps(program, ensure_ascii=False).encode("utf-8")
    payload = b'{"program":' + code_bytes + b',"dataset":' + data_bytes + b"}"
    if len(payload) > _MAX_WIRE:
        raise _Rejected("SBX-LIMIT", "wire_bytes")
    return payload


def _no_number(_: str) -> Any:
    raise _Rejected("SBX-SYNTAX", "output_shape")


def _distinct_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Rejected("SBX-SYNTAX", "output_shape")
        result[key] = value
    return result


def _numeric_results(value: object, depth: int = 0) -> int:
    if depth > _MAX_DEPTH:
        raise _Rejected("SBX-LIMIT", "output_depth")
    if isinstance(value, str):
        if len(value) > 81 or not _RATIONAL.fullmatch(value):
            raise _Rejected("SBX-SYNTAX", "output_number")
        number = Fraction(value)
        if max(number.numerator.bit_length(), number.denominator.bit_length()) > _MAX_BITS:
            raise _Rejected("SBX-LIMIT", "output_integer")
        if value != f"{number.numerator}/{number.denominator}":
            raise _Rejected("SBX-SYNTAX", "output_number")
        return 1
    children: Iterable[object]
    if isinstance(value, dict):
        for key in value:
            if (
                not isinstance(key, str)
                or not _KEY.fullmatch(key)
                or "__" in key
                or key.upper().startswith("PII_")
                or (key.isdigit() and len(key) >= 11)
            ):
                raise _Rejected("SBX-SYNTAX", "output_key")
        children = value.values()
    elif isinstance(value, list):
        children = iter(value)
    else:
        raise _Rejected("SBX-SYNTAX", "output_shape")
    total = 0
    for item in children:
        total += _numeric_results(item, depth + 1)
        if total > _MAX_SCALARS:
            raise _Rejected("SBX-LIMIT", "output_scalars")
    return total


def validate_results(value: object) -> bool:
    """Check the independently bounded numeric result schema for receipt gates."""
    try:
        if not isinstance(value, dict):
            return False
        _numeric_results(value)
        return (
            len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            <= _MAX_OUTPUT
        )
    except (ValueError, TypeError, RecursionError):
        return False


def _response(output: bytes) -> SandboxRun:
    try:
        body = json.loads(
            output.decode("utf-8"),
            parse_float=_no_number,
            parse_int=_no_number,
            parse_constant=_no_number,
            object_pairs_hook=_distinct_pairs,
        )
        if not isinstance(body, dict):
            raise _Rejected("SBX-SYNTAX", "output_shape")
        if body.get("status") == "rejected":
            if (
                set(body) != {"status", "rule", "reason"}
                or body["rule"] not in {"SBX-SYNTAX", "SBX-LIMIT"}
                or not isinstance(body["reason"], str)
            ):
                raise _Rejected("SBX-SYNTAX", "output_shape")
            return _reject(
                body["rule"], "worker_limit" if body["rule"] == "SBX-LIMIT" else "worker_syntax"
            )
        if (
            set(body) != {"status", "results"}
            or body.get("status") != "ok"
            or not isinstance(body["results"], dict)
        ):
            raise _Rejected("SBX-SYNTAX", "output_shape")
        _numeric_results(body["results"])
        return SandboxRun("ok", results=body["results"])
    except _Rejected as exc:
        return _reject(exc.rule, exc.reason)
    except (ValueError, TypeError, RecursionError):
        return _reject("SBX-SYNTAX", "output_shape")


def _kill(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        pass


def _read_output(
    process: subprocess.Popen[bytes],
    stream: BinaryIO,
    output: bytearray,
    overflow: Event,
    error: Event,
) -> None:
    try:
        while chunk := os.read(stream.fileno(), 4096):
            available = _MAX_OUTPUT - len(output)
            output.extend(chunk[:available])
            if len(chunk) > available:
                overflow.set()
                _kill(process)
                break
    except OSError:
        error.set()
    finally:
        stream.close()


def _write_input(stream: BinaryIO, payload: bytes) -> None:
    try:
        stream.write(payload)
        stream.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def run_sandbox(program: str, dataset: list[dict[str, JsonValue]]) -> SandboxRun:
    """Run only the installed interpreter; no caller can select an executable."""
    try:
        payload = _payload(program, dataset)
    except _Rejected as exc:
        return _reject(exc.rule, exc.reason)
    except (ValueError, TypeError, RecursionError):
        return _reject("SBX-SYNTAX", "input_shape")
    environment = (
        {"SystemRoot": os.environ["SystemRoot"]}
        if os.name == "nt" and "SystemRoot" in os.environ
        else {}
    )
    try:
        with _working_directory() as directory:
            process = subprocess.Popen(
                _worker_command(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=directory,
                env=environment,
                close_fds=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            assert process.stdin is not None and process.stdout is not None
            input_stream, output_stream = process.stdin, process.stdout
            output = bytearray()
            overflow, error = Event(), Event()
            reader = Thread(
                target=_read_output,
                args=(process, process.stdout, output, overflow, error),
                name="sandbox-output",
                daemon=True,
            )
            writer = Thread(
                target=_write_input,
                args=(process.stdin, payload),
                name="sandbox-input",
                daemon=True,
            )
            # Our bounded threads own these pipes. communicate only waits/reaps;
            # its Windows synchronous stdin write cannot trap the timeout.
            process.stdin = None
            process.stdout = None
            timed_out = False
            try:
                reader.start()
                writer.start()
                try:
                    process.communicate(timeout=_DEADLINE)
                except subprocess.TimeoutExpired:
                    timed_out = True
            finally:
                if process.poll() is None:
                    _kill(process)
                    process.communicate()
                for thread, stream in ((reader, output_stream), (writer, input_stream)):
                    if thread.ident is None:
                        stream.close()
                    else:
                        thread.join(timeout=0.25)
            if overflow.is_set():
                return _reject("SBX-LIMIT", "output_bytes")
            if timed_out:
                return _reject("SBX-TIMEOUT", "deadline")
            if process.returncode != 0 or error.is_set() or reader.is_alive() or writer.is_alive():
                return _reject("SBX-SYNTAX", "worker_failed")
            return _response(bytes(output))
    except (OSError, ValueError, RuntimeError):
        return _reject("SBX-SYNTAX", "worker_start")
