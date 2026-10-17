"""Canonical append-only audit chains with explicit retained checkpoints.

Payloads must already contain tokenized business data. Rejecting known sensitive
field names is a final guard; it cannot identify every unknown personal value.
"""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Any, cast

from corridor.crypto.jcs import jcs_bytes, json_value
from corridor.schemas.base import loads_exact
from corridor.schemas.models import JsonValue
from corridor.schemas.time import parse_time

_GENESIS = "0" * 64
_FIELDS = {
    "seq",
    "ts",
    "prev_hash",
    "event",
    "principal_token",
    "plan_id",
    "node_id",
    "payload",
    "payload_hash",
    "record_hash",
}
_SENSITIVE = {
    "otp",
    "otp_code",
    "sms_code",
    "one_time_code",
    "password",
    "passphrase",
    "pin",
    "secret",
    "api_key",
    "private_key",
    "signing_key",
    "phone",
    "phone_number",
    "mobile_number",
    "account",
    "account_number",
    "full_account",
    "full_name",
    "name",
    "raw_text",
    "raw_utterance",
    "utterance",
    "passport_number",
}


def _privacy(value: JsonValue) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.casefold().replace("-", "_").replace(" ", "_")
            if normalized in _SENSITIVE or normalized.endswith((
                "_password",
                "_private_key",
                "_otp",
                "_account_number",
                "_phone_number",
            )):
                raise ValueError("PII-OUT")
            _privacy(child)
    elif isinstance(value, list):
        for child in value:
            _privacy(child)


def _hash(value: object) -> str:
    return sha256(jcs_bytes(value)).hexdigest()


def _valid_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _head(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {"seq": len(records), "head": records[-1]["record_hash"] if records else _GENESIS}


def _checkpoint_valid(checkpoint: object, records: list[dict[str, Any]]) -> bool:
    return (
        isinstance(checkpoint, dict)
        and set(checkpoint) == {"seq", "head"}
        and type(checkpoint["seq"]) is int
        and checkpoint["seq"] >= 0
        and _valid_hash(checkpoint["head"])
        and checkpoint == _head(records)
    )


def _parse(data: bytes) -> list[dict[str, Any]]:
    if data and not data.endswith(b"\n"):
        raise ValueError("AUD-CHAIN")
    records: list[dict[str, Any]] = []
    previous = _GENESIS
    for raw in data.splitlines(keepends=True):
        if not raw.endswith(b"\n"):
            raise ValueError("AUD-CHAIN")
        line = raw[:-1]
        value = loads_exact(line)
        if not isinstance(value, dict) or set(value) != _FIELDS or jcs_bytes(value) != line:
            raise ValueError("AUD-CHAIN")
        if (
            type(value["seq"]) is not int
            or value["seq"] != len(records) + 1
            or value["prev_hash"] != previous
            or not _valid_hash(value["record_hash"])
            or not isinstance(value["payload"], dict)
            or not isinstance(value["event"], str)
            or not value["event"]
            or not isinstance(value["principal_token"], str)
            or not value["principal_token"]
            or any(
                value[key] is not None and not isinstance(value[key], str)
                for key in ("plan_id", "node_id")
            )
        ):
            raise ValueError("AUD-CHAIN")
        parse_time(value["ts"])
        _privacy(value["payload"])
        if value["payload_hash"] != _hash(value["payload"]):
            raise ValueError("AUD-CHAIN")
        if value["record_hash"] != _hash({
            key: item for key, item in value.items() if key != "record_hash"
        }):
            raise ValueError("AUD-CHAIN")
        records.append(value)
        previous = value["record_hash"]
    return records


class AuditLog:
    """One gateway-owned log; callers serialize business writes with their lock."""

    def __init__(self, path: Path | None = None, checkpoint_path: Path | None = None) -> None:
        self.path = path
        self.checkpoint_path = checkpoint_path
        self._lock = RLock()
        self._broken = False
        self._checkpoint_required = False
        if checkpoint_path is not None and (
            path is None or path.resolve() == checkpoint_path.resolve()
        ):
            raise ValueError("AUD-CHAIN")
        try:
            self._records = _parse(path.read_bytes()) if path is not None and path.exists() else []
            if checkpoint_path is not None:
                if checkpoint_path.exists():
                    if not _checkpoint_valid(
                        loads_exact(checkpoint_path.read_bytes()), self._records
                    ):
                        raise ValueError("AUD-CHAIN")
                    self._checkpoint_required = True
                elif self._records:
                    raise ValueError("AUD-CHAIN")
        except OSError as exc:
            raise OSError("AUD-WRITE") from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("AUD-CHAIN") from exc

    def _current(self) -> list[dict[str, Any]]:
        if self.path is None:
            return _parse(b"".join(jcs_bytes(record) + b"\n" for record in self._records))
        return _parse(self.path.read_bytes()) if self.path.exists() else []

    def verify(self, checkpoint: dict[str, Any] | None = None) -> bool:
        with self._lock:
            if self._broken:
                return False
            try:
                current = self._current()
                if not _checkpoint_valid(_head(self._records), current):
                    return False
                if checkpoint is not None and not _checkpoint_valid(checkpoint, current):
                    return False
                if self._checkpoint_required:
                    if self.checkpoint_path is None or not self.checkpoint_path.exists():
                        return False
                    if not _checkpoint_valid(
                        loads_exact(self.checkpoint_path.read_bytes()), current
                    ):
                        return False
                return True
            except (OSError, ValueError, TypeError, KeyError):
                return False

    def append(
        self,
        event: str,
        *,
        now: str,
        principal_token: str,
        plan_id: str | None = None,
        node_id: str | None = None,
        payload: dict[str, JsonValue] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if not self.verify():
                raise ValueError("AUD-CHAIN")
            parse_time(now)
            if (
                not isinstance(event, str)
                or not event
                or not isinstance(principal_token, str)
                or not principal_token
                or any(
                    value is not None and not isinstance(value, str) for value in (plan_id, node_id)
                )
            ):
                raise ValueError("AUD-CHAIN")
            safe_payload = cast(
                dict[str, JsonValue], json_value(payload if payload is not None else {})
            )
            if not isinstance(safe_payload, dict):
                raise ValueError("AUD-CHAIN")
            _privacy(safe_payload)
            record = {
                "seq": len(self._records) + 1,
                "ts": now,
                "prev_hash": _head(self._records)["head"],
                "event": event,
                "principal_token": principal_token,
                "plan_id": plan_id,
                "node_id": node_id,
                "payload": safe_payload,
                "payload_hash": _hash(safe_payload),
            }
            record["record_hash"] = _hash(record)
            data = jcs_bytes(record) + b"\n"
            try:
                if self.path is not None:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    with self.path.open("ab") as stream:
                        if stream.write(data) != len(data):
                            raise OSError("AUD-WRITE")
                        stream.flush()
                self._records.append(record)
                if self.checkpoint_path is not None:
                    self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
                    checkpoint_data = jcs_bytes(_head(self._records))
                    with self.checkpoint_path.open("wb") as stream:
                        if stream.write(checkpoint_data) != len(checkpoint_data):
                            raise OSError("AUD-WRITE")
                        stream.flush()
                    self._checkpoint_required = True
            except OSError as exc:
                # A partially written log or failed checkpoint is retained as evidence.
                self._broken = True
                raise OSError("AUD-WRITE") from exc
            return deepcopy(record)

    def checkpoint(self) -> dict[str, Any]:
        with self._lock:
            if not self.verify():
                raise ValueError("AUD-CHAIN")
            return deepcopy(_head(self._records))

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.verify():
                raise ValueError("AUD-CHAIN")
            return deepcopy(self._records)
