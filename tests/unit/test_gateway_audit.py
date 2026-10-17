"""Canonical append-only audit evidence and retained-checkpoint verification."""

from copy import deepcopy
from hashlib import sha256

import pytest

from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.audit import AuditLog
from corridor.schemas.base import loads_exact

NOW = "2026-10-16T02:00:00Z"


def append(log, **kwargs):
    return log.append(
        "kernel_verdict",
        now=NOW,
        principal_token="CUSTOMER_SYNTHETIC",
        plan_id="PLAN",
        node_id="NODE",
        **kwargs,
    )


def test_in_memory_chain_has_exact_payload_and_record_hashes():
    log = AuditLog()
    assert log.checkpoint() == {"seq": 0, "head": "0" * 64}
    payload = {"sig": "a" * 128, "amount": "200/1", "rule_ids": ["AUTH-SCOPE"]}
    first = append(log, payload=payload)
    assert first["seq"] == 1 and first["prev_hash"] == "0" * 64
    assert first["payload_hash"] == sha256(jcs_bytes(payload)).hexdigest()
    assert first["payload_hash"] != H(payload)  # Audit hashing must not discard a signature.
    body = {key: value for key, value in first.items() if key != "record_hash"}
    assert first["record_hash"] == sha256(jcs_bytes(body)).hexdigest()
    second = append(log)
    assert second["seq"] == 2 and second["prev_hash"] == first["record_hash"]
    assert log.verify() and log.verify(log.checkpoint())


def test_binary_jcs_lines_and_restart_with_checkpoint(tmp_path):
    path, checkpoint = tmp_path / "audit.jsonl", tmp_path / "checkpoint.json"
    log = AuditLog(path, checkpoint)
    record = append(log, payload={"amount": "1/100"})
    assert path.read_bytes() == jcs_bytes(record) + b"\n"
    assert b"\r" not in path.read_bytes()
    assert loads_exact(checkpoint.read_bytes()) == log.checkpoint()
    restarted = AuditLog(path, checkpoint)
    assert restarted.records() == [record]
    assert restarted.verify()
    append(restarted)
    assert restarted.checkpoint()["seq"] == 2


@pytest.mark.rule("AUD-CHAIN")
@pytest.mark.parametrize(
    "tamper", ["content", "delete", "reorder", "partial", "newline", "spacing"]
)
def test_corrupt_log_never_appends_or_repairs_itself(tmp_path, tamper):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    records = [append(log, payload={"value_hash": H(index)}) for index in range(3)]
    lines = [jcs_bytes(record) + b"\n" for record in records]
    if tamper == "content":
        lines[0] = lines[0].replace(b"kernel_verdict", b"unknown_event")
    elif tamper == "delete":
        del lines[1]
    elif tamper == "reorder":
        lines[0], lines[1] = lines[1], lines[0]
    elif tamper == "partial":
        lines[-1] = lines[-1][:20]
    elif tamper == "newline":
        lines[-1] = lines[-1].rstrip(b"\n")
    else:
        lines[0] = b" " + lines[0]
    corrupted = b"".join(lines)
    path.write_bytes(corrupted)
    assert not log.verify()
    with pytest.raises(ValueError, match="AUD-CHAIN") as error:
        append(log)
    assert str(error.value) == "AUD-CHAIN"
    assert path.read_bytes() == corrupted


def test_valid_tail_truncation_requires_retained_checkpoint_on_restart(tmp_path):
    path, checkpoint_path = tmp_path / "audit.jsonl", tmp_path / "head.json"
    log = AuditLog(path, checkpoint_path)
    first = append(log)
    append(log)
    retained = log.checkpoint()
    path.write_bytes(jcs_bytes(first) + b"\n")
    assert not log.verify()
    standalone = AuditLog(path)
    assert standalone.verify()  # A self-consistent prefix cannot prove completeness.
    assert not standalone.verify(retained)
    with pytest.raises(ValueError, match="AUD-CHAIN"):
        AuditLog(path, checkpoint_path)


def test_missing_retained_checkpoint_is_not_silently_replaced(tmp_path):
    path, checkpoint = tmp_path / "audit.jsonl", tmp_path / "head.json"
    log = AuditLog(path, checkpoint)
    append(log)
    checkpoint.unlink()
    with pytest.raises(ValueError, match="AUD-CHAIN"):
        AuditLog(path, checkpoint)


def test_records_and_payload_are_detached_copies():
    log = AuditLog()
    payload = {"ids": ["INPUT_1"]}
    record = append(log, payload=payload)
    pristine = deepcopy(record)
    payload["ids"].append("INPUT_2")
    record["payload"]["ids"].append("INPUT_3")
    copied = log.records()
    copied[0]["payload"]["ids"].append("INPUT_4")
    assert log.records() == [pristine]
    assert log.verify()


@pytest.mark.rule("PII-OUT")
@pytest.mark.parametrize(
    "key", ["otp", "password", "private_key", "phone", "account_number", "full_name", "raw_text"]
)
def test_sensitive_payload_keys_fail_without_leaking_values(tmp_path, key):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    with pytest.raises(ValueError, match="^PII-OUT$") as error:
        append(log, payload={"nested": [{key: "SYNTHETIC_SECRET_MARKER"}]})
    assert str(error.value) == "PII-OUT"
    assert not path.exists() or path.read_bytes() == b""
    assert log.records() == []


def test_tokenized_identifiers_hashes_and_signatures_are_allowed():
    log = AuditLog()
    append(
        log,
        payload={
            "name_token": "NAME_X",
            "phone_token": "PHONE_X",
            "token_id": "TOKEN_X",
            "input_hash": H("input"),
            "sig": "0" * 128,
        },
    )
    assert log.verify()


def test_file_write_failure_is_reported_without_false_success(tmp_path):
    directory = tmp_path / "audit_is_a_directory"
    directory.mkdir()
    with pytest.raises(OSError, match="AUD-WRITE"):
        AuditLog(directory)


@pytest.mark.rule("AUD-WRITE")
def test_checkpoint_write_failure_does_not_claim_log_rollback(tmp_path):
    path, checkpoint = tmp_path / "audit.jsonl", tmp_path / "checkpoint.json"
    log = AuditLog(path, checkpoint)
    checkpoint.mkdir()
    with pytest.raises(OSError, match="AUD-WRITE") as error:
        append(log)
    assert "AUD-WRITE" in str(error.value)
    assert path.read_bytes().endswith(b"\n")
    assert len(path.read_bytes().splitlines()) == 1


def test_bad_checkpoint_and_boolean_sequence_are_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    record = append(log)
    assert not log.verify({"seq": True, "head": record["record_hash"]})
    record["seq"] = True
    record["record_hash"] = sha256(
        jcs_bytes({k: v for k, v in record.items() if k != "record_hash"})
    ).hexdigest()
    path.write_bytes(jcs_bytes(record) + b"\n")
    with pytest.raises(ValueError, match="AUD-CHAIN"):
        AuditLog(path)


@pytest.mark.parametrize(
    "field,value", [("principal_token", 42), ("plan_id", 42), ("node_id", []), ("event", [])]
)
def test_invalid_record_metadata_never_poisons_the_chain(tmp_path, field, value):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    args = {
        "event": "test_event",
        "now": NOW,
        "principal_token": "CUSTOMER_TEST",
        "plan_id": "PLAN",
        "node_id": "NODE",
        field: value,
    }
    with pytest.raises(ValueError, match="AUD-CHAIN"):
        log.append(**args)
    assert log.records() == [] and log.verify()
    assert not path.exists()
