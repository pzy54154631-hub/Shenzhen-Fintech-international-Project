"""The verification CLI checks evidence instead of creating a new empty log."""

from typer.testing import CliRunner

from corridor.cli import app
from corridor.crypto.jcs import jcs_bytes
from corridor.gateway.audit import AuditLog


def test_verify_cli_requires_existing_evidence_and_checks_retained_head(tmp_path):
    runner = CliRunner()
    path = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "head.json"
    assert runner.invoke(app, ["verify-log", "--log", str(path)]).exit_code != 0
    assert not path.exists()
    audit = AuditLog(path)
    audit.append("fixture", now="2026-10-16T02:00:00Z", principal_token="CUSTOMER_SYNTHETIC")
    checkpoint.write_bytes(jcs_bytes(audit.checkpoint()))
    args = ["verify-log", "--log", str(path), "--checkpoint", str(checkpoint)]
    assert runner.invoke(app, args).exit_code == 0
    path.write_bytes(b"")
    assert runner.invoke(app, args).exit_code != 0


def test_unlock_cli_does_not_invent_a_missing_session(tmp_path):
    missing = tmp_path / "missing.jsonl"
    assert CliRunner().invoke(app, ["unlock", "--state", str(missing)]).exit_code != 0
    assert not missing.exists()
