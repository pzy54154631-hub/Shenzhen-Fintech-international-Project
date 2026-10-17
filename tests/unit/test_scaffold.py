"""Scaffolding exposes commands and the retained generic rule catalog."""

from typer.testing import CliRunner

from corridor.cli import app
from corridor.kernel.rules import RULES


def test_cli_and_tcb() -> None:
    runner = CliRunner()
    assert runner.invoke(app, ["--help"]).exit_code == 0
    result = runner.invoke(app, ["tcb"])
    assert result.exit_code == 0
    for package in ("kernel", "stores", "schemas", "crypto", "gateway"):
        assert f"{package}:" in result.stdout


def test_generic_rules_remain_registered() -> None:
    for name in ("SCHEMA-INVALID", "SCHEMA-TIME", "SCHEMA-UNIT", "CERT-HASH"):
        assert RULES[name].enforced_by == "kernel"


def test_evidence_command_fails_explicitly_for_missing_source(tmp_path) -> None:
    source = tmp_path / "missing-evidence"
    target = tmp_path / "artifacts" / "bundle.zip"
    result = CliRunner().invoke(app, ["evidence", "--source", str(source), "--output", str(target)])
    assert result.exit_code == 2
    assert "Evidence source must be a directory" in result.output
    assert not source.exists()
    assert not target.parent.exists()


def test_full_profile_reaches_pytest(monkeypatch) -> None:
    captured = []
    monkeypatch.setattr("corridor.cli.test.pytest.main", lambda args: captured.extend(args) or 0)
    assert CliRunner().invoke(app, ["test", "--full", "--rules-coverage"]).exit_code == 0
    assert "--full" in captured and "--rules-coverage" in captured
