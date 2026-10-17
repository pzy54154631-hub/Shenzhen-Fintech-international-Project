"""Synthetic fixture reproducibility and frozen data integrity."""

import re
from pathlib import Path

from typer.testing import CliRunner

from corridor.cli import app
from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import CATALOG, INPUT, verify
from corridor.kernel.rules import RULES
from corridor.schemas.base import loads_exact
from corridor.sim.fixtures import make_state, signed_amount, write_fixtures
from corridor.sim.keys import public_key


def test_fixture_bytes_repeat_and_directory_has_no_marketing(tmp_path):
    first = tmp_path / "a"
    second = tmp_path / "b"
    write_fixtures(first)
    write_fixtures(second)
    assert {p.name: p.read_bytes() for p in first.iterdir()} == {
        p.name: p.read_bytes() for p in second.iterdir()
    }
    state = make_state()
    assert verify(state.roots.bank_pubkey, CATALOG, state.catalog, state.catalog.sig)
    assert b"sponsored" not in jcs_bytes(state)
    assert public_key("device") != public_key("gateway") != public_key("mfa")
    value = signed_amount("test", "200/1")
    assert verify(public_key("device"), INPUT, value, value.sig)
    assert not verify(public_key("gateway"), INPUT, value, value.sig)
    assert H(state) == H(make_state())


def test_bank_rules_equal_main_specification():
    root = Path(__file__).resolve().parents[2]
    # Keep the adopted specification independent of the executable registry and
    # available in the public repository, which excludes internal design prose.
    specification = loads_exact((root / "tests/fixtures/rule_specification.json").read_bytes())
    # The private worktree also checks the source documents so later design edits
    # cannot silently leave this portable specification snapshot stale.
    for group, name, pattern in (
        ("bank", "DESIGN-BANK.md", r"^\| ([A-Z]+(?:-[A-Z]+)+) \| [KGW] /"),
        ("wealth", "DESIGN-WEALTH.md", r"^\| (ALLOC-[A-Z]+) \| K /"),
        ("inventory", "safety-rules-bank.md", r"^\| ([A-Z]+(?:-[A-Z]+)+) \|"),
    ):
        original = root / "docs" / name
        if original.exists():
            assert set(specification[group]) == set(
                re.findall(pattern, original.read_text(encoding="utf-8"), re.M)
            )
    documented = set(specification["bank"])
    wealth_rules = set(specification["wealth"])
    assert len(wealth_rules) == 6
    # Adopted wealth and F1/F2 rules preserve the human-owned base specification.
    assert set(RULES) == documented | wealth_rules | {
        "AUTH-CONSUMED",
        "RISK-ANSWERS-CONSUMED",
        "RISK-ANSWERS-STALE",
        "APR-BUDGET",
        "RISK-RETAKE-LIMIT",
        "RISK-UPGRADE-REVIEW",
    }
    assert set(RULES) == set(specification["inventory"])
    inventory = (root / "docs/submission/rule-matrix.md").read_text(encoding="utf-8")
    assert set(RULES) == set(re.findall(r"^\| `([A-Z]+(?:-[A-Z]+)+)` \|", inventory, re.M))


def test_setup_checks_hash_and_schema_without_network(tmp_path):
    write_fixtures(tmp_path)
    runner = CliRunner()
    assert runner.invoke(app, ["setup", "--data-dir", str(tmp_path)]).exit_code == 0
    path = tmp_path / "state.json"
    path.write_bytes(path.read_bytes().replace(b"10000/1", b"99999/1", 1))
    result = runner.invoke(app, ["setup", "--data-dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "integrity" in result.output.lower()


def test_device_and_private_vault_remain_separate_from_public_state():
    from corridor.crypto.sign import CONTROL
    from corridor.gateway.vault import PIIVault
    from corridor.sim.device import Device

    device = Device()
    authorization = device.login(session_id="session", expires_at="2026-10-17T02:00:00Z")
    assert verify(public_key("device"), CONTROL, authorization, authorization.sig)
    vault = PIIVault()
    token = vault.register("SYNTHETIC-PRIVATE-ACCOUNT")
    assert vault.tokenize("SYNTHETIC-PRIVATE-ACCOUNT") == token
    assert "SYNTHETIC-PRIVATE-ACCOUNT" not in repr(vault)
    assert "SYNTHETIC-PRIVATE-ACCOUNT" not in jcs_bytes(make_state()).decode("utf-8")
