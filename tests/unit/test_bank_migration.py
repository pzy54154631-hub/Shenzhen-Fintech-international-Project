"""The executable package exposes only the domestic bank domain."""

import ast
import importlib.util
from pathlib import Path

import pytest
from typer.testing import CliRunner

from corridor import schemas
from corridor.cli import app
from corridor.crypto.sign import CONTEXTS
from corridor.kernel.rules import RULES
from corridor.schemas import models
from corridor.schemas.money import Money

SOURCE = Path(__file__).resolve().parents[2] / "src" / "corridor"
REMOVED_MODELS = (
    "RFQ",
    "SignedQuote",
    "SignedUnavailable",
    "DirectoryProvider",
    "ECBSnapshot",
    "StandingMandate",
    "Lease",
    "LeaseRevocation",
    "LeaseTerm",
    "PaymentAction",
    "QuoteCost",
    "PDR",
    "Household",
    "HouseholdMember",
    "HouseholdAccount",
    "GroundTruthQuote",
    "IntendedPayment",
    "Assumption",
)


@pytest.mark.parametrize("name", REMOVED_MODELS)
def test_removed_domain_models_are_not_public_or_declared(name: str) -> None:
    assert not hasattr(schemas, name)
    assert not hasattr(models, name)
    for path in SOURCE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not any(
            isinstance(node, ast.ClassDef) and node.name == name for node in ast.walk(tree)
        )


@pytest.mark.parametrize("currency", ["USD", "EUR", "INR", "MXN"])
def test_money_is_cny_only(currency: str) -> None:
    with pytest.raises(ValueError):
        Money.model_validate({"amount": "1/1", "ccy": currency})


def test_obsolete_signature_domains_and_rules_are_gone() -> None:
    assert all(ctx.startswith("corridor/bank/") and ctx.endswith("/v1") for ctx in CONTEXTS)
    for rule in RULES:
        assert not rule.startswith(("BX-", "CMP-", "EGR-", "AUTH-NARROW-", "AUTH-MEMBER-"))
        assert "CORRIDOR" not in rule


def test_old_execution_package_is_replaced() -> None:
    assert importlib.util.find_spec("corridor.eval.simbank") is None
    assert importlib.util.find_spec("corridor.eval.mockbank") is not None


def test_setup_has_no_refresh_option_or_network_configuration() -> None:
    runner = CliRunner()
    help_result = runner.invoke(app, ["setup", "--help"])
    assert help_result.exit_code == 0
    assert "--refresh" not in help_result.stdout
    assert "local" in help_result.stdout.lower()
    assert runner.invoke(app, ["setup", "--refresh"]).exit_code != 0
    source = (SOURCE / "cli" / "setup.py").read_text(encoding="utf-8")
    assert "data/fx" not in source and "http" not in source


def test_runtime_has_no_obsolete_market_contracts() -> None:
    forbidden = ("ecb.europa", "api.frankfurter", "corridor/rfq/", "corridor/quote/")
    for path in SOURCE.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert not any(value in source for value in forbidden), path
