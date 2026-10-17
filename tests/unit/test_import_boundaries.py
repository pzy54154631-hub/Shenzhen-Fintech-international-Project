"""The AST contract is authoritative for production import boundaries."""

from pathlib import Path

import pytest

from tests._ast_checks import import_violations

SOURCE = Path(__file__).resolve().parents[2] / "src" / "corridor"


def test_production_import_boundaries() -> None:
    errors = []
    for path in sorted(SOURCE.rglob("*.py")):
        module = ".".join(path.relative_to(SOURCE.parent).with_suffix("").parts)
        errors.extend(import_violations(path.read_text(encoding="utf-8"), module))
    assert not errors, "\n".join(errors)


@pytest.mark.parametrize(
    "source",
    [
        "import corridor.agent.planner as safe",
        "from corridor import agent",
        "from ..agent import planner",
        "from corridor.agent import *",
        "import httpx as local",
        "from urllib.parse import urlparse",
        "import importlib as il; il.import_module('corridor.sim.keys')",
        "from importlib import import_module as load; load('httpx')",
        "loader = __import__; loader('corridor.gateway')",
        "import importlib; getattr(importlib, 'import_module')('requests')",
        "import importlib; name = 'corridor.' + 'agent'; importlib.import_module(name)",
        "import importlib; importlib.import_module(name)",
        "import importlib; importlib.import_module('..sim', 'corridor.kernel')",
    ],
)
def test_rejects_tcb_dependency_bypasses(source: str) -> None:
    assert import_violations(source, "corridor.kernel.check")


@pytest.mark.parametrize("package", ["kernel", "stores", "schemas", "crypto"])
def test_all_core_tcb_packages_are_protected(package: str) -> None:
    assert import_violations("import asyncio", f"corridor.{package}.module")


@pytest.mark.parametrize("package", ["mockbank", "reforacle"])
@pytest.mark.parametrize("dependency", ["kernel", "stores", "gateway", "agent"])
def test_independent_evaluation_cannot_read_decision_or_execution_policy(package, dependency):
    assert import_violations(f"import corridor.{dependency}", f"corridor.eval.{package}.oracle")


@pytest.mark.parametrize(
    "source",
    ["from ... import kernel", "import corridor.stores", "from ...stores import state"],
)
@pytest.mark.parametrize("package", ["mockbank", "reforacle"])
def test_independent_evaluators_cannot_read_kernel_or_stores(source: str, package: str) -> None:
    assert import_violations(source, f"corridor.eval.{package}.harm")


@pytest.mark.parametrize(
    "source",
    [
        "from corridor.eval.mockbank.exec import MockBank",
        "from corridor.eval.mockbank import exec",
        "from ..eval.mockbank import exec",
        "import importlib; importlib.import_module('corridor.eval.mockbank.exec')",
    ],
)
def test_untrusted_callers_cannot_import_execution(source: str) -> None:
    assert import_violations(source, "corridor.agent.planner")


@pytest.mark.parametrize("module", ["corridor.gateway.core", "corridor.bench.baseline_exec"])
def test_only_execution_entrypoints_can_import_mockbank_exec(module: str) -> None:
    assert not import_violations("import corridor.eval.mockbank.exec", module)


def test_package_init_resolves_relative_imports() -> None:
    assert import_violations("from .. import sim", "corridor.kernel.__init__")
    assert not import_violations("from . import rules", "corridor.kernel.__init__")


def test_similar_package_names_are_not_false_positives() -> None:
    assert not import_violations("import httpx_local", "corridor.kernel.check")
    assert import_violations(
        "import corridor.eval.mockbank.exec", "corridor.bench.baseline_exec_extra"
    )


@pytest.mark.parametrize(
    "module", ["corridor.agent.planner", "corridor.ui.app", "corridor.gateway.service"]
)
def test_baseline_bypass_is_available_only_to_bench(module: str) -> None:
    assert import_violations("from corridor.bench.baseline_exec import BaselineExecutor", module)
    assert not import_violations(
        "from corridor.bench.baseline_exec import BaselineExecutor", "corridor.bench.matrix"
    )
