"""Rule coverage reporting and deterministic property-test configuration."""

import ast
import re
from collections.abc import Iterable

import pytest
from hypothesis import settings

_ASSERTED = pytest.StashKey[set[str]]()
_COVERED = pytest.StashKey[set[str]]()


def asserted_rule_ids(expression: str, explanation: str) -> set[str]:
    """Only positive, executed comparisons count, never reprs in diagnostic details."""
    from corridor.kernel.rules import RULES

    tree = ast.parse(expression, mode="eval")
    if any(isinstance(node, (ast.Or, ast.IfExp)) for node in ast.walk(tree)):
        return set()

    def comparisons_in(node: ast.AST) -> list[ast.Compare]:
        if isinstance(node, ast.Compare):
            return [node]
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            return [comparison for value in node.values for comparison in comparisons_in(value)]
        return []

    comparisons = comparisons_in(tree.body)
    positive = [
        node for node in comparisons if all(isinstance(op, (ast.Eq, ast.In)) for op in node.ops)
    ]
    if not positive:
        return set()
    # Compared sets may span lines; pytest's '+ where' details contain object reprs.
    comparison = re.split(r"\n\s*\+", explanation, maxsplit=1)[0]
    values = (
        set(re.findall(r"['\"]([A-Z]+(?:-[A-Z]+)+)['\"]", comparison))
        if len(positive) == len(comparisons)
        else set()
    )
    # pytest truncates equal container reprs even for successful assertions.
    # Literal expectations in an executed positive comparison remain exact.
    for part in positive:
        for operand in (part.left, *part.comparators):
            literals = (
                operand.elts if isinstance(operand, (ast.List, ast.Set, ast.Tuple)) else [operand]
            )
            values.update(
                node.value
                for node in literals
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            )
    return values & RULES.keys()


def require_rule_assertions(marked: set[str], asserted: set[str]) -> None:
    missing = marked - asserted
    if missing:
        raise AssertionError(
            "Rule markers without executed rule assertions: " + ", ".join(sorted(missing))
        )


def missing_rule_ids(registered: Iterable[str], covered: Iterable[str]) -> list[str]:
    return sorted(set(registered) - set(covered))


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("corridor")
    group.addoption("--full", action="store_true", help="Use 10,000 Hypothesis examples.")
    group.addoption(
        "--rules-coverage", action="store_true", help="Report rules without marked tests."
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "rule(id): golden coverage for a registered rule")
    settings.register_profile("dev", max_examples=100, deadline=None, derandomize=True)
    settings.register_profile("full", max_examples=10_000, deadline=None, derandomize=True)
    settings.load_profile("full" if config.getoption("--full") else "dev")
    config.stash[_COVERED] = set()


def pytest_assertion_pass(item: pytest.Item, lineno: int, orig: str, expl: str) -> None:
    if any(item.iter_markers("rule")):
        item.stash.setdefault(_ASSERTED, set()).update(asserted_rule_ids(orig, expl))


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item):
    yield
    marked = {marker.args[0] for marker in item.iter_markers("rule")}
    asserted = item.stash.get(_ASSERTED, set())
    require_rule_assertions(marked, asserted)
    item.config.stash[_COVERED].update(marked & asserted)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    from corridor.kernel.rules import RULES

    for item in items:
        for marker in item.iter_markers("rule"):
            if len(marker.args) != 1 or marker.kwargs or marker.args[0] not in RULES:
                raise pytest.UsageError(f"{item.nodeid}: invalid rule marker {marker.args!r}")


def pytest_terminal_summary(terminalreporter: object, config: pytest.Config) -> None:
    if not config.getoption("--rules-coverage"):
        return
    from corridor.kernel.rules import RULES

    covered = config.stash[_COVERED]
    missing = missing_rule_ids(RULES, covered)
    getattr(terminalreporter, "write_sep")("=", "Rules without golden tests")
    getattr(terminalreporter, "write_line")("\n".join(missing) if missing else "(none)")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if session.config.getoption("--rules-coverage"):
        from corridor.kernel.rules import RULES

        if missing_rule_ids(RULES, session.config.stash[_COVERED]):
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
