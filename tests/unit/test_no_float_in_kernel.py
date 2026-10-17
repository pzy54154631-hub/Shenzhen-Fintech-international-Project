"""Money in the kernel must never become binary floating point."""

from pathlib import Path

import pytest

from tests._ast_checks import float_violations

KERNEL = Path(__file__).resolve().parents[2] / "src" / "corridor" / "kernel"


def test_no_float_in_kernel() -> None:
    errors = []
    for path in sorted(KERNEL.rglob("*.py")):
        errors.extend(float_violations(path.read_text(encoding="utf-8"), str(path)))
    assert not errors, "\n".join(errors)


@pytest.mark.parametrize(
    "source",
    [
        "amount = 0.01",
        "amount = 1e3",
        "amount = float('1.2')",
        "from builtins import float as convert; amount = convert('1.2')",
        "import builtins as b; amount = b.float('1.2')",
        "convert = float; amount = convert('1.2')",
        "import builtins; amount = getattr(builtins, 'float')('1.2')",
    ],
)
def test_float_checker_rejects_literals_and_aliases(source: str) -> None:
    assert float_violations(source, "kernel.py")


def test_fraction_and_float_text_are_allowed() -> None:
    source = "from fractions import Fraction\namount = Fraction('0.01')\nlabel = 'float(1)'"
    assert not float_violations(source, "kernel.py")
