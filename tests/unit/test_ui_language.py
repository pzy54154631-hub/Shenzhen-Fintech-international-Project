"""International-track UI and trusted fact templates remain English-only."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CJK = re.compile(r"[\u4e00-\u9fff]")


def test_ui_and_fact_template_string_literals_are_english_only():
    paths = sorted((ROOT / "src/corridor/ui").rglob("*.py"))
    paths.append(ROOT / "src/corridor/gateway/facts.py")
    violations = []
    for path in paths:
        source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(source):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and CJK.search(node.value)
            ):
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not violations, "Non-English UI string literals: " + ", ".join(violations)
