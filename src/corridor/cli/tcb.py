"""Report trusted code size and direct third-party imports."""

import ast
import sys
from pathlib import Path

import typer


def run() -> None:
    root = Path(__file__).resolve().parents[1]
    for package in ("kernel", "stores", "schemas", "crypto", "gateway"):
        lines = 0
        dependencies = set()
        for path in sorted((root / package).rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            lines += sum(
                bool(line.strip()) and not line.lstrip().startswith("#")
                for line in source.splitlines()
            )
            for node in ast.walk(ast.parse(source)):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    if top not in sys.stdlib_module_names and top != "corridor":
                        dependencies.add(top)
        deps = ", ".join(sorted(dependencies)) or "stdlib only"
        typer.echo(f"{package}: {lines} LOC; dependencies: {deps}")


def register(app: typer.Typer) -> None:
    app.command("tcb")(run)
