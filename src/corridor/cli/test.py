"""Run the repository test suite."""

import pytest
import typer


def run(full: bool = False, rules_coverage: bool = False) -> None:
    args = ["-q"]
    if full:
        args.append("--full")
    if rules_coverage:
        args.append("--rules-coverage")
    raise typer.Exit(pytest.main(args))


def register(app: typer.Typer) -> None:
    app.command("test")(run)
