"""Validate local synthetic fixtures without network access."""

from pathlib import Path

import typer

from corridor.sim.fixtures import validate_fixtures


def run(
    data_dir: Path = typer.Option(Path("data/bank"), help="Local frozen fixture directory."),
) -> None:
    """Validate local bank fixtures and configuration without network access."""
    try:
        state = validate_fixtures(data_dir)
    except (ValueError, OSError, KeyError) as exc:
        typer.echo(f"Local fixture integrity check failed: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"Local bank-v1 fixtures verified: {len(state.accounts)} synthetic accounts.")


def register(app: typer.Typer) -> None:
    app.command("setup")(run)
