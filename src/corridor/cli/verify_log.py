"""Verify an existing audit chain and an optional independently retained head."""

from pathlib import Path

import typer

from corridor.gateway.audit import AuditLog
from corridor.schemas.base import loads_exact


def run(
    log: Path = typer.Option(Path("evidence/audit/bank.jsonl"), "--log"),
    checkpoint: Path | None = typer.Option(None, "--checkpoint"),
) -> None:
    if not log.is_file():
        typer.echo("Audit log does not exist.", err=True)
        raise typer.Exit(2)
    try:
        expected = loads_exact(checkpoint.read_bytes()) if checkpoint is not None else None
        audit = AuditLog(log)
        if not audit.verify(expected):
            raise ValueError("AUD-CHAIN")
    except (ValueError, OSError, TypeError):
        typer.echo("AUD-CHAIN: audit verification failed.", err=True)
        raise typer.Exit(1) from None
    suffix = "checkpoint matched" if checkpoint is not None else "chain consistency only"
    typer.echo(f"Audit verified: {len(audit.records())} records; {suffix}.")


def register(app: typer.Typer) -> None:
    app.command("verify-log")(run)
