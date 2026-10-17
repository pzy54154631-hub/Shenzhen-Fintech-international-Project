"""Interactive simulated device control; no command-line password or OTP values."""

from pathlib import Path

import typer


def run(
    state_path: Path = typer.Option(Path("evidence/gateway/state.jsonl"), "--state"),
    audit_path: Path = typer.Option(Path("evidence/audit/bank.jsonl"), "--audit"),
    principal: str = typer.Option("C_DEMO", "--principal"),
) -> None:
    if not state_path.is_file() or not audit_path.is_file():
        typer.echo("Unlock requires an existing persisted state and audit log.", err=True)
        raise typer.Exit(2)
    from corridor.crypto.jcs import H
    from corridor.gateway.audit import AuditLog
    from corridor.gateway.mfa import MFAVerifier
    from corridor.gateway.runtime import create_gateway
    from corridor.sim.device import Device
    from corridor.sim.fixtures import make_state
    from corridor.sim.keys import signing_key
    from corridor.stores.bank import BankStore

    try:
        store = BankStore(make_state(), path=state_path)
        current = store.snapshot()
        verifier = MFAVerifier(signing_key("mfa"))
        gateway = create_gateway(
            store,
            bank_key=signing_key("bank"),
            audit=AuditLog(audit_path, checkpoint_path=audit_path.with_suffix(".checkpoint.json")),
            mfa=verifier,
        )
        if principal not in current.security.locked_at:
            typer.echo("The customer is not locked.")
            return
        if not typer.confirm("Confirm unlock on the simulated owner device?"):
            raise typer.Exit(2)
        scope = gateway.unlock_scope(principal)
        challenge = gateway.request_unlock_mfa(principal)
        if challenge is None:
            typer.echo("CTRL-MFA: unlock conditions are not satisfied.", err=True)
            raise typer.Exit(1)
        # This console is the explicit simulated device panel, not a chat tool.
        typer.echo(f"Simulated device challenge: {verifier.test_code(challenge)}")
        code = typer.prompt("Enter the device code", hide_input=True)
        grant = verifier.verify(challenge, code, now=current.now)
        if grant is None:
            typer.echo("CTRL-MFA: device verification failed.", err=True)
            raise typer.Exit(1)
        confirmation = Device(principal).confirm_input(
            intent_id=H(scope),
            slot="unlock",
            value=scope,
            now=current.now,
        )
        result = gateway.unlock(principal, confirmation, grant)
        if result.rule_ids:
            typer.echo("Unlock rejected: " + ", ".join(result.rule_ids), err=True)
            raise typer.Exit(1)
        typer.echo("Unlocked; previous approvals remain void.")
    except (ValueError, OSError, KeyError):
        typer.echo("Unlock failed; persisted evidence was retained.", err=True)
        raise typer.Exit(1) from None


def register(app: typer.Typer) -> None:
    app.command("unlock")(run)
