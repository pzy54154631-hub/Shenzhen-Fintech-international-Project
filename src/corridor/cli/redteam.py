"""Run frozen external blind attacks without inventing missing results."""

from pathlib import Path

import typer

from corridor.bench.blind import run_blind_suite


def run(
    suite: str = typer.Option("blind"),
    cases: Path = typer.Option(Path("data/blind")),
    output: Path = typer.Option(Path("evidence/redteam/blind")),
    planner: str = typer.Option("record"),
    model: str = typer.Option("gpt-6.1-sol"),
    replay_dir: Path = typer.Option(Path("evidence/redteam/replay")),
    max_calls: int = typer.Option(250),
    max_usd: str | None = typer.Option(None),
    budget_path: Path = typer.Option(Path("evidence/wealth/live-budget.json")),
) -> None:
    if suite in {"blind-nl", "wealth"}:
        _natural_suite(
            suite, cases, output, planner, model, replay_dir, max_calls, max_usd, budget_path
        )
        return
    if suite != "blind":
        typer.echo("Use adversary for the development attack suite.", err=True)
        raise typer.Exit(2)
    result = run_blind_suite(cases, output)
    typer.echo(
        f"blind: {result['status']}; {result['executed']}/16; "
        f"violations {result['violation_rate']['display']}"
    )
    if result["status"] == "invalid" or any(not row["passed"] for row in result["cases"]):
        raise typer.Exit(2)


def _natural_suite(
    suite, cases, output, planner, model, replay_dir, max_calls, max_usd, budget_path
):
    from corridor.agent.llm import LLMClient
    from corridor.bench.blind_nl import load_frozen_cases, run_natural_blind_suite
    from corridor.bench.recording import LaneRecordingClient, network_disabled

    if planner not in {"record", "strict"}:
        typer.echo(
            "Natural-language evaluation requires record or strict; no scripted substitution."
        )
        raise typer.Exit(2)
    if suite == "blind-nl":
        load_frozen_cases(cases)  # Integrity must pass before credentials or model initialization.
    try:
        client = (
            LaneRecordingClient(
                mode="record",
                model=model,
                replay_dir=replay_dir,
                max_calls=max_calls,
                max_usd=max_usd,
                budget_path=budget_path,
                budget_group="blind" if suite == "blind-nl" else "redteam",
            )
            if planner == "record"
            else LLMClient(mode="strict", model=model, replay_dir=replay_dir, env_file=None)
        )

        def execute():
            if suite == "blind-nl":
                return run_natural_blind_suite(cases, output, client)
            from corridor.bench.wealth_redteam import run_wealth_redteam

            return run_wealth_redteam(client, output)

        if planner == "strict":
            with network_disabled():
                result = execute()
        else:
            result = execute()
        if suite == "blind-nl":
            typer.echo(
                f"blind-nl: {result['status']}; {result['executed']}/16; "
                f"violations {result['violation_rate']['display']}"
            )
            if not all(row["passed"] for row in result["cases"]):
                raise typer.Exit(1)
        else:
            from corridor.bench.wealth_redteam import render_wealth_redteam

            report = Path("results/wealth-redteam-" + planner + ".md")
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(render_wealth_redteam(result), encoding="utf-8")
            typer.echo(f"wealth redteam: {result.get('status', 'see report')}; {report}")
            if (
                result["incomplete"]
                or result["terminal_errors"]
                or result["forbidden_cases"]
                or result["benign_completed"] != result["benign_cases"]
            ):
                raise typer.Exit(1)
    except typer.Exit:
        raise
    except (ValueError, RuntimeError, OSError) as exc:
        typer.echo(f"Natural-language evaluation failed: {type(exc).__name__}", err=True)
        raise typer.Exit(2) from None


def register(app: typer.Typer) -> None:
    app.command("redteam")(run)
