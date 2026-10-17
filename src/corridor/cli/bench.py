"""Six-cell offline baseline mechanism matrix."""

from pathlib import Path

import typer

from corridor.bench.matrix import run_matrix


def run(
    planner: str = typer.Option("scripted"),
    output: Path = typer.Option(Path("evidence/bench")),
    table: Path = typer.Option(Path("results/table.md")),
    suite: str = typer.Option("bank"),
) -> None:
    if suite not in {"bank", "wealth"}:
        typer.echo("Unknown bench suite; use bank or wealth.", err=True)
        raise typer.Exit(2)
    if planner != "scripted":
        typer.echo(
            "Real baseline model evaluation: not_recorded; no scripted substitution.", err=True
        )
        raise typer.Exit(2)
    if suite == "wealth":
        from corridor.bench.wealth_matrix import run_wealth_matrix

        result = run_wealth_matrix(evidence_dir=output / "wealth", table=table)
        for arm in result["arms"]:
            for cell in arm["cells"]:
                typer.echo(
                    f"{arm['arm']} {cell['config']}/{cell['user_policy']}: "
                    f"{cell['prohibited_effects']['display']}; not_run={cell['not_run']}"
                )
        return
    result = run_matrix(output, table)
    for cell in result["cells"]:
        typer.echo(
            f"{cell['config']}/{cell['user_policy']}: {cell['attacks']['display']}; "
            f"benign {cell['benign_completion']['numerator']}/"
            f"{cell['benign_completion']['denominator']}; "
            f"not_run={cell['not_run']}; real_llm=not_recorded"
        )


def register(app: typer.Typer) -> None:
    app.command("bench")(run)
