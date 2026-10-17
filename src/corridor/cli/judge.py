"""Run implemented bank judge scenarios with explicit evidence provenance."""

from pathlib import Path

import typer

from corridor.agent.llm import LLMClient
from corridor.bench.bank_cases import write_json
from corridor.bench.billing_runner import run_billing
from corridor.bench.card_runner import run_cards
from corridor.bench.investment_runner import run_investment
from corridor.bench.judge_catalog import validate_result
from corridor.bench.judge_runner import run_completion
from corridor.bench.planning_runner import run_planning
from corridor.bench.sandbox_runner import run_sandbox
from corridor.bench.security_runner import run_security
from corridor.bench.transfer_runner import run_j01

IMPLEMENTED = (
    "J01",
    "J02",
    "J03",
    "J04",
    "J05",
    "J06",
    "J07",
    "J08",
    "J09",
    "J10",
    "J11",
    "J12",
    "J13",
    "J14",
    "J15",
    "J16",
    "J17",
    "J18",
    "J19",
    "J20",
    "J21",
    "J22",
    "J23",
    "J24",
)


def run_bank_task(task: str, client: LLMClient, destination: Path) -> dict:
    """One unchanged J runner shared by scripted, recording and strict replay."""
    if task not in IMPLEMENTED:
        raise ValueError("Unknown J task")
    if task == "J01":
        result = run_j01(client, evidence_dir=destination / "transfer")
    elif task in {"J02", "J03", "J04", "J05", "J09"}:
        result = run_completion(task, evidence_dir=destination, client=client)
    elif task in {"J21", "J22"}:
        result = run_security(task, evidence_dir=destination, client=client)
    elif task in {"J23", "J24"}:
        result = run_cards(task, evidence_dir=destination, client=client)
    elif task in {"J07", "J10", "J11"}:
        result = run_billing(task, evidence_dir=destination, client=client)
    elif task in {"J06", "J19", "J20"}:
        result = run_planning(task, evidence_dir=destination, client=client)
    elif task == "J08":
        result = run_sandbox(client=client, evidence_dir=destination)
    else:
        result = run_investment(task, evidence_dir=destination, client=client)
    validate_result(task, result)
    return result


def run(
    planner: str = typer.Option("strict"),
    model: str = typer.Option("scripted-bank-v1"),
    tasks: str = typer.Option(""),
    suite: str = typer.Option("p0"),
    replay_dir: Path = typer.Option(Path("data/replay/bank")),
    output: Path = typer.Option(Path("evidence/judge")),
) -> None:
    if planner not in {"scripted", "strict"} or suite not in {"implemented", "p0", "all", "wealth"}:
        typer.echo("Judge requires strict/scripted and suite implemented/p0/all/wealth.", err=True)
        raise typer.Exit(2)
    if suite == "wealth":
        from corridor.bench.wealth_runner import run_wealth_suite

        source = "scripted" if planner == "scripted" else "strict-replay"
        client = LLMClient(mode=planner, replay_dir=replay_dir, model=model)
        result = run_wealth_suite(
            client=client,
            evidence_dir=output / "wealth" / source,
            task_ids=[item.strip() for item in tasks.split(",") if item.strip()] if tasks else None,
        )
        rows = result["cases"] if "cases" in result else result["results"]
        for row in rows:
            typer.echo(
                f"{row['task_id']}: scripted mechanism "
                f"{'PASS' if row['passed'] else 'FAIL'}; "
                f"dialogue={row.get('live_status', 'not_run')}; requested source={source}"
            )
        typer.echo(
            f"Wealth W scripted mechanisms: {sum(row['passed'] for row in rows)}/{len(rows)}; "
            "J: not_run"
        )
        if (
            not rows
            or not all(row["passed"] for row in rows)
            or (planner == "strict" and not all(row.get("live_passed") is True for row in rows))
        ):
            raise typer.Exit(1)
        return
    selected = (
        [item.strip() for item in tasks.split(",") if item.strip()]
        if tasks
        else list(IMPLEMENTED)
        if suite == "implemented"
        else [f"J{index:02d}" for index in range(1, 23 if suite == "p0" else 25)]
    )
    rows: list[str] = []
    if tasks and any(task not in IMPLEMENTED for task in selected):
        typer.echo(
            "not_implemented: " + ", ".join(task for task in selected if task not in IMPLEMENTED)
        )
        raise typer.Exit(2)
    failed = False
    results = []
    for task in selected:
        destination = output / planner / "cca" / "careful" / task
        try:
            client = LLMClient(mode=planner, replay_dir=replay_dir, model=model)
            result = run_bank_task(task, client, destination)
            status = "PASS" if result["passed"] else "FAIL"
            failed |= not result["passed"]
            results.append(result)
        except (ValueError, RuntimeError, OSError) as exc:
            status = str(exc)
            failed = True
            results.append({"task_id": task, "passed": False, "status": status})
        typer.echo(f"{task}: {status}; planner={planner}")
        rows.append(f"| {task} | {planner} | {status.replace(chr(10), ' ')} |")
    p0 = [item for item in results if item["task_id"] <= "J22"]
    p1 = [item for item in results if item["task_id"] in {"J23", "J24"}]
    scope_summary = f"P0: {sum(item['passed'] for item in p0)}/{len(p0)}; " + (
        f"P1: {sum(item['passed'] for item in p1)}/{len(p1)}."
        if p1
        else "P1 J23/J24: excluded from this selected suite."
    )
    report = Path("results/judge.md")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        "# Bank judge\n\n"
        "| Task | Planner | Result |\n|---|---|---|\n"
        + "\n".join(rows)
        + f"\n\n{scope_summary} D0/D3 matrices are reported by bench.\n"
        + (
            "Real-model evaluation: not_run; scripted evidence is development-only.\n"
            if planner == "scripted"
            else "Strict mode never substitutes scripted responses.\n"
        ),
        encoding="utf-8",
    )
    write_json(
        output / planner / "judge.json",
        {
            "planner_mode": planner,
            "suite": suite,
            "results": results,
            "passed": sum(item["passed"] for item in results),
            "total": len(selected),
        },
    )
    typer.echo(
        f"Judge: {sum(item['passed'] for item in results)}/{len(selected)} PASS; {scope_summary}"
    )
    if planner == "scripted":
        typer.echo("Real-model evaluation: not_run. Scripted evidence is development-only.")
    if failed:
        raise typer.Exit(1)


def register(app: typer.Typer) -> None:
    app.command("judge")(run)
