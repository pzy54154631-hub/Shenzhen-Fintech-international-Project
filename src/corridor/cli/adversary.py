"""Run forty Byzantine attempts and controls without any model calls."""

from pathlib import Path

import typer

from corridor.bench.adversary import run_adversary
from corridor.bench.bank_cases import write_json


def run(
    output: Path = typer.Option(Path("evidence/adversary")),
    results: Path = typer.Option(Path("results")),
) -> None:
    result = run_adversary(output)
    results.mkdir(parents=True, exist_ok=True)
    write_json(results / "adversary.json", result)
    lines = [
        "# Byzantine mechanism evaluation",
        "",
        "No LLM calls. Eight families × five development attacks, each with a benign twin.",
        "Paired/related attacks: confidence bounds are descriptive, not independence guarantees.",
        "",
        f"Violations: {result['violation_rate']['display']}.",
        f"Prohibited new effects: {result['prohibited_effect_rate']['display']}.",
        f"Legitimate prior effects: {result['legitimate_prior_effects']}.",
        f"Benign completion: {result['benign_completion_rate']['display']}.",
        f"False blocks: {result['false_block_rate']['display']}.",
        f"Contract assertion failures: {result['assertion_failures']}; "
        f"indeterminate oracle cases: {result['indeterminate_cases']}.",
        "",
        "| Case | Family | Expected rule | Result | Prior effects | Prohibited effects | Twin |",
        "|---|---|---|---|---:|---:|---|",
    ]
    for attack, twin in zip(result["attacks"], result["benign_twins"], strict=True):
        lines.append(
            f"| {attack['case_id']} | {attack['family']} | {attack['expected_rule']} | "
            f"{'PASS' if attack['passed'] else 'FAIL'} | {attack['legitimate_prior_effects']} | "
            f"{attack['prohibited_effects']} | {'complete' if twin['completed'] else 'failed'} |"
        )
    diff = result["differential"]
    lines += [
        "",
        f"Differential: {diff['valid_samples']} valid samples, {diff['accepted']} accepted, "
        f"{diff['disagreements']} disagreements.",
        "",
        "| Family | Samples | Accepted | Disagreements |",
        "|---|---:|---:|---:|",
    ]
    for family, counts in diff["families"].items():
        lines.append(
            f"| {family} | {counts['valid_samples']} | {counts['accepted']} | "
            f"{counts['disagreements']} |"
        )
    lines += [
        "",
        "Real-model evaluation: not_run. Blind evaluation: not_run (separate command).",
        "",
    ]
    report = "\n".join(lines)
    (results / "adversary.md").write_text(report, encoding="utf-8")
    (output / "report.md").write_text(report, encoding="utf-8")
    typer.echo(f"Violations: {result['violation_rate']['display']}")
    typer.echo(
        f"Prohibited new effects: {result['prohibited_effect_rate']['display']}; "
        f"legitimate prior effects: {result['legitimate_prior_effects']}"
    )
    typer.echo(f"Benign controls: {result['benign_completed']}/{result['benign_count']} complete")
    typer.echo(
        f"Differential: {diff['valid_samples']} valid, {diff['accepted']} accepted, "
        f"{diff['disagreements']} disagreements; LLM calls: 0"
    )
    if not result["passed"]:
        raise typer.Exit(1)


def register(app: typer.Typer) -> None:
    app.command("adversary")(run)
