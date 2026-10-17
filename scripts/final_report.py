"""Build the final English result ledger from completed, retained F5 artifacts."""

import re
from fractions import Fraction
from pathlib import Path

from corridor.bench.metrics import binomial_summary
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact
from corridor.schemas.money import fraction_string

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "final-f5"
COMPACT = ROOT / "evidence" / "final-summary"
J_TASKS = tuple(f"J{number:02d}" for number in range(1, 25))
W_TASKS = tuple(f"W{number:02d}" for number in range(1, 13))
MODELS = ("gpt-6.1-sol", "gpt-6-luna", "gpt-5.4-mini")


def read(path: Path):
    return loads_exact(path.read_bytes())


def link(path: Path) -> str:
    relative = path.relative_to(ROOT).as_posix()
    return f"[{relative}](../{relative})"


def upper(count: int, total: int) -> str:
    summary = binomial_summary(count, total)
    if not total:
        return "not_run"
    if not count:
        return (
            f"approximately min(1, 3/{total}) = {float(min(Fraction(1), Fraction(3, total))):.4%}"
        )
    return f"{float(summary['wilson_95']['upper']):.4%} (Wilson)"


def exact_ids(rows, key, expected, label):
    observed = [row[key] for row in rows]
    if len(observed) != len(set(observed)) or set(observed) != set(expected):
        raise ValueError(f"Incomplete or repeated {label} coverage")


def evidence_mode(sources):
    observed = set(sources)
    if not observed or observed == {"not_run"}:
        return "not_run"
    return next(iter(observed)) if len(observed) == 1 else "mixed"


def failed_outcomes(rows, *, require_completion=False):
    return [
        row
        for row in rows
        if row.get("passed") is not True
        or require_completion
        and row.get("task_completed") is not True
    ]


def _population(rows, measured_key, effect, cash_key):
    measured = [row for row in rows if row.get(measured_key) is True]
    incomplete = [row for row in rows if row.get(measured_key) is not True]
    return {
        "total": len(measured),
        "passed": sum(row.get("passed") is True for row in measured),
        "adverse": sum(bool(effect(row)) for row in measured),
        "incomplete": len(incomplete),
        "observed_effects_all": sum(bool(effect(row)) for row in rows),
        "incomplete_observed_effects": sum(bool(effect(row)) for row in incomplete),
        "incomplete_funds_cny": fraction_string(
            sum((Fraction(row.get(cash_key, "0/1")) for row in incomplete), Fraction())
        ),
        "evidence_failures": sum(bool(row.get("evidence_failures")) for row in rows),
    }


def redteam_population(report):
    return _population(
        [pair["attack"] for pair in report["pairs"]],
        "measured",
        lambda row: row.get("observed_forbidden_effects"),
        "funds_moved",
    )


def blind_population(report):
    return _population(
        report["cases"],
        "evaluated",
        lambda row: row.get("violation_observed"),
        "cash_debit_cny",
    )


def validate_recording(run, stage, model):
    expected = J_TASKS + W_TASKS if stage == "main" else ("J02", "W04")
    if run["model_profile"]["model"].removeprefix("openai/") != model:
        raise ValueError("Recording model identity mismatch")
    exact_ids(run["results"], "task_id", expected, "model task")


def _diagnostics(population, mode, path):
    return (
        f"{mode}: {population['incomplete']} incomplete observations; "
        f"{population['incomplete_observed_effects']} with observed forbidden effects; "
        f"confirmed debit {population['incomplete_funds_cny']} CNY in incomplete observations "
        f"(not a loss estimate); {population['evidence_failures']} independent evidence failures. "
        f"These diagnostics are separate from the measured rate. {link(path)}"
    )


def main() -> None:
    lines = [
        "# Final integrated results",
        "",
        "Every experiment below uses synthetic data and simulated authentication. "
        "No real financial transaction is performed. Evidence modes and denominators are "
        "kept separate; replay is a reproducibility check, not a second independent sample.",
        "",
        "The replay-equality measurements below are historical F5 results obtained on the code "
        "before I1. Strict replay on the current code: 142/142 verified, with 141 raw observations "
        "byte-for-byte identical and 1 (J01) verified by a migration proof because the bilingual "
        "port changed the audit fact-hash format. The original recordings remain unchanged; "
        "replay verification preserves recorded failures. "
        "See the [reproduction instructions](../README.md).",
        "",
        "For completion rows, the upper bound concerns the failure proportion. "
        "For attack rows, it concerns observed forbidden effects. Zero-event bounds use "
        "min(1, 3/n); nonzero rows use the upper endpoint of a 95% Wilson interval. "
        "Paired and authored cases are correlated, so these bounds are descriptive. "
        "Counts, costs, source hashes and file sizes are measurements with no binomial bound.",
        "",
        "## Quality gates",
        "",
        "| Check | Role | Mode | Measured result | Evidence |",
        "|---|---|---|---|---|",
    ]
    aggregate: dict = {"schema_version": "f5-final-summary-v1", "gates": [], "measurements": []}
    failures = []
    gates = ["test", "rules", "ruff", "format", "mypy", "imports"]
    test_gates = ["test"]
    for label in ("test-rules-final", "test-rules-verified"):
        if (EVIDENCE / "checks" / f"{label}.json").is_file():
            gates.append(label)
            test_gates.append(label)
    aggregate["preferred_test_gate"] = test_gates[-1]
    for label in gates:
        path = EVIDENCE / "checks" / f"{label}.json"
        record = read(path)
        log = (ROOT / record["log"]).read_text(encoding="utf-8")
        matches = re.findall(
            r"^[= \t]*(\d+ (?:failed|passed|skipped|errors?|xfailed|xpassed|deselected)\b[^\r\n]*)",
            log,
            re.MULTILINE,
        )
        measured = (
            matches[-1].strip(" =") if matches else "PASS" if record["returncode"] == 0 else "FAIL"
        )
        role = (
            "retained_attempt"
            if label in test_gates and label != aggregate["preferred_test_gate"]
            else "final_gate"
        )
        role_label = "retained earlier attempt" if role == "retained_attempt" else "final gate"
        interruption_path = path.with_name(label + "-interruption.json")
        interrupted = interruption_path.is_file() and record["returncode"] != 0
        if label in {"rules", "test-rules-final", "test-rules-verified"}:
            measured += "; uncovered rules: " + ("none" if "(none)" in log else "see log")
        if interrupted:
            measured = "INTERRUPTED; no complete pytest summary or rules coverage result"
            failures.append(
                f"Quality gate {label}: INTERRUPTED; {link(path)}; {link(interruption_path)}."
            )
        elif record["returncode"] != 0:
            measured = "FAIL; " + measured
            failures.append(f"Quality gate {label}: FAIL; {link(path)}.")
        lines.append(f"| {label} | {role_label} | scripted | {measured} | {link(path)} |")
        aggregate["gates"].append({
            "check": label,
            "role": role,
            "mode": "scripted",
            "evidence": path.relative_to(ROOT).as_posix(),
            "result": measured,
            "exit": record["returncode"],
        })
    if aggregate["preferred_test_gate"] != "test":
        lines += [
            "",
            "Earlier test rows are retained earlier attempts. The preferred final "
            f"test/rules gate is `{aggregate['preferred_test_gate']}`; "
            "its result does not replace the earlier "
            "log or remove earlier failures from the retained-failures list.",
        ]
    interruption_path = EVIDENCE / "checks" / "test-rules-final-interruption.json"
    if interruption_path.is_file():
        lines += [
            "",
            "The `test-rules-final` attempt was interrupted after reporting/test edits "
            "occurred during its run. Its retained log contains an early reporting-test "
            "failure, but no complete traceback or final pytest summary was produced. "
            "Production source bytes were unchanged. " + link(interruption_path) + ".",
        ]

    lines += [
        "",
        "## Scripted mechanisms",
        "",
        "| Suite | Completion / observations | Adverse count and 95% upper | Evidence |",
        "|---|---|---|---|",
    ]

    def measurement(name, mode, passed, total, adverse, path, detail=""):
        row = {
            "name": name,
            "mode": mode,
            "passed": passed,
            "total": total,
            "adverse": adverse,
            "upper_95": upper(adverse, total),
            "evidence": path.relative_to(ROOT).as_posix(),
            "detail": detail,
        }
        aggregate["measurements"].append(row)
        return row

    path = EVIDENCE / "judge" / "scripted" / "judge.json"
    j = read(path)
    exact_ids(j["results"], "task_id", J_TASKS, "scripted J task")
    for row in failed_outcomes(j["results"]):
        failures.append(f"Scripted {row['task_id']}: failed task assertions; {link(path)}.")
    measurement("J01-J24", "scripted", j["passed"], j["total"], j["total"] - j["passed"], path)
    lines.append(
        f"| J01–J24 | {j['passed']}/{j['total']} | "
        f"{j['total'] - j['passed']}/{j['total']}; "
        f"{upper(j['total'] - j['passed'], j['total'])} | {link(path)} |"
    )
    wpaths = sorted((EVIDENCE / "judge" / "wealth" / "scripted").glob("W*/result.json"))
    wealth = [read(path) for path in wpaths]
    exact_ids(wealth, "task_id", W_TASKS, "scripted W task")
    passed, total = sum(row["passed"] for row in wealth), len(wealth)
    wsub = sum(len(row["subcases"]) for row in wealth)
    subpass = sum(sub["passed"] for row in wealth for sub in row["subcases"])
    wroot = EVIDENCE / "judge" / "wealth" / "scripted"
    for row in failed_outcomes(wealth):
        failures.append(f"Scripted {row['task_id']}: failed mechanism assertions; {link(wroot)}.")
    measurement(
        "W01-W12",
        "scripted",
        passed,
        total,
        total - passed,
        wroot,
        f"{subpass}/{wsub} formal subcases",
    )
    lines.append(
        f"| W01–W12 | {passed}/{total} tasks; {subpass}/{wsub} subcases | "
        f"{total - passed}/{total}; {upper(total - passed, total)}; "
        f"subcase failure {wsub - subpass}/{wsub}, {upper(wsub - subpass, wsub)} | {link(wroot)} |"
    )
    path = EVIDENCE / "adversary" / "result.json"
    adv = read(path)
    count = adv["violation_rate"]["numerator"]
    total = adv["violation_rate"]["denominator"]
    measurement("Byzantine forbidden effects", "scripted", total - count, total, count, path)
    lines.append(
        f"| Byzantine attempts | {total} attacks; "
        f"{adv['benign_completed']}/{adv['benign_count']} benign complete | "
        f"{count}/{total}; {upper(count, total)} | {link(path)} |"
    )
    diff = adv["differential"]
    lines.append(
        f"| Independent differential | {diff['valid_samples']} valid; "
        f"{diff['accepted']} accepted | {diff['disagreements']}/{diff['valid_samples']} "
        f"disagreements; {upper(diff['disagreements'], diff['valid_samples'])} | {link(path)} |"
    )
    lines += [
        "",
        f"The Byzantine run retains {adv['legitimate_prior_effects']} lawful prior effects; "
        "these are not forbidden new movements.",
    ]

    lines += [
        "",
        "## M10 final model recording and offline replay",
        "",
        "| Suite / model | Mode | Completion | Failure upper 95% | Replay identical | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for stage in ("main", "contrast"):
        expected_models = (MODELS[0],) if stage == "main" else MODELS
        expected_paths = {
            EVIDENCE / stage / model / f"recording-{model}.json" for model in expected_models
        }
        if set((EVIDENCE / stage).glob("*/recording-*.json")) != expected_paths:
            raise ValueError("Final model recording coverage is incomplete or unexpected")
        for path in sorted(expected_paths):
            run = read(path)
            validate_recording(run, stage, path.parent.name)
            for suite in ("J", "W"):
                rows = [row for row in run["results"] if row["task_id"].startswith(suite)]
                if not rows:
                    continue
                total = len(rows)
                passed = sum(row["passed"] for row in rows)
                identical = sum(row["strict_replay"] == "PASS" for row in rows)
                recorded = sum(row["source"] == "live-recorded" for row in rows)
                mode = evidence_mode([row["source"] for row in rows])
                mode_label = (
                    f"{mode}; live-recorded {recorded}/{total}; not recorded {total - recorded}"
                )
                name = f"{stage} {suite} / {run['model_profile']['model']}"
                measurement(
                    name,
                    mode,
                    passed,
                    total,
                    total - passed,
                    path,
                    f"Recorded tasks {recorded}/{total}; "
                    f"strict replay identical {identical}/{total}",
                )
                lines.append(
                    f"| {name} | {mode_label} | {passed}/{total} | "
                    f"{upper(total - passed, total)} | {identical}/{total}; "
                    f"mismatch upper {upper(total - identical, total)} | {link(path)} |"
                )
                if suite == "W":
                    flows = run["W"]
                    aggregate["measurements"][-1]["workflow_passed"] = flows["workflow_passed"]
                    aggregate["measurements"][-1]["workflow_total"] = flows["workflow_total"]
                    workflow_upper = upper(
                        flows["workflow_total"] - flows["workflow_passed"], flows["workflow_total"]
                    )
                    lines.append(
                        f"| {name} advisory workflows | {mode_label}; formal probes scripted | "
                        f"{flows['workflow_passed']}/{flows['workflow_total']} | "
                        f"{workflow_upper} "
                        f"| Task-level equality above | {link(path)} |"
                    )
                for row in rows:
                    if not row["passed"] or row["strict_replay"] != "PASS":
                        failures.append(
                            f"Failure retained: {stage} / {run['model_profile']['model']} / "
                            f"`{row['task_id']}`; "
                            f"source `{row['source']}`; "
                            f"strict replay `{row['strict_replay']}`; "
                            "error `"
                            + str(row.get("error_type", row.get("live_status", "task assertions")))
                            + f"`; {link(path)}."
                        )
    lines += [
        "",
        "W model rows concern task-specific advisory workflows. The formal mechanism "
        "subcases remain labelled scripted, including certificate mutations. "
        "A workflow pass is not unrestricted language competence or full live mutation coverage.",
        "The gateway verifies approval-token signatures at runtime. Workflow exports retain "
        "token IDs and hashes, not nonce-bearing token bodies; those exports alone cannot "
        "independently reconstruct every approval-token signature.",
    ]

    path = EVIDENCE / "dialogue" / "dialogue-recording.json"
    dialogue = read(path)
    detailed_path = EVIDENCE / "dialogue" / "record" / "summary.json"
    detailed = read(detailed_path)
    from corridor.agent.wealth_guard_validation import GUARANTEE_PROMPTS
    from corridor.agent.wealth_validation import CASES

    exact_ids(
        detailed["runs"],
        "task_id",
        {case.task_id for case in CASES} | {"W04", "W07"},
        "M2 dialogue",
    )
    exact_ids(
        detailed["extensions"],
        "task_id",
        {case.task_id for case in GUARANTEE_PROMPTS},
        "M4 output guard",
    )
    validation_mode = evidence_mode([
        evidence_mode(row.get("sources", []))
        for row in [*detailed["runs"], *detailed["extensions"]]
    ])
    lines += [
        "",
        "## M2 dialogue and M4 output guard",
        "",
        f"Observed mode: {validation_mode}; transport-disabled strict-replay "
        f"status: {dialogue['strict_replay']}. "
        "Unrun budget rows stay in the completion denominator.",
        "",
        "| Measurement | Observed mode | Completed | Failure upper 95% | Evidence |",
        "|---|---|---|---|---|",
    ]
    for name, rows in (("M2", detailed["runs"]), ("M4", detailed["extensions"])):
        passed, total = sum(row["passed"] for row in rows), len(rows)
        if (passed, total) != (dialogue[name + "_passed"], dialogue[name + "_total"]):
            raise ValueError("Dialogue aggregate differs from its case evidence")
        mode = evidence_mode([evidence_mode(row.get("sources", [])) for row in rows])
        recorded = sum(row.get("sources") == ["live-recorded"] for row in rows)
        measurement(
            name,
            mode,
            passed,
            total,
            total - passed,
            path,
            f"Recorded cases {recorded}/{total}; strict replay {dialogue['strict_replay']}",
        )
        lines.append(
            f"| {name} | {mode}; live-recorded {recorded}/{total} | {passed}/{total} | "
            f"{upper(total - passed, total)} | {link(path)} |"
        )
        for row in failed_outcomes(rows):
            failures.append(
                f"{name} / {row['task_id']}: {row.get('status', 'failed')}; "
                f"sources {row.get('sources', [])}; {link(detailed_path)}."
            )
    if dialogue["strict_replay"] != "PASS":
        failures.append(f"M2/M4 strict replay: {dialogue['strict_replay']}; {link(path)}.")
    lines += [
        "",
        f"M2 contains {detailed['dataset_utterances']} fixed utterances in "
        f"{detailed['dataset_tasks']} dialogue cases plus two comparison smokes. "
        f"Mean turns to signed goals: {detailed['mean_turns_to_signed_goals']} over "
        f"{detailed['mean_turns_denominator']} completed goal-signing cases. "
        f"Exact offline observation equality: {dialogue['strict_replay']}. "
        f"Token/call/utterance evidence: {link(detailed_path)}.",
    ]

    lines += [
        "",
        "## Frozen corpus and authored redteam",
        "",
        "| Suite | Mode | Evaluated / denominator | Forbidden effects, 95% upper | "
        "Benign completion | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    nl_diagnostics = []
    aggregate["nl_diagnostics"] = []
    for mode in ("live-recorded", "strict-replay"):
        path = EVIDENCE / "blind" / mode / "summary.json"
        blind = read(path)
        exact_ids(
            blind["cases"],
            "case_id",
            {f"case-{number:02d}" for number in range(1, 17)},
            "frozen blind case",
        )
        population = blind_population(blind)
        total, count = population["total"], population["adverse"]
        if (total, count) != (
            blind["violation_rate"]["denominator"],
            blind["violation_rate"]["numerator"],
        ):
            raise ValueError("Blind aggregate differs from its measured case population")
        actual_mode = evidence_mode([row["source"] for row in blind["cases"]])
        measurement(
            "Frozen blind",
            actual_mode,
            population["passed"],
            total,
            count,
            path,
            "Forbidden-predicate rate; independent evidence failures reported separately",
        )
        lines.append(
            f"| Frozen blind | {actual_mode} (requested {mode}) | {total}/16; "
            f"passed {population['passed']}/{total}; failure upper "
            f"{upper(total - population['passed'], total)} | {count}/{total}; "
            f"{upper(count, total)} | not applicable | {link(path)} |"
        )
        nl_diagnostics.append("Frozen blind / " + _diagnostics(population, actual_mode, path))
        aggregate["nl_diagnostics"].append({
            "suite": "Frozen blind",
            "mode": actual_mode,
            "requested_mode": mode,
            "evidence": path.relative_to(ROOT).as_posix(),
            **population,
        })
        for row in failed_outcomes(blind["cases"]):
            failures.append(
                f"Frozen blind / {mode} / {row['case_id']}: evaluated={row['evaluated']}; "
                f"predicate failure={row['violation_observed']}; independent evidence failures "
                f"{row.get('evidence_failures', [])}; error "
                f"{row.get('error_type', row.get('terminal_error'))}; {link(path)}."
            )
        path = EVIDENCE / "redteam" / mode / "summary.json"
        red = read(path)
        from corridor.bench.wealth_redteam import wealth_redteam_corpus

        exact_ids(
            red["pairs"],
            "pair_id",
            {pair.pair_id for pair in wealth_redteam_corpus()},
            "authored M7 pair",
        )
        population = redteam_population(red)
        total, count = population["total"], population["adverse"]
        if total != red["attack_evaluated"]:
            raise ValueError("M7 aggregate differs from its measured attack population")
        actual_mode = evidence_mode([
            pair[kind]["source"] for pair in red["pairs"] for kind in ("attack", "benign")
        ])
        measurement(
            "M7 attacks",
            actual_mode,
            population["passed"],
            total,
            count,
            path,
            "Measured attack effects; incomplete effects and evidence diagnostics separate",
        )
        lines.append(
            f"| M7 authored | {actual_mode} (requested {mode}) | "
            f"{total}/{red['attack_cases']} attacks | "
            f"{count}/{total}; {upper(count, total)} | "
            f"{red['benign_completed']}/{red['benign_cases']}; failure upper "
            f"{upper(red['benign_cases'] - red['benign_completed'], red['benign_cases'])} "
            f"| {link(path)} |"
        )
        for name, category in red["categories"].items():
            rate = category["observed_violations"]
            category_pairs = [pair for pair in red["pairs"] if pair["category"] == name]
            category_population = redteam_population({"pairs": category_pairs})
            category_mode = evidence_mode([
                pair[kind]["source"] for pair in category_pairs for kind in ("attack", "benign")
            ])
            if (rate["numerator"], rate["denominator"]) != (
                category_population["adverse"],
                category_population["total"],
            ):
                raise ValueError("M7 category rate differs from its measured attack population")
            benign_upper = upper(
                category["benign_cases"] - category["benign_completed"], category["benign_cases"]
            )
            lines.append(
                f"| M7 {name} | {category_mode} (requested {mode}) | "
                f"{category['attack_evaluated']}/{category['attack_cases']} | "
                f"{rate['numerator']}/{rate['denominator']}; "
                f"{upper(rate['numerator'], rate['denominator'])} | "
                f"{category['benign_completed']}/{category['benign_cases']}; failure upper "
                f"{benign_upper} "
                f"| {link(path)} |"
            )
        nl_diagnostics.append("M7 / " + _diagnostics(population, actual_mode, path))
        aggregate["nl_diagnostics"].append({
            "suite": "M7",
            "mode": actual_mode,
            "requested_mode": mode,
            "evidence": path.relative_to(ROOT).as_posix(),
            **population,
        })
        for pair in red["pairs"]:
            for kind in ("attack", "benign"):
                outcome = pair[kind]
                if failed_outcomes([outcome], require_completion=kind == "benign"):
                    failures.append(
                        f"M7 / {mode} / {pair['pair_id']} / {kind}: "
                        f"{outcome['evaluation_status']}; errors "
                        f"{outcome['error_types']}; observed forbidden effects "
                        f"{outcome['observed_forbidden_effects']}; independent evidence failures "
                        f"{outcome['evidence_failures']}; task completed="
                        f"{outcome['task_completed']}; {link(path)}."
                    )
    lines += [
        "",
        *nl_diagnostics,
        "",
        "The frozen corpus was authored in an isolated session and retained byte-for-byte. "
        "It was already exercised during Lane E development; this is a final-code rerun, "
        "not an untouched first-pass holdout. The disclosed NL adapter has bounded tools; "
        "blind case 13 uses a single-product projection, not a complete three-leg request.",
    ]
    for stage in ("blind", "redteam"):
        equality_path = EVIDENCE / "checks" / f"{stage}-replay-comparison.json"
        equality = read(equality_path)
        lines.append(
            f"Exact {stage} live/strict observation equality: "
            f"{equality['matched_cases']}/{equality['total']}; mismatch upper "
            f"{upper(equality['total'] - equality['matched_cases'], equality['total'])}. "
            f"{link(equality_path)}"
        )
        if not equality["identical"]:
            failures.append(
                f"{stage} live/strict observation equality failed: "
                f"{equality['matched_cases']}/{equality['total']}; {link(equality_path)}."
            )

    path = EVIDENCE / "bench" / "wealth" / "matrix.json"
    matrix = read(path)
    lines += [
        "",
        "## D0 / D3 / CCA matrix",
        "",
        "Mode: scripted; 31 prespecified execution projections per cell, distinct from "
        "the 74 formal W subcases. Two arms × three configurations × two user policies. "
        "D3 retains CNY 1,000 per-write and CNY 5,000 daily limits. "
        "Main principal is CNY 10,000; the prespecified scaled principal is CNY 1,000.",
        "",
        "| Arm | Config / user | Prohibited outcomes / all rows | Upper 95% | "
        "Adversarial outcomes | Upper 95% | MFA protocol gaps | "
        "Benign completion | Failure upper 95% |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    matrix_changes = []
    for arm in matrix["arms"]:
        for cell in arm["cells"]:
            rate, done = cell["prohibited_effects"], cell["benign_completion"]
            attacks = cell["attack_violations"]
            gaps = cell["missing_mfa_protocol_gaps"]
            lines.append(
                f"| {arm['arm']} | {cell['config']} / {cell['user_policy']} | "
                f"{rate['numerator']}/{rate['denominator']} | "
                f"{upper(rate['numerator'], rate['denominator'])} | "
                f"{attacks['numerator']}/{attacks['denominator']} | "
                f"{upper(attacks['numerator'], attacks['denominator'])} | "
                f"{gaps['numerator']}/{gaps['denominator']} | "
                f"{done['numerator']}/{done['denominator']} | "
                f"{upper(done['denominator'] - done['numerator'], done['denominator'])} |"
            )
            if cell["config"] in {"d0", "d3"}:
                previous = (
                    8
                    if cell["config"] == "d0"
                    else 0
                    if arm["arm"] == "main"
                    else 8
                    if cell["user_policy"] == "all_approve"
                    else 4
                )
                matrix_changes.append({
                    "arm": arm["arm"],
                    "config": cell["config"],
                    "user_policy": cell["user_policy"],
                    "historical_lane_e_business_violations": previous,
                    "corrected_business_violations": rate["numerator"],
                    "denominator": rate["denominator"],
                    "mfa_protocol_gaps": gaps["numerator"],
                    "protocol_only_attack_rows": cell["attack_predicate_not_applicable"],
                })
    lines += [
        "",
        f"Every cell and exact cash/fee/liquidity outcome: {link(path)}. "
        "The benign partial-stop projection remains incomplete by design. "
        "Performance benchmark differences (not guaranteed) are not realized cash losses.",
        "Accepted forged proposals count as prohibited outcomes even if no money moves. "
        "Baseline proof-only attacks have no applicable CCA protocol predicate; actual "
        "business effects remain measured against visible goals. All ten adversarial rows "
        "remain in each attack denominator. MFA-gap counts are protocol diagnostics, not "
        "business-loss estimates; their binomial bounds are not applicable.",
        "",
        "### Fourth-round evaluation correction",
        "",
        "The earlier Lane E matrix used a missing-MFA row with an empty intended allocation. "
        "F5 judges D0/D3 against the visible goal and reports MFA separately. "
        "The historical counts below are attributed to docs/status/LANE-E.md; corrected "
        "counts use the final scripted matrix. This is a measurement correction, not a "
        "change in baseline protection.",
        "",
        "| Arm | Baseline / user | Earlier business violations | Corrected | "
        "MFA gaps | Protocol-only attack rows |",
        "|---|---|---|---|---|---|",
    ]
    aggregate["matrix_accounting_changes"] = matrix_changes
    for row in matrix_changes:
        lines.append(
            f"| {row['arm']} | {row['config']} / {row['user_policy']} | "
            f"{row['historical_lane_e_business_violations']}/{row['denominator']} | "
            f"{row['corrected_business_violations']}/{row['denominator']} | "
            f"{row['mfa_protocol_gaps']} | {row['protocol_only_attack_rows']} |"
        )

    journal_path = ROOT / "evidence" / "final" / "live-budget.json"
    journal = read(journal_path)
    aggregate["live_budget"] = journal
    aggregate["retained_failures"] = failures
    lines += ["", "## Retained failures", ""]
    lines += failures or [
        "No failed final task, incomplete blind observation or failed M7 pair was observed. "
        "Historical pre-freeze attempts remain under their original evidence directories."
    ]
    lines += [
        "",
        "## Budget, evidence and limits",
        "",
        f"Conservative live attempts: **{journal['attempts']}/1,500**; the shared journal "
        "enforces the stricter 1,200-attempt ceiling. All model calls pass through "
        f"agent/llm.py call and USD guards. {link(journal_path)}",
        "",
        "The final code was frozen before recording. Command logs retain source hashes "
        "before and after each run. The compact verification checks those hashes, bank "
        "manifests, sealed bundles and the separate offline replay. Fourth-round review "
        "confirmed ten findings including one high severity; all are repaired, with four "
        "rejected findings retained as specification-aligned regression tests. "
        "Review details: [F5](../docs/status/F5.md).",
        "",
        "Allocation is a policy-checked heuristic, with an incomplete greedy constructor. "
        "Sponsor independence holds within the declared catalogue and policy. "
        "Trusted state, modelled fees and demo key management remain assumptions. "
        "No financial, regulatory or universal safety guarantee is claimed.",
        "",
        "Video production, measured rehearsal duration, public repository publication, "
        "registration and external submission are not_run. No fabricated duration, URL "
        "or submission receipt is supplied.",
        "",
    ]
    COMPACT.mkdir(parents=True, exist_ok=True)
    (COMPACT / "summary.json").write_bytes(jcs_bytes(aggregate))
    target = ROOT / "results" / "FINAL-RESULTS.md"
    target.write_text("\n".join(lines), encoding="utf-8")
    print(target)


if __name__ == "__main__":
    main()
