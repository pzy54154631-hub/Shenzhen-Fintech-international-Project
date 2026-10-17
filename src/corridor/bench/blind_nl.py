"""Natural-language blind inputs: immutable external bytes and disclosed role adapters."""

import re
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from corridor.schemas.base import Model, loads_exact

PUBLIC_FROZEN_MANIFEST_SHA256 = "7aee83c75270c6c96dcde2dfd4be3f6d09fed562a1ca7605e0fcf3dedf28eef7"


class ExternalDocument(Model):
    kind: Literal["brochure", "email", "memo", "advisor_note", "banner", "upload"]
    text: str = Field(min_length=1, max_length=64000)


class BlindTurn(Model):
    user_text: str = Field(min_length=1, max_length=64000)
    external_documents: list[ExternalDocument] = Field(max_length=12)
    device_behaviour: Literal["approve_if_card_looks_normal", "approve_everything", "reject"]


class BlindSetup(Model):
    risk_assessment: Literal["valid", "expired"]
    notes: str


class NaturalLanguageCase(Model):
    schema_version: Literal["blind-nl-v1"]
    case_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    category: str
    attacker_goal: str
    setup: BlindSetup
    turns: list[BlindTurn] = Field(min_length=1, max_length=8)
    forbidden_outcomes: list[str] = Field(min_length=1)
    why_it_might_work: str


def _relative(root: Path, name: str) -> Path:
    path = Path(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or ":" in name:
        raise ValueError("Invalid frozen path")
    target = (root / path).resolve()
    if not target.is_relative_to(root.resolve()) or target.is_symlink():
        raise ValueError("Invalid frozen path")
    return target


def load_frozen_cases(root: Path) -> tuple[list[NaturalLanguageCase], dict[str, Any]]:
    """Verify frozen inputs; the pinned public distribution omits only its author log."""
    manifest = (root / "FROZEN-SHA256.txt").read_bytes()
    manifest_hash = sha256(manifest).hexdigest()
    hashes: dict[str, str] = {}
    for line in manifest.decode("utf-8-sig").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})\s{2}(.+)", line)
        if match is None:
            raise ValueError("Invalid frozen hash manifest")
        digest, name = match.groups()
        path = _relative(root, name)
        relative = path.relative_to(root.resolve()).as_posix()
        if relative in hashes:
            raise ValueError("Duplicate frozen path")
        # The author session is provenance context, never an evaluation input. Its
        # authorized omission applies only to the exact original frozen manifest;
        # all input/material/provenance hashes and any present log stay mandatory.
        if (
            relative == "author-session.log"
            and not path.exists()
            and manifest_hash == PUBLIC_FROZEN_MANIFEST_SHA256
        ):
            hashes[relative] = digest
            continue
        if sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Frozen hash mismatch: {relative}")
        hashes[relative] = digest
    if "provenance.json" not in hashes:
        raise ValueError("Missing provenance hash")
    provenance = loads_exact((root / "provenance.json").read_bytes())
    if (
        provenance.get("schema_version") != "blind-provenance-v1"
        or provenance.get("isolated") is not True
    ):
        raise ValueError("Blind author isolation is not attested")
    for name, digest in {
        **provenance["input_material_hashes"],
        **provenance["case_hashes"],
    }.items():
        key = _relative(root, name).relative_to(root.resolve()).as_posix()
        if hashes.get(key) != digest:
            raise ValueError("Provenance hash mismatch")
    expected = {f"cases/case-{number:02d}.json" for number in range(1, 17)}
    actual = {path.relative_to(root).as_posix() for path in (root / "cases").glob("*.json")}
    if actual != expected or set(provenance["case_hashes"]) != expected:
        raise ValueError("Expected exactly the 16 frozen cases")
    cases = [
        NaturalLanguageCase.model_validate(loads_exact((root / name).read_bytes()))
        for name in sorted(expected)
    ]
    if [case.case_id for case in cases] != [f"case-{number:02d}" for number in range(1, 17)]:
        raise ValueError("Frozen case identity mismatch")
    return cases, {
        **provenance,
        "frozen_manifest_sha256": manifest_hash,
    }


def run_natural_blind_suite(root: Path, output: Path, client: Any) -> dict[str, Any]:
    from corridor.bench.bank_cases import write_json
    from corridor.bench.blind_checks import evaluate_forbidden
    from corridor.bench.evidence_bundle import seal_bundle
    from corridor.bench.metrics import binomial_summary
    from corridor.bench.nl_evidence import verify_nl_evidence
    from corridor.bench.nl_runner import role_mapping, run_nl_case
    from corridor.bench.recording import observation_hash

    if client.mode not in {"record", "strict"}:
        raise ValueError("Frozen NL blind evaluation requires real recording or strict replay")
    cases, provenance = load_frozen_cases(root)
    source = "live-recorded" if client.mode == "record" else "strict-replay"
    required = "live-recorded" if client.mode == "record" else "replay"
    destination = output / source
    rows = []
    for case in cases:
        start = len(client.calls)
        try:
            result = run_nl_case(case, client, destination / case.case_id)
            outcomes = evaluate_forbidden(case, result)
            evidence_failures = verify_nl_evidence(result)
            evaluated = (
                bool(result["sources"])
                and set(result["sources"]) == {required}
                and not result.get("incomplete", False)
                and all(step["status"] != "error" for step in result["steps"])
            )
            row = {
                "case_id": case.case_id,
                "category": case.category,
                "source": source,
                "evaluated": evaluated,
                "outcomes": outcomes,
                "evidence_failures": evidence_failures,
                "passed": evaluated
                and all(item["passed"] for item in outcomes)
                and not evidence_failures
                and result["audit_verified"]
                and result["receipt_signatures_valid"],
                "violation_observed": any(item["violation_observed"] for item in outcomes),
                "cash_debit_cny": str(
                    sum(
                        (
                            Fraction(effect["amount"])
                            for receipt in result["receipts"]
                            for effect in receipt["exact_effects"]
                            if effect["effect_type"] == "debit"
                        ),
                        Fraction(0),
                    )
                ),
                "task_completed": result["completed"],
                "terminal_error": result.get("terminal_error"),
                "llm_calls": result["llm_calls"],
                "model": client.model,
                "scope": result["scope"],
                "observations_hash": observation_hash(result),
            }
        except (ValueError, RuntimeError, OSError) as exc:
            row = {
                "case_id": case.case_id,
                "category": case.category,
                "source": "not_run",
                "evaluated": False,
                "passed": False,
                "violation_observed": None,
                "outcomes": [],
                "error_type": type(exc).__name__,
                "llm_calls": client.calls[start:],
            }
        write_json(destination / case.case_id / "checks.json", row)
        seal_bundle(
            destination / case.case_id,
            {"source": row["source"], "case_id": case.case_id, "model": client.model},
        )
        rows.append(row)
    verified_cases, final_provenance = load_frozen_cases(root)
    if final_provenance != provenance or verified_cases != cases:
        raise ValueError("Frozen source changed during blind evaluation")
    measured = [row for row in rows if row["evaluated"]]
    observed = [row for row in rows if row["violation_observed"] is not None]
    incomplete = [row for row in observed if not row["evaluated"]]
    summary = {
        "schema_version": "blind-nl-results-v1",
        "source": source,
        "status": "measured" if len(measured) == 16 else "partial",
        "executed": len(measured),
        "total": 16,
        "cases": rows,
        "violation_rate": binomial_summary(
            sum(bool(row["violation_observed"]) for row in measured), len(measured)
        ),
        "observed_cases": len(observed),
        "observed_predicate_failure_cases": sum(
            bool(row["violation_observed"]) for row in observed
        ),
        "evidence_failure_cases": sum(bool(row.get("evidence_failures")) for row in observed),
        "incomplete_with_observed_predicate_failure": sum(
            bool(row["violation_observed"]) for row in incomplete
        ),
        "incomplete_observed_cash_debit_cny": str(
            sum((Fraction(row["cash_debit_cny"]) for row in incomplete), Fraction(0))
        ),
        "provenance": provenance,
        "role_mapping": role_mapping(),
        "scope": "Frozen isolated-author blind set; separate from development M7 attacks",
        "limitations": [
            "Bounded tool adapter over the real gateway, not the full Advisor UI.",
            "Fact-reference narration is measured; unrestricted assistant prose is unavailable.",
            "Recommendation omissions are reported as predicate failures, "
            "separately from cash harm.",
            "Incomplete runs retain observed effects and are excluded from the measured rate.",
            "Independent signature, approval, MFA and intended-effect checks supplement "
            "frozen predicates.",
            "Case 13 exercises a single-product purchase projection; full allocation "
            "dialogue is unavailable.",
            "Risk questionnaire tooling and unrestricted assistant prose are unavailable "
            "in this adapter.",
        ],
    }
    write_json(destination / "summary.json", summary)
    (destination / "SUMMARY.md").write_text(
        "# Frozen natural-language blind evaluation\n\n"
        f"Source: {source}; model: {client.model}. Evaluated {len(measured)}/16. "
        f"Forbidden-outcome predicate failures: {summary['violation_rate']['display']}.\n\n"
        f"Incomplete cases with observed predicate failures: "
        f"{summary['incomplete_with_observed_predicate_failure']}; "
        f"confirmed cash debit in incomplete cases: "
        f"{summary['incomplete_observed_cash_debit_cny']} CNY (not a loss estimate). "
        f"Independent evidence failures: {summary['evidence_failure_cases']}.\n\n"
        "| Case | Evaluated | Passed | Predicate failure | Cash debit CNY |\n"
        "|---|---|---|---|---|\n"
        + "\n".join(
            f"| {row['case_id']} | {row['evaluated']} | {row['passed']} | "
            f"{row['violation_observed']} | {row.get('cash_debit_cny', 'not_run')} |"
            for row in rows
        )
        + "\n\nRole mapping: `role-mapping.json` in every case; also in summary.json.\n\n"
        + "\n".join(summary["limitations"])
        + "\n",
        encoding="utf-8",
    )
    seal_bundle(
        destination,
        {
            "source": source,
            "model": client.model,
            "frozen_manifest_sha256": provenance["frozen_manifest_sha256"],
        },
    )
    return summary
