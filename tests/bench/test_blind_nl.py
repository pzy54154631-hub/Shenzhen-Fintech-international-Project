"""Frozen-input integrity checks precede any model or bank interaction."""

from hashlib import sha256

import pytest

from corridor.bench.blind_nl import load_frozen_cases
from corridor.crypto.jcs import jcs_bytes


def _frozen(root):
    (root / "cases").mkdir()
    cases = {}
    for number in range(1, 17):
        name = f"cases/case-{number:02d}.json"
        raw = jcs_bytes({
            "schema_version": "blind-nl-v1",
            "case_id": f"case-{number:02d}",
            "category": "mixed",
            "attacker_goal": "test",
            "setup": {"risk_assessment": "valid", "notes": "synthetic"},
            "turns": [
                {
                    "user_text": "Compare products",
                    "external_documents": [],
                    "device_behaviour": "reject",
                }
            ],
            "forbidden_outcomes": ["no money-moving action"],
            "why_it_might_work": "fixture",
        })
        (root / name).write_bytes(raw)
        cases[name] = sha256(raw).hexdigest()
    provenance = {
        "schema_version": "blind-provenance-v1",
        "author": "isolated author",
        "isolated": True,
        "input_material_hashes": {},
        "case_hashes": cases,
    }
    raw = jcs_bytes(provenance)
    (root / "provenance.json").write_bytes(raw)
    entries = {**cases, "provenance.json": sha256(raw).hexdigest()}
    (root / "FROZEN-SHA256.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in entries.items()), encoding="utf-8"
    )


def test_frozen_inputs_are_verified_then_parsed(tmp_path):
    _frozen(tmp_path)
    cases, provenance = load_frozen_cases(tmp_path)
    assert len(cases) == 16
    assert provenance["isolated"] is True
    with (tmp_path / "cases/case-01.json").open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(ValueError, match="hash"):
        load_frozen_cases(tmp_path)


def test_frozen_manifest_cannot_escape_root(tmp_path):
    _frozen(tmp_path)
    with (tmp_path / "FROZEN-SHA256.txt").open("a", encoding="utf-8") as stream:
        stream.write("0" * 64 + "  ../outside.json\n")
    with pytest.raises(ValueError, match="path"):
        load_frozen_cases(tmp_path)


def test_incomplete_blind_run_retains_earlier_forbidden_debit(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from corridor.bench.blind_nl import run_natural_blind_suite

    source = tmp_path / "frozen"
    source.mkdir()
    _frozen(source)

    def observed(case, client, destination):
        incomplete = case.case_id == "case-02"
        return {
            "sources": ["live-recorded"],
            "steps": [{"status": "error" if incomplete else "settled"}],
            "incomplete": incomplete,
            "terminal_error": "ReplayMiss" if incomplete else None,
            "audit_verified": True,
            "receipt_signatures_valid": True,
            "receipts": [{"exact_effects": [{"effect_type": "debit", "amount": "1000/1"}]}]
            if incomplete
            else [],
            "completed": not incomplete,
            "llm_calls": [],
            "scope": "accounting test fixture",
        }

    monkeypatch.setattr("corridor.bench.nl_runner.run_nl_case", observed)
    monkeypatch.setattr("corridor.bench.nl_evidence.verify_nl_evidence", lambda result: [])
    monkeypatch.setattr(
        "corridor.bench.blind_checks.evaluate_forbidden",
        lambda case, result: [
            {
                "passed": not result["incomplete"],
                "violation_observed": result["incomplete"],
            }
        ],
    )
    result = run_natural_blind_suite(
        source, tmp_path / "output", SimpleNamespace(mode="record", model="test", calls=[])
    )
    assert result["executed"] == 15
    assert result["observed_cases"] == 16
    assert result["observed_predicate_failure_cases"] == 1
    assert result["incomplete_with_observed_predicate_failure"] == 1
    assert result["incomplete_observed_cash_debit_cny"] == "1000"
    assert result["cases"][1]["violation_observed"] is True
    assert result["cases"][1]["passed"] is False
