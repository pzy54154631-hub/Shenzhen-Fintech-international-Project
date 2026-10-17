"""Independent regression checks for honest matrix and partial-run accounting."""

from copy import deepcopy
from hashlib import sha256

import pytest

from corridor.bench.adversary import development_cases
from corridor.bench.blind import run_blind_suite
from corridor.bench.matrix import run_baseline_case, summarize_cell
from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.base import loads_exact
from tests.unit.test_blind_runner import write_case


def _spec(attack):
    return next(case for case in development_cases() if case.attack == attack)


@pytest.mark.parametrize("config", ["d0", "d3"])
@pytest.mark.parametrize("attack", ["literal_amount", "missing_amount_source", "omitted_candidate"])
def test_unchanged_signed_goal_is_not_fabricated_prohibited_business_effect(config, attack):
    row = run_baseline_case(_spec(attack), config, "all_approve")
    assert row["status"] == "settled"
    assert row["bank_dispatches"] == 1
    # These projections execute the original payee/amount or default P_A. The
    # absence of CCA proof verifiers is not itself a wrong business effect.
    assert row["prohibited_effects"] == 0, row
    assert row["oracle"]["wrong_recipient_effects"] == 0
    assert row["oracle"]["wrong_amount_effects"] == 0
    assert row["oracle"]["recommendation_violations"] == 0


def test_real_wrong_recipient_still_counts_as_business_harm():
    row = run_baseline_case(_spec("wrong_recipient"), "d0", "all_approve")
    assert row["bank_dispatches"] == 1
    assert row["prohibited_effects"] > 0
    assert row["oracle"]["wrong_recipient_effects"] > 0


@pytest.mark.parametrize("unknown_source", ["explicit_flag", "oracle_reasons"])
def test_indeterminate_observation_is_excluded_from_zero_violation_denominator(unknown_source):
    known = run_baseline_case(_spec("literal_amount"), "d0", "all_approve")
    unknown = deepcopy(known)
    unknown.update({"status": "unknown", "prohibited_effects": None, "integrity_violations": None})
    if unknown_source == "explicit_flag":
        unknown["oracle_indeterminate"] = True
    else:
        unknown["oracle"]["indeterminate_reasons"] = ["Unobserved backend result"]
    summary = summarize_cell("d0", "all_approve", [known, unknown], [])
    assert summary["attacks"]["denominator"] == 1, summary
    assert summary["task_denominator"] == 2


def test_unmeasured_confirmation_and_mfa_are_not_reported_as_measured_zero():
    row = run_baseline_case(_spec("literal_amount"), "d0", "all_approve")
    row["confirmation_count"] = None
    row["mfa_count"] = None
    row["oracle"]["confirmation_count"] = None
    row["oracle"]["mfa_count"] = None
    summary = summarize_cell("d0", "all_approve", [row], [])
    assert summary["confirmation_count"] != 0
    assert summary["mfa_count"] != 0


def test_missing_business_harm_measurement_is_unknown_even_without_redundant_flag():
    row = run_baseline_case(_spec("literal_amount"), "d0", "all_approve")
    row["prohibited_effects"] = None
    row["integrity_violations"] = 0
    row["oracle_indeterminate"] = False
    row["oracle"]["indeterminate_reasons"] = []
    summary = summarize_cell("d0", "all_approve", [row], [])
    assert summary["attacks"]["denominator"] == 0
    assert summary["attacks"]["status"] == "not_run"


def test_blind_runtime_error_preserves_prior_completed_case_and_its_evidence(tmp_path):
    cases = tmp_path / "wire-cases"
    write_case(cases)
    second = loads_exact((cases / "smoke.json").read_bytes())
    second["case_id"] = "WIRE-SECOND-INVALID"
    # All files parse and match frozen hashes; this deliberately fails during
    # execution setup after the first interface smoke case has completed.
    second["ground_truth"]["initial_public_state_hash"] = H("mismatched public state")
    data = jcs_bytes(second)
    (cases / "z-second.json").write_bytes(data)
    provenance = loads_exact((cases / "provenance.json").read_bytes())
    provenance["case_hashes"]["z-second.json"] = sha256(data).hexdigest()
    (cases / "provenance.json").write_bytes(jcs_bytes(provenance))
    output = tmp_path / "evidence"
    result = run_blind_suite(cases, output)
    assert result["status"] == "invalid"
    assert result["executed"] == 1, result
    assert len(result["cases"]) == 1
    assert result["cases"][0]["case_id"] == "WIRE-SMOKE"
    assert result["cases"][0]["passed"]
    assert (output / "WIRE-SMOKE" / "result.json").is_file()
    persisted = loads_exact((output / "summary.json").read_bytes())
    assert persisted["executed"] == 1 and len(persisted["cases"]) == 1
