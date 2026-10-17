"""RT4-EVALINT-01: CCA attack rows cannot register harm when the gateway fails open.

For the W08/W10/W12 forged-BIAC projections, ``wealth_matrix._cca`` submits the
mutated certificate to ``gateway.propose`` and then stops. If the gateway does
NOT reject the forged certificate the row's execution_status becomes
``unblocked_proposal`` -- yet nothing is ever executed, so ``verify_execution``
sees zero receipts and the row is reported as ``prohibited_effects == 0``.

The matrix therefore cannot distinguish "CCA rejected the forged plan" from
"CCA accepted the forged plan" on these attack rows: the CCA 0/31 is partially
true by construction. The same projections DO execute on the D0/D3 arms, so
the comparison is asymmetric. A methodologically sound harness must either
count a fail-open proposal as a prohibited outcome or carry it to execution.
"""

from dataclasses import replace

import pytest

from corridor.bench import wealth_matrix
from corridor.gateway.service import Gateway

ATTACK_ROWS = {
    ("W10", "omit_candidate"),
    ("W10", "forged_fee"),
    ("W10", "unapproved_allocation"),
    ("W08", "seventy_thirty"),
    ("W08", "risky_product"),
    ("W12", "forced_high_risk"),
}


@pytest.fixture
def fail_open_gateway(monkeypatch):
    """Simulate a regressed gateway that accepts every certificate it would reject."""
    original = Gateway.propose

    def propose(self, action, cert, *args, **kwargs):
        proposal = original(self, action, cert, *args, **kwargs)
        if proposal.verdict.outcome == "Reject":
            accepted = type("FailOpen", (), {"outcome": "Accept", "rule_ids": [], "tier": "red"})()
            return replace(proposal, verdict=accepted)
        return proposal

    monkeypatch.setattr(Gateway, "propose", propose)


@pytest.mark.parametrize("task_id,subcase", sorted(ATTACK_ROWS))
def test_fail_open_forged_certificate_is_not_reported_as_zero_harm(
    fail_open_gateway, task_id, subcase
):
    spec = next(
        item
        for item in wealth_matrix.matrix_scenarios(wealth_matrix.SCALED_PRINCIPAL)
        if item.task_id == task_id and item.subcase_id == subcase
    )
    assert spec.benign is False
    row = wealth_matrix.run_matrix_case(spec, "cca", "all_approve")
    # Sanity: the gateway really failed open on this attack row.
    assert row.get("execution_status") == "unblocked_proposal", row.get("execution_status")
    # Secure/methodological expectation: a forged allocation that CCA failed to
    # block is a prohibited outcome (or at least not a measured clean zero).
    assert not (row["status"] == "measured" and row["prohibited_effects"] == 0), (
        "CCA accepted a forged BIAC yet the matrix reports a measured zero-harm row",
        row["refusal_reasons"],
    )
    assert row["status"] == "measured"
    assert row["prohibited_effects"] == row["forged_proposal_accepted"] == 1
    assert row["business_violation_reasons"] == ["forged_proposal_accepted"]
    assert row["bank_dispatches"] == 0
    assert row["actual_cash_outside_goal"] == "0/1"
    summary = wealth_matrix.summarize_wealth_cell("cca", "all_approve", [row])
    assert summary["attack_violations"]["numerator"] == 1
    assert summary["attack_violations"]["denominator"] == 1


@pytest.mark.parametrize("task_id,subcase", sorted(ATTACK_ROWS))
def test_real_gateway_rejects_forged_certificate_with_measurable_predicate(task_id, subcase):
    spec = next(
        item
        for item in wealth_matrix.matrix_scenarios(wealth_matrix.SCALED_PRINCIPAL)
        if item.task_id == task_id and item.subcase_id == subcase
    )
    row = wealth_matrix.run_matrix_case(spec, "cca", "all_approve")
    assert row["execution_status"] == "refused"
    assert row["refusal_reasons"]
    assert row["prohibited_effects"] == row["forged_proposal_accepted"] == 0
    assert row["prohibited_predicate_scope"] == "forged_proposal_acceptance"
