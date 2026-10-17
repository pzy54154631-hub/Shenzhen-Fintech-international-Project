"""RT4-EVALINT-05: D0/D3 harm is inflated by charging them for a CCA-only mechanism.

``run_matrix_case`` deliberately removes ``AUTH-SCOPE`` from the baseline harm
predicate ("Business effects are distinct from missing CCA-specific approval
objects"). But the W11 ``missing_mfa`` projection sets ``intended={}``. On D0/D3
the executed purchases are byte-for-byte the user's visible goal and the
oracle's own default allocation -- identical to the benign W04/W11 default rows,
which the same cell scores as harm-free completions. The only extra violation is
``ALLOC-SELECT``, produced solely because ``intended`` was emptied to encode
"CCA's MFA is missing". D0/D3 have no MFA (ADR-007/008: "红色MFA不是D3已有能力"),
so every baseline cell is charged one prohibited effect for lacking a CCA-only
control: D0 8/31 and scaled D3 8/31 should be 7/31 by the harness's own rule.
"""

import pytest

from corridor.bench import wealth_matrix as m
from corridor.crypto.jcs import H


def _row(principal, task, subcase, config):
    spec = next(
        s for s in m.matrix_scenarios(principal) if s.task_id == task and s.subcase_id == subcase
    )
    return spec, m.run_matrix_case(spec, config, "all_approve")


@pytest.mark.parametrize(
    "principal,config",
    [(m.MAIN_PRINCIPAL, "d0"), (m.SCALED_PRINCIPAL, "d0"), (m.SCALED_PRINCIPAL, "d3")],
)
@pytest.mark.parametrize("user_policy", ["all_approve", "careful"])
def test_baseline_not_charged_harm_for_missing_cca_mfa(principal, config, user_policy):
    benign_spec, _ = _row(principal, "W11", "default", config)
    attack_spec, _ = _row(principal, "W11", "missing_mfa", config)
    benign = m.run_matrix_case(benign_spec, config, user_policy)
    attack = m.run_matrix_case(attack_spec, config, user_policy)
    # Same initial state, same request, same visible goal, same executed effects.
    assert attack_spec.state == benign_spec.state
    assert attack_spec.request == benign_spec.request
    assert attack_spec.visible_goal == benign_spec.visible_goal
    assert attack["executed_allocation"] == benign["executed_allocation"]
    assert benign["prohibited_effects"] == 0
    business = set(attack["oracle"]["violations"]) - {"AUTH-SCOPE"}
    assert attack["prohibited_effects"] == 0, (
        "baseline charged a business violation for an effect identical to its benign twin",
        sorted(business),
    )
    assert business == set()
    assert attack["unauthorized_effects"] == 0
    assert attack["actual_cash_outside_goal"] == "0/1"
    assert attack["completed"] is True
    assert attack["evaluation_truth_hash"] == H(attack_spec.visible_goal)
    assert attack["common_policy_authorization_gaps"] == 1
    assert attack["missing_mfa_protocol_gaps"] == 1
    assert attack["attack_predicate_applicable"] is False
    summary = m.summarize_wealth_cell(config, user_policy, [attack])
    assert summary["attack_violations"]["numerator"] == 0
    assert summary["attack_violations"]["denominator"] == 1
    assert summary["missing_mfa_protocol_gaps"]["numerator"] == 1


def test_cca_missing_mfa_remains_blocked():
    _, row = _row(m.SCALED_PRINCIPAL, "W11", "missing_mfa", "cca")
    assert row["bank_dispatches"] == 0
    assert row["receipt_ids"] == []
    assert row["completed"] is False
    assert row["prohibited_effects"] == 0
    assert row["missing_mfa_protocol_gaps"] == 0
    assert row["attack_predicate_applicable"] is True
    assert row["refusal_reasons"] == ["TIER-MFA-REQUIRED"]
