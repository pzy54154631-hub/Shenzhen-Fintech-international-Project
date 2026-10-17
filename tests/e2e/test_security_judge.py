"""Judge security assertions exercise actual approvals, controls and recovery."""

import pytest

from corridor.bench.security_runner import run_security


@pytest.mark.parametrize("task", ["J21", "J22"])
def test_security_judge_all_subcases(task, tmp_path):
    result = run_security(task, evidence_dir=tmp_path)
    assert result["passed"], result["checks"]
    assert len(result["checks"]) >= 10
    assert (tmp_path / "result.json").exists()


@pytest.mark.rule("IDEM-DUP")
def test_fresh_nonce_cannot_repeat_executed_intent():
    from corridor.bench.security_runner import duplicate_case

    case, result = duplicate_case()
    assert result.rule_ids == ["IDEM-DUP"]
    assert case.gateway.bank.execute_count == 1


def test_unlock_rejection_exposes_control_requirement():
    from corridor.bench.security_runner import unlock_case

    _, checks = unlock_case("cooldown")
    assert all(checks.values()), checks


@pytest.mark.rule("MFA-REUSE")
def test_consumed_mfa_grant_cannot_be_registered_again():
    from corridor.bench.investment_runner import _with_mfa
    from corridor.bench.planning_runner import prepare_transfer
    from corridor.bench.security_runner import _case

    case = _case("GOLDEN", "consumed_mfa")
    prepared = _with_mfa(case, prepare_transfer(case, "1200/1", step=0))
    grant = case.state.security.mfa_grants[prepared.cert.mfa_grant_refs[0]]
    assert case.dispatch(prepared).status == "settled"
    assert case.gateway.submit_mfa(grant).rule_ids == ["MFA-REUSE"]
    assert case.gateway.bank.execute_count == 1
