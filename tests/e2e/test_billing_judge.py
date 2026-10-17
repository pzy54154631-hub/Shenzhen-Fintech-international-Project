"""B6 judge cases exercise the shared gateway and retain inspectable evidence."""

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.bank_cases import BankCase
from corridor.bench.billing_runner import prepare_analysis, run_j07, run_j10, run_j11
from corridor.schemas.bank import InputTerm, StateTerm
from corridor.schemas.base import loads_exact
from corridor.sim.billing import subscription_state


@pytest.mark.parametrize("runner,task", [(run_j07, "J07"), (run_j10, "J10"), (run_j11, "J11")])
def test_scripted_billing_cases_have_real_gateway_evidence(runner, task, tmp_path):
    result = runner(LLMClient(mode="scripted"), evidence_dir=tmp_path)
    assert result["passed"], result
    assert result["task_id"] == task
    assert result["real_model_evaluation"] == "not_run"
    assert result["checks"] and all(result["checks"].values())
    manifest = loads_exact((tmp_path / "manifest.json").read_bytes())
    assert manifest["sources"] and set(manifest["sources"]) == {"scripted"}
    assert manifest["passed"]
    assert list(tmp_path.glob("*/audit.jsonl"))
    for case_dir in tmp_path.iterdir():
        if case_dir.is_dir():
            assert (case_dir / "audit.checkpoint.json").exists()
            assert (case_dir / "final_state.json").exists()


@pytest.mark.parametrize("runner", [run_j07, run_j10, run_j11])
def test_billing_judge_strict_mode_never_falls_back(runner, tmp_path):
    with pytest.raises(RuntimeError, match="task_id=J"):
        runner(LLMClient(mode="strict", replay_dir=tmp_path))


def test_transfer_report_and_subscriptions_share_one_real_gateway():
    case = BankCase(subscription_state(), task_id="B6", subcase_id="three_scenes")
    amount = case.device.confirm_input(
        intent_id=case.intent(),
        slot="amount",
        value={"amount": "200/1", "ccy": "CNY"},
        now=case.state.now,
    )
    contact = case.device.confirm_input(
        intent_id=case.intent(),
        slot="contact_ref",
        value="CONTACT_CHEN",
        now=case.state.now,
    )
    authority = case.operation(
        "transfer",
        ["A_CURRENT", "CONTACT_CHEN"],
        [amount, contact],
        amount_bound="200/1",
    )
    transfer = case.prepare(
        "transfer",
        {"source_ref": "A_CURRENT", "contact_ref": "CONTACT_CHEN", "amount_ref": amount.id},
        {
            "source_ref": StateTerm(
                collection="accounts",
                object_ref="A_CURRENT",
                field="id",
                version=1,
            ),
            "contact_ref": StateTerm(
                collection="contacts",
                object_ref="CONTACT_CHEN",
                field="id",
                version=1,
            ),
            "amount_ref": InputTerm(input_ref=amount.id, slot="amount"),
        },
        inputs=[amount, contact],
        authorization=authority,
    )
    assert case.gateway.dispatch(transfer.action, transfer.cert).rule_ids == ["APR-REQUIRED"]
    assert case.gateway.bank.execute_count == 0
    assert case.dispatch(transfer).status == "settled"
    report = prepare_analysis(case, "bill_report", period="2026", step=1)
    reported = case.dispatch(report)
    assert reported.status == "settled"
    assert reported.analysis_receipt.results["net_spend"].value == "432/1"
    query = prepare_analysis(case, "subscription_query", period="2026", step=2)
    assert case.gateway.dispatch(query.action, query.cert).analysis_receipt is None
    queried = case.dispatch(query)
    assert queried.status == "settled"
    assert queried.analysis_receipt.results["candidate_merchants"].value == ["SUB_A", "SUB_B"]
    assert case.gateway.bank.execute_count == 1
    assert len(case.state.security.consumed_nonces) == 2
    assert case.gateway.bank.final_state()["balances"]["A_CURRENT"] == "9800/1"
    assert case.gateway.verify_log()
