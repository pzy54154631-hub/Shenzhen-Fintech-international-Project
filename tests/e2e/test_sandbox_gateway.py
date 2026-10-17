"""Sandbox registry is owned, immutable, private and financially powerless."""

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.crypto.jcs import H
from corridor.schemas.bank import ReadTerm
from corridor.schemas.narrative import Narrative
from corridor.sim.billing import report_state


def sandbox_case(program="{'total': sum_money(dataset)}"):
    case = BankCase(report_state(), task_id="B9-BOUNDARY", subcase_id="sandbox")
    dataset = case.gateway.register_dataset(case.device.principal, "A_CURRENT", "2026-10")
    source = case.gateway.register_program(case.device.principal, program)
    args = {"dataset_ref": dataset, "program_ref": source}
    terms = {
        key: ReadTerm(
            session_authorization_ref=case.session_authorization.id, query_field=key, value=value
        )
        for key, value in args.items()
    }
    prepared = case.prepare("sandbox_analyze", args, terms)
    return case, prepared


def test_owned_sandbox_receipt_is_registered_and_labeled_exploratory():
    case, prepared = sandbox_case()
    result = case.gateway.query(prepared.action, prepared.cert)
    assert result.status == "settled", result
    receipt = result.analysis_receipt
    assert receipt.trust == "exploratory" and receipt.program_hash
    assert receipt.id in case.state.receipts
    assert case.gateway.bank.execute_count == 0
    rendered = case.gateway.render_narrative(
        Narrative(fact_refs=[{"receipt_ref": receipt.id, "field": "total"}], note=""),
        case.device.principal,
    )
    assert rendered.status == "rendered", rendered
    assert rendered.rule_ids == []
    assert rendered.facts[0].receipt_ref == receipt.id
    assert rendered.facts[0].exact_value == receipt.results["total"].value


def test_dataset_registration_rejects_other_owner_before_reading_rows():
    case, _ = sandbox_case()
    with pytest.raises(ValueError, match="READ-ROLE"):
        case.gateway.register_dataset("OTHER", "A_CURRENT", "2026-10")


def test_program_pii_rejected_before_source_is_audited():
    case, _ = sandbox_case()
    raw = "13812345678"
    with pytest.raises(ValueError, match="PII-CTX"):
        case.gateway.register_program(case.device.principal, "{'leak': '" + raw + "'}")
    assert raw not in str(case.gateway.audit.records())


def test_unregistered_handle_rejected_without_worker_or_bank_execution():
    case, prepared = sandbox_case()
    forged = "PROG_" + "0" * 64
    action = prepared.action.model_copy(
        update={"args": prepared.action.args.model_copy(update={"program_ref": forged})}
    )
    cert = prepared.cert.model_copy(update={"action_hash": H(action)})
    result = case.gateway.query(action, cert)
    assert result.status == "rejected"
    assert case.gateway.bank.execute_count == 0
