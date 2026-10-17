import pytest

from corridor.gateway.facts import render_narrative
from corridor.gateway.privacy import PIIVault
from corridor.i18n import tr
from corridor.schemas.narrative import FactRef, Narrative
from tests.gateway_cases import approve, gateway_case


def _receipt_case():
    gateway, device, action, cert = gateway_case()
    result = gateway.dispatch(action, cert, approve(gateway, device, action, cert))
    assert result.status == "settled"
    return gateway, result.receipt


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("status", "settled"),
        ("amount", "200/1"),
        ("balance_before", "10000/1"),
        ("balance_after", "9800/1"),
        ("destination_ref", "DEST_CONTACT_CHEN"),
    ],
)
def test_five_real_execution_facts_render_exactly(field, expected):
    gateway, receipt = _receipt_case()
    result = render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field=field, expected=expected)]),
        gateway.store.snapshot(),
        "C_DEMO",
        PIIVault(),
    )
    assert result.status == "rendered" and result.rule_ids == []
    assert result.facts[0].exact_value == expected
    if field == "amount":
        assert result.facts[0].display_value == "200.00"


@pytest.mark.rule("RCPT-MISMATCH")
@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("status", "failed"),
        ("amount", "201/1"),
        ("balance_before", "1/1"),
        ("balance_after", "9999/1"),
        ("destination_ref", "WRONG_DEST"),
    ],
)
def test_five_forged_facts_fail_closed(field, expected):
    gateway, receipt = _receipt_case()
    result = render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field=field, expected=expected)]),
        gateway.store.snapshot(),
        "C_DEMO",
        PIIVault(),
    )
    assert result.status == "rejected" and "RCPT-MISMATCH" in result.rule_ids
    assert result.facts == []


@pytest.mark.parametrize(
    "note",
    [
        "已经替你办好",
        "转账二百元成功",
        "余额9800元",
        "所有款项均已到账",
        "你的账号现在正常",
        "已办妥",
        "搞定了",
        "All done",
        "Funds are there",
    ],
)
def test_unverified_note_cannot_claim_completion_or_account_facts(note):
    gateway, _ = _receipt_case()
    result = render_narrative(Narrative(note=note), gateway.store.snapshot(), "C_DEMO", PIIVault())
    assert "RCPT-MISMATCH" in result.rule_ids
    assert note not in result.text and result.facts == []
    assert result.note == tr("Assistant note (unverified): Please rely on the verified bank facts.")


def test_query_receipt_never_claims_transfer_success():
    gateway, _, action, cert = gateway_case(query=True)
    receipt = gateway.query(action, cert).receipt
    result = render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field="status")]),
        gateway.store.snapshot(),
        "C_DEMO",
        PIIVault(),
    )
    assert result.status == "rendered"
    assert receipt.kind == "balance_query"
    assert result.facts[0].exact_value == "settled"
    assert result.facts[0].display_value == tr("Query completed")


@pytest.mark.rule("BANK-RECEIPT")
def test_receipt_signature_and_trusted_principal_ledger_are_required():
    gateway, receipt = _receipt_case()
    narrative = Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field="status")])
    state = gateway.store.snapshot()
    bad = receipt.model_copy(update={"sig": "0" * 128})
    result = render_narrative(
        narrative, state.model_copy(update={"receipts": {bad.id: bad}}), "C_DEMO", PIIVault()
    )
    assert result.rule_ids == ["BANK-RECEIPT"]
    assert render_narrative(narrative, state, "OTHER", PIIVault()).status == "rejected"


@pytest.mark.rule("PII-OUT")
def test_raw_pii_note_is_replaced_and_unknown_has_pending_template():
    gateway, device, action, cert = gateway_case()
    from corridor.kernel.binding import intent_key

    gateway.bank.faults[intent_key(action, gateway.store.snapshot())] = "response_loss"
    assert (
        gateway.dispatch(action, cert, approve(gateway, device, action, cert)).status == "unknown"
    )
    result = render_narrative(
        Narrative(note="联系小陈"),
        gateway.store.snapshot(),
        "C_DEMO",
        PIIVault({"NAME_CHEN": "小陈"}),
    )
    assert "PII-OUT" in result.rule_ids and "小陈" not in result.text
    assert result.facts == []
    assert tr("Results awaiting reconciliation.") in result.text


def test_shallow_model_copy_cannot_crash_narrative_gate():
    gateway, _ = _receipt_case()
    bad = Narrative().model_copy(update={"note": 123})
    result = render_narrative(bad, gateway.store.snapshot(), "C_DEMO", PIIVault())
    assert result.status == "rejected" and result.rule_ids == ["RCPT-MISMATCH"]


def test_missing_receipt_has_no_success_and_harmless_note_is_labeled():
    gateway, _ = _receipt_case()
    result = render_narrative(
        Narrative(
            fact_refs=[FactRef(receipt_ref="NOT_A_RECEIPT", field="status")],
            note="Please review the recipient.",
        ),
        gateway.store.snapshot(),
        "C_DEMO",
        PIIVault(),
    )
    assert result.rule_ids == ["RCPT-MISMATCH"] and result.facts == []
    assert result.note == tr(
        "Assistant note (unverified): {note}", note=tr("Please review the recipient.")
    )
