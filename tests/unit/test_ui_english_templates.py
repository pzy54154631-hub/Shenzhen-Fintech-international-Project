"""English presentation keeps authenticated values and approval warnings intact."""

from unittest.mock import MagicMock

from corridor.gateway.facts import render_narrative
from corridor.gateway.privacy import PIIVault
from corridor.schemas.narrative import FactRef, Narrative
from corridor.ui import components
from tests.gateway_cases import approve, gateway_case


def test_english_bank_facts_preserve_exact_authenticated_amounts():
    gateway, device, action, cert = gateway_case()
    execution = gateway.dispatch(action, cert, approve(gateway, device, action, cert))
    assert execution.status == "settled"
    receipt = execution.receipt
    assert receipt is not None
    result = render_narrative(
        Narrative(
            fact_refs=[
                FactRef(receipt_ref=receipt.id, field="status", expected="settled"),
                FactRef(receipt_ref=receipt.id, field="amount", expected="200/1"),
                FactRef(receipt_ref=receipt.id, field="balance_after", expected="9800/1"),
            ]
        ),
        gateway.store.snapshot(),
        device.principal,
        PIIVault(),
    )
    assert result.status == "rendered" and result.rule_ids == []
    assert [fact.exact_value for fact in result.facts] == ["settled", "200/1", "9800/1"]
    assert result.text == (
        "Transfer settled.\nTransfer amount: 200.00 CNY.\nVerified balance: 9800.00 CNY."
    )


def test_english_unverified_note_cannot_assert_bank_completion():
    gateway, device, _, _ = gateway_case()
    result = render_narrative(
        Narrative(note="All funds have arrived."),
        gateway.store.snapshot(),
        device.principal,
        PIIVault(),
    )
    assert result.rule_ids == ["RCPT-MISMATCH"]
    assert result.facts == []
    assert result.note == "Assistant note (unverified): Please rely on the verified bank facts."
    assert "All funds have arrived." not in result.text


def test_english_safe_note_is_separate_from_verified_facts():
    gateway, device, _, _ = gateway_case()
    result = render_narrative(
        Narrative(note="Please review the recipient."),
        gateway.store.snapshot(),
        device.principal,
        PIIVault(),
    )
    assert result.status == "rendered" and result.rule_ids == []
    assert result.facts == []
    assert result.text == (
        "No verifiable transaction result is available.\n"
        "Assistant note (unverified): Please review the recipient."
    )


def test_component_card_explains_red_approval_and_keeps_canonical_value(monkeypatch):
    display = MagicMock()
    monkeypatch.setattr(components, "st", display)
    components.render_card({"kind": "purchase_product", "amount": "200/1", "tier": "red"})
    text = " ".join(str(call) for call in display.mock_calls)
    assert "Purchase confirmation" in text
    assert "CNY 200.00" in text
    assert display.json.call_args.args[0]["amount"] == "200/1"
    assert "Technical evidence" in text
    assert "Red · independent simulated MFA required" in text
    assert "Investment purchases require separate device MFA." in text


def test_english_labels_keep_benchmark_qualification():
    assert components.LABELS["expected_net"] == "Net performance benchmark (not guaranteed)"
    assert components.KINDS["purchase_product"] == "Product purchase"
    assert components.text_value(True) == "Yes"
    assert components.text_value(False) == "No"
    assert components.text_value(None) == "Not applicable"
