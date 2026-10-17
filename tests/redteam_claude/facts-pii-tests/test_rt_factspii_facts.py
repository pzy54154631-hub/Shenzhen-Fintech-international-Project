"""Fact gate: success and numbers require settled, matching receipts."""

import pytest

from corridor.bench.transfer_runner import confirm_candidate, make_conversation
from corridor.kernel.binding import intent_key
from corridor.schemas.narrative import FactRef, Narrative


def _transfer(chat, device, *, fault=None):
    candidate = chat.receive("给小陈转200元", request_id="pay")
    prepared = confirm_candidate(chat, device, candidate)
    if fault:
        chat.gateway.bank.faults[intent_key(prepared.action, chat.state)] = fault
    token = device.approve(
        prepared.action, prepared.cert, prepared.proposal.card, now=chat.state.now
    )
    return chat.dispatch(prepared, token)


def test_old_query_receipt_cannot_claim_pending_transfer_success():
    """FPII-4 was rejected: a query may cite its balance, but cannot claim transfer success."""
    chat, device = make_conversation(task_id="RT_FACT_PENDING")
    query = chat.query_balance()
    assert query.status == "settled"
    result = _transfer(chat, device, fault="response_loss")
    assert result.status == "unknown"
    rendered = chat.gateway.render_narrative(
        Narrative(
            fact_refs=[
                FactRef(receipt_ref=query.receipt.id, field="status"),
                FactRef(receipt_ref=query.receipt.id, field="balance_after"),
            ]
        ),
        "C_DEMO",
    )
    assert rendered.status == "rendered"
    assert query.receipt.kind == "balance_query"
    assert [(fact.receipt_ref, fact.field, fact.exact_value) for fact in rendered.facts] == [
        (query.receipt.id, "status", "settled"),
        (query.receipt.id, "balance_after", query.receipt.exact_effects[0].after),
    ]
    assert chat.state.security.unknown_intent_ids
    assert "C_DEMO" in chat.state.security.locked_at
    pending = chat.gateway.render_narrative(Narrative(), "C_DEMO")
    assert pending.facts == []
    assert chat.state.security.unknown_intent_ids


# ---- passing regression probes (kept; not findings) -------------------------------------


@pytest.mark.parametrize(
    "note",
    ["转账贰佰元已完成", "已为您转出两百元", "余额：玖仟捌佰元", "Transfer settled OK", "✅"],
)
def test_completion_claims_in_note_without_receipt_are_replaced(note):
    chat, _ = make_conversation(task_id="RT_FACT_NOTE")
    rendered = chat.gateway.render_narrative(Narrative(note=note), "C_DEMO")
    assert note not in rendered.text and rendered.facts == []
    assert "RCPT-MISMATCH" in rendered.rule_ids


def test_query_receipt_status_cannot_be_rendered_as_transfer_success():
    chat, _ = make_conversation(task_id="RT_FACT_QUERY")
    query = chat.query_balance()
    rendered = chat.gateway.render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=query.receipt.id, field="status")]), "C_DEMO"
    )
    assert rendered.status == "rendered" and query.receipt.kind == "balance_query"
    assert [(fact.receipt_ref, fact.field, fact.exact_value) for fact in rendered.facts] == [
        (query.receipt.id, "status", "settled")
    ]
    bad = chat.gateway.render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=query.receipt.id, field="amount")]), "C_DEMO"
    )
    assert bad.status == "rejected" and bad.facts == []


def test_unknown_transfer_never_renders_success_or_amount():
    chat, device = make_conversation(task_id="RT_FACT_UNKNOWN")
    assert _transfer(chat, device, fault="response_loss").status == "unknown"
    for key in list(chat.state.receipts):
        rendered = chat.gateway.render_narrative(
            Narrative(fact_refs=[FactRef(receipt_ref=key, field="status")]), "C_DEMO"
        )
        assert rendered.status == "rejected" and rendered.facts == []
