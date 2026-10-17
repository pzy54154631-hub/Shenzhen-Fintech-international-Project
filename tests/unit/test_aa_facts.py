"""AA receipt facts disclose requests without inventing customer collections."""

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT
from corridor.gateway.facts import render_narrative
from corridor.gateway.privacy import PIIVault
from corridor.schemas.bank import AnalysisReceipt, AnalysisResult, BusinessEvent
from corridor.schemas.narrative import FactRef, Narrative
from corridor.sim.fixtures import make_state
from tests.bank_cases import signed


def aa_receipt():
    state = make_state()
    receipt = signed(
        AnalysisReceipt(
            receipt_id="AA",
            dataset_hash=H("DATA"),
            function_id="aa_split_v1",
            parameters={"principal": "C_DEMO", "action_hash": H("ACTION")},
            results={
                "total": AnalysisResult(value="10/1", unit="CNY", source_tx_ids=[]),
                "status": AnalysisResult(
                    value="requested", unit="request_status", source_tx_ids=[]
                ),
                "request_ids": AnalysisResult(
                    value=["R1", "R2", "R3"], unit="request_ids", source_tx_ids=[]
                ),
                "shares.CONTACT_CHEN": AnalysisResult(value="167/50", unit="CNY", source_tx_ids=[]),
                "shares.CONTACT_LIN_A": AnalysisResult(
                    value="333/100", unit="CNY", source_tx_ids=[]
                ),
                "shares.CONTACT_LIN_B": AnalysisResult(
                    value="333/100", unit="CNY", source_tx_ids=[]
                ),
            },
            trust="builtin",
            computed_at=state.now,
            sig="0" * 128,
        ),
        RECEIPT,
        "gateway",
    )
    event = BusinessEvent(
        id="AA_EVENT",
        intent_key=H("AA_EVENT"),
        event="settled",
        kind="aa_request",
        principal="C_DEMO",
        object_delta={
            "analysis_receipt_id": receipt.id,
            "action_hash": receipt.parameters["action_hash"],
            "receipt_hash": H(receipt),
        },
        ts=state.now,
    )
    return receipt, state.model_copy(update={"receipts": {receipt.id: receipt}, "ledger": [event]})


def render(receipt, state, field, principal="C_DEMO"):
    return render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field=field)]),
        state,
        principal,
        PIIVault(),
    )


def test_aa_registered_requested_total_and_split_render_without_payment_claim():
    receipt, state = aa_receipt()
    for field in receipt.results:
        result = render(receipt, state, field)
        assert result.status == "rendered", result
        assert result.facts[0].exact_value == receipt.results[field].value
        assert receipt.function_id == "aa_split_v1"
    result = render(receipt, state, "status")
    assert result.facts[0].exact_value == "requested"


@pytest.mark.parametrize(
    "change", ["wrong_owner", "bad_sig", "missing_event", "wrong_event_kind", "wrong_participant"]
)
def test_aa_fact_gate_requires_owner_signature_registration_and_owned_participants(change):
    receipt, state = aa_receipt()
    if change == "wrong_owner":
        assert render(receipt, state, "total", "OTHER").status == "rejected"
        return
    if change == "bad_sig":
        receipt = receipt.model_copy(update={"sig": "0" * 128})
        state = state.model_copy(update={"receipts": {receipt.id: receipt}})
    elif change == "missing_event":
        state = state.model_copy(update={"ledger": []})
    elif change == "wrong_event_kind":
        state = state.model_copy(
            update={"ledger": [state.ledger[0].model_copy(update={"kind": "bill_report"})]}
        )
    else:
        contact = state.contacts["CONTACT_CHEN"].model_copy(update={"owner": "OTHER"})
        state = state.model_copy(update={"contacts": {**state.contacts, contact.id: contact}})
    assert render(receipt, state, "total").status == "rejected"


@pytest.mark.parametrize("change", ["total", "share", "status"])
def test_aa_receipt_cannot_claim_completed_collection_or_inconsistent_split(change):
    receipt, state = aa_receipt()
    field = {"total": "total", "share": "shares.CONTACT_CHEN", "status": "status"}[change]
    value = "settled" if change == "status" else "1/1"
    results = {**receipt.results, field: receipt.results[field].model_copy(update={"value": value})}
    receipt = signed(receipt.model_copy(update={"results": results}), RECEIPT, "gateway")
    event = state.ledger[0].model_copy(
        update={"object_delta": {**state.ledger[0].object_delta, "receipt_hash": H(receipt)}}
    )
    state = state.model_copy(update={"receipts": {receipt.id: receipt}, "ledger": [event]})
    assert render(receipt, state, field).status == "rejected"
