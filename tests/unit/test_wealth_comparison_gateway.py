"""The allocation fact path traverses plans, kernel checking and signed receipts."""

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, sign, verify
from corridor.gateway.facts import render_narrative
from corridor.gateway.orchestration import compile_node
from corridor.gateway.runtime import create_gateway
from corridor.schemas.bank import Plan, PlanNode
from corridor.schemas.narrative import FactRef, Narrative
from corridor.sim.keys import signing_key
from corridor.stores.bank import BankStore
from tests.wealth_cases import allocation_case


def _comparison():
    action, cert, state = allocation_case()
    gateway = create_gateway(
        BankStore(state), bank_key=signing_key("bank"), gateway_key=signing_key("gateway")
    )
    plan = Plan(
        plan_id=action.plan_id,
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=action.intent_id,
        goal_input_refs=[action.args.request_ref],
        nodes=[
            PlanNode(
                node_id=action.node_id,
                tool=action.kind,
                args={"request_ref": cert.derivations["args.request_ref"]},
            )
        ],
        ownership_epoch=0,
    )
    assert gateway.submit_plan(plan).status == "registered"
    action, cert = compile_node(gateway, plan, action.node_id)
    result = gateway.query(action, cert)
    assert result.status == "settled", result.rule_ids
    return gateway, action, cert, result


def test_comparison_returns_a_signed_built_in_receipt_without_bank_execution():
    gateway, _, cert, result = _comparison()
    state = gateway.store.snapshot()
    receipt = result.analysis_receipt
    assert receipt.function_id == "allocation_compare_v1"
    assert receipt.trust == "builtin"
    assert receipt.results["biac_hash"].value == H(cert.allocation)
    assert receipt.results["allocation"].value == cert.allocation.model_dump(mode="json")
    assert verify(state.roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
    assert gateway.bank.execute_count == 0
    assert gateway.verify_log()


def test_allocation_narrative_renders_only_signed_scalar_facts():
    gateway, action, _, result = _comparison()
    receipt = result.analysis_receipt
    rendered = gateway.render_narrative(
        Narrative(
            fact_refs=[
                FactRef(receipt_ref=receipt.id, field="total_principal"),
                FactRef(receipt_ref=receipt.id, field="projected_net"),
            ]
        ),
        action.principal,
    )
    assert rendered.status == "rendered", rendered.rule_ids
    assert [fact.exact_value for fact in rendered.facts] == ["10000/1", "350/1"]
    assert "10,000.00" in rendered.text or "10000.00" in rendered.text
    assert "Performance benchmark (not guaranteed)" in rendered.text
    assert gateway.bank.execute_count == 0


def test_allocation_suitability_metadata_is_signed_and_persists_session_cap():
    gateway, action, _, result = _comparison()
    receipt = result.analysis_receipt
    metadata = receipt.parameters["suitability"]
    assert metadata["effective_level"] == 2
    assert metadata["raw_level"] == 2
    state = gateway.store.snapshot()
    event = next(
        event
        for event in state.ledger
        if event.object_delta.get("analysis_receipt_id") == receipt.id
    )
    assert event.object_delta["device_session_id"] == action.device_session_id
    assert event.object_delta["effective_level_cap"] == metadata["effective_level"]
    assert verify(state.roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
    assert "effective_level" not in receipt.results


@pytest.mark.parametrize(
    "mutation",
    [
        "signature",
        "missing_event",
        "wrong_event_kind",
        "wrong_owner",
        "claimed_value",
        "resigned_inconsistent_scalar",
        "resigned_wrong_biac_hash",
        "resigned_wrong_principal",
        "unlisted_fact",
    ],
)
def test_allocation_narrative_rejects_unverified_or_inconsistent_facts(mutation):
    gateway, action, _, result = _comparison()
    state = gateway.store.snapshot()
    receipt = result.analysis_receipt
    fact = FactRef(receipt_ref=receipt.id, field="total_principal")
    principal = action.principal
    if mutation == "signature":
        receipt = receipt.model_copy(update={"sig": "0" * 128})
    elif mutation == "missing_event":
        state = state.model_copy(update={"ledger": []})
    elif mutation == "wrong_event_kind":
        state = state.model_copy(
            update={
                "ledger": [
                    event.model_copy(update={"kind": "product_compare"}) for event in state.ledger
                ]
            }
        )
    elif mutation == "wrong_owner":
        principal = "C_OTHER"
    elif mutation == "claimed_value":
        fact = fact.model_copy(update={"expected": "999999/1"})
    elif mutation == "unlisted_fact":
        fact = fact.model_copy(update={"field": "guaranteed_profit"})
    else:
        if mutation == "resigned_wrong_principal":
            allocation = {**receipt.results["allocation"].value, "principal": "C_OTHER"}
            results = {
                **receipt.results,
                "allocation": receipt.results["allocation"].model_copy(
                    update={"value": allocation}
                ),
                "biac_hash": receipt.results["biac_hash"].model_copy(
                    update={"value": H(allocation)}
                ),
            }
        else:
            field = "total_principal" if mutation == "resigned_inconsistent_scalar" else "biac_hash"
            value = "999999/1" if field == "total_principal" else "f" * 64
            results = {
                **receipt.results,
                field: receipt.results[field].model_copy(update={"value": value}),
            }
        receipt = receipt.model_copy(update={"results": results})
        receipt = receipt.model_copy(update={"sig": sign(signing_key("gateway"), RECEIPT, receipt)})
        state = state.model_copy(
            update={
                "ledger": [
                    event.model_copy(
                        update={"object_delta": {**event.object_delta, "receipt_hash": H(receipt)}}
                    )
                    for event in state.ledger
                ]
            }
        )
    state = state.model_copy(update={"receipts": {**state.receipts, receipt.id: receipt}})
    rendered = render_narrative(Narrative(fact_refs=[fact]), state, principal, gateway.vault)
    assert rendered.status != "rendered"
    assert "RCPT-MISMATCH" in rendered.rule_ids
    assert rendered.facts == []
