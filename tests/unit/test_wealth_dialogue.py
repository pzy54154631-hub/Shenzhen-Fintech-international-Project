"""W6 model outputs select handles; signed inputs and gateway facts supply values."""

from copy import deepcopy

import pytest

from corridor.agent.llm import LLMClient, LLMResult
from corridor.bench.wealth_smoke import confirm_wealth_goal, make_wealth_conversation
from corridor.crypto.jcs import jcs_bytes
from corridor.sim.wealth import allocation_request


def test_vague_request_clarifies_all_missing_signed_goals_without_authority():
    chat, _ = make_wealth_conversation(client=LLMClient(mode="scripted"))
    before = chat.state
    candidate = chat.receive("I want something safe.", request_id="vague")
    assert set(candidate.missing_fields) == {
        "source_account_ref",
        "amount",
        "horizon_days",
        "liquidity_days",
        "liquidity_amount",
        "allowed_types",
        "objective",
    }
    assert candidate.question and "guarantee" not in candidate.question.lower()
    assert chat.state.user_inputs == before.user_inputs
    assert chat.state.authorizations == before.authorizations
    assert not chat.state.allocation_plans
    assert not chat.state.positions
    assert chat.receive("I want something safe.", request_id="vague") == candidate
    assert len(chat.client.calls) == 1
    with pytest.raises(ValueError, match="Request ID"):
        chat.receive("Buy the riskiest product", request_id="vague")


def test_three_typed_calls_use_only_device_handles_and_verified_fact_fields():
    client = LLMClient(mode="scripted")
    chat, device = make_wealth_conversation(client=client)
    observed = []
    original = client.complete

    def capture(**kwargs):
        observed.append(deepcopy({key: kwargs[key] for key in ("prompt", "tool_state")}))
        return original(**kwargs)

    client.complete = capture
    candidate = chat.receive("I want something safe.", request_id="vague")
    prepared = confirm_wealth_goal(chat, device, candidate)
    receipt = prepared.result.analysis_receipt
    assert receipt is not None
    rendered = chat.narrative(receipt.id)
    assert rendered.status == "rendered", rendered
    assert len(observed) == 3
    assert all(
        item["prompt"]["response_schema"]["additionalProperties"] is False for item in observed
    )
    assert observed[1]["prompt"]["response_schema"]["properties"]["request_ref"]["enum"] == [
        prepared.action.args.request_ref
    ]
    allowed = observed[2]["prompt"]["response_schema"]["properties"]["fact_refs"]["items"]["enum"]
    assert set(allowed) == set(chat.fact_fields)
    assert {fact.field for fact in rendered.facts} == set(chat.fact_fields)
    wire = jcs_bytes(observed)
    for secret in (b'"sig"', b'"device_pubkey"', b'"bank_pubkey"', b'"private_key"'):
        assert secret not in wire
    assert "expected" not in observed[2]["prompt"]["response_schema"]["properties"]
    assert not chat.state.positions


@pytest.mark.parametrize(
    "bad_output",
    [
        {"kind": "allocation_compare", "request_ref": "FORGED_REQUEST"},
        {"kind": "allocation_compare", "request_ref": "FORGED_REQUEST", "amount": "90000/1"},
    ],
)
def test_invented_or_literal_model_proposal_is_rejected_without_query(bad_output):
    chat, device = make_wealth_conversation(client=LLMClient(mode="scripted"))
    candidate = chat.receive("I want something safe.", request_id="vague")
    attempts = []

    def malicious(**kwargs):
        attempts.append(kwargs["step"])
        return LLMResult(bad_output, "test-adversary", "test-key")

    chat.client.complete = malicious
    with pytest.raises(ValueError, match="repair limit"):
        confirm_wealth_goal(chat, device, candidate)
    assert len(attempts) == 3
    assert not chat.state.receipts
    assert not chat.state.positions


@pytest.mark.parametrize("mutation", ["signature", "scope", "missing_goal"])
def test_invalid_signed_goals_fail_before_model_proposal(mutation):
    chat, device = make_wealth_conversation(client=LLMClient(mode="scripted"))
    candidate = chat.receive("I want something safe.", request_id="vague")
    payload = allocation_request().model_dump(mode="json")
    if mutation == "missing_goal":
        payload.pop("amount")
    value = device.confirm_input(
        intent_id=candidate.intent_id if mutation != "scope" else "FOREIGN",
        slot="allocation",
        value=payload,
        now=chat.state.now,
    )
    if mutation == "signature":
        value = value.model_copy(update={"sig": "0" * 128})
    with pytest.raises(ValueError):
        chat.compare(candidate, value)
    assert len(chat.client.calls) == 1
    assert not chat.state.receipts
    assert not chat.state.positions


def test_forged_narrative_field_never_reaches_fact_renderer():
    chat, device = make_wealth_conversation(client=LLMClient(mode="scripted"))
    candidate = chat.receive("I want something safe.", request_id="vague")
    prepared = confirm_wealth_goal(chat, device, candidate)
    chat.client.complete = lambda **_: LLMResult(
        {"fact_refs": ["guaranteed_profit"]}, "test-adversary", "test-key"
    )
    with pytest.raises(ValueError, match="repair limit"):
        chat.narrative(prepared.result.analysis_receipt.id)
    assert not chat.state.positions
