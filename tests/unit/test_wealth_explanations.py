"""M6 advice uses verified receipts and never selects a relaxation for the user."""

import pytest

from corridor.agent.llm import LLMClient
from corridor.agent.wealth_dialogue import WealthDialogue
from corridor.bench.wealth_smoke import make_wealth_conversation
from corridor.crypto.jcs import H
from corridor.schemas.narrative import FactRef
from corridor.sim.wealth import allocation_request


def chat_case(task="M6", legacy=None):
    if legacy is None:
        legacy, device = make_wealth_conversation(
            client=LLMClient(mode="scripted", api="responses")
        )
    else:
        from corridor.sim.wealth_device import WealthDevice

        device = WealthDevice()
    chat = WealthDialogue(
        legacy.gateway,
        legacy.client,
        principal=legacy.principal,
        session_id=legacy.session_id,
        task_id=task,
    )
    return chat, device


def propose(chat, device, **changes):
    value = device.confirm_input(
        intent_id=chat.intent_id,
        slot="allocation",
        value=allocation_request(**changes).model_dump(mode="json"),
        now=chat.state.now,
    )
    chat.confirm_goals(value)
    return chat.turn("Propose allocation", request_id="propose")


def test_failed_construction_explains_policy_and_leaves_user_in_control():
    chat, device = chat_case()
    failed = propose(chat, device, amount="20000/1")
    assert chat.comparison is None and failed.rule_ids
    before = H(chat.state)
    explanation = chat.explain_failure()
    assert "No allocation was constructed" in explanation.message
    assert "closest allowed plan" in explanation.message
    assert explanation.alternatives == ()
    assert H(chat.state) == before
    assert chat.gateway.bank.execute_count == 0


def test_allowed_alternative_requires_a_current_kernel_passing_verified_receipt():
    chat, device = chat_case()
    propose(chat, device, amount="20000/1")
    other, other_device = chat_case("M6-alternative", legacy=chat)
    propose(other, other_device)
    ref = FactRef(receipt_ref=other.comparison.result.analysis_receipt.id, field="allocation")
    before = H(chat.state)
    explanation = chat.explain_failure(alternative_refs=[ref])
    assert len(explanation.alternatives) == 1
    assert explanation.alternatives[0].requires_device_confirmation
    assert explanation.alternatives[0].facts
    assert H(chat.state) == before
    assert chat.signed_request_ref != other.signed_request_ref
    assert chat.gateway.bank.execute_count == 0
    with pytest.raises(ValueError):
        chat.explain_failure(alternative_refs=[ref] * 4)
    with pytest.raises(ValueError):
        chat.explain_failure(alternative_refs=[FactRef(receipt_ref="FORGED", field="allocation")])


def test_correction_diff_is_derived_only_from_verified_old_and_new_biac_receipts():
    chat, device = chat_case()
    propose(chat, device)
    old = chat.comparison
    chat.turn("Actually 5000", request_id="correct")
    value = device.confirm_input(
        intent_id=chat.intent_id,
        slot="allocation",
        value=allocation_request(amount="5000/1").model_dump(mode="json"),
        now=chat.state.now,
    )
    chat.confirm_goals(value)
    chat.turn("Propose allocation", request_id="new")
    diff = chat.change_explanation()
    assert diff
    assert all(row.source_refs[0].receipt_ref == old.result.analysis_receipt.id for row in diff)
    principal = [row for row in diff if row.product_id == "P_A" and row.field == "principal"]
    assert principal[0].exact_value == "-2500/1"
    returns = [row for row in diff if row.field == "expected_net"]
    assert returns
    assert all("performance benchmark (not guaranteed)" in row.label.lower() for row in returns)
    assert chat.gateway.bank.execute_count == 0
