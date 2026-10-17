"""M2 dialogue: drafts never substitute for device signatures or approval."""

from copy import deepcopy

import pytest

from corridor.agent.llm import BudgetExceeded, LLMClient, LLMResult, ReplayMiss
from corridor.agent.wealth_dialogue import WealthDialogue
from corridor.bench.wealth_smoke import make_wealth_conversation
from corridor.crypto.jcs import H
from corridor.i18n import tr
from corridor.sim.wealth import allocation_request


def advisor(client=None):
    legacy, device = make_wealth_conversation(
        client=client or LLMClient(mode="scripted", api="responses")
    )
    chat = WealthDialogue(
        legacy.gateway,
        legacy.client,
        principal=legacy.principal,
        session_id=legacy.session_id,
        source_account_ref="A_CURRENT",
        allowed_types=["wealth"],
    )
    return chat, device


def signed_goals(chat, device, **changes):
    request = allocation_request(**changes)
    value = device.confirm_input(
        intent_id=chat.intent_id,
        slot="allocation",
        value=request.model_dump(mode="json"),
        now=chat.state.now,
    )
    return chat.confirm_goals(value)


def test_one_sentence_captures_every_stated_slot_and_asks_one_missing_question():
    chat, device = advisor()
    initial = H(chat.state)
    first = chat.turn(
        "I have 100k from my bonus, want something safe, might need 20k within a week",
        request_id="one",
    )
    assert first.pending_slots == ("horizon_days", "objective")
    assert first.question.count("?") == 1
    assert first.slots["amount"].value == "100000/1"
    assert first.slots["amount"].source == "heard, not signed"
    second = chat.turn("One year", request_id="two")
    assert second.pending_slots == ("objective",)
    third = chat.turn("Lowest fees", request_id="three")
    assert third.pending_slots == ()
    assert third.device_action == "confirm_goals"
    assert H(chat.state) == initial
    value = device.confirm_input(
        intent_id=chat.intent_id,
        slot="allocation",
        value=chat.goal_sheet().model_dump(mode="json"),
        now=chat.state.now,
    )
    confirmed = chat.confirm_goals(value)
    assert confirmed.phase == "goals_signed"
    assert all(slot.source == "signed on device" for slot in confirmed.slots.values())
    assert chat.metrics["assistant_turns"] == 3
    assert not chat.state.positions


def test_vague_goal_never_invents_amount_profile_or_certificate():
    chat, _ = advisor()
    before = chat.state
    turn = chat.turn("I want something safe", request_id="vague")
    assert turn.pending_slots == (
        "amount",
        "liquidity_amount",
        "liquidity_days",
        "horizon_days",
        "objective",
    )
    assert "amount" not in turn.slots
    assert turn.question.count("?") == 1
    assert chat.state == before
    assert chat.comparison is None


def test_signed_goal_proposal_uses_gateway_facts_and_no_purchase():
    chat, device = advisor()
    signed_goals(chat, device)
    turn = chat.turn("Please propose an allocation", request_id="propose")
    assert turn.tool == "propose_allocation"
    assert turn.phase == "proposal"
    assert turn.facts
    assert chat.comparison.result.status == "settled"
    assert all(
        fact.receipt_ref == chat.comparison.result.analysis_receipt.id for fact in turn.facts
    )
    assert chat.gateway.bank.execute_count == 0
    execute = chat.turn("Execute the plan", request_id="execute")
    assert execute.device_action == "select_allocation_items"
    assert not chat.state.allocation_plans
    assert chat.gateway.bank.execute_count == 0


def test_what_if_is_read_only_and_correction_withdraws_old_proposal():
    chat, device = advisor()
    signed_goals(chat, device)
    chat.turn("Propose an allocation", request_id="propose")
    old_request, old_intent = chat.signed_request_ref, chat.intent_id
    original_slots = deepcopy(chat.slots)
    before = H(chat.state)
    hypothetical = chat.turn("What if I invested 5000 instead?", request_id="what-if")
    assert hypothetical.utterance_kind == "what_if"
    assert hypothetical.device_action is None
    assert chat.signed_request_ref == old_request
    assert chat.slots == original_slots
    assert H(chat.state) == before
    changed = chat.turn("Actually 5000", request_id="correction")
    assert changed.utterance_kind == "correction"
    assert changed.phase == "adjusting"
    assert changed.proposal_withdrawn
    assert chat.comparison is None
    assert chat.signed_request_ref is None
    assert chat.intent_id != old_intent
    assert chat.gateway.bank.execute_count == 0
    assert chat.slots["amount"].value == "5000/1"


@pytest.mark.parametrize(
    "problem", [TimeoutError(), BudgetExceeded("limit"), ValueError("private")]
)
def test_api_failure_keeps_signed_slots_enters_guided_mode_and_never_purchases(problem):
    chat, device = advisor()
    signed_goals(chat, device)
    before = deepcopy(chat.slots)
    chat.client.complete = lambda **_: (_ for _ in ()).throw(problem)
    turn = chat.turn("Please execute the plan", request_id="failure")
    assert turn.mode == "guided"
    assert "Guided mode (assistant unavailable)" in turn.message
    assert "private" not in turn.message
    assert chat.slots == before
    assert chat.gateway.bank.execute_count == 0


def test_two_failed_repairs_fall_back_without_accepting_model_economic_literals():
    chat, device = advisor()
    signed_goals(chat, device)
    attempts = []

    def malformed(**kwargs):
        attempts.append(kwargs)
        return LLMResult({"tool": "capture_goal", "arguments": {"amount": "99999/1"}}, "test", "k")

    chat.client.complete = malformed
    turn = chat.turn("Propose an allocation", request_id="bad")
    assert turn.mode == "guided"
    assert len(attempts) == 3
    assert chat.slots["amount"].value == "10000/1"
    assert chat.gateway.bank.execute_count == 0


def test_strict_replay_miss_remains_fatal_for_evaluation():
    chat, _ = advisor(LLMClient(mode="strict", api="responses"))
    with pytest.raises(ReplayMiss):
        chat.turn("I want something safe", request_id="miss")


def test_risk_questionnaire_and_anti_coaching_never_submit_answers():
    chat, _ = advisor()
    before = H(chat.state)
    turn = chat.turn("Start my risk profile", request_id="profile")
    assert turn.device_action == "risk_questionnaire"
    refusal = chat.turn("What should I answer to get C4?", request_id="coaching")
    assert "cannot answer" in refusal.message
    assert H(chat.state) == before
    assert chat.gateway.audit.verify()


def test_idempotency_and_forged_signed_input():
    chat, device = advisor()
    first = chat.turn("I want something safe", request_id="same")
    assert chat.turn("I want something safe", request_id="same") == first
    with pytest.raises(ValueError, match="Request ID"):
        chat.turn("Actually 50k", request_id="same")
    value = device.confirm_input(
        intent_id=chat.intent_id,
        slot="allocation",
        value=allocation_request().model_dump(mode="json"),
        now=chat.state.now,
    ).model_copy(update={"sig": "0" * 128})
    with pytest.raises(ValueError, match="AUTH"):
        chat.confirm_goals(value)
    assert not chat.state.user_inputs


def test_signed_explicit_adjustment_binds_same_intent_model_and_new_comparison():
    chat, device = advisor()
    signed_goals(chat, device)
    chat.turn("Propose allocation", request_id="default")
    original = chat.comparison
    value = device.confirm_input(
        intent_id=chat.intent_id,
        slot="allocation",
        step=2,
        value=allocation_request(
            selection_mode="explicit_weights",
            target_weights={"R1": "3/5", "R2": "2/5", "R3": "0/1", "R4": "0/1", "R5": "0/1"},
            model_biac_hash=H(original.cert.allocation),
            reason_code="user_adjustment",
        ).model_dump(mode="json"),
        now=chat.state.now,
        supersedes=chat.signed_request_ref,
    )
    chat.confirm_adjustment(value)
    turn = chat.turn("Propose allocation", request_id="adjusted")
    assert turn.phase == "proposal"
    assert chat.comparison.plan.plan_id != original.plan.plan_id
    assert chat.comparison.cert.allocation.selection_mode == "explicit_weights"
    assert chat.comparison.cert.allocation.totals.projected_net == 330
    assert chat.gateway.bank.execute_count == 0


def test_product_comparison_and_exclusion_answers_are_verified_leaf_projections():
    chat, device = advisor()
    signed_goals(chat, device)
    chat.turn("Propose allocation", request_id="proposal")
    compared = chat.turn("Compare P_A and P_C", request_id="products")
    assert compared.projected_facts
    assert any(fact.path[-1] == "fee_sell" for fact in compared.projected_facts)
    assert all(fact.source_ref.field == "allocation" for fact in compared.projected_facts)
    excluded = chat.turn("Why not P_X?", request_id="excluded")
    assert any(fact.path[-1] == "reason_codes" for fact in excluded.projected_facts)
    assert chat.gateway.bank.execute_count == 0


def test_model_note_is_guarded_and_guarantee_question_uses_fact_template():
    chat, device = advisor()
    signed_goals(chat, device)
    chat.turn("Propose allocation", request_id="proposal")

    def fabricated(**kwargs):
        state = kwargs["tool_state"]
        return LLMResult(
            {
                "tool": state["required_tool"],
                "arguments": {
                    "refs": state["permitted_refs"],
                    "note": "You will earn CNY 9,999 guaranteed.",
                },
            },
            "scripted",
            "key",
        )

    chat.client.complete = fabricated
    reply = chat.turn("Promise me 5%", request_id="promise")
    assert "9,999" not in reply.assistant_note
    assert (
        tr(
            "I cannot promise a return. Losses are possible. "
            "Returns are a performance benchmark (not guaranteed). Review the verified facts."
        )
        in reply.message
    )
    assert "unverified_number" in reply.guard_reasons
    assert reply.facts
    assert [fact.exact_value for fact in reply.facts if fact.field == "projected_net"] == ["350/1"]
