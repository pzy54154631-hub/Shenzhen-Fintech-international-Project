"""Independent M2 state-machine attacks against real allocation approval cards."""

from copy import deepcopy

import pytest

from corridor.agent.llm import BudgetExceeded, LLMClient, LLMResult
from corridor.agent.wealth_dialogue import WealthDialogue
from corridor.bench.wealth_smoke import make_wealth_conversation
from corridor.crypto.jcs import H
from corridor.crypto.sign import RISK, sign
from corridor.gateway.service import GatewayResult
from corridor.schemas.bank import BankAction, BankCertificate
from corridor.sim.keys import signing_key
from corridor.sim.wealth import allocation_request
from corridor.stores.bank import add_seconds, available


def advisor(*, source_account_ref="A_CURRENT"):
    legacy, device = make_wealth_conversation(client=LLMClient(mode="scripted", api="responses"))
    chat = WealthDialogue(
        legacy.gateway,
        legacy.client,
        principal=legacy.principal,
        session_id=legacy.session_id,
        source_account_ref=source_account_ref,
        allowed_types=["wealth"],
    )
    return chat, device


def compare(chat, device):
    value = device.confirm_input(
        intent_id=chat.intent_id,
        slot="allocation",
        value=allocation_request().model_dump(mode="json"),
        now=chat.state.now,
    )
    chat.confirm_goals(value)
    turn = chat.turn("Propose an allocation", request_id="proposal")
    assert turn.phase == "proposal"
    return value


def register(chat, device, *, attach=True):
    compare(chat, device)
    draft = chat.gateway.draft_allocation(chat.principal, chat.intent_id, chat.signed_request_ref)
    signed = device.sign_allocation(
        draft,
        selected_items=[item.item_ref for item in draft.parent.items],
        now=chat.state.now,
    )
    result = chat.gateway.register_allocation(
        draft,
        selection=signed.selection,
        inputs=signed.inputs,
        authorizations=signed.authorizations,
    )
    assert result.status == "ready", result
    if attach:
        chat.attach_execution(draft.parent.id)
    return draft.parent.id


def approved_leg(chat, device, parent_id, *, sequence=0):
    gateway = chat.gateway
    prepared = gateway.advance_allocation(parent_id)
    assert prepared.status in {"waiting_mfa", "waiting_approval"}, prepared
    action = BankAction.model_validate(prepared.details["action"])
    cert = BankCertificate.model_validate(prepared.details["cert"])
    request_id = H({"action": action, "cert": cert})
    challenge = gateway.request_mfa(action, cert, request_id=request_id)
    assert challenge is not None
    grant = device.complete_mfa(gateway.mfa, challenge, now=chat.state.now)
    assert grant is not None
    assert gateway.submit_mfa(grant).status == "accepted"
    cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    proposal = gateway.propose(action, cert, request_id=request_id)
    assert proposal.verdict.outcome != "Reject", proposal
    token = device.approve(action, cert, proposal.card, now=chat.state.now, sequence=sequence)
    return action, cert, token


def unavailable(**_):
    raise BudgetExceeded("synthetic budget exhaustion")


def test_correction_rejects_a_real_previous_approval_before_any_purchase():
    chat, device = advisor()
    parent_id = register(chat, device)
    action, cert, token = approved_leg(chat, device, parent_id)
    changed = chat.turn("Actually 5000", request_id="correction")
    result = chat.gateway.dispatch(action, cert, token)
    assert changed.proposal_withdrawn
    assert result.status == "rejected", result
    assert any(rule.startswith(("APR-", "AUTH-", "PLAN-")) for rule in result.rule_ids)
    assert chat.gateway.bank.execute_count == 0
    assert chat.gateway.allocation_snapshot(parent_id)["status"] == "cancelled"


def test_correction_after_first_leg_preserves_settlement_and_blocks_second_card():
    chat, device = advisor()
    parent_id = register(chat, device)
    first = approved_leg(chat, device, parent_id)
    assert chat.gateway.dispatch(*first).status == "settled"
    second = approved_leg(chat, device, parent_id, sequence=1)
    changed = chat.turn("Actually 5000", request_id="after-first-leg")
    result = chat.gateway.dispatch(*second)
    assert result.status == "rejected", result
    assert chat.gateway.bank.execute_count == 1
    assert chat.gateway.allocation_snapshot(parent_id)["status"] == "partially_executed"
    assert "Partially executed" in changed.message
    assert {
        position.product_ref: position.principal_amount
        for position in chat.state.positions.values()
    } == {"P_A": 5000}
    assert available(chat.state, "A_CURRENT") == 7000


@pytest.mark.parametrize("utterance", ["Stop", "Handoff to an advisor", "Cancel this plan"])
def test_stop_and_handoff_are_effective_even_when_the_model_is_unavailable(utterance):
    chat, device = advisor()
    parent_id = register(chat, device)
    old_card = approved_leg(chat, device, parent_id)
    chat.client.complete = unavailable
    chat.turn(utterance, request_id="stop-during-outage")
    result = chat.gateway.dispatch(*old_card)
    assert result.status == "rejected", result
    assert chat.gateway.bank.execute_count == 0
    assert chat.gateway.allocation_snapshot(parent_id)["status"] == "cancelled"


def test_device_registered_plan_is_withdrawn_even_before_ui_attachment():
    chat, device = advisor()
    parent_id = register(chat, device, attach=False)
    old_card = approved_leg(chat, device, parent_id)
    changed = chat.turn("Actually 5000", request_id="before-attach")
    result = chat.gateway.dispatch(*old_card)
    assert changed.proposal_withdrawn
    assert result.status == "rejected", result
    assert chat.gateway.bank.execute_count == 0


def test_ambiguous_economic_correction_does_not_retain_a_signed_old_amount():
    chat, device = advisor()
    parent_id = register(chat, device)
    old_card = approved_leg(chat, device, parent_id)
    changed = chat.turn("Invest 100k or invest 200k", request_id="ambiguous")
    result = chat.gateway.dispatch(*old_card)
    assert result.status == "rejected", result
    assert chat.gateway.bank.execute_count == 0
    assert changed.proposal_withdrawn
    assert "amount" in changed.pending_slots
    assert chat.signed_request_ref is None
    with pytest.raises(ValueError):
        chat.goal_sheet()


def test_unknown_correction_keeps_a_lookup_route_and_never_suggests_resubmission():
    chat, device = advisor()
    parent_id = register(chat, device)
    action, cert, token = approved_leg(chat, device, parent_id)
    key = H({"principal": action.principal, "intent_id": action.intent_id, "kind": action.kind})
    chat.gateway.bank.faults[key] = "response_loss"
    result = chat.gateway.dispatch(action, cert, token)
    assert result.status == "unknown"
    changed = chat.turn("Actually 5000", request_id="unknown-correction")
    assert "do not retry" in changed.message
    assert changed.device_action == "lookup"
    assert chat.gateway.allocation_snapshot(parent_id)["status"] == "unknown"
    assert chat.gateway.bank.execute_count == 1


def test_guided_mode_uses_deterministic_proposal_and_does_not_recall_model():
    chat, device = advisor()
    compare(chat, device)
    original = deepcopy(chat.slots)
    calls = []

    def failing(**kwargs):
        calls.append(kwargs)
        raise TimeoutError

    chat.client.complete = failing
    chat.turn("Explain the facts", request_id="outage")
    assert chat.mode == "guided"
    result = chat.turn("Propose an allocation", request_id="guided-proposal")
    assert result.phase == "proposal"
    assert result.facts
    assert len(calls) == 1
    assert chat.slots == original
    assert chat.gateway.bank.execute_count == 0


def test_missing_source_account_routes_to_device_without_parser_crash():
    chat, _ = advisor(source_account_ref=None)
    first = chat.turn(
        "Invest 10000 for 365 days, need 0 within 3 days, lowest fees", request_id="all-but-source"
    )
    assert first.pending_slots == ("source_account_ref",)
    second = chat.turn("Choose my account on the device", request_id="source")
    assert second.pending_slots == ("source_account_ref",)
    assert chat.gateway.bank.execute_count == 0


@pytest.mark.parametrize(
    "output",
    [
        {"tool": "execute_plan", "arguments": {"refs": [], "note": "I approved it"}},
        {"tool": "propose_allocation", "arguments": {"refs": ["FORGED_REQUEST"], "note": ""}},
        {"tool": "propose_allocation", "arguments": {"refs": [], "note": "CNY 9999 is guaranteed"}},
    ],
)
def test_malicious_tool_or_handle_never_changes_economics_or_renders_model_numbers(output):
    chat, device = advisor()
    compare(chat, device)
    before = deepcopy(chat.slots)
    chat.client.complete = lambda **_: LLMResult(output, "test-adversary", "key")
    result = chat.turn("Propose an allocation", request_id="malicious")
    assert "9999" not in result.message
    assert "I approved it" not in result.message
    assert chat.slots == before
    assert chat.gateway.bank.execute_count == 0


def test_new_intent_withdraws_pending_card_and_discards_previous_economic_slots():
    chat, device = advisor()
    parent_id = register(chat, device)
    old_card = approved_leg(chat, device, parent_id)
    previous_intent = chat.intent_id
    result = chat.turn("Start a new plan: invest 5000", request_id="new-intent")
    assert result.utterance_kind == "new_intent"
    assert chat.intent_id != previous_intent
    assert chat.signed_request_ref is None
    assert "horizon_days" in result.pending_slots
    assert "objective" in result.pending_slots
    assert chat.slots["amount"].value == "5000/1"
    assert chat.gateway.dispatch(*old_card).status == "rejected"
    assert chat.gateway.bank.execute_count == 0


def test_expired_profile_withdraws_old_proposal_and_routes_back_to_questionnaire():
    chat, device = advisor()
    compare(chat, device)
    state = chat.state
    assessment_ref = state.customers[chat.principal].risk_profile_ref
    expired = state.risk_assessments[assessment_ref].model_copy(
        update={"issued_at": add_seconds(state.now, -86400), "expires_at": state.now}
    )
    expired = expired.model_copy(update={"sig": sign(signing_key("risk"), RISK, expired)})
    chat.gateway.store.update(risk_assessments={**state.risk_assessments, expired.id: expired})
    refusal = chat.turn("Propose an allocation", request_id="expired-profile")
    assert "BIC-RISK" in refusal.rule_ids
    assert refusal.device_action == "risk_questionnaire"
    assert chat.comparison is None
    execute = chat.turn("Execute the plan", request_id="expired-execute")
    assert execute.device_action != "select_allocation_items"
    assert chat.gateway.bank.execute_count == 0


def test_hypothetical_stop_is_read_only_and_keeps_current_plan_ready():
    chat, device = advisor()
    parent_id = register(chat, device)
    state_hash = H(chat.state)
    signed_ref, current_intent = chat.signed_request_ref, chat.intent_id
    result = chat.turn("What if I stop this plan?", request_id="what-if-stop")
    assert result.utterance_kind == "what_if"
    assert H(chat.state) == state_hash
    assert chat.signed_request_ref == signed_ref
    assert chat.intent_id == current_intent
    assert chat.gateway.allocation_snapshot(parent_id)["status"] == "ready"
    assert chat.gateway.bank.execute_count == 0


def test_conditional_amount_question_is_not_treated_as_an_actual_correction():
    chat, device = advisor()
    compare(chat, device)
    state_hash = H(chat.state)
    signed_ref, current_intent = chat.signed_request_ref, chat.intent_id
    result = chat.turn("If I invest 5000, what changes?", request_id="conditional-amount")
    assert result.utterance_kind == "what_if"
    assert H(chat.state) == state_hash
    assert chat.signed_request_ref == signed_ref
    assert chat.intent_id == current_intent
    assert chat.gateway.bank.execute_count == 0


@pytest.mark.parametrize("utterance", ["Propose an allocation", "Execute the plan"])
def test_unknown_followups_keep_the_reconciliation_route(utterance):
    chat, device = advisor()
    parent_id = register(chat, device)
    action, cert, token = approved_leg(chat, device, parent_id)
    key = H({"principal": action.principal, "intent_id": action.intent_id, "kind": action.kind})
    chat.gateway.bank.faults[key] = "response_loss"
    assert chat.gateway.dispatch(action, cert, token).status == "unknown"
    chat.turn("Actually 5000", request_id="unknown-correction")
    followup = chat.turn(utterance, request_id="unknown-followup")
    assert followup.device_action == "lookup"
    assert "do not retry" in followup.message
    assert chat.gateway.bank.execute_count == 1


@pytest.mark.parametrize("utterance", ["Actually 5000", "Stop", "Handoff to an advisor"])
def test_first_leg_failed_terminal_can_be_corrected_or_stopped(utterance):
    chat, device = advisor()
    parent_id = register(chat, device)
    action, cert, token = approved_leg(chat, device, parent_id)
    key = H({"principal": action.principal, "intent_id": action.intent_id, "kind": action.kind})
    chat.gateway.bank.faults[key] = "failed"
    assert chat.gateway.dispatch(action, cert, token).status == "failed"
    assert chat.gateway.allocation_snapshot(parent_id)["status"] == "failed"
    previous_intent = chat.intent_id
    result = chat.turn(utterance, request_id="after-failed-purchase")
    assert result.proposal_withdrawn
    assert chat.intent_id != previous_intent
    assert chat.signed_request_ref is None
    assert chat.execution_ref is None
    assert chat.reconciliation_ref is None
    assert chat.gateway.bank.execute_count == 1
    assert not chat.state.positions
    assert available(chat.state, "A_CURRENT") == 12000
    assert chat.gateway.allocation_snapshot(parent_id)["status"] == "failed"
    assert all(
        chat.gateway.plan_snapshot(item.child_plan_id)["blocked"]
        for item in chat.state.allocation_plans[parent_id].items
    )
    if utterance.startswith("Actually"):
        assert chat.slots["amount"].value == "5000/1"
        assert result.device_action == "confirm_goals"
    else:
        assert result.device_action == "advisor"


@pytest.mark.parametrize("status", ["rejected", "failed"])
def test_failed_terminal_does_not_mask_a_stop_audit_write_failure(monkeypatch, status):
    chat, device = advisor()
    parent_id = register(chat, device)
    action, cert, token = approved_leg(chat, device, parent_id)
    key = H({"principal": action.principal, "intent_id": action.intent_id, "kind": action.kind})
    chat.gateway.bank.faults[key] = "failed"
    assert chat.gateway.dispatch(action, cert, token).status == "failed"
    snapshot = chat.gateway.allocation_snapshot(parent_id)
    monkeypatch.setattr(
        chat.gateway,
        "stop_allocation",
        lambda *_, **__: GatewayResult(status, ["AUD-WRITE"], details=snapshot),
    )
    previous_intent, signed_ref = chat.intent_id, chat.signed_request_ref
    with pytest.raises(ValueError, match="Cannot safely stop"):
        chat.turn("Actually 5000", request_id="failed-stop-audit")
    assert chat.intent_id == previous_intent
    assert chat.signed_request_ref == signed_ref
    assert chat.gateway.bank.execute_count == 1
    assert not chat.state.positions
