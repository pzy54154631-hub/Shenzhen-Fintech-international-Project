"""Wealth UI corrections retire stale proposals without changing money authority."""

import pytest

from corridor.agent.llm import BudgetExceeded, LLMOutputError, ReplayMiss
from corridor.crypto.jcs import H
from corridor.ui.wealth_controller import WealthController

GOALS = {
    "source_account_ref": "A_CURRENT",
    "amount": "10000",
    "horizon_days": 365,
    "liquidity_days": 3,
    "liquidity_amount": "0",
    "allowed_types": ["wealth"],
    "objective": "net_return",
}


def compared():
    controller = WealthController()
    assert controller.start_session()["status"] == "ready"
    assert controller.submit_risk_answers([1] * 5)["status"] == "settled"
    controller.receive_goal("I want something safe", request_id="first-goal")
    assert controller.confirm_goals(GOALS)["status"] == "comparison_only"
    assert controller.gateway.bank.execute_count == 0
    return controller


def assert_no_purchase(controller):
    assert controller.gateway.bank.execute_count == 0
    assert not controller.state.positions
    assert not controller.state.allocation_plans
    assert not controller.state.security.consumed_nonces
    assert controller.gateway.verify_log()


def test_repeating_identical_goal_confirmation_is_idempotent():
    controller = compared()
    before = H(controller.state)
    signed = controller.signed_goals
    certificate = H(controller.comparison.cert.allocation)
    result = controller.confirm_goals(dict(GOALS))
    assert result["status"] == "comparison_only"
    assert H(controller.state) == before
    assert controller.signed_goals == signed
    assert H(controller.comparison.cert.allocation) == certificate
    assert_no_purchase(controller)


def test_edited_goals_get_fresh_intent_and_replace_the_old_comparison():
    controller = compared()
    old_input = controller.signed_goals
    old_intent = controller.comparison.action.intent_id
    old_certificate = H(controller.comparison.cert.allocation)
    result = controller.confirm_goals({**GOALS, "amount": "9000"})
    assert result["status"] == "comparison_only"
    assert controller.signed_goals.id != old_input.id
    assert controller.signed_goals.scope_id != old_intent
    assert controller.comparison.action.intent_id == controller.signed_goals.scope_id
    assert controller.comparison.cert.allocation.totals.principal == 9000
    assert H(controller.comparison.cert.allocation) != old_certificate
    assert controller.state.user_inputs[old_input.id] == old_input
    assert controller.state.user_inputs[controller.signed_goals.id] == controller.signed_goals
    assert_no_purchase(controller)


def test_comparison_failure_withdraws_the_old_display(monkeypatch):
    controller = compared()

    def unavailable(*args, **kwargs):
        raise ValueError("Synthetic comparison rejection")

    monkeypatch.setattr(controller.wealth_chat, "compare", unavailable)
    result = controller.confirm_goals({**GOALS, "amount": "9000"})
    assert result["status"] == "rejected"
    assert "No allocation was constructed" in result["message"]
    assert controller.comparison is None
    assert controller.draft is None
    assert controller.leg is None
    assert_no_purchase(controller)


def test_new_goal_discussion_withdraws_the_old_comparison_without_signing():
    controller = compared()
    prior_inputs = H(controller.state.user_inputs)
    prior_intent = controller.candidate.intent_id
    result = controller.receive_goal("Actually, use 8000 instead", request_id="correction")
    assert result["status"] == "collecting"
    assert controller.candidate.intent_id != prior_intent
    assert controller.comparison is None
    assert controller.draft is None
    assert controller.leg is None
    assert H(controller.state.user_inputs) == prior_inputs
    assert_no_purchase(controller)


def test_stop_withdraws_wealth_proposal_and_goal_confirmation():
    controller = compared()
    prior_inputs = H(controller.state.user_inputs)
    controller.stop()
    assert controller.comparison is None
    assert controller.candidate is None
    assert controller.draft is None
    assert controller.leg is None
    assert H(controller.state.user_inputs) == prior_inputs
    assert_no_purchase(controller)


@pytest.mark.parametrize("error_type", [TimeoutError, LLMOutputError, BudgetExceeded])
def test_model_failure_enters_guided_mode_with_signed_goals_and_no_purchase(
    monkeypatch, error_type
):
    controller = compared()
    signed = controller.signed_goals
    prior_inputs = H(controller.state.user_inputs)

    def unavailable(**kwargs):
        raise error_type("Synthetic assistant failure")

    monkeypatch.setattr(controller.client, "complete", unavailable)
    result = controller.receive_goal("Please revise my goals", request_id="assistant-failure")
    assert result["status"] == "collecting"
    assert result["guided"] is True
    assert controller.guided is True
    assert controller.signed_goals == signed
    assert controller.comparison is None
    assert controller.draft is None
    assert controller.leg is None
    assert H(controller.state.user_inputs) == prior_inputs
    assert_no_purchase(controller)


def test_strict_replay_miss_remains_fatal_and_withdraws_the_old_comparison(monkeypatch):
    controller = compared()
    signed = controller.signed_goals
    prior_inputs = H(controller.state.user_inputs)
    controller.client.mode = "strict"

    def missing(**kwargs):
        raise ReplayMiss("Synthetic missing strict replay")

    monkeypatch.setattr(controller.client, "complete", missing)
    with pytest.raises(ReplayMiss, match="Synthetic missing strict replay"):
        controller.receive_goal("Please revise my goals", request_id="strict-miss")
    assert controller.guided is False
    assert controller.signed_goals == signed
    assert controller.comparison is None
    assert H(controller.state.user_inputs) == prior_inputs
    assert_no_purchase(controller)
