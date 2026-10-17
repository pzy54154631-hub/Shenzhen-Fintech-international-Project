"""F3 UI integration follows dialogue state and gateway-owned approval facts."""

from corridor.agent.wealth_dialogue import WealthDialogue
from corridor.crypto.jcs import H
from corridor.ui.wealth_controller import WealthController
from tests.unit.test_ui_wealth_controller import GOALS, prepared_controller


def test_conversation_accumulates_unsigned_slots_and_asks_one_question():
    controller = WealthController()
    controller.start_session()
    first = controller.receive_goal("I have 10000 to invest", request_id="amount")
    assert isinstance(controller.wealth_chat, WealthDialogue)
    assert first["slots"]["amount"]["value"] == "10000/1"
    assert first["slots"]["amount"]["source"] == "heard, not signed"
    assert first["question"] and first["question"].count("?") == 1
    second = controller.receive_goal("I need 2000 within 3 days", request_id="liquidity")
    assert second["slots"]["amount"]["value"] == "10000/1"
    assert second["slots"]["liquidity_amount"]["value"] == "2000/1"
    assert not controller.state.user_inputs


def test_what_if_preserves_signed_comparison_and_registered_execution():
    controller = prepared_controller()
    overview = controller.prepare_allocation()
    controller.start_allocation([row["item_ref"] for row in overview["items"]])
    parent = controller.parent_id
    before = H(controller.state)
    comparison = controller.comparison
    result = controller.receive_goal("What if I invest 9000 instead?", request_id="what-if")
    assert result["utterance_kind"] == "what_if"
    assert controller.parent_id == parent
    assert controller.comparison == comparison
    assert H(controller.state) == before
    assert controller.wealth_chat.execution_ref == parent


def test_controller_uses_gateway_budget_and_enriched_execution(monkeypatch):
    controller = prepared_controller()
    budget = controller.gateway.approval_budget(controller.device.principal)
    budget["remaining"] = 3
    monkeypatch.setattr(controller.gateway, "approval_budget", lambda principal: budget)
    assert controller.approval_window() == budget
    overview = controller.prepare_allocation()
    controller.start_allocation([row["item_ref"] for row in overview["items"]])
    snapshot = controller.execution_snapshot()
    assert snapshot["next_leg"]["leg_index"] == 1
    assert snapshot["next_leg"]["leg_count"] == 2
    assert snapshot["approval_budget"] == controller.gateway.allocation_approval_budget(
        controller.parent_id
    )
    assert controller.wealth_chat.execution_ref == controller.parent_id


def test_invalid_device_correction_also_withdraws_old_verified_leg():
    controller = prepared_controller()
    overview = controller.prepare_allocation()
    controller.start_allocation([row["item_ref"] for row in overview["items"]])
    action_id = controller.leg["action"].action_id
    controller.verify_leg(action_id)
    result = controller.confirm_goals({**GOALS, "amount": "invalid"})
    assert result["status"] == "rejected"
    assert controller.comparison is None
    assert controller.wealth_chat.comparison is None
    assert controller.parent_id is None
    assert controller.leg is None
    assert controller.approve_leg(action_id)["status"] == "rejected"
    assert controller.gateway.bank.execute_count == 0


def test_device_signs_complete_dialogue_goals_and_publishes_verified_facts():
    controller = WealthController()
    controller.start_session()
    controller.submit_risk_answers([1] * 5)
    controller.receive_goal("I have 10000 to invest", request_id="goals")
    result = controller.confirm_goals(GOALS)
    assert result["status"] == "comparison_only"
    assert controller.wealth_chat.signed_request_ref == controller.signed_goals.id
    assert controller.wealth_chat.comparison == controller.comparison
    assert result["facts"]
    assert all(slot["source"] == "signed on device" for slot in result["slots"].values())
    assert controller.gateway.bank.execute_count == 0


def test_suitability_signal_is_displayed_without_editing_signed_answers():
    controller = prepared_controller()
    profile = controller.risk_profile()
    result = controller.receive_goal("一分都不能亏", request_id="loss")
    assert result["suitability_signal"]["effective_level_cap"] == 1
    assert result["suitability_signal"]["status"] == "clarification_required"
    assert controller.risk_profile() == profile
    assert controller.comparison is None
    result = controller.receive_goal("教我怎么答", request_id="coach")
    assert result["suitability_signal"]["signal"] == "coaching_request"
    assert "cannot" in result["message"].lower()
    assert controller.gateway.bank.execute_count == 0


def test_statement_uses_gateway_effective_profile_and_keeps_raw_signature(monkeypatch):
    from io import BytesIO
    from unittest.mock import MagicMock
    from zipfile import ZipFile

    from corridor.ui import wealth_statement

    controller = prepared_controller()
    raw_profile = controller.risk_profile()
    controller.receive_goal("I cannot accept any loss", request_id="lower-risk")
    assert controller.confirm_goals(GOALS)["status"] == "comparison_only"
    receipt = controller.comparison.result.analysis_receipt
    display = MagicMock()
    monkeypatch.setattr(wealth_statement, "st", display)
    statement = wealth_statement.render_biac(
        controller.comparison.cert.allocation,
        controller.signed_goals.value,
        controller.state.allocation_policies[
            controller.signed_goals.value["allocation_policy_ref"]
        ],
        raw_profile,
        suitability=receipt.parameters["suitability"],
        audit_jsonl=b"{}\n",
    )
    assert "Suitable for C1 (Conservative)" in statement.text
    assert "Signed questionnaire level: C2" in statement.text
    assert statement.numeric_sources["suitability.effective_level"]["exact"] == "1/1"
    assert any(
        "policy.profiles.C1.bands" in path
        for row in statement.numeric_sources.values()
        for path in row["sources"]
    )
    assert controller.risk_profile() == raw_profile
    bundle = display.download_button.call_args_list[-1].kwargs["data"]
    with ZipFile(BytesIO(bundle)) as archive:
        html = archive.read("suitability-statement.html").decode("utf-8")
    assert 'data-source="suitability.effective_level"' in html
