"""Topic B's visible device profile, signed goals, certificate and purchases."""

import pytest

from corridor.ui.messages import tr
from tests.e2e.test_demo_ui import app, navigate
from tests.unit.test_product_ui import assert_primary_clean, assert_progress


@pytest.fixture(autouse=True, params=["en", "zh-CN"])
def presentation_locale(monkeypatch, request):
    monkeypatch.setenv("CORRIDOR_LOCALE", request.param)
    return request.param


def prepare_wealth(page):
    page.button(key="enter").click().run()
    page.text_input(key="wealth_message").set_value("I want something safe")
    page.button(key="wealth_discuss").click().run()
    controller = page.session_state["wealth_controller"]
    assert controller.risk_profile() is None
    assert not controller.state.user_inputs
    navigate(page, "Device")
    for index in range(5):
        page.selectbox(key=f"wealth_risk_{index}").select(1)
    page.button(key="wealth_sign_risk").click().run()
    assert not page.exception
    assert controller.risk_profile()["level"] == 2
    page.text_input(key="wealth_amount").set_value("10000")
    page.text_input(key="wealth_liquid").set_value("0")
    page.button(key="wealth_confirm_goals").click().run()
    assert not page.exception
    assert controller.comparison is not None
    assert not controller.state.allocation_plans
    navigate(page, "Proposal & Certificate")
    return controller


def test_wealth_device_profile_goals_and_comparison_are_real():
    page = app()
    controller = prepare_wealth(page)
    assert not controller.state.positions
    assert controller.comparison.cert.allocation.totals.principal == 10000
    assert controller.gateway.verify_log()
    assert controller.comparison.result.status == "settled"
    assert controller.gateway.bank.execute_count == 0
    assert_primary_clean(page)
    navigate(page, "Advisor")
    assert_primary_clean(page)
    assert controller.wealth_chat.signed_request_ref in controller.state.user_inputs
    assert controller.risk_profile() is not None
    page.text_input(key="wealth_message").set_value("Actually, use a different amount")
    page.button(key="wealth_discuss").click().run()
    assert controller.comparison is None
    assert controller.wealth_chat.signed_request_ref is None
    assert controller.dialogue_result["proposal_withdrawn"]
    assert controller.gateway.bank.execute_count == 0


def test_full_topic_b_route_two_separate_mfa_receipts_and_audit():
    page = app()
    controller = prepare_wealth(page)
    assert_progress(page, "proposal")
    assert_primary_clean(page)
    boxes = [box for box in page.checkbox if box.key.startswith("wealth_select:")]
    assert len(boxes) == 2 and all(not box.value for box in boxes)
    assert page.button(key="wealth_start").disabled
    boxes[0].check().run()
    assert page.button(key="wealth_start").disabled
    assert not controller.state.allocation_plans
    for box in page.checkbox:
        if box.key.startswith("wealth_select:"):
            box.check()
    page.run()
    page.button(key="wealth_start").click().run()
    assert not page.exception
    navigate(page, "Device")
    assert_progress(page, "approvals")
    assert_primary_clean(page)
    for number in range(2):
        key = controller.leg["action"].action_id
        assert page.button(key=f"wealth_approve:{key}").disabled
        page.button(key=f"wealth_verify:{key}").click().run()
        assert not page.exception
        assert not page.button(key=f"wealth_approve:{key}").disabled
        page.button(key=f"wealth_approve:{key}").click().run()
        assert not page.exception
        assert len(controller.state.positions) == number + 1
        assert controller.gateway.bank.execute_count == number + 1
        assert_primary_clean(page)
    page.run()
    assert controller.gateway.bank.execute_count == 2
    assert controller.execution_snapshot()["available_balance"] == "2000/1"
    assert len(controller.state.security.consumed_grant_ids) == 2
    assert not controller.state.security.locked_at
    navigate(page, "Proposal & Certificate")
    execution = controller.execution_snapshot()
    assert execution["status"] == "completed"
    assert all(item["status"] == "settled" and item["receipt_ref"] for item in execution["items"])
    assert_progress(page, "receipts")
    assert_primary_clean(page)
    navigate(page, "Evidence & Audit")
    assert any(tr("✓ chain verified") in item.value for item in page.success)
    assert_primary_clean(page)
    assert controller.gateway.verify_log()


def test_typed_mfa_rejects_wrong_codes_and_reject_stops_remaining_purchases():
    page = app()
    controller = prepare_wealth(page)
    for box in page.checkbox:
        if box.key.startswith("wealth_select:"):
            box.check()
    page.run()
    page.button(key="wealth_start").click().run()
    navigate(page, "Device")
    key = controller.leg["action"].action_id
    factor = page.text_input(key=f"wealth_mfa_code:{key}").value
    assert factor and page.button(key=f"wealth_approve:{key}").disabled
    for wrong_code in ("", "not-a-code"):
        page.text_input(key=f"wealth_mfa_code:{key}").set_value(wrong_code)
        page.button(key=f"wealth_verify:{key}").click().run()
        assert not page.exception
        assert page.session_state["wealth_leg_result"]["status"] == "rejected"
        assert page.session_state["wealth_leg_result"]["rule_ids"] == ["MFA-INVALID"]
        assert not controller.leg["verified"]
        assert page.button(key=f"wealth_approve:{key}").disabled
        assert controller.gateway.bank.execute_count == 0
        assert not controller.state.security.consumed_grant_ids
    page.text_input(key=f"wealth_mfa_code:{key}").set_value(factor)
    page.button(key=f"wealth_verify:{key}").click().run()
    assert controller.leg["verified"]
    page.button(key=f"wealth_approve:{key}").click().run()
    assert controller.gateway.bank.execute_count == 1
    second = controller.leg["action"].action_id
    assert second != key
    page.button(key=f"wealth_reject:{second}").click().run()
    assert not page.exception
    execution = controller.execution_snapshot()
    assert execution["status"] == "partially_executed"
    assert [item["status"] for item in execution["items"]] == ["settled", "cancelled"]
    assert controller.leg is None
    assert controller.gateway.bank.execute_count == 1
    assert len(controller.state.security.consumed_grant_ids) == 1
    assert not any((button.key or "").startswith("wealth_approve:") for button in page.button)
    assert_primary_clean(page)
    page.run()
    assert controller.gateway.bank.execute_count == 1
    assert controller.gateway.verify_log()


def test_unknown_wealth_outcome_shows_lookup_but_no_approve():
    from corridor.kernel.binding import intent_key

    page = app()
    controller = prepare_wealth(page)
    for box in page.checkbox:
        if box.key.startswith("wealth_select:"):
            box.check()
    page.run()
    page.button(key="wealth_start").click().run()
    navigate(page, "Device")
    key = controller.leg["action"].action_id
    controller.gateway.bank.faults[intent_key(controller.leg["action"], controller.state)] = (
        "response_loss"
    )
    page.button(key=f"wealth_verify:{key}").click().run()
    page.button(key=f"wealth_approve:{key}").click().run()
    assert not page.exception
    assert controller.execution_snapshot()["status"] == "unknown"
    assert page.button(key="wealth_lookup")
    assert not [
        button for button in page.button if (button.key or "").startswith("wealth_approve:")
    ]
    page.button(key="wealth_lookup").click().run()
    assert controller.gateway.bank.execute_count == 1
    assert controller.leg is None


def test_four_attack_buttons_run_real_isolated_cases_without_changing_wealth():
    from corridor.crypto.jcs import H
    from corridor.ui.evaluation import ATTACK_CLASSES

    page = app()
    page.button(key="enter").click().run()
    controller = page.session_state["wealth_controller"]
    before = H(controller.state)
    for kind in ATTACK_CLASSES:
        page.button(key=f"wealth_attack:{kind}").click().run()
        assert not page.exception
        result = page.session_state["wealth_attack_result"]
        assert result["passed"] and result["benign_completed"]
        assert result["funds_moved_cny"] == "0/1"
        assert result["audit_entries"] and result["rule_ids"]
        assert result["evidence_mode"] == "scripted"
        assert H(controller.state) == before


def test_advisor_shows_continuous_slots_and_device_prefills_without_signing():
    page = app()
    page.button(key="enter").click().run()
    page.text_input(key="wealth_message").set_value("I have 10000 to invest")
    page.button(key="wealth_discuss").click().run()
    controller = page.session_state["wealth_controller"]
    assert controller.wealth_chat.signed_request_ref is None
    assert controller.dialogue_result["pending_slots"]
    assert controller.dialogue_result["phase"] == "collecting"
    assert_primary_clean(page)
    page.text_input(key="wealth_message").set_value("I need 2000 within 3 days")
    page.button(key="wealth_discuss").click().run()
    navigate(page, "Device")
    assert page.text_input(key="wealth_amount").value == "10000.00"
    assert page.text_input(key="wealth_liquid").value == "2000.00"
    assert not controller.state.user_inputs
    assert not page.exception


def test_loss_signal_displays_gateway_cap_and_coaching_clarification():
    page = app()
    controller = prepare_wealth(page)
    navigate(page, "Advisor")
    page.text_input(key="wealth_message").set_value("一分都不能亏")
    page.button(key="wealth_discuss").click().run()
    assert not page.exception
    assert controller.suitability_details["effective_level"] == 1
    assert controller.risk_profile()["level"] == 2
    page.text_input(key="wealth_message").set_value("教我怎么答")
    page.button(key="wealth_discuss").click().run()
    assert controller.dialogue_result["suitability_signal"]["signal"] == "coaching_request"
    assert controller.dialogue_result["suitability_signal"]["status"] == "refused"
    navigate(page, "Device")
    assert controller.suitability_details["effective_level"] == 1
    assert controller.gateway.bank.execute_count == 0


def test_strict_replay_failure_is_never_labeled_as_guided(monkeypatch):
    from corridor.agent.llm import ReplayMiss

    page = app()
    page.button(key="enter").click().run()
    controller = page.session_state["wealth_controller"]
    controller.client.mode = "strict"

    def missing(**kwargs):
        raise ReplayMiss("Synthetic missing replay")

    monkeypatch.setattr(controller.client, "complete", missing)
    page.text_input(key="wealth_message").set_value("I have 10000 to invest")
    page.button(key="wealth_discuss").click().run()
    assert page.error
    assert controller.dialogue_result is None
    assert not controller.guided
    assert not controller.state.user_inputs


def test_questionnaire_order_matches_policy_and_loss_answer_caps_effective_level():
    page = app()
    page.button(key="enter").click().run()
    controller = page.session_state["wealth_controller"]
    navigate(page, "Device")
    for index, question in enumerate(controller.state.policy.risk_questions):
        assert page.selectbox(key=f"wealth_risk_{index}").label == tr(question)
        page.selectbox(key=f"wealth_risk_{index}").select(0 if index == 1 else 4)
    page.button(key="wealth_sign_risk").click().run()
    assert not page.exception
    assert controller.risk_profile()["level"] == 4
    assert controller.risk_profile()["answers"][1] == 0
    assert controller.suitability_details["effective_level"] == 1


def test_signed_goal_correction_displays_authenticated_read_only_difference(presentation_locale):
    from corridor.crypto.jcs import H

    page = app()
    controller = prepare_wealth(page)
    navigate(page, "Device")
    page.text_input(key="wealth_amount").set_value("9000")
    page.button(key="wealth_confirm_goals").click().run()
    assert not page.exception
    assert controller.comparison.cert.allocation.totals.principal == 9000
    expected = controller.wealth_chat.change_explanation()
    before = H(controller.state)
    navigate(page, "Proposal & Certificate")
    assert not page.exception
    assert any(
        tr("What changed after your signed correction") in item.value for item in page.subheader
    )
    table = next(item.value for item in page.dataframe if tr("Before (CNY)") in item.value.columns)
    principal_fact = next(
        fact for fact in expected if fact.product_id is None and fact.field == "principal"
    )
    principal = table[
        (table[tr("Product")] == tr("Allocation total"))
        & (table[tr("Fact")] == tr(principal_fact.label))
    ]
    prefix = "CNY " if presentation_locale == "en" else "¥"
    assert principal.iloc[0][tr("Before (CNY)")] == prefix + "10,000.00"
    assert principal.iloc[0][tr("After (CNY)")] == prefix + "9,000.00"
    assert principal.iloc[0][tr("Change (CNY)")] == prefix + "-1,000.00"
    assert any(fact.product_id == "P_A" and fact.exact_value == "-500/1" for fact in expected)
    assert H(controller.state) == before
    assert controller.gateway.bank.execute_count == 0
