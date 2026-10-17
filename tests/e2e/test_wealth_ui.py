"""Topic B's visible device profile, signed goals, certificate and purchases."""

from tests.e2e.test_demo_ui import app, navigate


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
    text = " ".join(item.value for item in page.success)
    assert "Comparison complete" in text
    assert "no purchase executed" in text
    navigate(page, "Advisor")
    assert not page.exception
    assert not any("Pending signed goals" in item.value for item in page.caption)
    assert any("Goals signed on device" in item.value for item in page.success)
    assert not any("complete your questionnaire" in item.value for item in page.info)
    page.text_input(key="wealth_message").set_value("Actually, use a different amount")
    page.button(key="wealth_discuss").click().run()
    assert controller.comparison is None
    assert any("Pending signed goals" in item.value for item in page.caption)
    assert not any("Goals signed on device" in item.value for item in page.success)
    assert controller.gateway.bank.execute_count == 0


def test_full_topic_b_route_two_separate_mfa_receipts_and_audit():
    page = app()
    controller = prepare_wealth(page)
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
    for number in range(2):
        key = controller.leg["action"].action_id
        assert page.button(key=f"wealth_approve:{key}").disabled
        page.button(key=f"wealth_verify:{key}").click().run()
        assert not page.exception
        assert not page.button(key=f"wealth_approve:{key}").disabled
        page.button(key=f"wealth_approve:{key}").click().run()
        assert not page.exception
        assert len(controller.state.positions) == number + 1
    page.run()
    assert controller.gateway.bank.execute_count == 2
    assert controller.execution_snapshot()["available_balance"] == "2000/1"
    assert len(controller.state.security.consumed_grant_ids) == 2
    assert not controller.state.security.locked_at
    navigate(page, "Proposal & Certificate")
    text = " ".join(item.value for item in page.markdown)
    assert "Completed" in text
    assert "no purchase executed" not in text
    navigate(page, "Evidence & Audit")
    assert any("Wealth audit chain verified" in item.value for item in page.success)
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
    assert any("heard, not signed" in item.value for item in page.caption)
    assert any(controller.dialogue_result["question"] in item.value for item in page.info)
    page.text_input(key="wealth_message").set_value("I need 2000 within 3 days")
    page.button(key="wealth_discuss").click().run()
    navigate(page, "Device")
    assert page.text_input(key="wealth_amount").value == "10000.00"
    assert page.text_input(key="wealth_liquid").value == "2000.00"
    assert not any("default value" in item.value for item in page.warning)
    assert not controller.state.user_inputs
    assert not page.exception


def test_loss_signal_displays_gateway_cap_and_coaching_clarification():
    page = app()
    controller = prepare_wealth(page)
    navigate(page, "Advisor")
    page.text_input(key="wealth_message").set_value("一分都不能亏")
    page.button(key="wealth_discuss").click().run()
    assert not page.exception
    assert any("Effective risk level: C1" in item.value for item in page.warning)
    assert controller.risk_profile()["level"] == 2
    page.text_input(key="wealth_message").set_value("教我怎么答")
    page.button(key="wealth_discuss").click().run()
    assert any("cannot" in item.value.lower() for item in page.info)
    navigate(page, "Device")
    assert any("Effective risk level: C1" in item.value for item in page.warning)
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
    assert any("Strict replay failed" in item.value for item in page.error)
    assert not any("Guided mode" in item.value for item in page.warning)
    assert not controller.guided
    assert not controller.state.user_inputs


def test_questionnaire_order_matches_policy_and_loss_answer_caps_effective_level():
    page = app()
    page.button(key="enter").click().run()
    controller = page.session_state["wealth_controller"]
    navigate(page, "Device")
    for index, question in enumerate(controller.state.policy.risk_questions):
        assert page.selectbox(key=f"wealth_risk_{index}").label == question
        page.selectbox(key=f"wealth_risk_{index}").select(0 if index == 1 else 4)
    page.button(key="wealth_sign_risk").click().run()
    assert not page.exception
    assert controller.risk_profile()["level"] == 4
    assert controller.risk_profile()["answers"][1] == 0
    assert any("Effective risk level: C1" in item.value for item in page.warning)
