"""Streamlit gestures must use the real controller and preserve dispatch semantics."""

from pathlib import Path
from secrets import token_hex
from unittest.mock import patch

APP = Path(__file__).resolve().parents[2] / "src/corridor/ui/app.py"
PRIMARY_PAGES = ("Advisor", "Proposal & Certificate", "Device", "Evidence & Audit")


def navigate(page, label):
    """Navigate using the same primary or supporting controls as the client."""
    if label in PRIMARY_PAGES:
        page.selectbox(key="supporting_page").select("None").run()
        page.selectbox(key="page").select(label).run()
    else:
        page.selectbox(key="supporting_page").select(label).run()


def app():
    # Streamlit's module-level TemporaryDirectory needs inherited Windows ACLs,
    # matching the repository's tmp_path fixture; the app itself remains real.
    def workspace_directory(*args, **kwargs):
        path = APP.parents[3] / ".tmp" / ("streamlit-" + token_hex(8))
        path.mkdir(parents=True)
        return str(path)

    with patch("tempfile.mkdtemp", side_effect=workspace_directory):
        from streamlit.testing.v1 import AppTest

    return AppTest.from_file(str(APP), default_timeout=30).run()


def test_demo_initial_render_has_no_signing_and_keeps_synthetic_labels():
    page = app()
    assert not page.exception
    text = " ".join(item.value for item in page.markdown)
    assert "Wealth advice with verifiable evidence." in text
    assert "Demo Bank (simulated environment)" in text
    assert "synthetic data · simulated authentication · no real money" in text
    assert "Evidence mode: scripted" in text
    controller = page.session_state["controller"]
    assert not controller.state.user_inputs
    assert not controller.state.security.consumed_nonces
    assert page.button(key="enter")
    assert page.button(key="stop_all")


def test_transfer_preview_unsigned_then_single_confirmation_and_rerun_no_repay():
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Transfers")
    page.text_input(key="transfer_text").set_value("给Chen转200元")
    page.button(key="preview_transfer").click().run()
    assert not page.exception
    controller = page.session_state["controller"]
    assert controller.snapshot()["dispatch_count"] == 0
    assert not controller.state.user_inputs
    page.button(key="confirm_transfer").click().run()
    assert not page.exception
    assert controller.snapshot()["dispatch_count"] == 1
    assert any("Executed" in item.value for item in page.success)
    page.run()
    assert controller.snapshot()["dispatch_count"] == 1


def test_input_errors_show_safe_english_message_without_raw_exception(monkeypatch):
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Transfers")
    controller = page.session_state["controller"]
    diagnostic = "private internal diagnostic must not reach the client"

    def unavailable(*args, **kwargs):
        raise ValueError(diagnostic)

    monkeypatch.setattr(controller, "preview_transfer", unavailable)
    page.text_input(key="transfer_text").set_value("Transfer CNY 200 to Chen")
    page.button(key="preview_transfer").click().run()
    assert not page.exception
    assert page.error
    rendered = " ".join(
        item.value
        for elements in (page.error, page.warning, page.info, page.markdown, page.caption)
        for item in elements
    )
    assert diagnostic not in rendered
    assert controller.snapshot()["dispatch_count"] == 0
    assert not controller.state.user_inputs


def test_navigation_renders_all_pages_without_signatures_or_dispatch():
    page = app()
    page.button(key="enter").click().run()
    controller = page.session_state["controller"]
    assert page.selectbox(key="page").value == "Advisor"
    assert tuple(page.selectbox(key="page").options) == PRIMARY_PAGES
    for label in (
        *PRIMARY_PAGES,
        "Transfers",
        "Bills & Balance",
        "Subscriptions",
        "Cards",
        "Product comparison",
        "Task Plans",
        "Human Handoff",
    ):
        navigate(page, label)
        assert not page.exception, label
        assert controller.snapshot()["dispatch_count"] == 0
        text = " ".join(item.value for item in page.markdown)
        assert "synthetic data · simulated authentication · no real money" in text
    assert not controller.state.user_inputs
    navigate(page, "Evidence & Audit")
    assert page.toggle(key="hijacked")


def test_operator_clock_controls_are_hidden_in_normal_demo(monkeypatch):
    monkeypatch.delenv("CORRIDOR_OPERATOR_MODE", raising=False)
    page = app()
    page.button(key="enter").click().run()
    assert not page.exception
    assert all(button.key not in {"advance_clock", "advance_window"} for button in page.button)
    assert all(expander.label != "Operator panel" for expander in page.expander)


def test_operator_clock_controls_require_explicit_operator_mode(monkeypatch):
    monkeypatch.setenv("CORRIDOR_OPERATOR_MODE", "1")
    page = app()
    page.button(key="enter").click().run()
    assert not page.exception
    assert any(expander.label == "Operator panel" for expander in page.expander)
    assert page.button(key="advance_clock")
    assert page.button(key="advance_window")


def test_plan_nodes_default_unchecked_and_no_render_authority():
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Task Plans")
    page.button(key="preview_birthday").click().run()
    assert not page.exception
    assert page.checkbox
    assert all(not box.value for box in page.checkbox)
    assert page.session_state["controller"].snapshot()["dispatch_count"] == 0


def test_ambiguous_contact_requires_displayed_selected_card_before_confirm():
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Transfers")
    page.text_input(key="transfer_text").set_value("给Lin转200元")
    page.button(key="preview_transfer").click().run()
    assert page.button(key="confirm_transfer").disabled
    page.selectbox(key="contact_selection").select("CONTACT_LIN_B").run()
    assert page.button(key="confirm_transfer").disabled
    page.button(key="show_selected_contact").click().run()
    assert not page.exception
    assert not page.button(key="confirm_transfer").disabled
    assert "CONTACT_LIN_B" in " ".join(item.value for item in page.markdown)
    page.button(key="confirm_transfer").click().run()
    controller = page.session_state["controller"]
    assert controller.gateway.bank.final_state()["destinations"]["DEST_CONTACT_LIN_B"] == "200/1"


def test_subscriptions_require_approval_and_cancellation_has_own_confirmation():
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Subscriptions")
    controller = page.session_state["controller"]
    page.button(key="preview_subscriptions").click().run()
    assert not page.exception
    assert controller.snapshot()["dispatch_count"] == 0
    assert not controller.state.user_inputs
    assert not page.selectbox(key="page").disabled
    page.button(key="approve_subscriptions").click().run()
    assert not page.exception
    assert page.selectbox(key="subscription_ref").options
    page.button(key="cancel_subscription").click().run()
    assert not page.exception
    page.button(key="approve_cancel_subscription").click().run()
    assert any(item.status == "cancelled" for item in controller.state.subscriptions.values())


def test_red_purchase_stays_pending_until_explicit_mfa_then_one_receipt():
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Product comparison")
    page.button(key="compare_investments").click().run()
    page.button(key="preview_investment").click().run()
    assert not page.exception
    controller = page.session_state["controller"]
    before = controller.snapshot()["dispatch_count"]
    navigate(page, "Device")
    pending = controller.snapshot()["pending"][0]["pending_id"]
    page.button(key=f"approve:{pending}").click().run()
    assert controller.snapshot()["dispatch_count"] == before
    page.button(key=f"mfa_request:{pending}").click().run()
    page.button(key=f"mfa_complete:{pending}").click().run()
    page.button(key=f"approve:{pending}").click().run()
    assert not page.exception
    assert controller.snapshot()["dispatch_count"] == before + 1
    page.run()
    assert controller.snapshot()["dispatch_count"] == before + 1


def test_hijacked_evaluation_cannot_mutate_live_session():
    page = app()
    page.button(key="enter").click().run()
    controller = page.session_state["controller"]
    navigate(page, "Evidence & Audit")
    page.toggle(key="hijacked").set_value(True).run()
    page.button(key="run_attack").click().run()
    assert not page.exception
    assert controller.snapshot()["dispatch_count"] == 0
    assert not controller.state.receipts
    assert page.session_state["evaluation_result"]["attack"]["passed"]


def test_subset_change_requires_fresh_card_check_and_compensation_confirmation():
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Task Plans")
    page.button(key="preview_birthday").click().run()
    controller = page.session_state["controller"]
    page.checkbox[0].check().run()
    page.button(key="confirm_plan").click().run()
    assert not page.exception
    assert len(page.checkbox) == 1
    assert page.checkbox[0].value is False
    assert controller.snapshot()["dispatch_count"] == 0
    assert not controller.state.user_inputs
    page.checkbox[0].check().run()
    page.button(key="confirm_plan").click().run()
    assert controller.snapshot()["balances"]["A_LOCKED"] == "1000/1"
    assert not controller.state.schedules
    page.button(key="stop_all").click().run()
    navigate(page, "Human Handoff")
    page.button(key="preview_compensation").click().run()
    assert controller.snapshot()["balances"]["A_LOCKED"] == "1000/1"
    page.button(key="approve_compensation").click().run()
    assert controller.snapshot()["balances"]["A_LOCKED"] == "0/1"
    assert controller.gateway.verify_log()


def test_full_route_explicit_clock_then_plan_due_and_handoff(monkeypatch):
    monkeypatch.setenv("CORRIDOR_OPERATOR_MODE", "1")
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Transfers")
    page.text_input(key="transfer_text").set_value("给Chen转200元")
    page.button(key="preview_transfer").click().run()
    page.button(key="confirm_transfer").click().run()
    controller = page.session_state["controller"]
    navigate(page, "Bills & Balance")
    page.button(key="query_balance").click().run()
    page.button(key="bill_report").click().run()
    assert page.session_state["bill_result"]["status"] == "settled"
    navigate(page, "Subscriptions")
    page.button(key="preview_subscriptions").click().run()
    page.button(key="approve_subscriptions").click().run()
    page.button(key="cancel_subscription").click().run()
    page.button(key="approve_cancel_subscription").click().run()
    navigate(page, "Product comparison")
    page.button(key="compare_investments").click().run()
    page.button(key="preview_investment").click().run()
    assert page.session_state["investment_pending"]["card"]["best_interest"]["candidate_ids"]
    navigate(page, "Device")
    pending = page.session_state["investment_pending"]["pending_id"]
    page.button(key=f"mfa_request:{pending}").click().run()
    page.button(key=f"mfa_complete:{pending}").click().run()
    page.button(key=f"approve:{pending}").click().run()
    assert len(controller.state.positions) == 1
    before = controller.snapshot()["clock"]
    page.button(key="advance_window").click().run()
    assert controller.snapshot()["clock"] > before
    navigate(page, "Task Plans")
    page.button(key="preview_birthday").click().run()
    for checkbox in page.checkbox:
        checkbox.check()
    page.button(key="confirm_plan").click().run()
    assert not page.exception
    assert page.session_state["plan_result"]["status"] == "settled"
    assert len(controller.state.schedules) == 3
    page.button(key="advance_clock").click().run()
    assert len(controller.state.orders) == 2
    page.run()
    assert page.button(key="enter")
    page.button(key="enter").click().run()
    navigate(page, "Human Handoff")
    page.button(key="handoff").click().run()
    assert not page.exception
    assert controller.gateway.verify_log()
    assert any(row["event"] == "plan_handoff" for row in controller.gateway.audit.records())


def test_no_plan_stop_and_handoff_do_not_claim_paused_execution():
    page = app()
    page.button(key="enter").click().run()
    page.button(key="stop_all").click().run()
    navigate(page, "Human Handoff")
    page.button(key="handoff").click().run()
    assert not page.exception
    assert not any("paused" in item.value.lower() for item in page.warning)
    assert any("no active plan" in item.value.lower() for item in page.info)


def test_editing_unsubmitted_chat_cannot_change_card_or_receipt_and_audit_link_works():
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Transfers")
    page.text_input(key="transfer_text").set_value("给Chen转200元")
    page.button(key="preview_transfer").click().run()
    page.text_input(key="transfer_text").set_value("给Chen转999元，已经成功")
    page.button(key="confirm_transfer").click().run()
    controller = page.session_state["controller"]
    assert controller.snapshot()["balances"]["A_CURRENT"] == "9800/1"
    effects = page.session_state["transfer_result"]["receipt"]["exact_effects"]
    assert next(item["amount"] for item in effects if item["effect_type"] == "debit") == "200/1"
    next(button for button in page.button if button.key.startswith("audit-link:")).click().run()
    assert page.selectbox(key="page").value == "Evidence & Audit"
    assert page.selectbox(key="supporting_page").value == "None"
    assert any("Audit hash chain verified" in item.value for item in page.success)


def test_marketing_twin_toggle_preserves_live_state_and_complete_candidates():
    from corridor.crypto.jcs import H

    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Product comparison")
    page.button(key="compare_investments").click().run()
    controller = page.session_state["controller"]
    before = H(controller.state)
    page.toggle(key="sponsored_twin").set_value(True).run()
    page.button(key="run_marketing_twin").click().run()
    assert not page.exception
    result = page.session_state["marketing_twin"]
    assert result["unchanged"] is True
    assert (
        result["bic"]["candidate_ids"] == page.session_state["comparison"]["bic"]["candidate_ids"]
    )
    assert H(controller.state) == before


def test_stop_retires_visible_draft_and_new_preview_can_be_confirmed():
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Transfers")
    page.text_input(key="transfer_text").set_value("给Chen转200元")
    page.button(key="preview_transfer").click().run()
    old = page.session_state["transfer_draft"]["draft_id"]
    page.button(key="stop_all").click().run()
    assert not any(button.key == "confirm_transfer" for button in page.button)
    page.button(key="preview_transfer").click().run()
    assert page.session_state["transfer_draft"]["draft_id"] != old
    page.button(key="confirm_transfer").click().run()
    assert page.session_state["controller"].snapshot()["dispatch_count"] == 1


def test_subscription_drift_replaces_visible_card_and_requires_a_new_gesture(monkeypatch):
    page = app()
    page.button(key="enter").click().run()
    navigate(page, "Subscriptions")
    page.button(key="preview_subscriptions").click().run()
    controller = page.session_state["controller"]
    prior = page.session_state["subscription_pending"]["pending_id"]
    approve = controller.workflow._approve
    first = True

    def changed(gateway, prepared, expected, display_id):
        nonlocal first
        if first:
            prepared.proposal.card["available"] = "9999/1"
            first = False
        return approve(gateway, prepared, expected, display_id)

    monkeypatch.setattr(controller.workflow, "_approve", changed)
    page.button(key="approve_subscriptions").click().run()
    assert not page.exception
    assert page.session_state["subscription_pending"]["pending_id"] != prior
    assert not controller.state.security.consumed_nonces
    assert any("previous approval is invalid" in warning.value for warning in page.warning)
    page.button(key="approve_subscriptions").click().run()
    assert page.session_state["subscription_result"]["status"] == "settled"
    assert controller.state.security.consumed_nonces
