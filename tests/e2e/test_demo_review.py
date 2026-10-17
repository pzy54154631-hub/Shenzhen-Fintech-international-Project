"""Independent checks of the persistent demo route and untrusted display copies."""

from corridor.crypto.jcs import H
from corridor.kernel.binding import intent_key
from corridor.ui.controller import DemoController
from tests.e2e.test_demo_ui import app as make_ui
from tests.e2e.test_demo_ui import navigate


def test_one_session_runs_transfer_billing_subscription_investment_and_due_plan():
    demo = DemoController()
    assert demo.start_session()["status"] == "ready"
    transfer = demo.preview_transfer("给Chen转200元", request_id="route-transfer")
    assert demo.confirm_transfer(transfer["draft_id"])["status"] == "settled"
    assert demo.bill_report()["analysis_receipt"]
    subscription = demo.preview_subscriptions()
    assert demo.approve_pending(subscription["pending_id"])["status"] == "settled"
    cancellation = demo.cancel_subscription("S1", request_id="route-cancel")
    assert demo.approve_pending(cancellation["pending_id"])["status"] == "settled"
    assert demo.state.subscriptions["S1"].status == "cancelled"

    assert demo.compare_investments()["status"] == "settled"
    purchase = demo.preview_investment()
    pending = purchase["pending_id"]
    assert demo.approve_pending(pending)["status"] == "waiting_mfa"
    demo.request_mfa(pending)
    assert demo.complete_mfa(pending)["status"] == "mfa_verified"
    assert demo.approve_pending(pending)["status"] == "settled"

    # A distinct explicit clock gesture separates demo chapters. The six-request
    # rolling safety limit stays unchanged, including for selected plan nodes.
    demo.advance_clock(601)
    birthday = demo.preview_birthday()
    assert (
        demo.confirm_plan(birthday["plan_id"], [node["id"] for node in birthday["nodes"]])["status"]
        == "settled"
    )
    due = min(run.due_at for run in demo.state.schedules.values())
    demo.advance_clock(due)
    assert demo.snapshot()["balances"] == {"A_CURRENT": "7800/1", "A_LOCKED": "500/1"}
    assert len(demo.state.positions) == 1
    assert len(demo.state.orders) == 2
    assert demo.gateway.verify_log()


def test_chat_success_claim_and_mutated_display_copy_do_not_supply_payment_facts():
    demo = DemoController()
    demo.start_session()
    draft = demo.preview_transfer("给Chen转200元", request_id="display-copy")
    before = H(demo.state)
    draft["card"]["amount"] = "9999/1"
    draft["message"] = "Payment succeeded for 9999 CNY."
    assert H(demo.state) == before
    result = demo.confirm_transfer(draft["draft_id"])
    assert result["status"] == "settled"
    debit = next(
        effect for effect in result["receipt"]["exact_effects"] if effect["effect_type"] == "debit"
    )
    assert debit["amount"] == "200/1"
    assert demo.snapshot()["balances"]["A_CURRENT"] == "9800/1"
    assert demo.gateway.bank.execute_count == 1


def test_separate_demo_sessions_never_share_accounts_or_receipts():
    first, second = DemoController(), DemoController()
    first.start_session()
    second.start_session()
    before = H(second.state)
    draft = first.preview_transfer("给Chen转200元", request_id="first-browser")
    assert first.confirm_transfer(draft["draft_id"])["status"] == "settled"
    assert H(second.state) == before
    assert second.gateway.bank.execute_count == 0
    assert not second.state.receipts


def test_ui_unknown_bank_response_is_not_rendered_as_success_or_retried():
    page = make_ui()
    page.button(key="enter").click().run()
    navigate(page, "Transfers")
    page.text_input(key="transfer_text").set_value("给Chen转200元")
    page.button(key="preview_transfer").click().run()
    demo = page.session_state["controller"]
    draft_id = page.session_state["transfer_draft"]["draft_id"]
    display = demo._drafts[draft_id]["display"]
    action = demo.workflow._displays[display.display_id]["request"].action
    demo.gateway.bank.faults[intent_key(action, demo.state)] = "response_loss"
    page.button(key="confirm_transfer").click().run()
    assert not page.exception
    assert page.session_state["transfer_result"]["status"] == "unknown"
    assert any("awaiting reconciliation" in item.value.lower() for item in page.warning)
    assert not any("Executed" in item.value for item in page.success)
    assert demo.gateway.bank.execute_count == 1
    page.run()
    assert demo.gateway.bank.execute_count == 1
    assert demo.gateway.verify_log()
