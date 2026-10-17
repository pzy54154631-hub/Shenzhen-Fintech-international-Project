"""The supporting demo controller uses one persistent, real CCA session."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.ui.controller import DemoController


def controller():
    app = DemoController()
    assert not app.state.authorizations
    assert app.start_session()["status"] == "ready"
    return app


def test_transfer_preview_is_unsigned_and_one_gesture_executes_once():
    app = controller()
    before = H({"inputs": app.state.user_inputs, "auth": app.state.authorizations})
    draft = app.preview_transfer("给Chen转200元", request_id="transfer-one")
    assert draft["card"]["amount"] == "200/1"
    assert H({"inputs": app.state.user_inputs, "auth": app.state.authorizations}) == before
    result = app.confirm_transfer(draft["draft_id"])
    assert result["status"] == "settled"
    assert app.snapshot()["balances"]["A_CURRENT"] == "9800/1"
    assert app.confirm_transfer(draft["draft_id"]) == result
    assert app.gateway.bank.execute_count == 1
    assert app.gateway.verify_log()


def test_ambiguous_transfer_needs_explicit_selected_contact():
    app = controller()
    draft = app.preview_transfer("给Lin转200元", request_id="ambiguous")
    assert draft["status"] == "clarify"
    assert app.gateway.bank.execute_count == 0
    selected = app.select_contact(draft["draft_id"], "CONTACT_LIN_B")
    result = app.confirm_transfer(selected["draft_id"])
    assert result["status"] == "settled"
    assert app.gateway.bank.final_state()["destinations"] == {"DEST_CONTACT_LIN_B": "200/1"}


def test_green_report_and_yellow_subscriptions_keep_distinct_authority():
    app = controller()
    assert app.query_balance()["status"] == "settled"
    report = app.bill_report()
    assert report["status"] == "settled"
    assert report["analysis_receipt"]["results"]["net_spend"]["value"] == "1877/1"
    inputs = H(app.state.user_inputs)
    draft = app.preview_subscriptions()
    assert draft["card"]["tier"] == "yellow"
    assert H(app.state.user_inputs) == inputs
    assert not app.state.security.consumed_nonces
    listed = app.approve_pending(draft["pending_id"])
    assert listed["analysis_receipt"]["results"]["cancellable_authorizations"]["value"] == ["S1"]
    cancel = app.cancel_subscription("S1", request_id="cancel-one")
    assert app.state.subscriptions["S1"].status == "active"
    cancelled = app.approve_pending(cancel["pending_id"])
    assert cancelled["status"] == "settled"
    assert app.state.subscriptions["S1"].status == "cancelled"


def test_red_purchase_requires_separate_mfa_and_retains_full_bic():
    app = controller()
    compared = app.compare_investments()
    assert compared["status"] == "settled"
    draft = app.preview_investment()
    assert draft["card"]["tier"] == "red"
    assert len(draft["card"]["best_interest"]["rows"]) == 2
    pending = draft["pending_id"]
    assert app.approve_pending(pending)["status"] == "waiting_mfa"
    assert app.gateway.bank.execute_count == 0
    assert app.request_mfa(pending)["challenge_id"]
    assert app.complete_mfa(pending)["status"] == "mfa_verified"
    assert app.approve_pending(pending)["status"] == "settled"
    assert app.snapshot()["balances"]["A_CURRENT"] == "9000/1"
    assert len(app.state.positions) == 1


def test_birthday_partial_selection_signs_no_unchecked_nodes_and_can_compensate():
    app = controller()
    before = H({"inputs": app.state.user_inputs, "auth": app.state.authorizations})
    draft = app.preview_birthday(selected_indices=[0])
    assert H({"inputs": app.state.user_inputs, "auth": app.state.authorizations}) == before
    selected = [draft["nodes"][0]["id"]]
    result = app.confirm_plan(draft["plan_id"], selected)
    assert result["status"] == "settled"
    assert app.snapshot()["balances"]["A_LOCKED"] == "1000/1"
    assert not app.state.schedules
    assert len(app.state.authorizations) == 2  # login plus selected lock only
    app.stop(draft["plan_id"])
    compensation = app.compensate(draft["plan_id"])
    assert app.approve_pending(compensation["pending_id"])["status"] == "settled"
    assert app.snapshot()["balances"]["A_LOCKED"] == "0/1"
    assert app.gateway.verify_log()


def test_birthday_full_dag_executes_only_due_authorized_nodes():
    app = controller()
    draft = app.preview_birthday()
    result = app.confirm_plan(draft["plan_id"], [node["id"] for node in draft["nodes"]])
    assert result["status"] == "settled"
    assert len(app.state.schedules) == 3
    due = min(run.due_at for run in app.state.schedules.values())
    app.advance_clock(due)
    assert len(app.state.orders) == 2
    assert Fraction(app.snapshot()["balances"]["A_CURRENT"]) == 9000
    assert app.gateway.verify_log()


def test_changed_birthday_subset_is_redisplayed_before_any_signatures():
    app = controller()
    draft = app.preview_birthday()
    before = H({"inputs": app.state.user_inputs, "auth": app.state.authorizations})
    selected = [draft["nodes"][0]["id"]]
    result = app.confirm_plan(draft["plan_id"], selected)
    assert result["status"] == "redisplay"
    assert H({"inputs": app.state.user_inputs, "auth": app.state.authorizations}) == before
    assert app.gateway.bank.execute_count == 0
    replacement = result["replacement"]
    assert len(replacement["nodes"]) == 1
    assert (
        app.confirm_plan(replacement["plan_id"], [replacement["nodes"][0]["id"]])["status"]
        == "settled"
    )
    assert len(app.state.authorizations) == 2
    assert not app.state.schedules


def test_later_plan_card_drift_retains_partial_results_without_claiming_completion(monkeypatch):
    app = controller()
    draft = app.preview_birthday()
    real_approve = app.workflow._approve
    calls = 0

    def drifting_approve(gateway, prepared, expected, display_id):
        nonlocal calls
        calls += 1
        if calls == 2:
            prepared.proposal.card["amount"] = "999/1"
        return real_approve(gateway, prepared, expected, display_id)

    monkeypatch.setattr(app.workflow, "_approve", drifting_approve)
    result = app.confirm_plan(draft["plan_id"], [node["id"] for node in draft["nodes"]])
    assert result["status"] == "redisplay"
    assert len(result["results"]) == 1
    assert next(iter(result["results"].values()))["status"] == "settled"
    assert draft["plan_id"] not in app._results
    assert app.gateway.bank.execute_count == 1
    assert not app.state.schedules


def test_clock_expiry_requires_new_explicit_device_login():
    app = controller()
    previous = app.session
    app.advance_clock(3601)
    assert app.snapshot()["logged_in"] is False
    with pytest.raises(ValueError, match="device login"):
        app.query_balance()
    assert app.start_session()["status"] == "ready"
    assert app.session != previous
    assert app.query_balance()["status"] == "settled"


def test_explicit_product_choice_and_delayed_redemption_use_actual_receipts():
    app = controller()
    app.compare_investments()
    draft = app.preview_investment("P_B", request_id="explicit-purchase")
    assert draft["card"]["best_interest"]["best_choice"] is False
    assert draft["card"]["best_interest"]["rows"][1]["gap"] == "5/1"
    app.request_mfa(draft["pending_id"])
    app.complete_mfa(draft["pending_id"])
    assert app.approve_pending(draft["pending_id"])["status"] == "settled"
    position = next(iter(app.state.positions.values()))
    app.advance_clock(position.redeemable_at)
    app.start_session()
    before = H(app.state.user_inputs)
    redemption = app.redeem(position.id, request_id="redeem-one")
    assert H(app.state.user_inputs) == before
    result = app.approve_pending(redemption["pending_id"])
    assert result["status"] == "pending"
    if result["receipt"]["settle_at"]:
        app.advance_clock(result["receipt"]["settle_at"])
    assert app.state.positions[position.id].status == "closed"
    assert app.gateway.verify_log()


def test_red_transfer_stays_pending_through_duplicate_click_and_requires_mfa():
    app = controller()
    draft = app.preview_transfer("给Chen转1200元", request_id="red-transfer")
    pending = app.confirm_transfer(draft["draft_id"])
    assert pending["status"] == "waiting_mfa"
    app.request_mfa(pending["pending_id"])
    app.complete_mfa(pending["pending_id"])
    app.confirm_transfer(draft["draft_id"])
    assert app.approve_pending(pending["pending_id"])["status"] == "settled"
    assert app.gateway.bank.execute_count == 1


def test_handoff_and_explicit_resume_do_not_restore_cancelled_schedules():
    app = controller()
    draft = app.preview_birthday()
    app.confirm_plan(draft["plan_id"], [node["id"] for node in draft["nodes"]])
    assert app.handoff(draft["plan_id"])["status"] == "handoff"
    assert all(run.status == "cancelled" for run in app.state.schedules.values())
    before = H(app.state.user_inputs)
    scope = app.resume_scope(draft["plan_id"])
    assert scope["plan_id"] == draft["plan_id"]
    assert H(app.state.user_inputs) == before
    assert app.resume(draft["plan_id"])["status"] == "resumed"
    app.advance_clock(min(run.due_at for run in app.state.schedules.values()))
    assert not app.state.orders


def test_marketing_twin_and_duplicate_preview_never_change_signed_facts():
    app = controller()
    compared = app.compare_investments()
    before = H(app.state)
    for sponsored in (False, True):
        twin = app.marketing_twin(sponsored)
        assert twin["unchanged"]
        assert twin["bic"]["rows"] == compared["bic"]["rows"]
        assert H(app.state) == before
    first = app.preview_investment(request_id="purchase-duplicate")
    signatures = H({"inputs": app.state.user_inputs, "auth": app.state.authorizations})
    assert app.preview_investment(request_id="purchase-duplicate") == first
    assert H({"inputs": app.state.user_inputs, "auth": app.state.authorizations}) == signatures
    with pytest.raises(ValueError, match="Request"):
        app.preview_investment("P_B", request_id="purchase-duplicate")
    plan = app.preview_birthday(request_id="birthday-duplicate")
    assert app.preview_birthday(request_id="birthday-duplicate") == plan


def test_transfer_drift_requires_redisplay_then_accepts_a_fresh_gesture():
    app = controller()
    earlier = app.preview_transfer("给Chen转200元", request_id="earlier")
    later = app.preview_transfer("给Chen转100元", request_id="later")
    assert app.confirm_transfer(later["draft_id"])["status"] == "settled"
    before = H({"inputs": app.state.user_inputs, "auth": app.state.authorizations})
    drift = app.confirm_transfer(earlier["draft_id"])
    assert drift["status"] == "redisplay"
    assert H({"inputs": app.state.user_inputs, "auth": app.state.authorizations}) == before
    assert drift["card"]["available"] == "9900/1"
    assert app.confirm_transfer(earlier["draft_id"])["status"] == "settled"
    assert app.snapshot()["balances"]["A_CURRENT"] == "9700/1"


def test_global_stop_retires_unsigned_drafts_without_creating_authority():
    app = controller()
    transfer = app.preview_transfer("给Chen转200元", request_id="stopped-draft")
    subscription = app.preview_subscriptions()
    before = H({"inputs": app.state.user_inputs, "auth": app.state.authorizations})
    assert app.stop()["status"] == "interrupted"
    assert H({"inputs": app.state.user_inputs, "auth": app.state.authorizations}) == before
    with pytest.raises(KeyError):
        app.confirm_transfer(transfer["draft_id"])
    with pytest.raises(KeyError):
        app.approve_pending(subscription["pending_id"])
    assert app.gateway.bank.execute_count == 0


def test_yellow_preparation_drift_returns_a_new_unsigned_card_for_reconfirmation(monkeypatch):
    app = controller()
    draft = app.preview_subscriptions()
    approve = app.workflow._approve
    first = True

    def changed(gateway, prepared, expected, display_id):
        nonlocal first
        if first:
            prepared.proposal.card["available"] = "9999/1"
            first = False
        return approve(gateway, prepared, expected, display_id)

    monkeypatch.setattr(app.workflow, "_approve", changed)
    result = app.approve_pending(draft["pending_id"])
    assert result["status"] == "redisplay"
    replacement = result["replacement"]
    assert replacement["pending_id"] != draft["pending_id"]
    assert app.gateway.bank.execute_count == 0
    assert not app.state.security.consumed_nonces
    assert app.approve_pending(replacement["pending_id"])["status"] == "settled"
