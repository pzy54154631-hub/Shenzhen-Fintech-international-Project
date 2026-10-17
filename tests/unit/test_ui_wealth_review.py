"""Review regressions: cached UI approvals must track the current trusted context."""

from corridor.ui import wealth_views
from tests.unit.test_ui_wealth_controller import GOALS, prepared_controller


def start_first_leg(controller):
    overview = controller.prepare_allocation()
    assert (
        controller.start_allocation([item["item_ref"] for item in overview["items"]])["status"]
        == "waiting_mfa"
    )
    identifier = controller.leg["action"].action_id
    assert controller.verify_leg(identifier)["status"] == "mfa_verified"
    return identifier


def test_successful_profile_retake_withdraws_old_comparison_and_approval():
    controller = prepared_controller()
    identifier = start_first_leg(controller)
    old_parent = controller.parent_id
    controller.advance_clock(1)
    assert controller.submit_risk_answers([1, 1, 1, 1, 2])["status"] == "settled"
    assert controller.comparison is None
    assert controller.draft is None and controller.leg is None
    assert controller.parent_id is None and old_parent in controller.history
    assert controller.approve_leg(identifier)["status"] == "rejected"
    assert controller.gateway.bank.execute_count == 0


def test_identical_goal_confirmation_does_not_reuse_expired_profile_comparison():
    controller = prepared_controller()
    controller.advance_clock(controller.risk_profile()["expires_at"])
    controller.start_session()
    result = controller.confirm_goals(GOALS)
    assert result["status"] == "rejected"
    assert "BIC-RISK" in result["rule_ids"]
    assert controller.comparison is None
    assert controller.gateway.bank.execute_count == 0


def test_device_session_renewal_discards_old_verified_leg():
    controller = prepared_controller()
    identifier = start_first_leg(controller)
    old_session, old_parent = controller.session, controller.parent_id
    controller.advance_clock(3601)
    controller.start_session()
    assert controller.session != old_session
    assert controller.leg is None and controller.parent_id is None
    assert controller.comparison is None and old_parent in controller.history
    assert controller.approve_leg(identifier)["status"] == "rejected"
    assert controller.gateway.bank.execute_count == 0


def test_changed_goals_void_prior_device_leg_without_moving_funds():
    controller = prepared_controller()
    identifier = start_first_leg(controller)
    old_parent = controller.parent_id
    assert controller.confirm_goals({**GOALS, "amount": "9000/1"})["status"] == "comparison_only"
    assert controller.parent_id is None and controller.leg is None
    assert old_parent in controller.history
    assert controller.approve_leg(identifier)["status"] == "rejected"
    assert controller.gateway.bank.execute_count == 0


def test_proposal_refresh_after_profile_change_does_not_expose_exception(monkeypatch):
    from unittest.mock import MagicMock

    controller = prepared_controller()
    controller.advance_clock(1)
    assert controller.submit_risk_answers([1, 1, 1, 1, 2])["status"] == "settled"
    monkeypatch.setattr(wealth_views, "st", MagicMock())
    wealth_views.proposal(controller)
