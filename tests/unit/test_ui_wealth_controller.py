"""Device gestures, authentic comparisons and per-leg wealth execution."""

from corridor.ui.wealth_controller import WealthController

GOALS = {
    "amount": "10000/1",
    "horizon_days": 365,
    "liquidity_days": 3,
    "liquidity_amount": "0/1",
    "allowed_types": ["wealth"],
    "objective": "net_return",
    "source_account_ref": "A_CURRENT",
}


def prepared_controller():
    controller = WealthController()
    controller.start_session()
    controller.submit_risk_answers([1, 1, 1, 1, 1])
    controller.receive_goal("Compare my goals", request_id="goals")
    assert controller.confirm_goals(GOALS)["status"] == "comparison_only"
    return controller


def test_each_wealth_leg_needs_separate_mfa_and_two_purchases_do_not_lock():
    controller = prepared_controller()
    overview = controller.prepare_allocation()
    assert not controller.state.allocation_plans
    selected = [item["item_ref"] for item in overview["items"]]
    assert controller.start_allocation(selected[:1])["status"] == "draft"
    assert not controller.state.allocation_plans
    assert controller.start_allocation(selected)["status"] == "waiting_mfa"
    now = controller.state.now
    grants = []
    for number in range(2):
        key = controller.leg["action"].action_id
        assert controller.approve_leg(key)["status"] == "waiting_mfa"
        assert controller.verify_leg(key)["status"] == "mfa_verified"
        grants.extend(controller.leg["cert"].mfa_grant_refs)
        assert controller.approve_leg(key)["status"] == "settled"
        assert len(controller.state.positions) == number + 1
        controller.approve_leg(key)
        assert len(controller.state.positions) == number + 1
    assert len(set(grants)) == 2
    assert controller.execution_snapshot()["status"] == "completed"
    assert controller.state.now == now
    assert not controller.state.security.locked_at
    assert controller.approval_window()["used"] == 2


def test_preflight_refuses_before_child_signatures_or_bank_calls():
    controller = prepared_controller()
    from corridor.schemas.state import ApprovalRequest

    controller.gateway.store.update(
        security=controller.state.security.model_copy(
            update={
                "approval_requests": {
                    controller.device.principal: [
                        ApprovalRequest(request_id=f"prior-{n}", ts=controller.state.now)
                        for n in range(4)
                    ]
                }
            }
        )
    )
    overview = controller.prepare_allocation()
    before = len(controller.state.user_inputs)
    result = controller.start_allocation([row["item_ref"] for row in overview["items"]])
    assert result["status"] == "approval_budget"
    assert result["needed"] == 2 and result["remaining"] == 1
    assert len(controller.state.user_inputs) == before
    assert not controller.state.allocation_plans
    assert controller.gateway.bank.execute_count == 0


def test_four_legs_complete_without_clock_advance_or_lock():
    from fractions import Fraction

    from corridor.crypto.sign import CATALOG, sign
    from corridor.sim.keys import signing_key
    from corridor.sim.wealth import make_wealth_state

    state = make_wealth_state()
    catalog = state.catalog.model_copy(
        update={
            "products": [
                product.model_copy(update={"max_amount": Fraction(3000)})
                if product.id != "P_Y"
                else product
                for product in state.catalog.products
            ]
        }
    )
    catalog = catalog.model_copy(update={"sig": sign(signing_key("bank"), CATALOG, catalog)})
    controller = WealthController(initial_state=state.model_copy(update={"catalog": catalog}))
    controller.start_session()
    controller.receive_goal("Compare", request_id="four-legs")
    assert controller.confirm_goals(GOALS)["status"] == "comparison_only"
    overview = controller.prepare_allocation()
    assert len(overview["items"]) == 4
    now = controller.state.now
    controller.start_allocation([item["item_ref"] for item in overview["items"]])
    for _ in range(4):
        key = controller.leg["action"].action_id
        assert controller.verify_leg(key)["status"] == "mfa_verified"
        assert controller.approve_leg(key)["status"] == "settled"
    assert controller.execution_snapshot()["status"] == "completed"
    assert controller.approval_window()["used"] == 4
    assert not controller.state.security.locked_at
    assert controller.state.now == now


def test_failed_second_leg_and_unknown_lookup_never_retry_purchases():
    from corridor.kernel.binding import intent_key

    for fault, expected in (("failed", "partially_executed"), ("response_loss", "unknown")):
        controller = prepared_controller()
        overview = controller.prepare_allocation()
        controller.start_allocation([row["item_ref"] for row in overview["items"]])
        first = controller.leg["action"].action_id
        controller.verify_leg(first)
        controller.approve_leg(first)
        second = controller.leg["action"].action_id
        key = intent_key(controller.leg["action"], controller.state)
        controller.gateway.bank.faults[key] = fault
        controller.verify_leg(second)
        controller.approve_leg(second)
        assert controller.execution_snapshot()["status"] == expected
        assert controller.leg is None
        controller.approve_leg(second)
        assert controller.gateway.bank.execute_count == 2
        if fault == "response_loss":
            controller.lookup_pending()
            assert controller.execution_snapshot()["status"] == "completed"
            assert controller.gateway.bank.execute_count == 2
        else:
            assert controller.execution_snapshot()["available_balance"] == "7000/1"


def test_questionnaire_is_explicit_and_never_calls_the_model(monkeypatch):
    controller = WealthController()
    controller.start_session()
    assert controller.risk_profile() is None
    assert not controller.state.user_inputs

    def forbidden(**kwargs):
        raise AssertionError("Questionnaire answers must stay on the device")

    monkeypatch.setattr(controller.client, "complete", forbidden)
    result = controller.submit_risk_answers([1, 1, 1, 1, 1])
    assert result["status"] == "settled", result
    assert controller.risk_profile()["level"] == 2
    assert not controller.state.positions
    assert controller.gateway.verify_log()


def test_vague_advice_does_not_create_profile_goals_or_purchase():
    controller = WealthController()
    controller.start_session()
    result = controller.receive_goal("I want something safe", request_id="vague")
    assert "amount" in result["pending_slots"]
    assert controller.risk_profile() is None
    assert not controller.state.user_inputs
    assert not controller.state.allocation_plans


def test_expired_profile_cannot_construct_biac():
    controller = WealthController()
    controller.start_session()
    controller.submit_risk_answers([1, 1, 1, 1, 1])
    expiry = controller.risk_profile()["expires_at"]
    controller.advance_clock(expiry)
    controller.start_session()
    controller.receive_goal("Compare my goals", request_id="expired")
    result = controller.confirm_goals({
        "amount": "10000/1",
        "horizon_days": 365,
        "liquidity_days": 3,
        "liquidity_amount": "0/1",
        "allowed_types": ["wealth"],
        "objective": "net_return",
        "source_account_ref": "A_CURRENT",
    })
    assert result["status"] == "rejected"
    assert "BIC-RISK" in result["rule_ids"]
    assert controller.comparison is None
    assert not controller.state.positions
