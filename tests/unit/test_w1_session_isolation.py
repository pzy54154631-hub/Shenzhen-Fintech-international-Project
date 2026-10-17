"""Browser sessions keep synthetic money, authorization and evidence independent."""

import pytest

from corridor.crypto.jcs import H
from corridor.sim.wealth import make_wealth_state
from corridor.ui.controller import DemoController
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


@pytest.mark.parametrize("controller_type", [DemoController, WealthController])
def test_sessions_own_their_gateway_bank_audit_clock_and_mutable_state(controller_type):
    first, second = controller_type(), controller_type()
    for attribute in ("gateway", "device", "client", "chat"):
        assert getattr(first, attribute) is not getattr(second, attribute)
    for attribute in ("store", "bank", "audit", "mfa", "vault"):
        assert getattr(first.gateway, attribute) is not getattr(second.gateway, attribute)

    original = H(second.state)
    original_audit = second.gateway.audit.records()
    original_clock = second.state.now
    first.start_session()
    first.advance_clock(60)
    first.gateway.bank.faults["first-session-only"] = "failed"

    assert H(second.state) == original
    assert second.gateway.audit.records() == original_audit
    assert second.state.now == original_clock
    assert first.state.now != second.state.now
    assert not second.gateway.bank.faults
    assert second.session_authorization is None
    assert not second.snapshot()["logged_in"]


def test_supporting_sessions_cannot_read_or_approve_each_others_transfer(tmp_path):
    first_path, second_path = tmp_path / "first-bank", tmp_path / "second-bank"
    first = DemoController(evidence_dir=first_path)
    second = DemoController(evidence_dir=second_path)
    first.start_session()
    second.start_session()
    second_before = H(second.state)
    second_audit = second.gateway.audit.records()

    draft = first.preview_transfer("给Chen转1200元", request_id="shared-request-id")
    pending = first.confirm_transfer(draft["draft_id"])
    assert pending["status"] == "waiting_mfa"
    assert first.snapshot()["pending"]
    assert not second.snapshot()["pending"]
    with pytest.raises(KeyError):
        second.approve_pending(pending["pending_id"])

    challenge = first.request_mfa(pending["pending_id"])["challenge_id"]
    assert challenge not in second.gateway.mfa._challenges
    assert first.complete_mfa(pending["pending_id"])["status"] == "mfa_verified"
    result = first.approve_pending(pending["pending_id"])
    assert result["status"] == "settled"
    assert first.snapshot()["balances"]["A_CURRENT"] == "8800/1"
    assert second.snapshot()["balances"]["A_CURRENT"] == "10000/1"
    assert result["receipt"]["receipt_id"] not in second.state.receipts
    assert second.gateway.bank.lookup(result["receipt"]["intent_key"]) is None
    assert H(second.state) == second_before
    assert second.gateway.audit.records() == second_audit
    assert not second.state.security.consumed_nonces
    assert first.gateway.verify_log() and second.gateway.verify_log()
    assert first_path.resolve() != second_path.resolve()
    assert list(first_path.glob("*.json"))
    assert not list(second_path.glob("*.json"))


def test_wealth_sessions_cannot_read_approvals_receipts_or_positions(tmp_path):
    first_path, second_path = tmp_path / "first-wealth", tmp_path / "second-wealth"
    first = WealthController(evidence_dir=first_path)
    second = WealthController(evidence_dir=second_path)
    first.start_session()
    second.start_session()
    second_before = H(second.state)
    second_audit = second.gateway.audit.records()

    assert first.submit_risk_answers([1] * 5)["status"] == "settled"
    first.receive_goal("Compare my goals", request_id="shared-request-id")
    assert first.confirm_goals(GOALS)["status"] == "comparison_only"
    overview = first.prepare_allocation()
    selected = [item["item_ref"] for item in overview["items"]]
    assert first.start_allocation(selected)["status"] == "waiting_mfa"
    assert first.approval_window()["used"] == 1
    assert second.approval_window()["used"] == 0
    assert second.leg is None
    assert second.execution_snapshot() is None
    assert second.risk_profile() is None
    assert not second.state.user_inputs

    for _ in selected:
        action_id = first.leg["action"].action_id
        assert second.approve_leg(action_id) == {"status": "rejected", "rule_ids": ["APR-VOID"]}
        assert second.verify_leg(action_id) == {"status": "rejected", "rule_ids": ["APR-VOID"]}
        assert first.verify_leg(action_id)["status"] == "mfa_verified"
        assert first.approve_leg(action_id)["status"] == "settled"

    assert first.execution_snapshot()["status"] == "completed"
    assert first.snapshot()["balances"]["A_CURRENT"] == "2000/1"
    assert second.snapshot()["balances"]["A_CURRENT"] == "12000/1"
    assert len(first.state.positions) == len(selected)
    assert not second.state.positions
    assert not second.state.receipts
    assert not second.leg_results
    assert not second.state.security.consumed_nonces
    assert second.gateway.bank.execute_count == 0
    assert H(second.state) == second_before
    assert second.gateway.audit.records() == second_audit
    assert first.gateway.verify_log() and second.gateway.verify_log()
    assert first_path.resolve() != second_path.resolve()
    assert list(first_path.glob("*.json"))
    assert not list(second_path.glob("*.json"))


def test_sessions_detach_even_when_given_the_same_initial_fixture():
    initial = make_wealth_state()
    first = WealthController(initial_state=initial)
    second = WealthController(initial_state=initial)
    second_before = H(second.state)
    first.start_session()
    first.receive_goal("Compare my goals", request_id="first-session")
    assert first.confirm_goals(GOALS)["status"] == "comparison_only"

    initial.accounts.clear()
    detached = first.state
    detached.user_inputs.clear()
    detached.accounts.clear()
    assert first.state.user_inputs
    assert first.state.accounts
    assert H(second.state) == second_before
    assert not second.state.user_inputs
