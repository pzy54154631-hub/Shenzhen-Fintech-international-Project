"""B6 cancellation uses the real device, kernel, gateway and bank boundary."""

import pytest

from corridor.crypto.jcs import H
from corridor.gateway.runtime import create_gateway
from corridor.kernel.binding import dependency_hashes, intent_key
from corridor.schemas.bank import BankAction, BankCertificate, Plan, PlanNode, StateTerm
from corridor.sim.device import Device
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key, stable_id
from corridor.stores.bank import BankStore, add_seconds


def cancellation_case():
    state = make_state()
    device = Device()
    gateway = create_gateway(BankStore(state), bank_key=signing_key("bank"))
    session = stable_id("B6-cancellation", 0, "session")
    assert (
        gateway.login(
            device.login(session_id=session, expires_at=add_seconds(state.now, 3600))
        ).status
        == "accepted"
    )
    intent = stable_id("B6-cancellation", 0, "intent")
    selection = device.confirm_input(
        intent_id=intent, slot="subscription", value="SUB_AUTH", now=state.now
    )
    assert gateway.submit_input(selection).status == "accepted"
    authority = device.authorize({
        "id": stable_id(intent, 0, "authority"),
        "intent_id": intent,
        "allowed_kind": "cancel_subscription",
        "object_refs": ["SUB_AUTH"],
        "expires_at": add_seconds(state.now, 3600),
        "input_hashes": [H(selection)],
    })
    assert gateway.submit_authorization(authority).status == "accepted"
    term = StateTerm(collection="subscriptions", object_ref="SUB_AUTH", field="id", version=1)
    node = PlanNode(
        node_id=stable_id(intent, 0, "node"),
        tool="cancel_subscription",
        args={"authorization_ref": term},
    )
    plan = Plan(
        plan_id=stable_id(intent, 0, "plan"),
        revision=1,
        principal=device.principal,
        device_session_id=session,
        intent_id=intent,
        goal_input_refs=[selection.id],
        nodes=[node],
        ownership_epoch=0,
    )
    assert gateway.submit_plan(plan).status == "registered"
    action = BankAction(
        action_id=stable_id(intent, 0, "action"),
        intent_id=intent,
        principal=device.principal,
        device_session_id=session,
        plan_id=plan.plan_id,
        plan_hash=H(plan),
        node_id=node.node_id,
        kind=node.tool,
        args={"authorization_ref": "SUB_AUTH"},
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=authority.id,
        derivations={"args.authorization_ref": term},
        dependency_hashes={},
    )
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(action, cert, gateway.store.snapshot())}
    )
    return gateway, device, action, cert


def test_cancel_requires_separate_yellow_approval_and_prevents_future_debit():
    gateway, device, action, cert = cancellation_case()
    history = H(gateway.bank.final_state()["transactions"])
    before = gateway.bank.execute_count
    proposal = gateway.propose(action, cert)
    assert proposal.verdict.outcome == "Accept"
    assert proposal.verdict.tier == "yellow"
    assert gateway.query(action, cert).rule_ids == ["READ-ROLE"]
    assert gateway.dispatch(action, cert).rule_ids == ["APR-REQUIRED"]
    assert gateway.bank.execute_count == before
    assert gateway.store.snapshot().subscriptions["SUB_AUTH"].status == "active"
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    result = gateway.dispatch(action, cert, token)
    assert result.status == "settled" and result.receipt is not None
    assert result.receipt.exact_effects[0].after == "cancelled"
    assert gateway.store.snapshot().subscriptions["SUB_AUTH"].status == "cancelled"
    assert gateway.bank.execute_count == before + 1
    assert gateway.dispatch(action, cert, token).rule_ids == ["APR-REUSE"]
    assert gateway.bank.execute_count == before + 1
    assert gateway.bank.advance_clock("2026-10-18T02:00:00Z") == []
    assert H(gateway.bank.final_state()["transactions"]) == history
    assert gateway.bank.final_state()["balances"]["A_CURRENT"] == "10000/1"
    assert gateway.verify_log()


@pytest.mark.parametrize("fault", ["failed", "response_loss"])
def test_cancellation_failure_or_unknown_never_claims_confirmed_cancellation(fault):
    gateway, device, action, cert = cancellation_case()
    proposal = gateway.propose(action, cert)
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    gateway.bank.faults[intent_key(action, gateway.store.snapshot())] = fault
    result = gateway.dispatch(action, cert, token)
    assert result.status == ("failed" if fault == "failed" else "unknown")
    assert gateway.store.snapshot().subscriptions["SUB_AUTH"].status == "active"
    assert gateway.bank.execute_count == 1
    assert gateway.verify_log()
