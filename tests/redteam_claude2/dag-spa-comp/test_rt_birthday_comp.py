"""Red-team: birthday chain dependencies and compensation bounds (7.2-7.4, PROP-016)."""

import pytest

from corridor.bench.planning_runner import (
    _case,
    approve_birthday,
    approve_case,
    birthday_prepared,
    prepare_birthday,
    prepare_funds,
    prepare_refund,
)
from corridor.crypto.jcs import H
from corridor.kernel.binding import intent_key
from corridor.sim.planning import BIRTHDAY_DUE
from corridor.stores.bank import add_seconds


def _birthday(name):
    case = _case("RT2", name, None)
    bundle = prepare_birthday(case)
    return case, bundle


def test_no_orders_before_due():
    case, bundle = _birthday("bday-early")
    approve_birthday(case, bundle)
    case.gateway.advance_clock(add_seconds(BIRTHDAY_DUE, -1))
    # planner tries every scheduled run early
    for run in list(case.state.schedules.values()):
        action, cert = case.gateway.prepare_scheduled_run(run.id)
        assert case.gateway.dispatch(action, cert).status == "rejected"
    assert not case.state.orders and case.gateway.bank.execute_count == 1


def test_failed_lock_blocks_unlock_and_orders():
    case, bundle = _birthday("bday-lock-failed")
    lock = birthday_prepared(case, bundle, 0)
    case.gateway.bank.faults[intent_key(lock.action, case.state)] = "failed"
    assert case.dispatch(lock).status == "failed"
    for index in (1, 2, 3):
        result, _ = approve_case(case, birthday_prepared(case, bundle, index))
        assert result.status == "controlled"
    case.gateway.advance_clock(BIRTHDAY_DUE)
    case.gateway.tick()
    assert not case.state.orders
    final = case.gateway.bank.final_state()["balances"]
    assert final["A_CURRENT"] == "10000/1" and final["A_LOCKED"] == "0/1"


def test_unknown_unlock_blocks_orders():
    case, bundle = _birthday("bday-unlock-unknown")
    approve_birthday(case, bundle)
    unlock_spa = bundle["spas"][0]
    case.gateway.bank.faults[H({"spa_id": unlock_spa.id, "run_index": 0})] = "response_loss"
    case.gateway.advance_clock(BIRTHDAY_DUE)
    case.gateway.tick()
    assert not case.state.orders


def test_compensation_cannot_exceed_original_lock():
    case, bundle = _birthday("comp-exceed")
    lock = birthday_prepared(case, bundle, 0)
    locked = case.dispatch(lock)
    assert locked.status == "settled"
    case.gateway.interrupt(bundle["plan"].plan_id)
    first = prepare_funds(
        case,
        "unlock_funds",
        "600/1",
        step=10,
        purpose={"original_receipt_ref": locked.receipt.id},
    )
    assert case.dispatch(first).status == "settled"
    second = prepare_funds(
        case,
        "unlock_funds",
        "600/1",
        step=11,
        purpose={"original_receipt_ref": locked.receipt.id, "original_node_id": "x"},
    )
    assert "DOMAIN-COMPENSATION" in second.proposal.verdict.rule_ids


def test_unlock_compensation_cannot_cite_a_payment_receipt():
    case, bundle = _birthday("comp-nonrev")
    approve_birthday(case, bundle)
    case.gateway.advance_clock(BIRTHDAY_DUE)
    order_receipt = next(
        r for r in case.state.receipts.values() if getattr(r, "kind", None) == "merchant_order"
    )
    bad = prepare_funds(
        case,
        "unlock_funds",
        "300/1",
        step=10,
        purpose={"original_receipt_ref": order_receipt.id},
    )
    assert "DOMAIN-COMPENSATION" in bad.proposal.verdict.rule_ids


@pytest.mark.rule("DOMAIN-COMPENSATION")
def test_duplicate_refund_request_rejected_by_kernel():
    """DOMAIN-COMPENSATION: one refund_request per paid receipt; never an unknown bank call."""
    case, bundle = _birthday("comp-refund-dup")
    approve_birthday(case, bundle)
    case.gateway.advance_clock(BIRTHDAY_DUE)
    order_receipt = next(
        r for r in case.state.receipts.values() if getattr(r, "kind", None) == "merchant_order"
    )
    before = case.gateway.bank.final_state()["balances"]["A_CURRENT"]
    refund = prepare_refund(case, order_receipt.id, step=12)
    assert case.dispatch(refund).status == "settled"
    assert case.gateway.bank.final_state()["balances"]["A_CURRENT"] == before
    calls = case.gateway.bank.execute_count
    again = prepare_refund(case, order_receipt.id, step=13)
    second = case.dispatch(again)
    unknown = [e for e in case.state.ledger if e.kind == "refund_request" and e.event == "unknown"]
    assert again.proposal.verdict.outcome == "Reject", (second.status, second.rule_ids)
    assert second.status == "rejected" and "DOMAIN-COMPENSATION" in second.rule_ids
    assert case.gateway.bank.execute_count == calls and not unknown


def _complete_run_mfa(case, plan, run_id):
    from corridor.bench.bank_cases import PreparedCase

    action, cert = case.gateway.prepare_scheduled_run(run_id)
    proposal = case.gateway.propose(action, cert)
    challenge = case.gateway.request_mfa(action, cert)
    assert challenge is not None
    grant = case.device.complete_mfa(case.gateway.mfa, challenge, now=case.state.now)
    assert case.gateway.submit_mfa(grant).status == "accepted"
    cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    case.preparations.append(PreparedCase(action, cert, plan, proposal))
    return case.gateway.dispatch(action, cert)


def test_compensation_request_marks_paid_node_and_blocks_downstream_run():
    """DSC-3 was rejected: rollback marks paid nodes non_reversible (§7.3/7.4).

    Suggestions must not execute compensation or undo the paid effect; stopping
    forward execution on a non_reversible dependency is the conservative behavior.
    """
    from corridor.bench.planning_runner import prepare_spa

    case, bundle = _birthday("comp-suggest-dos")
    approve_birthday(case, bundle)
    # Another yellow 600 SPA due the same China day pushes the day over 1000.
    other, _ = prepare_spa(case, amount="600/1", start=BIRTHDAY_DUE, step=30)
    approve_case(case, other)
    case.gateway.advance_clock(BIRTHDAY_DUE)
    plan = bundle["plan"]
    flowers_spa, cake_spa = bundle["spas"][1], bundle["spas"][2]
    run = {
        s.id: next(r for r in case.state.schedules.values() if r.spa_ref == s.id)
        for s in (flowers_spa, cake_spa)
    }
    assert run[flowers_spa.id].status == "waiting_mfa"
    assert _complete_run_mfa(case, plan, run[flowers_spa.id].id).status == "settled"
    case.gateway.tick()
    cake_run = case.state.schedules[run[cake_spa.id].id]
    assert cake_run.status == "waiting_mfa"
    before = case.gateway.propose(*case.gateway.prepare_scheduled_run(cake_run.id))
    assert before.verdict.outcome == "Escalate"
    calls = case.gateway.bank.execute_count
    balances = case.gateway.bank.final_state()["balances"]
    case.gateway.request_compensation(plan.plan_id)
    flowers = plan.nodes[2].node_id
    status = case.gateway.plan_snapshot(plan.plan_id)["nodes"][flowers]["status"]
    after = case.gateway.propose(*case.gateway.prepare_scheduled_run(cake_run.id))
    assert status == "non_reversible"
    assert after.verdict.outcome == "Reject" and "PLAN-SCOPE" in after.verdict.rule_ids
    assert case.gateway.bank.execute_count == calls
    assert case.gateway.bank.final_state()["balances"] == balances
