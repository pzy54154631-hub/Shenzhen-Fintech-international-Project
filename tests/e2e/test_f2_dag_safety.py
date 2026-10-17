"""F2 regressions for terminal Stop, canonical SPA evaluation and refund reuse."""

import pytest

from corridor.bench.planning_runner import _case, prepare_refund, prepare_transfer
from corridor.crypto.jcs import H
from corridor.gateway.service import Gateway
from corridor.kernel import check
from corridor.stores.bank import BankStore, add_seconds
from tests.bank_cases import recertify
from tests.e2e.test_gateway_spa import (
    _approve_dispatch,
    _due_action,
    _gateway,
    _scheduled_case,
)
from tests.e2e.test_plan_controls import _advance_all, _plan_case, _query


@pytest.mark.parametrize(
    "status",
    [
        pytest.param("reserved", marks=pytest.mark.rule("DOMAIN-COMPENSATION")),
        pytest.param("unknown", marks=pytest.mark.rule("DOMAIN-COMPENSATION")),
        pytest.param("settled", marks=pytest.mark.rule("DOMAIN-COMPENSATION")),
        "failed",
    ],
)
def test_refund_reuse_matches_original_receipt_and_latest_status(status):
    case = _case("F2", f"refund-{status}", None)
    payment = case.dispatch(prepare_transfer(case, "100/1", step=0))
    assert payment.status == "settled"
    first = prepare_refund(case, payment.receipt.id, step=1)
    assert case.dispatch(first).status == "settled"
    again = prepare_refund(case, payment.receipt.id, step=2)
    state = case.state
    final = state.ledger[-1]
    assert final.kind == "refund_request" and final.event == "settled"
    # Preserve the historical reservation: a later failed terminal must release it.
    state = state.model_copy(
        update={"ledger": [*state.ledger[:-1], final.model_copy(update={"event": status})]}
    )
    result = check(*recertify(again.action, again.cert, state), phase="propose")
    if status == "failed":
        assert result.outcome == "Accept", result
    else:
        assert result.outcome == "Reject" and "DOMAIN-COMPENSATION" in result.rule_ids


@pytest.mark.parametrize("restart", [False, True])
def test_stopped_nodes_remain_cancelled_after_handoff_resume_and_direct_dispatch(restart):
    case, plan = _plan_case()
    assert case.gateway.submit_plan(plan).status == "registered"
    assert case.gateway.query(*_query(case, plan, "A")).status == "settled"
    assert case.gateway.interrupt(plan.plan_id).status == "interrupted"
    assert case.gateway.handoff(plan.plan_id).status == "handoff"
    assert case.gateway.plan_snapshot(plan.plan_id)["nodes"]["B"]["status"] == "cancelled"
    scope = case.gateway.resume_scope(plan.plan_id)
    confirmation = case.device.confirm_input(
        intent_id=H(scope), slot="plan_resume", value=scope, now=case.state.now
    )
    assert case.gateway.resume(plan.plan_id, confirmation).status == "resumed"
    if restart:
        case.gateway = Gateway(BankStore(case.state), case.gateway.bank, audit=case.gateway.audit)
    current = case.gateway._plans[plan.plan_id]
    direct = case.gateway.query(*_query(case, current, "B"))
    assert direct.status == "rejected" and "PLAN-SCOPE" in direct.rule_ids
    assert _advance_all(case.gateway, plan.plan_id, current.ownership_epoch) == []
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.plan_snapshot(plan.plan_id)["nodes"]["B"]["status"] == "cancelled"
    assert case.gateway.plan_snapshot(plan.plan_id)["nodes"]["C"]["status"] == "cancelled"


@pytest.mark.rule("DOMAIN-SPA")
@pytest.mark.parametrize("state_change", ["due", "locked", "expired"])
def test_forged_spa_action_has_no_state_side_effects(tmp_path, state_change):
    from fractions import Fraction

    gateway, device = _gateway(tmp_path)
    action, cert, _ = _scheduled_case(gateway, device, Fraction(200))
    _approve_dispatch(gateway, device, action, cert)
    action, cert, run = _due_action(gateway, action, cert)
    if state_change == "locked":
        gateway.lock(action.principal, "test_lock")
    elif state_change == "expired":
        gateway.store.update(now=add_seconds(run.expires_at, 1))
    forged = action.model_copy(
        update={"args": action.args.model_copy(update={"contact_ref": "CONTACT_LI"})}
    )
    forged_cert = cert.model_copy(update={"action_hash": H(forged)})
    before = gateway.store.snapshot()
    result = gateway.dispatch(forged, forged_cert)
    assert result.status == "rejected" and "DOMAIN-SPA" in result.rule_ids
    assert gateway.store.snapshot() == before
    assert gateway.bank.execute_count == 0
    assert gateway.audit.verify()


@pytest.mark.parametrize("path", ["direct", "tick"])
@pytest.mark.parametrize("target_changed", [False, True])
def test_canonical_spa_run_skips_after_trusted_target_version_change(
    tmp_path, path, target_changed
):
    from fractions import Fraction

    gateway, device = _gateway(tmp_path)
    action, cert, _ = _scheduled_case(gateway, device, Fraction(200))
    _approve_dispatch(gateway, device, action, cert)
    action, cert, run = _due_action(gateway, action, cert)
    state = gateway.store.snapshot()
    contact = state.contacts[action.args.contact_ref]
    changes = {"version": 2, **({"destination_version": 2} if target_changed else {})}
    gateway.store.update(
        contacts={**state.contacts, contact.id: contact.model_copy(update=changes)}
    )
    results = [gateway.dispatch(action, cert)] if path == "direct" else gateway.tick()
    assert len(results) == 1 and results[0].status == "rejected"
    assert gateway.store.snapshot().schedules[run.id].status == "skipped", results[0]
    assert gateway.bank.execute_count == 0


@pytest.mark.parametrize("mutation", ["action_hash", "dependencies", "authority", "terms", "mfa"])
def test_certificate_tampering_alone_does_not_skip_canonical_spa_run(tmp_path, mutation):
    from fractions import Fraction

    gateway, device = _gateway(tmp_path)
    action, cert, _ = _scheduled_case(gateway, device, Fraction(200))
    _approve_dispatch(gateway, device, action, cert)
    action, cert, run = _due_action(gateway, action, cert)
    forged_cert = cert.model_copy(
        update={
            "action_hash": {"action_hash": H({"forged": True})},
            "dependencies": {"dependency_hashes": {}},
            "authority": {"authorization_ref": "OTHER_AUTHORITY"},
            "terms": {"derivations": {}},
            "mfa": {"mfa_grant_refs": ["UNKNOWN_GRANT"]},
        }[mutation]
    )
    before = gateway.store.snapshot().schedules[run.id]
    result = gateway.dispatch(action, forged_cert)
    assert result.status == "rejected"
    assert gateway.store.snapshot().schedules[run.id] == before
    assert gateway.bank.execute_count == 0
