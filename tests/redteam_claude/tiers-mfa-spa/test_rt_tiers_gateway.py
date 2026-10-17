"""Red-team probes through the real gateway/device/MockBank boundary."""

from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.schemas.bank import BankAction, BankCertificate, InputTerm, StateTerm
from corridor.stores.bank import add_seconds
from tests.bank_cases import recertify
from tests.e2e.test_gateway_spa import (
    PRINCIPAL,
    SESSION,
    _approve_dispatch,
    _complete_mfa,
    _gateway,
    _pay_today,
    _register_plan,
)


def _spa(gateway, device, amount, start):
    state = gateway.store.snapshot()
    spa_id = "SPA_RT"
    value = device.confirm_input(
        intent_id=spa_id,
        slot="amount",
        value={"amount": str(amount), "ccy": "CNY"},
        now=state.now,
    )
    assert gateway.submit_input(value).status == "accepted"
    spa = device.sign_spa({
        "id": spa_id,
        "source_ref": "A_CURRENT",
        "target": {"kind": "transfer", "contact_ref": "CONTACT_CHEN"},
        "destination_version": 1,
        "amount": amount,
        "schedule": {"type": "once"},
        "start": start,
        "end": add_seconds(start, 86400 * 30),
        "max_runs": 1,
        "creation_tier": "yellow",
        "plan_id": "PLAN_SPA_RT",
        "node_id": "NODE_SPA_RT",
    })
    assert gateway.submit_authorization(spa).status == "accepted"
    action = BankAction(
        action_id="CREATE_SPA_RT",
        intent_id=spa.id,
        principal=PRINCIPAL,
        device_session_id=SESSION,
        plan_id=spa.plan_id,
        plan_hash=H({}),
        node_id=spa.node_id,
        kind="schedule_transfer",
        args={
            "source_ref": "A_CURRENT",
            "contact_ref": "CONTACT_CHEN",
            "amount_ref": value.id,
            "schedule_ref": spa.id,
        },
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=spa.id,
        dependency_hashes={},
        derivations={
            "args.source_ref": StateTerm(
                collection="accounts", object_ref="A_CURRENT", field="id", version=1
            ),
            "args.contact_ref": StateTerm(
                collection="contacts", object_ref="CONTACT_CHEN", field="id", version=1
            ),
            "args.amount_ref": InputTerm(input_ref=value.id, slot="amount"),
            "args.schedule_ref": StateTerm(
                collection="authorizations", object_ref=spa.id, field="id", version=1
            ),
        },
    )
    action, cert = _register_plan(gateway, action, cert, [value.id])
    _approve_dispatch(gateway, device, action, cert)
    return action, cert, spa


def _run_action(gateway, creation_action, creation_cert):
    run = next(iter(gateway.store.snapshot().schedules.values()))
    action = BankAction.model_validate({
        **creation_action.model_dump(mode="python"),
        "action_id": run.id,
        "kind": "transfer",
        "args": {
            k: v
            for k, v in creation_action.args.model_dump(mode="python", exclude_none=True).items()
            if k != "schedule_ref"
        },
    })
    cert = creation_cert.model_copy(
        update={
            "mfa_grant_refs": [],
            "derivations": {
                k: t for k, t in creation_cert.derivations.items() if k != "args.schedule_ref"
            },
        }
    )
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    return action, cert, run


def _move(gateway, now):
    gateway.bank.advance_clock(now)
    gateway.store.update(now=now)


def test_waiting_mfa_run_cannot_auto_execute_after_retick_past_midnight(tmp_path):
    """DISCUSSION r3: a yellow SPA upgraded to waiting_mfa cannot bypass MFA by a later tick."""
    gateway, device = _gateway(tmp_path)
    # Due at local 2026-10-17 23:00 (UTC 15:00).
    action, cert, _ = _spa(gateway, device, Fraction(800), "2026-10-17T15:00:00Z")
    action, cert, run = _run_action(gateway, action, cert)
    _move(gateway, run.due_at)
    _pay_today(gateway, device, Fraction(300))
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    waiting = gateway.dispatch(action, cert)
    assert waiting.status == "waiting_mfa", waiting
    assert gateway.store.snapshot().schedules[run.id].status == "waiting_mfa"
    executed_before = gateway.bank.execute_count
    # Scheduler re-ticks 90 minutes later (local 2026-10-18 00:30), still inside 24h window.
    _move(gateway, "2026-10-17T16:30:00Z")
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    retry = gateway.dispatch(action, cert)
    assert retry.status == "waiting_mfa"
    assert "DOMAIN-SPA-TIER" in retry.rule_ids
    assert gateway.bank.execute_count == executed_before
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    assert gateway.propose(action, cert).card["tier"] == "red"
    cert, _ = _complete_mfa(gateway, device, action, cert)
    assert gateway.dispatch(action, cert).status == "settled"
    assert gateway.store.snapshot().schedules[run.id].status == "executed"


def test_split_yellow_transfers_second_needs_mfa(tmp_path):
    gateway, device = _gateway(tmp_path)
    _pay_today(gateway, device, Fraction(600))
    state = gateway.store.snapshot()
    from corridor.schemas.bank import BankAction as BA

    intent_id = "RT_SECOND"
    value = device.confirm_input(
        intent_id=intent_id, slot="amount", value={"amount": "600", "ccy": "CNY"}, now=state.now
    )
    assert gateway.submit_input(value).status == "accepted"
    auth = device.authorize({
        "id": "RT_SECOND_AUTH",
        "intent_id": intent_id,
        "allowed_kind": "transfer",
        "object_refs": ["A_CURRENT", "CONTACT_CHEN"],
        "amount_bound": Fraction(600),
        "expires_at": add_seconds(state.now, 3600),
        "input_hashes": [H(value)],
    })
    assert gateway.submit_authorization(auth).status == "accepted"
    action = BA(
        action_id="RT_SECOND_ACTION",
        intent_id=intent_id,
        principal=PRINCIPAL,
        device_session_id=SESSION,
        plan_id="RT_SECOND_PLAN",
        plan_hash=H({}),
        node_id="RT_SECOND_NODE",
        kind="transfer",
        args={"source_ref": "A_CURRENT", "contact_ref": "CONTACT_CHEN", "amount_ref": value.id},
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=auth.id,
        dependency_hashes={},
        derivations={
            "args.source_ref": StateTerm(
                collection="accounts", object_ref="A_CURRENT", field="id", version=1
            ),
            "args.contact_ref": StateTerm(
                collection="contacts", object_ref="CONTACT_CHEN", field="id", version=1
            ),
            "args.amount_ref": InputTerm(input_ref=value.id, slot="amount"),
        },
    )
    action, cert = _register_plan(gateway, action, cert, [value.id])
    proposal = gateway.propose(action, cert)
    assert proposal.card["tier"] == "red"
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    result = gateway.dispatch(action, cert, token)
    assert result.status != "settled"
    assert gateway.bank.execute_count == 1


def test_spa_run_blocked_by_safety_lock_is_skipped_not_retried_after_unlock(tmp_path):
    """DESIGN-BANK 4.3 / DISCUSSION r3: a failed due-time check (lock) skips the period;
    no automatic background retry once the lock is lifted."""
    gateway, device = _gateway(tmp_path)
    action, cert, _ = _spa(gateway, device, Fraction(200), "2026-10-17T02:00:00Z")
    action, cert, run = _run_action(gateway, action, cert)
    _move(gateway, run.due_at)
    gateway.lock(PRINCIPAL, "suspicious_activity")
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    blocked = gateway.dispatch(action, cert)
    assert blocked.rule_ids == ["APR-LOCK"]
    assert gateway.store.snapshot().schedules[run.id].status == "skipped"
    assert any(
        record["event"] == "schedule_status" and record["payload"]["rule_ids"] == ["APR-LOCK"]
        for record in gateway.audit.records()
    )
    # Unlock after the 30-minute cooldown with owner device + MFA.
    _move(gateway, add_seconds(run.due_at, 1800))
    scope = gateway.unlock_scope(PRINCIPAL)
    confirmation = device.confirm_input(
        intent_id=H(scope), slot="unlock", value=scope, now=gateway.store.snapshot().now
    )
    challenge = gateway.request_unlock_mfa(PRINCIPAL)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.unlock(PRINCIPAL, confirmation, grant).status == "unlocked"
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    retry = gateway.dispatch(action, cert)
    assert retry.status != "settled", "period blocked by the safety lock was auto-retried"
    assert gateway.bank.execute_count == 0


def test_scheduler_skips_due_locked_period_even_when_plan_was_voided(tmp_path):
    gateway, device = _gateway(tmp_path)
    action, cert, _ = _spa(gateway, device, Fraction(200), "2026-10-17T02:00:00Z")
    _, _, run = _run_action(gateway, action, cert)
    gateway.lock(PRINCIPAL, "suspicious_activity")
    gateway.advance_clock(run.due_at)
    assert gateway.store.snapshot().schedules[run.id].status == "skipped"
    assert gateway.bank.execute_count == 0
    assert any(
        row["event"] == "schedule_status" and row["payload"]["rule_ids"] == ["APR-LOCK"]
        for row in gateway.audit.records()
    )
