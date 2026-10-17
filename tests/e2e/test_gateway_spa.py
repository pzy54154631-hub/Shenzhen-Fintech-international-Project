"""SPA lifecycle through real device, gateway, store, and bank boundaries."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.eval.mockbank.exec import MockBank
from corridor.gateway.audit import AuditLog
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.service import Gateway
from corridor.schemas.bank import BankAction, BankCertificate, InputTerm, Plan, PlanNode, StateTerm
from corridor.sim.device import Device
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import BankStore, add_seconds, daily_total
from tests.bank_cases import recertify

PRINCIPAL = "C_DEMO"
SESSION = "SPA_E2E_SESSION"


def _gateway(tmp_path):
    initial = make_state()
    gateway = Gateway(
        BankStore(initial, path=tmp_path / "state.jsonl"),
        MockBank(initial, signing_key("bank")),
        audit=AuditLog(tmp_path / "audit.jsonl", tmp_path / "checkpoint.json"),
        mfa=MFAVerifier(signing_key("mfa")),
        evidence_dir=tmp_path / "decisions",
    )
    device = Device()
    login = device.login(session_id=SESSION, expires_at=add_seconds(initial.now, 86400 * 3))
    assert gateway.login(login).status == "accepted"
    return gateway, device


def _register_plan(gateway, action, cert, inputs):
    plan = Plan(
        plan_id=action.plan_id,
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=action.intent_id,
        goal_input_refs=inputs,
        nodes=[
            PlanNode(
                node_id=action.node_id,
                tool=action.kind,
                args={key.removeprefix("args."): term for key, term in cert.derivations.items()},
            )
        ],
        ownership_epoch=0,
    )
    result = gateway.submit_plan(plan)
    assert result.status == "registered", result
    action = action.model_copy(update={"plan_hash": H(plan)})
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    return action, cert


def _scheduled_case(gateway, device, amount, *, monthly=False):
    state = gateway.store.snapshot()
    spa_id = "SPA_E2E"
    user_input = device.confirm_input(
        intent_id=spa_id,
        slot="amount",
        value={"amount": str(amount), "ccy": "CNY"},
        now=state.now,
    )
    assert gateway.submit_input(user_input).status == "accepted"
    spa = device.sign_spa({
        "id": spa_id,
        "source_ref": "A_CURRENT",
        "target": {"kind": "transfer", "contact_ref": "CONTACT_CHEN"},
        "destination_version": 1,
        "amount": amount,
        "schedule": {"type": "monthly", "day": 17} if monthly else {"type": "once"},
        "start": add_seconds(state.now, 86400),
        "end": add_seconds(state.now, 86400 * 90),
        "max_runs": 3 if monthly else 1,
        "creation_tier": "red" if monthly or amount > 1000 else "yellow",
        "plan_id": "PLAN_SPA_E2E",
        "node_id": "NODE_SPA_E2E",
    })
    assert gateway.submit_authorization(spa).status == "accepted"
    action = BankAction(
        action_id="CREATE_SPA_E2E",
        intent_id=spa.id,
        principal=PRINCIPAL,
        device_session_id=SESSION,
        plan_id=spa.plan_id,
        plan_hash=H({}),
        node_id=spa.node_id,
        kind="schedule_transfer",
        args={
            "source_ref": spa.source_ref,
            "contact_ref": spa.target.contact_ref,
            "amount_ref": user_input.id,
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
            "args.amount_ref": InputTerm(input_ref=user_input.id, slot="amount"),
            "args.schedule_ref": StateTerm(
                collection="authorizations", object_ref=spa.id, field="id", version=1
            ),
        },
    )
    action, cert = _register_plan(gateway, action, cert, [user_input.id])
    return action, cert, spa


def _complete_mfa(gateway, device, action, cert):
    challenge_id = gateway.request_mfa(action, cert)
    assert challenge_id is not None
    grant = device.complete_mfa(gateway.mfa, challenge_id, now=gateway.store.snapshot().now)
    assert grant is not None
    assert gateway.submit_mfa(grant).status == "accepted"
    return cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]}), grant


def _approve_dispatch(gateway, device, action, cert):
    proposal = gateway.propose(action, cert)
    assert proposal.verdict.outcome in {"Accept", "Escalate"}, proposal.verdict
    grant = None
    if proposal.card["tier"] == "red":
        cert, grant = _complete_mfa(gateway, device, action, cert)
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    result = gateway.dispatch(action, cert, token)
    assert result.status in {"controlled", "settled"}, result
    return result, cert, token, grant


def _due_action(gateway, creation_action, creation_cert):
    state = gateway.store.snapshot()
    run = next(iter(state.schedules.values()))
    # No bank settlement or subscription charge is due before this first SPA run.
    assert run.due_at == "2026-10-17T02:00:00Z"
    assert gateway.bank.advance_clock(run.due_at) == []
    gateway.store.update(now=run.due_at)
    action = BankAction.model_validate({
        **creation_action.model_dump(mode="python"),
        "action_id": run.id,
        "kind": "transfer",
        "args": {
            key: value
            for key, value in creation_action.args.model_dump(
                mode="python", exclude_none=True
            ).items()
            if key != "schedule_ref"
        },
    })
    cert = creation_cert.model_copy(
        update={
            "mfa_grant_refs": [],
            "derivations": {
                key: term
                for key, term in creation_cert.derivations.items()
                if key != "args.schedule_ref"
            },
        }
    )
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    return action, cert, run


@pytest.mark.parametrize("amount", [Fraction(200), Fraction(1200)])
def test_real_creation_proves_due_execution_without_reusing_token_or_grant(tmp_path, amount):
    gateway, device = _gateway(tmp_path)
    action, cert, spa = _scheduled_case(gateway, device, amount)
    result, cert, token, grant = _approve_dispatch(gateway, device, action, cert)
    assert result.status == "controlled"
    assert gateway.bank.execute_count == 0
    state = gateway.store.snapshot()
    creation = [event for event in state.ledger if event.kind == "schedule_transfer"]
    assert len(creation) == 1
    assert creation[0].event == "settled"
    assert creation[0].object_delta == {
        "authorization_ref": spa.id,
        "spa_hash": H(spa),
        "creation_tier": spa.creation_tier,
        "approval_verified": True,
        "approval_hash": H(token),
        "mfa_verified": grant is not None,
        "mfa_hash": H(grant) if grant else None,
        "source_version": 1,
        "destination_version": 1,
    }
    assert token.nonce in state.security.consumed_nonces
    if grant:
        assert grant.grant_id in state.security.consumed_grant_ids
    action, cert, run = _due_action(gateway, action, cert)
    assert token.expiry < gateway.store.snapshot().now
    if grant:
        assert grant.expiry < gateway.store.snapshot().now
    result = gateway.dispatch(action, cert)
    assert result.status == "settled", result
    assert result.receipt.intent_key == H({"spa_id": spa.id, "run_index": 0})
    assert gateway.store.snapshot().schedules[run.id].status == "executed"
    expected_balance = Fraction(10000) - amount
    assert gateway.bank.final_state()["balances"]["A_CURRENT"] == (
        f"{expected_balance.numerator}/{expected_balance.denominator}"
    )
    assert gateway.bank.execute_count == 1
    assert gateway.audit.verify()
    duplicate = gateway.dispatch(action, cert)
    assert duplicate.status == "rejected"
    assert gateway.bank.execute_count == 1


def test_monthly_creation_registers_all_fixed_runs_and_requires_mfa(tmp_path):
    gateway, device = _gateway(tmp_path)
    action, cert, spa = _scheduled_case(gateway, device, Fraction(200), monthly=True)
    proposal = gateway.propose(action, cert)
    assert proposal.verdict.outcome == "Escalate"
    assert proposal.card["tier"] == "red"
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    missing = gateway.dispatch(action, cert, token)
    assert missing.status != "controlled"
    assert "TIER-MFA-REQUIRED" in missing.rule_ids
    assert gateway.store.snapshot().schedules == {}
    cert, grant = _complete_mfa(gateway, device, action, cert)
    token = device.approve(
        action, cert, proposal.card, now=gateway.store.snapshot().now, sequence=1
    )
    result = gateway.dispatch(action, cert, token)
    assert result.status == "controlled", result
    runs = list(gateway.store.snapshot().schedules.values())
    assert len(runs) == 3
    assert all(run.spa_ref == spa.id for run in runs)
    assert [run.run_index for run in runs] == [0, 1, 2]
    assert [run.due_at for run in runs] == [
        spa.start,
        "2026-11-17T02:00:00Z",
        "2026-12-17T02:00:00Z",
    ]
    assert grant.grant_id in gateway.store.snapshot().security.consumed_grant_ids
    assert gateway.bank.execute_count == 0


def _pay_today(gateway, device, amount):
    state = gateway.store.snapshot()
    intent_id = "SPA_OTHER_PAYMENT"
    value = device.confirm_input(
        intent_id=intent_id,
        slot="amount",
        value={"amount": str(amount), "ccy": "CNY"},
        now=state.now,
    )
    assert gateway.submit_input(value).status == "accepted"
    auth = device.authorize({
        "id": "SPA_OTHER_AUTH",
        "intent_id": intent_id,
        "allowed_kind": "transfer",
        "object_refs": ["A_CURRENT", "CONTACT_CHEN"],
        "amount_bound": amount,
        "expires_at": add_seconds(state.now, 3600),
        "input_hashes": [H(value)],
    })
    assert gateway.submit_authorization(auth).status == "accepted"
    action = BankAction(
        action_id="SPA_OTHER_ACTION",
        intent_id=intent_id,
        principal=PRINCIPAL,
        device_session_id=SESSION,
        plan_id="SPA_OTHER_PLAN",
        plan_hash=H({}),
        node_id="SPA_OTHER_NODE",
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
    return _approve_dispatch(gateway, device, action, cert)


def test_yellow_run_waits_for_new_mfa_after_real_same_day_payment(tmp_path):
    gateway, device = _gateway(tmp_path)
    action, cert, _ = _scheduled_case(gateway, device, Fraction(200))
    _approve_dispatch(gateway, device, action, cert)
    action, cert, run = _due_action(gateway, action, cert)
    _, _, _, previous_grant = _pay_today(gateway, device, Fraction(900))
    assert previous_grant is not None
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    waiting = gateway.dispatch(action, cert)
    assert waiting.status == "waiting_mfa", waiting
    assert "DOMAIN-SPA-TIER" in waiting.rule_ids
    assert gateway.store.snapshot().schedules[run.id].status == "waiting_mfa"
    assert gateway.bank.execute_count == 1
    assert gateway.bank.final_state()["balances"]["A_CURRENT"] == "9100/1"
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    proposal = gateway.propose(action, cert)
    assert proposal.card["tier"] == "red"
    cert, grant = _complete_mfa(gateway, device, action, cert)
    assert grant.grant_id != previous_grant.grant_id
    assert grant.scope_hash != previous_grant.scope_hash
    result = gateway.dispatch(action, cert)
    assert result.status == "settled", result
    assert grant.grant_id in gateway.store.snapshot().security.consumed_grant_ids
    assert gateway.bank.execute_count == 2
    assert gateway.bank.final_state()["balances"]["A_CURRENT"] == "8900/1"
    assert daily_total(gateway.store.snapshot(), PRINCIPAL) == 1100
    assert gateway.audit.verify()


def _cancel(gateway, device, spa):
    now = gateway.store.snapshot().now
    intent = "CANCEL_SPA_E2E"
    value = device.confirm_input(
        intent_id=intent, slot="schedule_cancel", value={"schedule_ref": spa.id}, now=now
    )
    assert gateway.submit_input(value).status == "accepted"
    authorization = device.authorize({
        "id": "CANCEL_SPA_AUTH",
        "intent_id": intent,
        "allowed_kind": "cancel_schedule",
        "object_refs": [spa.id],
        "expires_at": add_seconds(now, 3600),
        "input_hashes": [H(value)],
    })
    assert gateway.submit_authorization(authorization).status == "accepted"
    action = BankAction(
        action_id="CANCEL_SPA_ACTION",
        intent_id=intent,
        principal=PRINCIPAL,
        device_session_id=SESSION,
        plan_id="CANCEL_SPA_PLAN",
        plan_hash=H({}),
        node_id="CANCEL_SPA_NODE",
        kind="cancel_schedule",
        args={"schedule_ref": spa.id},
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=authorization.id,
        dependency_hashes={},
        derivations={
            "args.schedule_ref": StateTerm(
                collection="authorizations", object_ref=spa.id, field="id", version=1
            )
        },
    )
    action, cert = _register_plan(gateway, action, cert, [value.id])
    return _approve_dispatch(gateway, device, action, cert)


def test_confirmed_cancellation_prevents_due_bank_dispatch(tmp_path):
    gateway, device = _gateway(tmp_path)
    action, cert, spa = _scheduled_case(gateway, device, Fraction(200))
    _approve_dispatch(gateway, device, action, cert)
    cancelled, _, _, _ = _cancel(gateway, device, spa)
    assert cancelled.status == "controlled"
    assert all(run.status == "cancelled" for run in gateway.store.snapshot().schedules.values())
    action, cert, _ = _due_action(gateway, action, cert)
    result = gateway.dispatch(action, cert)
    assert result.status == "rejected"
    assert "DOMAIN-SPA" in result.rule_ids
    assert gateway.bank.execute_count == 0
    assert gateway.bank.final_state()["balances"]["A_CURRENT"] == "10000/1"


def test_due_action_parameter_change_is_rejected_and_never_sent_to_bank(tmp_path):
    gateway, device = _gateway(tmp_path)
    action, cert, _ = _scheduled_case(gateway, device, Fraction(200))
    _approve_dispatch(gateway, device, action, cert)
    action, cert, run = _due_action(gateway, action, cert)
    action = action.model_copy(
        update={"args": action.args.model_copy(update={"contact_ref": "CONTACT_LI"})}
    )
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    result = gateway.dispatch(action, cert)
    assert result.status == "rejected"
    assert "DOMAIN-SPA" in result.rule_ids
    # F2: only gateway-compiled actions may change a scheduled run's status.
    assert gateway.store.snapshot().schedules[run.id].status == "pending"
    assert gateway.bank.execute_count == 0
