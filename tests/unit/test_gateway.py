from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import APPROVE, sign
from corridor.gateway.service import Gateway
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds, available, latest_events
from tests.gateway_cases import approve, gateway_case


@pytest.mark.rule("CTRL-MFA")
def test_password_control_requires_device_route_and_changes_credential_once():
    from tests.gateway_cases import approve_red, control_case

    gateway, device, action, cert = control_case()
    cert, token = approve_red(gateway, device, action, cert)
    assert gateway.dispatch(action, cert, token).rule_ids == ["CTRL-MFA"]
    result = gateway.device_control(action, cert, token)
    assert result.status == "controlled" and result.receipt is None
    assert gateway.store.snapshot().customers[action.principal].credential_version == 2
    assert gateway.bank.execute_count == 0
    assert gateway.device_control(action, cert, token).status == "rejected"


def test_contact_control_binds_exact_verified_destination():
    from corridor.schemas.domain import Contact
    from corridor.sim.keys import stable_id
    from tests.gateway_cases import approve_red, control_case

    gateway, device, action, cert = control_case("register_contact_request")
    cert, token = approve_red(gateway, device, action, cert)
    now = gateway.store.snapshot().now
    contact = Contact(
        id="CONTACT_DEVICE",
        owner=action.principal,
        name_token="PERSON_DEVICE",
        destination_ref="DEST_DEVICE",
        verified_at=now,
        verification_ref=stable_id(action.intent_id, 9, "input-contact_verification"),
    )
    confirmation = device.confirm_input(
        intent_id=action.intent_id,
        slot="contact_verification",
        value={
            "action_hash": H(action),
            "contact_hash": H(contact),
            "draft_handle": action.args.draft_handle,
        },
        now=now,
        step=9,
    )
    result = gateway.device_control(action, cert, token, contact=contact, confirmation=confirmation)
    assert result.status == "controlled" and result.receipt is None
    assert gateway.store.snapshot().contacts[contact.id] == contact
    assert gateway.bank.execute_count == 0


def test_dispatch_rechecks_real_kernel_after_consuming_approval(monkeypatch):
    import corridor.gateway.service as service

    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    real_check = service.check
    calls = []

    def traced(*args, **kwargs):
        calls.append(kwargs["phase"])
        assert token.nonce in args[2].security.consumed_nonces
        return real_check(*args, **kwargs)

    monkeypatch.setattr(service, "check", traced)
    assert gateway.dispatch(action, cert, token).status == "settled"
    assert calls == ["dispatch"]


@pytest.mark.rule("AUD-WRITE")
def test_audit_write_failure_prevents_bank_call(monkeypatch):
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)

    def failed(*args, **kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(gateway.audit, "append", failed)
    assert gateway.dispatch(action, cert, token).rule_ids == ["AUD-WRITE"]
    assert gateway.bank.execute_count == 0
    assert action.principal in gateway.store.snapshot().security.locked_at


def test_bad_receipt_signature_is_unknown_then_canonical_lookup_recovers():
    from corridor.kernel.binding import intent_key

    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    key = intent_key(action, gateway.store.snapshot())
    gateway.bank.faults[key] = "bad_signature"
    assert gateway.dispatch(action, cert, token).status == "unknown"
    assert gateway.reconcile(key).status == "settled"
    assert gateway.bank.execute_count == 1


@pytest.mark.parametrize(
    ("field", "value", "rule"),
    [
        pytest.param("principal", "OTHER", "APR-ROLE", marks=pytest.mark.rule("APR-ROLE")),
        pytest.param(
            "device_session_id", "OTHER_SESSION", "APR-ROLE", marks=pytest.mark.rule("APR-ROLE")
        ),
        pytest.param("plan_hash", H("wrong"), "APR-SWAP", marks=pytest.mark.rule("APR-SWAP")),
        pytest.param("cert_hash", H("wrong"), "APR-SWAP", marks=pytest.mark.rule("APR-SWAP")),
        pytest.param("card_hash", H("wrong"), "APR-SWAP", marks=pytest.mark.rule("APR-SWAP")),
        pytest.param("node_id", "OTHER_NODE", "APR-SWAP", marks=pytest.mark.rule("APR-SWAP")),
        pytest.param("ownership_epoch", 1, "APR-SWAP", marks=pytest.mark.rule("APR-SWAP")),
    ],
)
def test_signed_token_cannot_cross_scope(field, value, rule):
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert).model_copy(update={field: value})
    token = token.model_copy(update={"sig": sign(signing_key("device"), APPROVE, token)})
    assert gateway.dispatch(action, cert, token).rule_ids == [rule]
    assert gateway.bank.execute_count == 0


@pytest.mark.rule("APR-REQUIRED")
def test_write_requires_approval_and_valid_write_settles(tmp_path):
    gateway, device, action, cert = gateway_case(path=tmp_path)
    assert gateway.dispatch(action, cert).rule_ids == ["APR-REQUIRED"]
    token = approve(gateway, device, action, cert)
    result = gateway.dispatch(action, cert, token)
    assert result.status == "settled"
    assert result.receipt.status == "settled"
    assert available(gateway.store.snapshot(), "A_CURRENT") == 9800
    assert gateway.bank.execute_count == 1
    assert list((tmp_path / "decisions").glob("*.json"))


def test_green_query_needs_session_but_no_payment_approval():
    gateway, _, action, cert = gateway_case(query=True)
    result = gateway.query(action, cert)
    assert result.status == "settled"
    assert available(gateway.store.snapshot(), "A_CURRENT") == 10000


@pytest.mark.rule("APR-REUSE")
def test_nonce_is_consumed_and_reuse_never_reexecutes():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    assert gateway.dispatch(action, cert, token).status == "settled"
    assert "APR-REUSE" in gateway.dispatch(action, cert, token).rule_ids
    assert gateway.bank.execute_count == 1


@pytest.mark.rule("APR-SIG")
def test_forged_approval_cannot_move_money():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    token = token.model_copy(update={"sig": sign(signing_key("attacker"), APPROVE, token)})
    assert "APR-SIG" in gateway.dispatch(action, cert, token).rule_ids
    assert gateway.bank.execute_count == 0


@pytest.mark.rule("APR-EXPIRED")
def test_expiry_is_half_open():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    gateway.store.update(now=token.expiry)
    assert "APR-EXPIRED" in gateway.dispatch(action, cert, token).rule_ids


@pytest.mark.rule("APR-DRIFT")
def test_drift_still_consumes_signed_nonce():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    state = gateway.store.snapshot()
    account = state.accounts["A_CURRENT"]
    gateway.store.update(
        accounts={**state.accounts, account.id: account.model_copy(update={"version": 2})}
    )
    result = gateway.dispatch(action, cert, token)
    assert "APR-DRIFT" in result.rule_ids
    assert token.nonce in gateway.store.snapshot().security.consumed_nonces
    assert gateway.bank.execute_count == 0


def test_red_mfa_is_scoped_stored_and_single_use():
    gateway, device, action, cert = gateway_case(Fraction(1500))
    proposal = gateway.propose(action, cert)
    assert proposal.verdict.outcome == "Escalate"
    challenge = gateway.request_mfa(action, cert)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.submit_mfa(grant).status == "accepted"
    cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    assert gateway.dispatch(action, cert, token).status == "settled"
    assert grant.grant_id in gateway.store.snapshot().security.consumed_grant_ids


@pytest.mark.rule("APR-LOCK")
def test_six_distinct_approval_requests_lock_but_retries_deduplicate():
    from tests.e2e.test_gateway_atomicity import add_transfer

    gateway, _, action, cert = gateway_case()
    cases = [add_transfer(gateway, Fraction(10), f"RATE{index}") for index in range(5)]
    for _ in range(8):
        gateway.propose(action, cert, request_id="SAME")
    assert action.principal not in gateway.store.snapshot().security.locked_at
    for other_action, other_cert in cases:
        gateway.propose(other_action, other_cert, request_id="SAME")
    assert action.principal in gateway.store.snapshot().security.locked_at
    assert "APR-LOCK" in gateway.dispatch(action, cert).rule_ids


def test_three_kernel_rejections_lock_and_login_does_not_reset():
    gateway, device, action, cert = gateway_case()
    bad = cert.model_copy(update={"action_hash": H("wrong")})
    for index in range(2):
        assert gateway.propose(action, bad, request_id=f"BAD_{index}").verdict.outcome == "Reject"
    login = device.login(
        session_id="NEW_SESSION", expires_at=add_seconds(gateway.store.snapshot().now, 3600)
    )
    assert gateway.login(login).status == "accepted"
    assert gateway.store.snapshot().security.reject_streak[action.principal] == 2
    assert gateway.propose(action, bad, request_id="BAD_2").verdict.outcome == "Reject"
    assert action.principal in gateway.store.snapshot().security.locked_at


@pytest.mark.rule("BANK-RECEIPT")
def test_response_loss_retains_reservation_and_reconcile_only_looks_up():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    from corridor.kernel.binding import intent_key

    key = intent_key(action, gateway.store.snapshot())
    gateway.bank.faults[key] = "response_loss"
    result = gateway.dispatch(action, cert, token)
    assert result.status == "unknown"
    assert "BANK-RECEIPT" in result.rule_ids
    assert available(gateway.store.snapshot(), "A_CURRENT") == 9800
    assert key in gateway.store.snapshot().security.unknown_intent_ids
    assert gateway.reconcile(key).status == "settled"
    assert gateway.bank.execute_count == 1
    assert latest_events(gateway.store.snapshot())[key].event == "settled"


@pytest.mark.rule("APR-VOID")
def test_interruption_voids_all_tokens_for_plan():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    gateway.interrupt(action.plan_id)
    assert "APR-VOID" in gateway.dispatch(action, cert, token).rule_ids
    assert gateway.bank.execute_count == 0


def test_unlock_needs_cooldown_signed_scope_and_fresh_mfa():
    gateway, device, action, _ = gateway_case()
    gateway.lock(action.principal, "test")
    state = gateway.store.snapshot()
    gateway.store.update(now=add_seconds(state.now, 1800))
    scope = gateway.unlock_scope(action.principal)
    confirmation = device.confirm_input(
        intent_id=H(scope), slot="unlock", value=scope, now=gateway.store.snapshot().now
    )
    challenge = gateway.request_unlock_mfa(action.principal)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.unlock(action.principal, confirmation, grant).status == "unlocked"
    assert action.principal not in gateway.store.snapshot().security.locked_at
    assert gateway.unlock(action.principal, confirmation, grant).status == "rejected"


@pytest.mark.parametrize("failure", ["cooldown", "missing", "scope", "unknown", "expired"])
def test_unlock_rejects_each_missing_prerequisite(failure):
    from corridor.crypto.sign import MFA

    gateway, device, action, _ = gateway_case()
    gateway.lock(action.principal, "test")
    if failure != "cooldown":
        gateway.store.update(now=add_seconds(gateway.store.snapshot().now, 1800))
    scope = gateway.unlock_scope(action.principal)
    confirmation = device.confirm_input(
        intent_id=H(scope), slot="unlock", value=scope, now=gateway.store.snapshot().now
    )
    challenge = gateway.request_unlock_mfa(action.principal)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    if failure == "missing":
        grant = None
    elif failure == "scope":
        grant = grant.model_copy(update={"scope_hash": H("different_unlock")})
        grant = grant.model_copy(update={"sig": sign(signing_key("mfa"), MFA, grant)})
    elif failure == "unknown":
        gateway.store.update(
            security=gateway.store.snapshot().security.model_copy(
                update={"unknown_intent_ids": [H("pending_intent")]}
            )
        )
    elif failure == "expired":
        gateway.store.update(now=grant.expiry)
    result = gateway.unlock(action.principal, confirmation, grant)
    expected = "MFA-INVALID" if failure in {"scope", "expired"} else "APR-LOCK"
    assert expected in result.rule_ids
    assert action.principal in gateway.store.snapshot().security.locked_at


def test_safety_lock_voided_plan_remains_void_after_restart_and_unlock(tmp_path):
    from corridor.gateway.audit import AuditLog

    gateway, device, action, cert = gateway_case(path=tmp_path)
    gateway.lock(action.principal, "test")
    gateway = Gateway(
        gateway.store, gateway.bank, audit=AuditLog(tmp_path / "audit.jsonl"), mfa=gateway.mfa
    )
    gateway.store.update(now=add_seconds(gateway.store.snapshot().now, 1800))
    scope = gateway.unlock_scope(action.principal)
    confirmation = device.confirm_input(
        intent_id=H(scope), slot="unlock", value=scope, now=gateway.store.snapshot().now
    )
    challenge = gateway.request_unlock_mfa(action.principal)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.unlock(action.principal, confirmation, grant).status == "unlocked"
    assert gateway.dispatch(action, cert).rule_ids == ["APR-VOID"]
    assert gateway.submit_plan(gateway._plans[action.plan_id]).rule_ids == ["APR-VOID"]
    assert gateway.handoff(action.plan_id).status == "handoff"
    scope = gateway.resume_scope(action.plan_id)
    confirmation = device.confirm_input(
        intent_id=H(scope), slot="plan_resume", value=scope, now=gateway.store.snapshot().now
    )
    assert gateway.resume(action.plan_id, confirmation).rule_ids == ["APR-VOID"]
    restarted = Gateway(gateway.store, gateway.bank, audit=AuditLog(tmp_path / "audit.jsonl"))
    assert restarted.resume(action.plan_id, confirmation).rule_ids == ["APR-VOID"]
    assert gateway.bank.execute_count == 0


@pytest.mark.parametrize(
    "failure",
    ["required", "signature", "expired", "swap", "replay", "duplicate", "locked", "schema"],
)
def test_every_dispatch_refusal_records_only_rule_ids_and_hashes(failure):
    from tests.bank_cases import recertify

    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    expected = {
        "required": "APR-REQUIRED",
        "signature": "APR-SIG",
        "expired": "APR-EXPIRED",
        "swap": "APR-SWAP",
        "replay": "APR-REUSE",
        "duplicate": "IDEM-DUP",
        "locked": "APR-LOCK",
        "schema": "SCHEMA-INVALID",
    }[failure]
    if failure == "required":
        token = None
    elif failure == "signature":
        token = token.model_copy(update={"sig": sign(signing_key("attacker"), APPROVE, token)})
    elif failure == "expired":
        gateway.store.update(now=token.expiry)
    elif failure == "swap":
        token = token.model_copy(update={"card_hash": H("other_card")})
        token = token.model_copy(update={"sig": sign(signing_key("device"), APPROVE, token)})
    elif failure in {"replay", "duplicate"}:
        assert gateway.dispatch(action, cert, token).status == "settled"
        if failure == "duplicate":
            action, cert, _ = recertify(action, cert, gateway.store.snapshot())
            token = approve(gateway, device, action, cert, sequence=1)
    elif failure == "locked":
        gateway.lock(action.principal, "test")
    elif failure == "schema":
        action = action.model_copy(update={"kind": "invalid"})
    before = len(gateway.audit.records())
    assert expected in gateway.dispatch(action, cert, token).rule_ids
    records = [x for x in gateway.audit.records()[before:] if x["event"] == "dispatch_rejected"]
    assert len(records) == 1
    payload = records[0]["payload"]
    assert expected in payload["rule_ids"]
    assert set(payload) == {"rule_ids", "action_hash", "cert_hash", "token_hash"}
    assert all(
        len(value) == 64 and all(c in "0123456789abcdef" for c in value)
        for key, value in payload.items()
        if key != "rule_ids"
    )


def test_decision_retry_preserves_failed_attempt_and_new_approval(tmp_path):
    from corridor.kernel.binding import intent_key
    from corridor.schemas.base import loads_exact
    from tests.bank_cases import recertify

    gateway, device, action, cert = gateway_case(path=tmp_path)
    key = intent_key(action, gateway.store.snapshot())
    gateway.bank.faults[key] = "failed"
    token = approve(gateway, device, action, cert)
    assert gateway.dispatch(action, cert, token).status == "failed"
    first_path = tmp_path / "decisions" / f"{key}.json"
    original = first_path.read_bytes()
    del gateway.bank.faults[key]
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    assert gateway.dispatch(action, cert).rule_ids == ["APR-REQUIRED"]
    retry_token = approve(gateway, device, action, cert, sequence=1)
    assert gateway.dispatch(action, cert, retry_token).status == "settled"
    assert first_path.read_bytes() == original
    records = [loads_exact(path.read_bytes()) for path in first_path.parent.glob(f"{key}*.json")]
    assert len(records) == 2
    assert {record["bank_receipt"]["status"] for record in records} == {"failed", "settled"}
    assert {record["token_id"] for record in records} == {token.token_id, retry_token.token_id}
    assert available(gateway.store.snapshot(), "A_CURRENT") == 9800


def test_restart_converts_unfinished_reservation_to_unknown(tmp_path):
    gateway, _, action, _ = gateway_case(path=tmp_path)
    from corridor.schemas.bank import AccountMovement, BusinessEvent

    key = H("reserved")
    gateway.store.append_event(
        BusinessEvent(
            id="RESERVE",
            intent_key=key,
            event="reserved",
            kind="transfer",
            principal=action.principal,
            debit=AccountMovement(account_ref="A_CURRENT", amount=Fraction(200)),
            ts=gateway.store.snapshot().now,
        )
    )
    recovered = Gateway(gateway.store, gateway.bank, audit=gateway.audit)
    assert latest_events(recovered.store.snapshot())[key].event == "unknown"
    assert action.principal in recovered.store.snapshot().security.locked_at


def test_same_mfa_request_does_not_reset_three_attempts():
    gateway, _, action, cert = gateway_case(Fraction(1500))
    gateway.propose(action, cert)
    challenge = gateway.request_mfa(action, cert, request_id="MFA_ONE")
    now = gateway.store.snapshot().now
    for _ in range(3):
        assert gateway.mfa.verify(challenge, "wrong", now=now) is None
    assert gateway.request_mfa(action, cert, request_id="MFA_ONE") == challenge
    assert gateway.mfa.verify(challenge, gateway.mfa.test_code(challenge), now=now) is None


@pytest.mark.rule("PLAN-SCHEMA")
@pytest.mark.rule("PLAN-SCOPE")
@pytest.mark.rule("PLAN-OWNER")
@pytest.mark.rule("PLAN-CYCLE")
def test_registration_validates_owner_scope_and_single_node():
    gateway, _, action, _ = gateway_case()
    plan = gateway._plans[action.plan_id]
    for changes, expected in [
        ({"device_session_id": "WRONG"}, "PLAN-OWNER"),
        ({"ownership_epoch": 1}, "PLAN-SCOPE"),
        (
            {"nodes": [plan.nodes[0].model_copy(update={"depends_on": [plan.nodes[0].node_id]})]},
            "PLAN-CYCLE",
        ),
        ({"nodes": []}, "PLAN-SCHEMA"),
    ]:
        assert gateway.submit_plan(plan.model_copy(update=changes)).rule_ids == [expected]


@pytest.mark.rule("AUD-CHAIN")
def test_tampered_audit_blocks_dispatch(tmp_path):
    gateway, device, action, cert = gateway_case(path=tmp_path)
    token = approve(gateway, device, action, cert)
    path = tmp_path / "audit.jsonl"
    path.write_bytes(path.read_bytes()[:-1])
    assert gateway.dispatch(action, cert, token).rule_ids == ["AUD-CHAIN"]
    assert gateway.bank.execute_count == 0


@pytest.mark.rule("READ-ROLE")
def test_query_api_cannot_dispatch_transfer():
    gateway, _, action, cert = gateway_case()
    assert gateway.query(action, cert).rule_ids == ["READ-ROLE"]
    assert gateway.bank.execute_count == 0


def test_locked_gateway_allows_green_reads_but_denies_new_inputs_and_plans():
    gateway, device, action, cert = gateway_case(query=True)
    gateway.lock(action.principal, "test")
    item = device.confirm_input(
        intent_id="NEW", slot="purpose", value="new", now=gateway.store.snapshot().now
    )
    assert gateway.submit_input(item).rule_ids == ["APR-LOCK"]
    assert gateway.submit_plan(gateway._plans[action.plan_id]).status == "registered"
    assert gateway.query(action, cert).status == "settled"


def test_mfa_challenge_write_failure_returns_none_and_locks(monkeypatch):
    gateway, _, action, cert = gateway_case(Fraction(1500))
    gateway.propose(action, cert)

    def failed(**changes):
        raise OSError("state disk unavailable")

    monkeypatch.setattr(gateway.store, "update", failed)
    assert gateway.request_mfa(action, cert) is None
    assert gateway._write_failed
