"""Persistence and privacy failures must remain visible across gateway recovery."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.audit import AuditLog
from corridor.gateway.service import Gateway
from corridor.kernel.binding import intent_key
from corridor.schemas.bank import ReadTerm
from corridor.schemas.base import loads_exact
from corridor.stores.bank import BankStore, available, latest_events
from tests.gateway_cases import approve, gateway_case


def _legacy_pending_transfer(tmp_path, monkeypatch):
    import corridor.gateway.bank_adapter as bank_adapter
    import corridor.gateway.service as service
    import corridor.kernel.binding as kernel_binding

    def legacy_key(action, state):
        return H({
            "principal": action.principal,
            "intent_id": action.intent_id,
            "node_id": action.node_id,
            "kind": action.kind,
        })

    with monkeypatch.context() as legacy:
        for module in (kernel_binding, service, bank_adapter):
            legacy.setattr(module, "intent_key", legacy_key)
        gateway, device, action, cert = gateway_case(path=tmp_path)
        token = approve(gateway, device, action, cert)
        key = legacy_key(action, gateway.store.snapshot())
        gateway.bank.faults[key] = "response_loss"
        assert gateway.dispatch(action, cert, token).status == "unknown"
    assert key != intent_key(action, gateway.store.snapshot())
    restarted = Gateway(
        BankStore(gateway.store.snapshot(), path=tmp_path / "state.jsonl"),
        gateway.bank,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        mfa=gateway.mfa,
        evidence_dir=tmp_path / "decisions",
    )
    return restarted, device, action, cert, token, key


def test_upgrade_reconciles_legacy_pending_key_without_executing_or_reusing_authority(
    tmp_path, monkeypatch
):
    from corridor.stores.bank import add_seconds
    from tests.bank_cases import recertify

    gateway, device, action, cert, token, legacy_key = _legacy_pending_transfer(
        tmp_path, monkeypatch
    )
    assert gateway.bank.lookup(legacy_key).status == "settled"
    result = gateway.reconcile(legacy_key)
    assert result.status == "settled", result
    assert gateway.bank.execute_count == 1
    assert available(gateway.store.snapshot(), "A_CURRENT") == 9800
    assert legacy_key not in gateway.store.snapshot().security.unknown_intent_ids
    assert latest_events(gateway.store.snapshot())[legacy_key].event == "settled"
    _assert_decision(
        tmp_path / "decisions" / f"{legacy_key}.json", action, cert, token, result.receipt
    )

    gateway.store.update(now=add_seconds(gateway.store.snapshot().now, 1800))
    scope = gateway.unlock_scope(action.principal)
    confirmation = device.confirm_input(
        intent_id=H(scope), slot="unlock", value=scope, now=gateway.store.snapshot().now
    )
    challenge = gateway.request_unlock_mfa(action.principal)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.unlock(action.principal, confirmation, grant).status == "unlocked"
    plan = gateway._plans[action.plan_id]
    node = plan.nodes[0].model_copy(update={"node_id": "REPLAY_NODE"})
    plan = plan.model_copy(update={"plan_id": "REPLAY_PLAN", "nodes": [node]})
    assert gateway.submit_plan(plan).status == "registered"
    action = action.model_copy(
        update={
            "plan_id": plan.plan_id,
            "plan_hash": H(plan),
            "node_id": node.node_id,
            "action_id": "REPLAY_ACTION",
        }
    )
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    proposal = gateway.propose(action, cert)
    assert "AUTH-CONSUMED" in proposal.verdict.rule_ids
    token = device.approve(
        action, cert, proposal.card, now=gateway.store.snapshot().now, sequence=1
    )
    assert "AUTH-CONSUMED" in gateway.dispatch(action, cert, token).rule_ids
    assert gateway.bank.execute_count == 1


@pytest.mark.parametrize("tamper", ["signature", "effects", "certificate", "order", "key"])
def test_legacy_reconciliation_still_rejects_unbound_or_unverified_evidence(
    tmp_path, monkeypatch, tamper
):
    from corridor.crypto.sign import RECEIPT, sign
    from corridor.sim.keys import signing_key

    gateway, _, action, _, _, key = _legacy_pending_transfer(tmp_path, monkeypatch)
    receipt = gateway.bank.lookup(key)
    if tamper in {"signature", "effects"}:
        if tamper == "signature":
            receipt = receipt.model_copy(update={"sig": "0" * 128})
        else:
            effect = receipt.exact_effects[0].model_copy(update={"amount": Fraction(1)})
            receipt = receipt.model_copy(
                update={"exact_effects": [effect, *receipt.exact_effects[1:]]}
            )
            receipt = receipt.model_copy(
                update={"sig": sign(signing_key("bank"), RECEIPT, receipt)}
            )
        monkeypatch.setattr(gateway.bank, "lookup", lambda requested_key: receipt)
    else:
        state = gateway.store.snapshot()
        event = latest_events(state)[key]
        delta = {**event.object_delta}
        if tamper == "certificate":
            delta["cert"] = {**delta["cert"], "analysis_receipt_refs": ["UNBOUND_RECEIPT"]}
        elif tamper == "order":
            delta["order"] = {
                **delta["order"],
                "args": {**delta["order"]["args"], "amount": "201/1"},
            }
        else:
            delta["order"] = {**delta["order"], "intent_key": H("unrelated_order")}
        gateway.store.append_event(
            event.model_copy(update={"id": "UNBOUND_EVENT", "object_delta": delta})
        )
    result = gateway.reconcile(key)
    assert result.status == "unknown" and "BANK-RECEIPT" in result.rule_ids
    assert key in gateway.store.snapshot().security.unknown_intent_ids
    assert action.principal in gateway.store.snapshot().security.locked_at
    assert gateway.bank.execute_count == 1


def _assert_decision(path, action, cert, token, receipt):
    record = loads_exact(path.read_bytes())
    assert H(record["action"]) == H(action)
    assert H(record["cert"]) == H(cert)
    assert record["token_id"] == token.token_id
    assert H(record["bank_receipt"]) == H(receipt)
    assert record["card_hash"] == token.card_hash
    assert record["tier"] == token.tier
    assert "mfa_grant_id" in record and "compensation_refs" in record
    assert record["verdict"]["outcome"] == "Accept"


def test_reconcile_cannot_claim_completion_while_decision_writes_still_fail(tmp_path, monkeypatch):
    gateway, device, action, cert = gateway_case(path=tmp_path)
    token = approve(gateway, device, action, cert)
    key = intent_key(action, gateway.store.snapshot())
    decision_path = tmp_path / "decisions" / f"{key}.json"
    original = gateway._decision

    def unavailable(*args, **kwargs):
        raise OSError("AUD-WRITE")

    monkeypatch.setattr(gateway, "_decision", unavailable)
    result = gateway.dispatch(action, cert, token)
    assert result.status == "unknown"
    assert not decision_path.exists()
    assert gateway.bank.execute_count == 1
    assert gateway.reconcile(key).status == "unknown"
    assert latest_events(gateway.store.snapshot())[key].event == "unknown"
    assert key in gateway.store.snapshot().security.unknown_intent_ids
    assert action.principal in gateway.store.snapshot().security.locked_at

    monkeypatch.setattr(gateway, "_decision", original)
    recovered = gateway.reconcile(key)
    assert recovered.status == "settled", recovered
    assert gateway.bank.execute_count == 1
    assert available(gateway.store.snapshot(), "A_CURRENT") == 9800
    _assert_decision(decision_path, action, cert, token, recovered.receipt)


def test_response_loss_recovery_after_restart_restores_complete_decision(tmp_path):
    gateway, device, action, cert = gateway_case(path=tmp_path)
    token = approve(gateway, device, action, cert)
    key = intent_key(action, gateway.store.snapshot())
    gateway.bank.faults[key] = "response_loss"
    assert gateway.dispatch(action, cert, token).status == "unknown"
    decision_path = tmp_path / "decisions" / f"{key}.json"
    assert not decision_path.exists()

    restarted = Gateway(
        BankStore(gateway.store.snapshot(), path=tmp_path / "state.jsonl"),
        gateway.bank,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        evidence_dir=tmp_path / "decisions",
    )
    result = restarted.reconcile(key)
    assert result.status == "settled", result
    assert decision_path.exists()
    _assert_decision(decision_path, action, cert, token, result.receipt)
    assert restarted.bank.execute_count == 1
    assert available(restarted.store.snapshot(), "A_CURRENT") == 9800
    assert key not in restarted.store.snapshot().security.unknown_intent_ids
    assert restarted.audit.verify()


def test_unvalidated_read_term_text_never_enters_plan_audit():
    gateway, _, action, _ = gateway_case(query=True)
    plan = gateway._plans[action.plan_id]
    private_text = "SYNTHETIC_PRIVATE_TEXT"
    node = plan.nodes[0].model_copy(
        update={
            "args": {
                "period": ReadTerm(
                    session_authorization_ref="SESSION_AUTH",
                    query_field="period",
                    value=private_text,
                )
            }
        }
    )
    malformed = plan.model_copy(update={"plan_id": "UNVALIDATED_READ_PLAN", "nodes": [node]})
    result = gateway.submit_plan(malformed)
    assert result.status == "rejected"
    assert private_text.encode("utf-8") not in jcs_bytes(gateway.audit.records())
    assert gateway.bank.execute_count == 0


def test_safety_lock_is_audited_once_with_the_persisted_principal():
    gateway, _, action, _ = gateway_case()
    gateway.lock(action.principal, "manual_safety_test")
    assert action.principal in gateway.store.snapshot().security.locked_at
    records = [record for record in gateway.audit.records() if record["event"] == "locked"]
    assert len(records) == 1
    assert records[0]["principal_token"] == action.principal
    assert records[0]["ts"] == gateway.store.snapshot().security.locked_at[action.principal]
    gateway.lock(action.principal, "manual_safety_test")
    assert len([record for record in gateway.audit.records() if record["event"] == "locked"]) == 1
    assert gateway.audit.verify()
