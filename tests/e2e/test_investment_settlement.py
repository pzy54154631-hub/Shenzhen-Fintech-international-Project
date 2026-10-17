"""Delayed redemptions keep units frozen until the real bank confirms settlement."""

from fractions import Fraction

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.bench.investment_runner import _position_state, prepare_redemption
from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.audit import AuditLog
from corridor.gateway.facts import render_narrative
from corridor.gateway.privacy import PIIVault
from corridor.gateway.service import Gateway
from corridor.kernel.binding import intent_key
from corridor.schemas.narrative import FactRef, Narrative
from corridor.sim.keys import signing_key
from corridor.stores.bank import BankStore, add_seconds, available, latest_events


def _case():
    state = _position_state()
    position = state.positions["POS_A"].model_copy(update={"product_ref": "P_B"})
    state = state.model_copy(update={"positions": {position.id: position}, "subscriptions": {}})
    return BankCase(state, task_id="B7-SETTLEMENT", subcase_id="delayed")


def _approved(case, *, amount="200/1", step=0):
    prepared = prepare_redemption(case, amount, step=step)
    assert prepared.proposal.verdict.outcome == "Accept"
    assert prepared.proposal.verdict.tier == "yellow"
    token = case.device.approve(
        prepared.action, prepared.cert, prepared.proposal.card, now=case.state.now
    )
    return prepared, token


def _advance(gateway, now):
    receipts = gateway.bank.advance_clock(now)
    gateway.store.update(now=now)
    return receipts


def _reopen(case, path):
    state_path, audit_path = path / "state.jsonl", path / "audit.jsonl"
    if not audit_path.exists():
        audit_path.write_bytes(
            b"".join(jcs_bytes(row) + b"\n" for row in case.gateway.audit.records())
        )
    return Gateway(
        BankStore(case.state, path=state_path),
        case.gateway.bank,
        audit=AuditLog(audit_path),
        mfa=case.gateway.mfa,
        analysis_key=signing_key("gateway"),
        risk_key=signing_key("risk"),
    )


def test_delayed_redemption_requires_confirmation_and_only_credits_at_settlement():
    case = _case()
    prepared, token = _approved(case)
    key = intent_key(prepared.action, case.state)
    original = case.state.positions["POS_A"]
    assert case.gateway.dispatch(prepared.action, prepared.cert).rule_ids == ["APR-REQUIRED"]
    assert case.gateway.bank.execute_count == 0
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status == "pending" and result.receipt.status == "pending"
    assert result.receipt.settle_at == "2026-10-17T02:00:00Z"
    assert available(case.state, "A_CURRENT") == 9000
    assert case.state.positions["POS_A"].units == 1000
    assert case.state.positions["POS_A"].reserved_units == 200
    assert latest_events(case.state)[key].event == "reserved"
    assert case.gateway.dispatch(prepared.action, prepared.cert, token).rule_ids == ["APR-REUSE"]
    assert _advance(case.gateway, "2026-10-17T01:59:59Z") == []
    assert case.gateway.reconcile(key).status == "pending"
    assert available(case.state, "A_CURRENT") == 9000
    assert case.state.positions["POS_A"].reserved_units == 200
    assert len(_advance(case.gateway, "2026-10-17T02:00:00Z")) == 1
    assert available(case.state, "A_CURRENT") == 9000
    settled = case.gateway.reconcile(key)
    assert settled.status == "settled" and settled.receipt.status == "settled"
    assert available(case.state, "A_CURRENT") == 9200
    assert case.state.positions["POS_A"].units == 800
    assert case.state.positions["POS_A"].reserved_units == 0
    assert case.state.positions["POS_A"].acquired_at == original.acquired_at
    assert latest_events(case.state)[key].event == "settled"
    assert case.gateway.reconcile(key).rule_ids == ["IDEM-DUP"]
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.verify_log()


def test_pending_redemption_survives_journal_restart_without_reexecution(tmp_path):
    case = _case()
    case.gateway = _reopen(case, tmp_path)
    prepared, token = _approved(case)
    key = intent_key(prepared.action, case.state)
    assert case.gateway.dispatch(prepared.action, prepared.cert, token).status == "pending"
    case.gateway = _reopen(case, tmp_path)
    assert not case.state.security.unknown_intent_ids
    assert not case.state.security.locked_at
    assert case.state.positions["POS_A"].reserved_units == 200
    assert case.gateway.dispatch(prepared.action, prepared.cert, token).status == "rejected"
    assert case.gateway.reconcile(key).status == "pending"
    _advance(case.gateway, "2026-10-17T02:00:00Z")
    assert case.gateway.reconcile(key).status == "settled"
    assert available(case.state, "A_CURRENT") == 9200
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.verify_log()


def test_confirmed_failed_redemption_restores_units_without_credit():
    case = _case()
    prepared, token = _approved(case)
    key = intent_key(prepared.action, case.state)
    before = H(case.state.positions)
    case.gateway.bank.faults[key] = "failed"
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status == "failed" and result.receipt.exact_effects == []
    assert H(case.state.positions) == before
    assert available(case.state, "A_CURRENT") == 9000
    assert latest_events(case.state)[key].event == "failed"
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.verify_log()


@pytest.mark.parametrize("fault", ["response_loss", "bad_signature"])
def test_unknown_redemption_keeps_units_frozen_and_recovers_through_lookup(fault):
    case = _case()
    prepared, token = _approved(case)
    key = intent_key(prepared.action, case.state)
    case.gateway.bank.faults[key] = fault
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status == "unknown"
    assert case.state.positions["POS_A"].reserved_units == 200
    assert available(case.state, "A_CURRENT") == 9000
    assert key in case.state.security.unknown_intent_ids
    assert case.gateway.dispatch(prepared.action, prepared.cert, token).rule_ids == ["APR-LOCK"]
    assert case.gateway.reconcile(key).status == "pending"
    assert case.state.positions["POS_A"].reserved_units == 200
    assert key not in case.state.security.unknown_intent_ids
    _advance(case.gateway, "2026-10-17T02:00:00Z")
    assert case.gateway.reconcile(key).status == "settled"
    assert available(case.state, "A_CURRENT") == 9200
    assert case.state.positions["POS_A"].reserved_units == 0
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.verify_log()


def test_two_pending_redemptions_share_a_lot_and_each_settle_once():
    case = _case()
    first, first_token = _approved(case, amount="200/1")
    assert case.gateway.dispatch(first.action, first.cert, first_token).status == "pending"
    second, second_token = _approved(case, amount="300/1", step=1)
    assert case.gateway.dispatch(second.action, second.cert, second_token).status == "pending"
    assert case.state.positions["POS_A"].reserved_units == 500
    assert available(case.state, "A_CURRENT") == 9000
    receipts = _advance(case.gateway, add_seconds(case.state.now, 86400))
    assert len(receipts) == 2
    for receipt in receipts:
        assert case.gateway.reconcile(receipt.intent_key).status == "settled"
        assert case.gateway.reconcile(receipt.intent_key).rule_ids == ["IDEM-DUP"]
    assert case.state.positions["POS_A"].principal_amount == Fraction(500)
    assert case.state.positions["POS_A"].reserved_units == 0
    assert available(case.state, "A_CURRENT") == 9500
    assert case.gateway.bank.execute_count == 2
    assert case.gateway.verify_log()


@pytest.mark.parametrize("tampered", [False, True])
def test_settled_redemption_facts_render_only_verified_amount_and_balance(tampered):
    case = _case()
    prepared, token = _approved(case)
    key = intent_key(prepared.action, case.state)
    assert case.gateway.dispatch(prepared.action, prepared.cert, token).status == "pending"
    _advance(case.gateway, "2026-10-17T02:00:00Z")
    receipt = case.gateway.reconcile(key).receipt
    assert receipt is not None and receipt.status == "settled"
    expected = {
        "status": "settled",
        "amount": "201/1" if tampered else "200/1",
        "balance_after": "9200/1",
    }
    result = render_narrative(
        Narrative(
            fact_refs=[
                FactRef(receipt_ref=receipt.id, field=field, expected=value)
                for field, value in expected.items()
            ]
        ),
        case.state,
        case.device.principal,
        PIIVault(),
    )
    if tampered:
        assert result.status == "rejected" and result.rule_ids == ["RCPT-MISMATCH"]
        assert result.facts == []
    else:
        assert result.status == "rendered" and result.rule_ids == []
        assert {fact.field: fact.exact_value for fact in result.facts} == expected
        assert all(fact.receipt_ref == receipt.id for fact in result.facts)
        assert receipt.kind == "redeem_product"
