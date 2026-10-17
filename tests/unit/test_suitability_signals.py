"""Untrusted dialogue hints may add friction, but cannot submit answers or upgrade risk."""

from corridor.crypto.jcs import H
from tests.gateway_cases import gateway_case


def test_coaching_refusal_submits_no_answers_or_authorizations():
    gateway, _, action, _ = gateway_case()
    before = gateway.store.snapshot()
    result = gateway.suitability_signal(action.principal, "coaching_request")
    assert result.status == "refused"
    after = gateway.store.snapshot()
    assert after.user_inputs == before.user_inputs
    assert after.authorizations == before.authorizations
    assert after.risk_assessments == before.risk_assessments
    assert gateway.bank.execute_count == 0
    assert gateway.audit.records()[-1]["event"] == "suitability_coaching_refused"
    assert result.rule_ids == []


def test_untrusted_loss_cue_adds_only_persistent_friction():
    gateway, _, action, _ = gateway_case()
    before = gateway.store.snapshot()
    result = gateway.suitability_signal(action.principal, "cannot_accept_loss")
    assert result.status == "clarification_required"
    assert result.details["effective_level_cap"] == 1
    after = gateway.store.snapshot()
    assert after.risk_assessments == before.risk_assessments
    assert after.user_inputs == before.user_inputs
    event = after.ledger[-1]
    assert event.object_delta["suitability_signal"] == "cannot_accept_loss"
    assert event.object_delta["effective_level_cap"] == 1
    assert event.debit is None and event.credit is None
    assert gateway.bank.execute_count == 0
    assert gateway.verify_log()


def test_dialogue_signal_cannot_clear_or_raise_the_risk_cap():
    gateway, _, action, _ = gateway_case()
    gateway.suitability_signal(action.principal, "cannot_accept_loss")
    before = H(gateway.store.snapshot())
    assert gateway.suitability_signal(action.principal, "set_C4").status == "rejected"
    assert gateway.suitability_signal(action.principal, "clear").status == "rejected"
    assert H(gateway.store.snapshot()) == before
