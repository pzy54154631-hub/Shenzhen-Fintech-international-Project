"""Business bindings remain stable across authentication bookkeeping and seconds."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL
from corridor.kernel.binding import binding, dependency_hashes, intent_key, mfa_scope
from corridor.schemas.bank import BankAction, BankCertificate, BusinessEvent
from corridor.sim.device import Device
from corridor.sim.fixtures import make_state
from corridor.stores.bank import execution_times
from tests.bank_cases import query_case, signed


def sample():
    state = make_state()
    value = Device().confirm_input(
        intent_id="I", slot="amount", value={"amount": "200/1", "ccy": "CNY"}, now=state.now
    )
    state = state.model_copy(update={"user_inputs": {value.id: value}})
    action = BankAction(
        action_id="ACTION",
        intent_id="I",
        principal="C_DEMO",
        device_session_id="SESSION",
        plan_id="PLAN",
        plan_hash=H({"plan": 1}),
        node_id="NODE",
        kind="transfer",
        args={"source_ref": "A_CURRENT", "contact_ref": "CONTACT_CHEN", "amount_ref": value.id},
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref="AUTH",
        derivations={
            "args.source_ref": {
                "t": "state",
                "collection": "accounts",
                "object_ref": "A_CURRENT",
                "field": "id",
                "version": 1,
            },
            "args.contact_ref": {
                "t": "state",
                "collection": "contacts",
                "object_ref": "CONTACT_CHEN",
                "field": "id",
                "version": 1,
            },
            "args.amount_ref": {"t": "input", "input_ref": value.id, "slot": "amount"},
        },
        dependency_hashes={},
    )
    return action, cert, state


def test_seconds_and_authentication_bookkeeping_do_not_change_card():
    action, cert, state = sample()
    changed = state.model_copy(
        update={
            "now": "2026-10-16T02:01:00Z",
            "security": state.security.model_copy(update={"consumed_nonces": ["a" * 32]}),
        }
    )
    assert binding(action, cert, state).card_core == binding(action, cert, changed).card_core
    assert dependency_hashes(action, cert, state) == dependency_hashes(action, cert, changed)


def test_business_date_balance_and_contact_version_change_card():
    action, cert, state = sample()
    original = H(binding(action, cert, state).card_core)
    midnight = state.model_copy(update={"now": "2026-10-16T16:00:00Z"})
    account = state.accounts["A_CURRENT"].model_copy(update={"opening_balance": Fraction(9000)})
    balance = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
    contact = state.contacts["CONTACT_CHEN"].model_copy(update={"version": 2})
    destination = state.model_copy(update={"contacts": {**state.contacts, contact.id: contact}})
    for changed in (midnight, balance, destination):
        assert H(binding(action, cert, changed).card_core) != original


def test_query_receipt_event_does_not_invalidate_financial_approval():
    action, cert, state = sample()
    query = BusinessEvent(
        id="Q",
        intent_key=H({"query": 1}),
        event="settled",
        kind="balance_query",
        principal="C_DEMO",
        ts=state.now,
    )
    changed = state.model_copy(update={"ledger": [query]})
    assert binding(action, cert, state).card_core == binding(action, cert, changed).card_core


def test_mfa_scope_binds_business_card_and_node():
    action, cert, state = sample()
    card_hash = H(binding(action, cert, state).card_core)
    scope = mfa_scope(action, card_hash)
    assert scope != mfa_scope(action, H({"swapped_card": True}))
    assert scope != mfa_scope(action.model_copy(update={"node_id": "OTHER"}), card_hash)
    assert scope != mfa_scope(action, card_hash, ownership_epoch=1)


def test_recovery_reservation_preserves_dispatch_day_but_failed_retry_starts_new_attempt():
    state = make_state()
    first = BusinessEvent(
        id="START",
        intent_key=H("intent"),
        event="reserved",
        kind="transfer",
        principal="C_DEMO",
        ts="2026-10-16T15:59:59Z",
    )
    unknown = first.model_copy(update={"id": "UNKNOWN", "event": "unknown"})
    recovery = first.model_copy(update={"id": "RECOVERY", "ts": "2026-10-16T16:00:01Z"})
    assert execution_times(state.model_copy(update={"ledger": [first, unknown, recovery]})) == {
        first.intent_key: first.ts,
    }
    failed = unknown.model_copy(update={"event": "failed"})
    assert execution_times(state.model_copy(update={"ledger": [first, failed, recovery]})) == {
        first.intent_key: recovery.ts,
    }


def test_reusable_session_queries_keep_distinct_node_keys():
    action, _, state = query_case()
    next_node = action.model_copy(update={"node_id": "SECOND_QUERY"})
    assert intent_key(action, state) != intent_key(next_node, state)
    assert intent_key(action, state) == H({
        "principal": action.principal,
        "intent_id": action.intent_id,
        "kind": action.kind,
        "node_id": action.node_id,
    })


@pytest.mark.parametrize(
    "kind", ["balance_query", "risk_assess", "purchase_product", "apply_virtual_card", "transfer"]
)
def test_operation_authority_never_uses_the_session_query_key_exception(kind):
    action, _, state = query_case()
    operation = state.authorizations["AUTH_INTENT_TEST"]
    operation = signed(operation.model_copy(update={"allowed_kind": kind}), CONTROL)
    state = state.model_copy(
        update={
            "authorizations": {
                **state.authorizations,
                operation.id: operation,
            }
        }
    )
    # The key is independent of the args discriminator, which check validates.
    action = action.model_copy(update={"kind": kind})
    next_node = action.model_copy(update={"node_id": "SECOND_NODE"})
    expected = H({"principal": action.principal, "intent_id": action.intent_id, "kind": kind})
    assert intent_key(action, state) == intent_key(next_node, state) == expected


def test_risk_assessment_state_change_is_not_a_reusable_read_key():
    action, _, state = query_case()
    session = state.authorizations["SESSION_AUTH"]
    session = signed(session.model_copy(update={"read_kinds": ["risk_assess"]}), CONTROL)
    state = state.model_copy(update={"authorizations": {session.id: session}})
    action = action.model_copy(update={"kind": "risk_assess"})
    assert intent_key(action, state) == intent_key(
        action.model_copy(update={"node_id": "SECOND_ASSESSMENT"}), state
    )
