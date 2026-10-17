"""Signed SPA scope and execution-instance checks with explicit synthetic evidence."""

from fractions import Fraction
from pathlib import Path

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, SPA, sign
from corridor.kernel.spa import inspect_spa
from corridor.schemas.bank import (
    AuthorizationRevocation,
    BankAction,
    BankCertificate,
    BusinessEvent,
    ScheduledPaymentAuthorization,
)
from corridor.schemas.domain import ScheduledTask
from corridor.schemas.state import BankState
from corridor.sim.keys import signing_key

START = "2026-10-17T02:00:00Z"
END = "2027-01-17T02:00:00Z"


def signed_spa(spa):
    return spa.model_copy(update={"sig": sign(signing_key("device"), SPA, spa)})


@pytest.fixture
def creation():
    state = BankState.model_validate_json(Path("data/bank/state.json").read_bytes())
    spa = signed_spa(
        ScheduledPaymentAuthorization(
            id="SPA_TEST",
            principal="C_DEMO",
            source_ref="A_CURRENT",
            target={"kind": "transfer", "contact_ref": "CONTACT_CHEN"},
            destination_version=1,
            amount=Fraction(200),
            schedule={"type": "once"},
            start=START,
            end=END,
            max_runs=1,
            creation_tier="yellow",
            plan_id="PLAN_TEST",
            node_id="NODE_TEST",
            sig="0" * 128,
        )
    )
    state = state.model_copy(update={"authorizations": {spa.id: spa}})
    action = BankAction(
        action_id="CREATE_TEST",
        intent_id=spa.id,
        principal="C_DEMO",
        device_session_id="SESSION_TEST",
        plan_id=spa.plan_id,
        plan_hash=H({"plan": 1}),
        node_id=spa.node_id,
        kind="schedule_transfer",
        args={
            "source_ref": spa.source_ref,
            "contact_ref": "CONTACT_CHEN",
            "amount_ref": "INPUT_AMOUNT",
            "schedule_ref": spa.id,
        },
    )
    cert = BankCertificate(
        action_hash=H(action), authorization_ref=spa.id, derivations={}, dependency_hashes={}
    )
    return action, cert, state, spa


def execution(creation, *, red=False, target="transfer"):
    action, cert, state, spa = creation
    if target == "merchant_order":
        body = spa.model_dump(mode="python")
        body["target"] = {
            "kind": "merchant_order",
            "merchant_ref": "FLOWERS",
            "offer_ref": "OFFER_FLOWERS",
        }
        body["amount"] = Fraction(300)
        spa = ScheduledPaymentAuthorization.model_validate(body)
        args = {"source_ref": "A_CURRENT", "merchant_ref": "FLOWERS", "offer_ref": "OFFER_FLOWERS"}
    elif target == "unlock_funds":
        body = spa.model_dump(mode="python")
        body["target"] = {"kind": "unlock_funds", "locked_ref": "A_LOCKED"}
        spa = ScheduledPaymentAuthorization.model_validate(body)
        args = {
            "source_ref": "A_CURRENT",
            "locked_ref": "A_LOCKED",
            "amount_ref": "INPUT_AMOUNT",
            "purpose_ref": "PURPOSE",
        }
    else:
        args = {
            "source_ref": "A_CURRENT",
            "contact_ref": "CONTACT_CHEN",
            "amount_ref": "INPUT_AMOUNT",
        }
    if red:
        body = spa.model_dump(mode="python")
        body.update({"amount": Fraction(3000), "creation_tier": "red"})
        spa = ScheduledPaymentAuthorization.model_validate(body)
    spa = signed_spa(spa)
    commitment = H({"spa_id": spa.id, "run_index": 0})
    task = ScheduledTask(
        id="RUN_TEST",
        owner="C_DEMO",
        plan_id=spa.plan_id,
        node_id=spa.node_id,
        spa_ref=spa.id,
        run_index=0,
        action_template={},
        input_refs=["INPUT_AMOUNT"],
        due_at=START,
        expires_at="2026-10-18T02:00:00Z",
        commitment_id=commitment,
        status="due",
    )
    event = BusinessEvent(
        id="SPA_CREATED",
        intent_key=H({
            "principal": "C_DEMO",
            "intent_id": spa.id,
            "node_id": spa.node_id,
            "kind": "schedule_transfer",
        }),
        event="settled",
        kind="schedule_transfer",
        principal="C_DEMO",
        ts=state.now,
        object_delta={
            "spa_hash": H(spa),
            "source_version": state.accounts[spa.source_ref].version,
            "destination_version": spa.destination_version,
            "creation_tier": spa.creation_tier,
            "approval_verified": True,
            "approval_hash": H({"approval": 1}),
            "mfa_verified": red,
            "mfa_hash": H({"mfa": 1}) if red else None,
        },
    )
    state = state.model_copy(
        update={
            "now": START,
            "authorizations": {spa.id: spa},
            "schedules": {task.id: task},
            "ledger": [event],
        }
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "action_id": task.id,
        "kind": target,
        "args": args,
    })
    cert = cert.model_copy(update={"action_hash": H(action)})
    return action, cert, state, spa


def replace_spa(case, **changes):
    action, cert, state, spa = case
    spa = signed_spa(
        ScheduledPaymentAuthorization.model_validate({**spa.model_dump(mode="python"), **changes})
    )
    return action, cert, state.model_copy(update={"authorizations": {spa.id: spa}}), spa


def result(case, amount=None):
    action, cert, state, spa = case
    return inspect_spa(action, cert, state, spa.amount if amount is None else amount)


def test_unrelated_authority_is_not_a_spa(creation):
    action, cert, state, _ = creation
    found = inspect_spa(
        action, cert.model_copy(update={"authorization_ref": "missing"}), state, Fraction(200)
    )
    assert not found.is_spa and not found.is_creation and not found.grant_exempt
    assert found.errors == [] and found.commitment_id is None


@pytest.mark.rule("DOMAIN-SPA")
def test_verified_gateway_cancellation_blocks_even_a_new_run_record(creation):
    action, cert, state, spa = execution(creation)
    cancelled = BusinessEvent(
        id="CANCELLED",
        intent_key=H({"cancel": spa.id}),
        event="settled",
        kind="cancel_schedule",
        principal=spa.principal,
        object_delta={"spa_ref": spa.id},
        ts=state.now,
    )
    state = state.model_copy(update={"ledger": [*state.ledger, cancelled]})
    # A pending task cannot resurrect a cancelled signed business authorization.
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


def test_create_old_contact_once_is_yellow_without_prior_event(creation):
    found = result(creation)
    assert found.is_spa and found.is_creation
    assert found.creation_tier == "yellow" and found.errors == []
    assert not found.grant_exempt and found.commitment_id is None


@pytest.mark.parametrize(
    "changes",
    [
        {"amount": "1000", "creation_tier": "yellow"},
        {"amount": "1000.01", "creation_tier": "red"},
        {"schedule": {"type": "monthly", "day": 17}, "max_runs": 3, "creation_tier": "red"},
        {"target": {"kind": "transfer", "contact_ref": "CONTACT_NEW"}, "creation_tier": "red"},
    ],
)
def test_creation_tier_is_recomputed(creation, changes):
    case = replace_spa(creation, **changes)
    action, cert, state, spa = case
    if spa.target.contact_ref == "CONTACT_NEW":
        action = action.model_copy(
            update={"args": action.args.model_copy(update={"contact_ref": "CONTACT_NEW"})}
        )
    found = inspect_spa(action, cert, state, spa.amount)
    assert found.errors == [] and found.creation_tier == changes["creation_tier"]


def test_signed_spa_cannot_self_promote_to_red_exemption(creation):
    found = result(replace_spa(creation, creation_tier="red"))
    assert found.creation_tier == "yellow"
    assert "DOMAIN-SPA" in found.errors and not found.grant_exempt


@pytest.mark.parametrize("amount", [Fraction(199), Fraction(201)])
def test_exact_amount_cannot_be_changed(creation, amount):
    assert "DOMAIN-SPA" in result(creation, amount).errors


def test_missing_amount_is_rejected(creation):
    action, cert, state, _ = creation
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, None).errors


def test_invalid_signature_is_rejected(creation):
    action, cert, state, spa = creation
    state = state.model_copy(
        update={"authorizations": {spa.id: spa.model_copy(update={"sig": "0" * 128})}}
    )
    found = inspect_spa(action, cert, state, spa.amount)
    assert "DOMAIN-SPA" in found.errors and "AUTH-SIG" in found.errors


def test_yellow_execution_has_fixed_commitment_and_needs_no_creation_mfa(creation):
    case = execution(creation)
    found = result(case)
    assert found.errors == [] and not found.is_creation and not found.grant_exempt
    assert found.commitment_id == H({"spa_id": "SPA_TEST", "run_index": 0})


def test_red_execution_uses_creation_evidence_without_old_grant_or_session(creation):
    case = execution(creation, red=True)
    found = result(case)
    assert found.errors == [] and found.grant_exempt and found.creation_tier == "red"
    assert not case[1].mfa_grant_refs and not case[2].security.active_device_sessions


@pytest.mark.parametrize("target", ["merchant_order", "unlock_funds"])
def test_merchant_and_internal_unlock_execution_scope(creation, target):
    assert result(execution(creation, target=target)).errors == []


@pytest.mark.parametrize("mutation", ["missing", "hash", "approval", "mfa", "scope", "time"])
def test_creation_evidence_cannot_be_fabricated_or_borrowed(creation, mutation):
    action, cert, state, spa = execution(creation, red=True)
    event = state.ledger[0]
    if mutation == "missing":
        events = []
    else:
        delta = dict(event.object_delta)
        if mutation == "hash":
            delta["spa_hash"] = H({"different": True})
        if mutation == "approval":
            delta["approval_verified"] = False
        if mutation == "mfa":
            delta["mfa_verified"] = False
        event = event.model_copy(update={"object_delta": delta})
        if mutation == "scope":
            event = event.model_copy(update={"intent_key": H({"other": 1})})
        if mutation == "time":
            event = event.model_copy(update={"ts": "2026-10-18T02:00:00Z"})
        events = [event]
    found = inspect_spa(action, cert, state.model_copy(update={"ledger": events}), spa.amount)
    assert "DOMAIN-SPA" in found.errors and not found.grant_exempt


@pytest.mark.parametrize(
    "field,value",
    [
        ("owner", "OTHER"),
        ("spa_ref", "OTHER"),
        ("plan_id", "OTHER"),
        ("node_id", "OTHER"),
        ("run_index", 1),
        ("commitment_id", "OTHER"),
        ("status", "executed"),
        ("status", "skipped"),
        ("status", "cancelled"),
        ("status", "expired"),
        ("due_at", "2026-10-17T01:59:59Z"),
        ("expires_at", "2026-10-19T02:00:00Z"),
    ],
)
def test_instance_scope_and_deadline_are_recomputed(creation, field, value):
    action, cert, state, spa = execution(creation)
    task = state.schedules[action.action_id].model_copy(update={field: value})
    state = state.model_copy(update={"schedules": {action.action_id: task}})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


@pytest.mark.parametrize("event_state", ["reserved", "unknown", "settled", "failed"])
def test_any_prior_attempt_prevents_retry_of_the_same_spa_run(creation, event_state):
    action, cert, state, spa = execution(creation)
    commitment = H({"spa_id": spa.id, "run_index": 0})
    event = BusinessEvent(
        id="ATTEMPT",
        intent_key=commitment,
        event=event_state,
        kind="transfer",
        principal="C_DEMO",
        commitment_id=commitment,
        ts=START,
    )
    state = state.model_copy(update={"ledger": [*state.ledger, event]})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


def test_signed_revocation_blocks_future_execution(creation):
    action, cert, state, spa = execution(creation)
    revoked = AuthorizationRevocation(
        id="REVOKED", principal="C_DEMO", authorization_ref=spa.id, revoked_at=START, sig="0" * 128
    )
    revoked = revoked.model_copy(update={"sig": sign(signing_key("device"), CONTROL, revoked)})
    state = state.model_copy(update={"authorizations": {spa.id: spa, revoked.id: revoked}})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


@pytest.mark.parametrize("now", ["2026-10-17T01:59:59Z", "2026-10-18T02:00:00Z", END])
def test_execution_has_a_half_open_due_window(creation, now):
    action, cert, state, spa = execution(creation)
    state = state.model_copy(update={"now": now})
    found = inspect_spa(action, cert, state, spa.amount)
    assert "DOMAIN-SPA" in found.errors and "DOMAIN-SCHEDULE" in found.errors


def test_waiting_mfa_cannot_extend_its_original_twenty_four_hours(creation):
    action, cert, state, spa = execution(creation)
    task = state.schedules[action.action_id].model_copy(update={"status": "waiting_mfa"})
    state = state.model_copy(update={"schedules": {task.id: task}, "now": "2026-10-18T01:59:59Z"})
    assert inspect_spa(action, cert, state, spa.amount).errors == []
    state = state.model_copy(update={"now": "2026-10-18T02:00:00Z"})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


def test_monthly_day_is_china_local_and_missing_days_are_skipped(creation):
    case = replace_spa(
        creation,
        schedule={"type": "monthly", "day": 31},
        max_runs=3,
        creation_tier="red",
        start="2026-10-30T18:00:00Z",
    )
    action, cert, state, spa = case
    # Local October 31 02:00 is the first run; November has no 31st.
    action, cert, state, spa = execution(case, red=True)
    spa = signed_spa(spa.model_copy(update={"start": "2026-10-30T18:00:00Z"}))
    task = state.schedules[action.action_id].model_copy(
        update={
            "due_at": "2026-12-30T18:00:00Z",
            "expires_at": "2026-12-31T18:00:00Z",
            "run_index": 1,
            "commitment_id": H({"spa_id": spa.id, "run_index": 1}),
        }
    )
    delta = {**state.ledger[0].object_delta, "spa_hash": H(spa)}
    state = state.model_copy(
        update={
            "now": task.due_at,
            "authorizations": {spa.id: spa},
            "schedules": {task.id: task},
            "ledger": [state.ledger[0].model_copy(update={"object_delta": delta})],
        }
    )
    assert inspect_spa(action, cert, state, spa.amount).errors == []


@pytest.mark.parametrize("during_creation", [True, False])
def test_safety_lock_prevents_creation_and_execution(creation, during_creation):
    action, cert, state, spa = creation if during_creation else execution(creation)
    state = state.model_copy(
        update={
            "security": state.security.model_copy(
                update={"locked_at": {"C_DEMO": state.now}, "lock_reason": {"C_DEMO": "TEST_LOCK"}}
            )
        }
    )
    found = inspect_spa(action, cert, state, spa.amount)
    assert "DOMAIN-SPA" in found.errors and "APR-LOCK" in found.errors
    assert not found.grant_exempt


def test_creation_requires_at_least_one_date_within_its_window(creation):
    case = replace_spa(
        creation,
        schedule={"type": "monthly", "day": 5},
        max_runs=1,
        creation_tier="red",
        start="2026-10-17T02:00:00Z",
        end="2026-10-18T02:00:00Z",
    )
    assert "DOMAIN-SCHEDULE" in result(case).errors


@pytest.mark.parametrize(
    "field,value",
    [
        ("owner", "OTHER"),
        ("destination_version", 2),
        ("verified_at", None),
        ("verified_at", "2026-10-19T02:00:00Z"),
        ("verification_ref", None),
    ],
)
def test_transfer_target_rechecks_current_owner_version_and_verification(creation, field, value):
    action, cert, state, spa = execution(creation)
    contacts = dict(state.contacts)
    contacts["CONTACT_CHEN"] = contacts["CONTACT_CHEN"].model_copy(update={field: value})
    state = state.model_copy(update={"contacts": contacts})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


@pytest.mark.parametrize("field,value", [("owner", "OTHER"), ("status", "closed")])
def test_source_account_must_remain_active_and_owned(creation, field, value):
    action, cert, state, spa = execution(creation)
    accounts = dict(state.accounts)
    accounts["A_CURRENT"] = accounts["A_CURRENT"].model_copy(update={field: value})
    state = state.model_copy(update={"accounts": accounts})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


@pytest.mark.parametrize("target", ["merchant_order", "unlock_funds"])
def test_non_transfer_target_version_changes_are_not_reinterpreted(creation, target):
    action, cert, state, spa = execution(creation, target=target)
    if target == "merchant_order":
        merchants = dict(state.merchants)
        merchant = merchants["FLOWERS"]
        merchants["FLOWERS"] = merchant.model_copy(
            update={"offers": [merchant.offers[0].model_copy(update={"version": 2})]}
        )
        state = state.model_copy(update={"merchants": merchants})
    else:
        accounts = dict(state.accounts)
        accounts["A_LOCKED"] = accounts["A_LOCKED"].model_copy(update={"version": 2})
        state = state.model_copy(update={"accounts": accounts})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


@pytest.mark.parametrize("field", ["intent_id", "principal", "plan_id", "node_id", "action_id"])
def test_execution_action_cannot_move_to_another_scope(creation, field):
    action, cert, state, spa = execution(creation)
    action = action.model_copy(update={field: "DIFFERENT"})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


def test_duplicate_instances_cannot_share_a_run(creation):
    action, cert, state, spa = execution(creation)
    duplicate = state.schedules[action.action_id].model_copy(update={"id": "SECOND_INSTANCE"})
    state = state.model_copy(update={"schedules": {**state.schedules, duplicate.id: duplicate}})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


def test_execution_expiry_is_truncated_at_spa_end(creation):
    case = replace_spa(creation, end="2026-10-17T03:00:00Z")
    action, cert, state, spa = execution(case)
    task = state.schedules[action.action_id].model_copy(update={"expires_at": spa.end})
    state = state.model_copy(update={"schedules": {task.id: task}})
    assert inspect_spa(action, cert, state, spa.amount).errors == []
    state = state.model_copy(update={"now": spa.end})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors


def test_yellow_creation_event_explicitly_records_absence_of_mfa(creation):
    action, cert, state, spa = execution(creation)
    event = state.ledger[0]
    delta = dict(event.object_delta)
    del delta["mfa_hash"]
    state = state.model_copy(update={"ledger": [event.model_copy(update={"object_delta": delta})]})
    assert "DOMAIN-SPA" in inspect_spa(action, cert, state, spa.amount).errors
