"""Red-team probes: daily cumulative, tiers, MFA grants, SPA runs (kernel level)."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import MFA
from corridor.kernel import check
from corridor.schemas.bank import BusinessEvent
from corridor.schemas.domain import ScheduledTask
from corridor.schemas.models import Accept, Escalate
from corridor.stores.bank import add_seconds
from tests.bank_cases import recertify, signed, spa_case, transfer_case, with_mfa


def _event(
    eid, *, amount, ts, kind="transfer", event="settled", account="A_CURRENT", commitment_id=None
):
    return BusinessEvent.model_validate({
        "id": eid,
        "intent_key": H({"rt": eid}),
        "event": event,
        "kind": kind,
        "principal": "C_DEMO",
        "commitment_id": commitment_id,
        "debit": {"account_ref": account, "amount": f"{amount}/1"},
        "ts": ts,
    })


def _with_ledger(case, *events, now=None):
    action, cert, state = case
    update = {"ledger": [*state.ledger, *events]}
    if now is not None:
        update["now"] = now
    state = state.model_copy(update=update)
    return recertify(action, cert, state)


def _second_current(state):
    acct = state.accounts["A_CURRENT"].model_copy(update={"id": "A_CURRENT2"})
    return state.model_copy(update={"accounts": {**state.accounts, "A_CURRENT2": acct}})


# -- daily cumulative --------------------------------------------------------------


@pytest.mark.parametrize("status", ["reserved", "unknown", "settled"])
def test_split_transfer_with_open_status_counts(status):
    case = transfer_case(Fraction(600))
    prior = _event("P", amount=600, ts=case[2].now, event=status)
    result = check(*_with_ledger(case, prior), phase="propose")
    assert isinstance(result, Escalate), result


def test_failed_prior_does_not_count():
    case = transfer_case(Fraction(600))
    prior = _event("P", amount=600, ts=case[2].now, event="failed")
    assert isinstance(check(*_with_ledger(case, prior), phase="propose"), Accept)


def test_other_source_account_of_same_principal_counts():
    action, cert, state = transfer_case(Fraction(600))
    state = _second_current(state)
    prior = _event("P", amount=600, ts=state.now, account="A_CURRENT2")
    result = check(*_with_ledger((action, cert, state), prior), phase="propose")
    assert isinstance(result, Escalate), result


def test_merchant_order_counts_toward_transfer_limit():
    case = transfer_case(Fraction(600))
    prior = _event("P", amount=600, ts=case[2].now, kind="merchant_order")
    assert isinstance(check(*_with_ledger(case, prior), phase="propose"), Escalate)


def test_china_day_not_utc_day_same_local_day_counts():
    # now = 2026-10-16T02:00Z (local 10:00). Prior at 2026-10-15T17:00Z = local 01:00 same day.
    case = transfer_case(Fraction(600))
    prior = _event("P", amount=600, ts="2026-10-15T17:00:00Z")
    assert isinstance(check(*_with_ledger(case, prior), phase="propose"), Escalate)


def test_china_day_previous_local_day_not_counted():
    case = transfer_case(Fraction(600))
    prior = _event("P", amount=600, ts="2026-10-15T15:59:59Z")
    assert isinstance(check(*_with_ledger(case, prior), phase="propose"), Accept)


def test_pending_spa_commitment_due_later_today_counts():
    _, _, scheduled = spa_case(Fraction(500), execution=True)
    # Move "now" back to earlier on the same China day before the run is due.
    run = next(iter(scheduled.schedules.values()))
    earlier = add_seconds(run.due_at, -3600)
    scheduled = scheduled.model_copy(update={"now": earlier})
    run = run.model_copy(update={"status": "pending"})
    scheduled = scheduled.model_copy(update={"schedules": {run.id: run}})
    action, cert, state = transfer_case(Fraction(600), state=scheduled, intent_id="OTHER")
    assert isinstance(check(action, cert, state, phase="propose"), Escalate)


# -- MFA grant validity -----------------------------------------------------------


def _replace_grant(case, **changes):
    action, cert, state = case
    grant = state.security.mfa_grants[cert.mfa_grant_refs[0]]
    label = changes.pop("_label", "mfa")
    grant = signed(grant.model_copy(update=changes), MFA, label)
    state = state.model_copy(
        update={
            "security": state.security.model_copy(update={"mfa_grants": {grant.grant_id: grant}})
        }
    )
    return action, cert, state


@pytest.mark.parametrize(
    "changes",
    [
        {"_label": "device"},
        {"_label": "gateway"},
        {"principal": "OTHER"},
        {"device_session_id": "OTHER_SESSION"},
        {"expiry": "2026-10-16T02:00:00Z", "issued_at": "2026-10-16T01:58:00Z"},
        {"issued_at": "2026-10-16T02:00:01Z", "expiry": "2026-10-16T02:02:00Z"},
        {"expiry": "2026-10-16T02:30:00Z"},
    ],
)
def test_bad_grants_do_not_override_red(changes):
    case = with_mfa(*transfer_case(Fraction(1500)))
    result = check(*_replace_grant(case, **changes), phase="dispatch")
    assert result.outcome == "Reject" and "MFA-INVALID" in result.rule_ids, result


def test_grant_for_other_amount_not_reusable():
    a1, c1, s1 = with_mfa(*transfer_case(Fraction(1500)))
    a2, c2, s2 = transfer_case(Fraction(1600))
    s2 = s2.model_copy(update={"security": s1.security})
    c2 = c2.model_copy(update={"mfa_grant_refs": c1.mfa_grant_refs})
    result = check(*recertify(a2, c2, s2), phase="dispatch")
    assert result.outcome != "Accept"


def test_new_payee_red_even_tiny():
    result = check(*transfer_case(Fraction(1), contact_ref="CONTACT_NEW"), phase="propose")
    assert isinstance(result, Escalate)


# -- SPA run-time tier ------------------------------------------------------------


def test_yellow_spa_run_after_unknown_prior_needs_mfa():
    action, cert, state = spa_case(Fraction(500), execution=True)
    prior = _event("P", amount=600, ts=state.now, event="unknown")
    result = check(*_with_ledger((action, cert, state), prior), phase="dispatch")
    assert isinstance(result, Escalate) and result.rule_ids == ["DOMAIN-SPA-TIER"]


def test_yellow_spa_run_with_pending_other_spa_same_day_needs_mfa():
    action, cert, state = spa_case(Fraction(600), execution=True)
    other = ScheduledTask(
        id="OTHER_RUN",
        owner="C_DEMO",
        plan_id="P2",
        node_id="N2",
        spa_ref="SPA_TEST",
        run_index=5,
        action_template={},
        input_refs=[],
        due_at=state.now,
        expires_at=add_seconds(state.now, 3600),
        commitment_id=H("other"),
        status="pending",
    )
    state = state.model_copy(update={"schedules": {**state.schedules, other.id: other}})
    result = check(*recertify(action, cert, state), phase="dispatch")
    assert result.outcome != "Accept"
