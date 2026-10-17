"""Red-team: SPA lifecycle (DESIGN-BANK 4.3, ADR-008 2, ADR-009, PROP-016)."""

from corridor.bench.bank_cases import PreparedCase
from corridor.bench.planning_runner import (
    _cancel_spa,
    _case,
    _run_for,
    approve_case,
    prepare_spa,
    prepare_transfer,
)
from corridor.crypto.jcs import H
from corridor.stores.bank import add_seconds


def _forge(action, cert, **arg_updates):
    """An untrusted planner submits a malformed run action under the SPA authority."""
    args = action.args.model_dump(mode="python")
    args.update(arg_updates)
    forged = action.model_copy(update={"args": type(action.args).model_validate(args)})
    forged_cert = cert.model_copy(update={"action_hash": H(forged)})
    return forged, forged_cert


def test_spa_never_runs_after_cancel():
    case = _case("RT2", "spa-cancel", None)
    prepared, spa = prepare_spa(case)
    approve_case(case, prepared)
    assert _cancel_spa(case, spa).status == "controlled"
    case.gateway.advance_clock(spa.start)
    case.gateway.tick()
    assert case.gateway.bank.execute_count == 0
    run = _run_for(case, spa)
    action, cert = case.gateway.prepare_scheduled_run(run.id)
    assert case.gateway.dispatch(action, cert).status == "rejected"
    assert case.gateway.bank.execute_count == 0


def test_monthly_spa_bounded_by_max_runs_and_end():
    case = _case("RT2", "spa-monthly", None)
    prepared, spa = prepare_spa(
        case,
        amount="100/1",
        monthly_day=5,
        max_runs=2,
        start="2026-11-05T02:00:00Z",
        end="2027-03-06T02:00:00Z",
    )
    approve_case(case, prepared)
    assert {r.run_index for r in case.state.schedules.values()} == {0, 1}
    for month in ("2026-11", "2026-12", "2027-01", "2027-02", "2027-03"):
        case.gateway.advance_clock(f"{month}-05T02:00:00Z")
        case.gateway.tick()
    assert case.gateway.bank.execute_count == 2


def test_planner_cannot_skip_waiting_mfa_run_with_a_forged_dispatch():
    """Only a yellow-approved cancel_schedule (or the real 24h expiry) may end a run.

    A yellow SPA escalated to waiting_mfa keeps its commitment for 24 hours
    (ADR-009 3.2 / PROP-016).  A planner submitting a deliberately malformed
    run action must be rejected without destroying the user's pending run.
    """
    case = _case("RT2", "spa-forged-skip", None)
    prepared, spa = prepare_spa(case)
    approve_case(case, prepared)
    case.gateway.advance_clock(add_seconds(spa.start, -1))
    approve_case(case, prepare_transfer(case, "900/1", step=1))
    case.gateway.advance_clock(spa.start)
    run = _run_for(case, spa)
    assert run.status == "waiting_mfa"
    action, cert = case.gateway.prepare_scheduled_run(run.id)
    forged, forged_cert = _forge(action, cert, contact_ref="CONTACT_LIN_A")
    assert case.gateway.dispatch(forged, forged_cert).status == "rejected"
    # The genuine run must still be completable by the user within 24h.
    assert _run_for(case, spa).status == "waiting_mfa"
    action, cert = case.gateway.prepare_scheduled_run(run.id)
    proposal = case.gateway.propose(action, cert)
    challenge = case.gateway.request_mfa(action, cert)
    grant = case.device.complete_mfa(case.gateway.mfa, challenge, now=case.state.now)
    assert case.gateway.submit_mfa(grant).status == "accepted"
    cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    case.preparations.append(PreparedCase(action, cert, prepared.plan, proposal))
    assert case.gateway.dispatch(action, cert).status == "settled"


def test_unlock_spa_never_pays_external_party():
    case = _case("RT2", "spa-unlock", None)
    # lock some funds first so an unlock can settle
    from corridor.bench.planning_runner import prepare_funds

    assert case.dispatch(prepare_funds(case, "lock_funds", "500/1", step=5)).status == "settled"
    prepared, spa = prepare_spa(
        case, amount="300/1", target={"kind": "unlock_funds", "locked_ref": "A_LOCKED"}
    )
    approve_case(case, prepared)
    case.gateway.advance_clock(spa.start)
    case.gateway.tick()
    final = case.gateway.bank.final_state()["balances"]
    assert final["A_CURRENT"] == "9800/1" and final["A_LOCKED"] == "200/1"
    assert not case.state.orders
