"""Approval lifecycle counting and zero-dispatch allocation preflight."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import CATALOG
from corridor.schemas.state import ApprovalRequest
from corridor.sim.wealth import make_wealth_state
from corridor.stores.bank import add_seconds
from tests.bank_cases import signed
from tests.gateway_cases import gateway_case
from tests.wealth_execution_cases import wealth_execution_case


def test_propose_and_mfa_count_one_unchanged_card():
    gateway, _, action, cert = gateway_case(Fraction(1500))
    proposal = gateway.propose(action, cert, request_id=action.intent_id)
    assert proposal.verdict.outcome == "Escalate"
    assert gateway.request_mfa(action, cert, request_id="DEVICE_PENDING") is not None
    assert len(gateway.store.snapshot().security.approval_requests[action.principal]) == 1


def test_changing_mfa_transport_id_cannot_reset_exhausted_attempts():
    gateway, _, action, cert = gateway_case(Fraction(1500))
    gateway.propose(action, cert, request_id="APPROVAL")
    first = gateway.request_mfa(action, cert, request_id="MFA_0")
    for _ in range(3):
        assert gateway.mfa.verify(first, "wrong", now=gateway.store.snapshot().now) is None
    for index in range(8):
        retry = gateway.request_mfa(action, cert, request_id=f"RETRY_{index}")
        assert retry == first
        assert (
            gateway.mfa.verify(
                retry, gateway.mfa.test_code(retry), now=gateway.store.snapshot().now
            )
            is None
        )
    gateway.propose(action, cert, request_id="NEW_EXPLICIT_APPROVAL")
    assert gateway.request_mfa(action, cert, request_id="MFA_NEW") != first
    assert len(gateway.store.snapshot().security.approval_requests[action.principal]) == 2


def test_restart_does_not_recreate_a_private_mfa_attempt_counter(tmp_path):
    case = wealth_execution_case(path=tmp_path)
    assert case.start()[0].status == "ready"
    prepared = case.prepare()
    first = case.gateway.request_mfa(prepared.action, prepared.cert, request_id="BEFORE")
    for _ in range(3):
        assert case.gateway.mfa.verify(first, "wrong", now=case.state.now) is None
    case.reopen()
    case.gateway.propose(
        prepared.action,
        prepared.cert,
        request_id=H({"action": prepared.action, "cert": prepared.cert}),
    )
    assert case.gateway.request_mfa(prepared.action, prepared.cert, request_id="AFTER") is None
    case.gateway.propose(prepared.action, prepared.cert, request_id="NEW_COUNTED_APPROVAL")
    fresh = case.gateway.request_mfa(prepared.action, prepared.cert, request_id="AFTER_FRESH")
    assert fresh is not None and fresh != first
    assert len(case.state.security.approval_requests["C_DEMO"]) == 2


@pytest.mark.parametrize("legs", [2, 4])
def test_two_and_four_leg_plans_complete_without_clock_advance(legs):
    state = make_wealth_state()
    if legs == 4:
        catalog = state.catalog.model_copy(
            update={
                "products": [
                    p.model_copy(update={"max_amount": Fraction(2500)})
                    if p.id in {"P_A", "P_B", "P_C", "P_D"}
                    else p
                    for p in state.catalog.products
                ]
            }
        )
        state = state.model_copy(update={"catalog": signed(catalog, CATALOG, "bank")})
    case = wealth_execution_case(state=state)
    assert len(case.draft.parent.items) == legs
    assert case.start()[0].status == "ready"
    now = case.state.now
    grants, tokens = set(), set()
    for index in range(legs):
        prepared = case.prepare()
        challenge = case.gateway.request_mfa(
            prepared.action, prepared.cert, request_id=f"DEVICE_PENDING_{index}"
        )
        assert challenge is not None
        grant = case.device.complete_mfa(case.gateway.mfa, challenge, now=case.state.now)
        assert case.gateway.submit_mfa(grant).status == "accepted"
        cert = prepared.cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
        token = case.device.approve(
            prepared.action, cert, prepared.card, now=case.state.now, sequence=index
        )
        result = case.gateway.dispatch(prepared.action, cert, token)
        assert result.status == "settled", result
        grants.add(grant.grant_id)
        tokens.add(token.token_id)
    assert case.state.now == now
    assert case.gateway.bank.execute_count == legs
    assert case.snapshot()["status"] == "completed"
    assert not case.state.security.locked_at
    assert len(grants) == len(tokens) == legs
    assert len(case.state.security.approval_requests["C_DEMO"]) == legs


@pytest.mark.rule("APR-BUDGET")
def test_preflight_rejects_insufficient_budget_before_any_bank_call():
    case = wealth_execution_case()
    assert case.start()[0].status == "ready"
    state = case.state
    case.gateway.store.update(
        security=state.security.model_copy(
            update={
                "approval_requests": {
                    "C_DEMO": [
                        ApprovalRequest(request_id=f"PRIOR_{i}", ts=state.now) for i in range(4)
                    ]
                }
            }
        )
    )
    result = case.gateway.advance_allocation(case.parent_id)
    assert result.status == "rejected"
    assert result.rule_ids == ["APR-BUDGET"]
    assert result.details["approval_budget"]["required"] == 2
    assert result.details["approval_budget"]["remaining"] == 1
    assert "Needs 2 approvals" in result.details["message"]
    assert case.gateway.bank.execute_count == 0
    assert len(case.state.security.approval_requests["C_DEMO"]) == 4


def test_approval_window_uses_half_open_cutoff_and_does_not_unlock():
    gateway, _, action, _ = gateway_case()
    state = gateway.store.snapshot()
    gateway.store.update(
        security=state.security.model_copy(
            update={
                "approval_requests": {
                    action.principal: [
                        ApprovalRequest(request_id="OLD", ts=add_seconds(state.now, -600))
                    ]
                }
            }
        )
    )
    assert gateway.approval_budget(action.principal)["remaining"] == 5
    gateway.lock(action.principal, "approval_rate")
    assert gateway.approval_budget(action.principal)["remaining"] == 0


@pytest.mark.rule("APR-LOCK")
def test_budget_refusal_does_not_bypass_red_injection_lock():
    case = wealth_execution_case()
    assert case.start()[0].status == "ready"
    prepared = case.prepare()
    state = case.state
    case.gateway.store.update(
        security=state.security.model_copy(
            update={
                "approval_requests": {
                    "C_DEMO": [
                        ApprovalRequest(request_id=f"PRIOR_{i}", ts=state.now) for i in range(4)
                    ]
                }
            }
        )
    )
    result = case.gateway.propose(prepared.action, prepared.cert, injection_flag=True)
    assert result.verdict.rule_ids == ["APR-LOCK"]
    assert case.state.security.lock_reason["C_DEMO"] == "red_injection"
    assert case.gateway.advance_allocation(case.parent_id).rule_ids == ["APR-LOCK"]
    assert case.gateway.bank.execute_count == 0


def test_stepper_reports_current_mfa_state():
    case = wealth_execution_case()
    assert case.start()[0].status == "ready"
    result = case.gateway.advance_allocation(case.parent_id)
    assert result.status == "waiting_mfa"
    assert result.details["leg"]["status"] == "waiting_mfa"
    assert result.details["leg"]["leg_index"] == 1
    assert result.details["leg"]["leg_count"] == 2


def test_preflight_exact_fit_credits_already_presented_current_card():
    case = wealth_execution_case()
    assert case.start()[0].status == "ready"
    state = case.state
    case.gateway.store.update(
        security=state.security.model_copy(
            update={
                "approval_requests": {
                    "C_DEMO": [
                        ApprovalRequest(request_id=f"PRIOR_{i}", ts=state.now) for i in range(3)
                    ]
                }
            }
        )
    )
    for index in range(2):
        assert case.execute_next(sequence=index)[0].status == "settled"
    assert case.gateway.bank.execute_count == 2
    assert not case.state.security.locked_at


def test_same_card_dedup_survives_restart_and_legacy_records_stay_conservative(tmp_path):
    case = wealth_execution_case(path=tmp_path)
    assert case.start()[0].status == "ready"
    prepared = case.prepare()
    case.reopen()
    case.gateway.propose(
        prepared.action,
        prepared.cert,
        request_id=H({
            "action": prepared.action,
            "cert": prepared.cert,
        }),
    )
    assert case.gateway.request_mfa(prepared.action, prepared.cert, request_id="NEW_UI")
    assert len(case.state.security.approval_requests["C_DEMO"]) == 1
    legacy = ApprovalRequest(request_id="LEGACY", ts=case.state.now)
    assert "card_hash" not in legacy.model_dump(mode="json")
    case.gateway.store.update(
        security=case.state.security.model_copy(update={"approval_requests": {"C_DEMO": [legacy]}})
    )
    assert case.gateway.request_mfa(prepared.action, prepared.cert, request_id="NEW_UI_2")
    assert len(case.state.security.approval_requests["C_DEMO"]) == 2
