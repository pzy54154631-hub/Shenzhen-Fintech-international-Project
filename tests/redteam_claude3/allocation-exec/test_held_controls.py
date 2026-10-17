"""Ideas probed by RT3 allocation-exec that held (kept as passing regressions)."""

import importlib

import pytest

from corridor.crypto.jcs import H
from corridor.gateway.allocations import advance_allocation
from corridor.schemas.bank import BankAction, BankCertificate
from corridor.sim.wealth import allocation_request
from tests.wealth_execution_cases import wealth_execution_case

tenant = importlib.import_module("tests.redteam_claude3.allocation-exec._tenant")


def _explicit(case, rows):
    request = allocation_request(
        selection_mode="explicit_items",
        items=[{"product_id": product, "principal": amount} for product, amount in rows],
        model_biac_hash=H(case.comparison_cert.allocation),
        reason_code="product_preference",
    )
    case.replace_request(request)


@pytest.mark.parametrize(
    "rows",
    [
        [("P_A", "3000/1"), ("P_B", "2000/1"), ("P_C", "5000/1")],
        [("P_A", "2500/1"), ("P_B", "2500/1"), ("P_C", "2500/1"), ("P_D", "2500/1")],
    ],
)
def test_three_and_four_leg_allocations_do_not_trip_approval_rate_lock(rows):
    case = wealth_execution_case()
    _explicit(case, rows)
    result, _ = case.start()
    assert result.status == "ready"
    principal = case.draft.parent.principal
    for sequence in range(len(rows)):
        outcome, _ = case.execute_next(sequence=sequence)
        assert outcome.status == "settled", outcome
    assert principal not in case.state.security.locked_at
    assert len(case.state.security.approval_requests[principal]) == len(rows)
    assert case.snapshot()["status"] == "completed"


def test_repeated_advance_of_same_leg_counts_one_approval_request():
    case = wealth_execution_case()
    case.start()
    principal = case.draft.parent.principal
    for _ in range(7):
        assert advance_allocation(case.gateway, case.parent_id).status == "waiting_mfa"
    assert len(case.state.security.approval_requests[principal]) == 1
    assert principal not in case.state.security.locked_at


def test_small_leg_is_still_red_with_its_own_mfa():
    case = wealth_execution_case()
    _explicit(case, [("P_A", "100/1"), ("P_B", "4900/1"), ("P_C", "5000/1")])
    case.start()
    prepared = advance_allocation(case.gateway, case.parent_id)
    assert prepared.status == "waiting_mfa"
    assert prepared.details["card"]["tier"] == "red"


def test_same_parent_intent_string_across_customers_stays_isolated():
    case = wealth_execution_case(state=tenant.two_tenant_state())
    other = tenant.OtherTenant(case.gateway, intents=(case.comparison_action.intent_id,))
    case.start()
    case.execute_next()
    case.execute_next(sequence=1)
    assert case.snapshot()["status"] == "completed"
    draft = other.register(case.comparison_action.intent_id)
    gateway = case.gateway
    for sequence in range(len(draft.parent.items)):
        prepared = advance_allocation(gateway, draft.parent.id)
        assert prepared.status == "waiting_mfa", prepared
        action = BankAction.model_validate(prepared.details["action"])
        cert = BankCertificate.model_validate(prepared.details["cert"])
        request_id = H({"action": action, "cert": cert})
        challenge = gateway.request_mfa(action, cert, request_id=request_id)
        grant = other.device.complete_mfa(gateway.mfa, challenge, now=case.state.now)
        assert gateway.submit_mfa(grant).status == "accepted"
        cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
        proposal = gateway.propose(action, cert, request_id=request_id)
        token = other.device.approve(
            action, cert, proposal.card, now=case.state.now, sequence=10 + sequence
        )
        assert gateway.dispatch(action, cert, token).status == "settled"
    assert case.snapshot()["status"] == "completed"
    assert gateway.bank.execute_count == 4
