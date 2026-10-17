"""F3 allocation scope isolation and non-consuming MFA validation regressions."""

from fractions import Fraction

import pytest

from corridor.gateway.allocations import draft_allocation, register_allocation
from corridor.kernel.binding import dependency_hashes
from corridor.sim.wealth import allocation_request
from tests.gateway_cases import approve_red, gateway_case
from tests.wealth_execution_cases import wealth_execution_case


def test_allowed_types_have_one_canonical_order_without_relaxing_validation():
    forward = allocation_request(allowed_types=["deposit", "wealth"])
    reverse = allocation_request(allowed_types=["wealth", "deposit"])
    assert reverse.allowed_types == ["deposit", "wealth"]
    assert reverse.model_dump(mode="json") == forward.model_dump(mode="json")
    with pytest.raises(ValueError, match="unique"):
        allocation_request(allowed_types=["wealth", "wealth"])


def test_unrelated_parent_registration_preserves_same_principal_pending_purchase():
    case = wealth_execution_case()
    assert case.start()[0].status == "ready"
    assert case.execute_next()[0].status == "settled"
    approved = case.approve(sequence=1)
    before = dependency_hashes(approved.action, approved.cert, case.state)
    compare_before = dependency_hashes(case.comparison_action, case.comparison_cert, case.state)
    other_intent = "F3_UNRELATED_PARENT"
    value = case.device.confirm_input(
        intent_id=other_intent,
        slot="allocation",
        value=allocation_request(amount="1000/1").model_dump(mode="json"),
        now=case.state.now,
        step=1,
    )
    assert case.gateway.submit_input(value).status == "accepted"
    draft = draft_allocation(case.gateway, value.principal, other_intent, value.id)
    signatures = case.device.sign_allocation(
        draft, [item.item_ref for item in draft.parent.items], now=case.state.now
    )
    assert (
        register_allocation(
            case.gateway,
            draft,
            selection=signatures.selection,
            inputs=signatures.inputs,
            authorizations=signatures.authorizations,
        ).status
        == "ready"
    )
    assert dependency_hashes(approved.action, approved.cert, case.state) == before
    assert (
        dependency_hashes(case.comparison_action, case.comparison_cert, case.state)
        == compare_before
    )
    assert case.gateway.dispatch(approved.action, approved.cert, approved.token).status == "settled"
    assert case.snapshot()["status"] == "completed"
    assert approved.grant.grant_id in case.state.security.consumed_grant_ids


def test_dependency_drift_consumes_nonce_but_preserves_mfa_grant():
    gateway, device, action, cert = gateway_case(Fraction(1500))
    cert, token = approve_red(gateway, device, action, cert)
    state = gateway.store.snapshot()
    account = state.accounts["A_CURRENT"]
    gateway.store.update(
        accounts={**state.accounts, account.id: account.model_copy(update={"version": 2})}
    )
    result = gateway.dispatch(action, cert, token)
    assert result.rule_ids == ["APR-DRIFT"]
    security = gateway.store.snapshot().security
    assert token.nonce in security.consumed_nonces
    assert cert.mfa_grant_refs[0] not in security.consumed_grant_ids
    assert gateway.dispatch(action, cert, token).rule_ids == ["APR-REUSE"]
    assert gateway.bank.execute_count == 0


def test_kernel_rejection_preserves_grant_and_valid_retry_consumes_it_once():
    gateway, device, action, cert = gateway_case(Fraction(1500))
    proposal = gateway.propose(action, cert)
    cert, token = approve_red(gateway, device, action, cert)
    malformed = cert.model_copy(update={"mfa_grant_refs": cert.mfa_grant_refs * 2})
    bad_token = device.approve(
        action, malformed, proposal.card, now=gateway.store.snapshot().now, sequence=1
    )
    rejected = gateway.dispatch(action, malformed, bad_token)
    assert rejected.status == "rejected"
    assert "MFA-INVALID" in rejected.rule_ids
    assert cert.mfa_grant_refs[0] not in gateway.store.snapshot().security.consumed_grant_ids
    assert gateway.bank.execute_count == 0
    assert gateway.dispatch(action, cert, token).status == "settled"
    assert gateway.store.snapshot().security.consumed_grant_ids.count(cert.mfa_grant_refs[0]) == 1
    assert gateway.dispatch(action, cert, token).rule_ids == ["APR-REUSE"]
    assert gateway.bank.execute_count == 1
