"""Red-team probes of the gateway approval / dispatch / lock / audit boundary.

Every test asserts the SECURE behaviour required by DESIGN-BANK section 4.2 / 8.
"""

from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.crypto.sign import APPROVE, sign
from corridor.kernel.binding import intent_key
from corridor.schemas.base import loads_exact
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds, available
from tests.bank_cases import recertify
from tests.e2e.test_gateway_atomicity import add_transfer
from tests.gateway_cases import approve, approve_red, gateway_case


def _second_plan_for_same_intent(gateway, action, cert, suffix="2"):
    """Planner re-registers the SAME signed intent under a fresh plan/node id."""
    plan = gateway._plans[action.plan_id]
    node = plan.nodes[0].model_copy(update={"node_id": action.node_id + suffix})
    plan2 = plan.model_copy(update={"plan_id": action.plan_id + suffix, "nodes": [node]})
    assert gateway.submit_plan(plan2).status == "registered"
    action2 = action.model_copy(
        update={
            "action_id": action.action_id + suffix,
            "plan_id": plan2.plan_id,
            "node_id": node.node_id,
            "plan_hash": H(plan2),
        }
    )
    action2, cert2, _ = recertify(action2, cert, gateway.store.snapshot())
    return action2, cert2


# --- 1. idempotency: one signed intent must execute at most once (section 4.2) -----------


def test_same_signed_intent_cannot_be_executed_twice_by_changing_node_id():
    gateway, device, action, cert = gateway_case(Fraction(200))
    token = approve(gateway, device, action, cert)
    assert gateway.dispatch(action, cert, token).status == "settled"

    # The user signed ONE intent ("转200给小陈"); the planner replays it on a new node.
    action2, cert2 = _second_plan_for_same_intent(gateway, action, cert)
    proposal = gateway.propose(action2, cert2, request_id="REPLAY")
    result = None
    if proposal.verdict.outcome != "Reject" and proposal.card:
        token2 = device.approve(
            action2, cert2, proposal.card, now=gateway.store.snapshot().now, sequence=1
        )
        result = gateway.dispatch(action2, cert2, token2)
    # Secure behaviour: same intent_id => IDEM-DUP / reject; money moves once.
    assert gateway.bank.execute_count == 1, result
    assert available(gateway.store.snapshot(), "A_CURRENT") == 9800


# --- 2. approval-rate lock (section 8.3) --------------------------------------------------


def test_reusing_one_request_id_for_distinct_approval_cards_still_counts_toward_rate_lock():
    gateway, _, action, cert = gateway_case(Fraction(10))
    cases = [(action, cert)] + [
        add_transfer(gateway, Fraction(10), f"RATE{index}") for index in range(7)
    ]
    for case_action, case_cert in cases:
        # A "network retry" id reused across eight DIFFERENT approval cards.
        gateway.propose(case_action, case_cert, request_id="SAME_REQUEST")
    assert action.principal in gateway.store.snapshot().security.locked_at


def test_sixth_approvable_card_is_not_shown_once_rate_lock_trips():
    gateway, device, action, cert = gateway_case(Fraction(10))
    proposals = [gateway.propose(action, cert, request_id=f"REQ_{index}") for index in range(6)]
    sixth = proposals[-1]
    assert action.principal in gateway.store.snapshot().security.locked_at
    assert sixth.verdict.outcome == "Reject" and sixth.verdict.rule_ids == ["APR-LOCK"]
    # GD-5 was rejected: a Reject may retain card facts, but cannot authorize dispatch.
    token = device.approve(action, cert, sixth.card, now=gateway.store.snapshot().now)
    assert gateway.dispatch(action, cert, token).rule_ids == ["APR-LOCK"]
    assert gateway.bank.execute_count == 0


# --- 3. failed attempts must leave audit evidence (section 8.4) ----------------------------


def test_replayed_token_rejection_leaves_audit_evidence():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    assert gateway.dispatch(action, cert, token).status == "settled"
    before = len(gateway.audit.records())
    result = gateway.dispatch(action, cert, token)
    assert "APR-REUSE" in result.rule_ids
    after = gateway.audit.records()[before:]
    assert any("APR-REUSE" in str(record["payload"]) for record in after), after


def test_forged_token_rejection_leaves_audit_evidence():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    forged = token.model_copy(update={"sig": sign(signing_key("attacker"), APPROVE, token)})
    before = len(gateway.audit.records())
    assert gateway.dispatch(action, cert, forged).rule_ids == ["APR-SIG"]
    after = gateway.audit.records()[before:]
    assert any("APR-SIG" in str(record["payload"]) for record in after), after


# --- 4. unlock must not revive pre-lock plans (section 8.3) --------------------------------


def _unlock(gateway, device, principal):
    gateway.store.update(now=add_seconds(gateway.store.snapshot().now, 1800))
    scope = gateway.unlock_scope(principal)
    confirmation = device.confirm_input(
        intent_id=H(scope), slot="unlock", value=scope, now=gateway.store.snapshot().now
    )
    challenge = gateway.request_unlock_mfa(principal)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.unlock(principal, confirmation, grant).status == "unlocked"


def test_unlock_does_not_revive_plan_registered_before_lock():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    gateway.lock(action.principal, "red_injection")
    _unlock(gateway, device, action.principal)
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    assert gateway.propose(action, cert).verdict.rule_ids == ["APR-VOID"]
    result = gateway.dispatch(action, cert, token)
    assert result.rule_ids == ["APR-VOID"]
    assert gateway.bank.execute_count == 0


# --- 5. lock forbids approvals, including MFA step-up (section 8.3) ------------------------


def test_mfa_grant_cannot_be_registered_while_principal_is_locked():
    gateway, device, action, cert = gateway_case(Fraction(1500))
    gateway.propose(action, cert)
    challenge = gateway.request_mfa(action, cert)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    gateway.lock(action.principal, "red_injection")
    assert gateway.submit_mfa(grant).rule_ids == ["APR-LOCK"]
    assert grant.grant_id not in gateway.store.snapshot().security.mfa_grants


# --- 6. decision record contents (section 8.4) ---------------------------------------------


def test_red_decision_record_contains_card_hash_tier_and_mfa_grant(tmp_path):
    gateway, device, action, cert = gateway_case(Fraction(1500), path=tmp_path)
    cert, token = approve_red(gateway, device, action, cert)
    result = gateway.dispatch(action, cert, token)
    assert result.status == "settled"
    key = intent_key(action, gateway.store.snapshot())
    record = loads_exact((tmp_path / "decisions" / f"{key}.json").read_bytes())
    assert record.get("card_hash") == token.card_hash
    assert record.get("mfa_grant_id") == cert.mfa_grant_refs[0]
    assert record.get("tier") == "red"
    assert "bank_receipt" in record


# --- regression probes that are expected to hold ------------------------------------------


def test_unlock_without_cooldown_is_rejected():
    gateway, device, action, _ = gateway_case()
    gateway.lock(action.principal, "test")
    scope = gateway.unlock_scope(action.principal)
    confirmation = device.confirm_input(
        intent_id=H(scope), slot="unlock", value=scope, now=gateway.store.snapshot().now
    )
    challenge = gateway.request_unlock_mfa(action.principal)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.unlock(action.principal, confirmation, grant).status == "rejected"
    assert action.principal in gateway.store.snapshot().security.locked_at


def test_unknown_result_is_never_reexecuted_by_redispatch_after_new_approval():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    key = intent_key(action, gateway.store.snapshot())
    gateway.bank.faults[key] = "response_loss"
    assert gateway.dispatch(action, cert, token).status == "unknown"
    token2 = device.approve(
        action,
        cert,
        gateway._cards[gateway._card_key(action, cert)],
        now=gateway.store.snapshot().now,
        sequence=7,
    )
    assert gateway.dispatch(action, cert, token2).status != "settled"
    assert gateway.bank.execute_count == 1


def test_yellow_token_cannot_be_used_after_action_swapped_to_other_contact():
    gateway, device, action, cert = gateway_case()
    token = approve(gateway, device, action, cert)
    swapped = action.model_copy(
        update={"args": action.args.model_copy(update={"contact_ref": "CONTACT_LI"})}
    )
    swapped, cert2, _ = recertify(swapped, cert, gateway.store.snapshot())
    assert gateway.dispatch(swapped, cert2, token).status == "rejected"
    assert gateway.bank.execute_count == 0
