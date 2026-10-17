"""The real gateway serializes approvals and recovers without resending money."""

from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.gateway.audit import AuditLog
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.service import Gateway
from corridor.kernel.binding import intent_key
from corridor.schemas.bank import Plan, PlanNode
from corridor.sim.keys import signing_key
from corridor.stores.bank import BankStore, available
from tests.bank_cases import recertify, transfer_case
from tests.gateway_cases import gateway_case


def add_transfer(gateway, amount, intent):
    action, cert, state = transfer_case(amount, intent_id=intent, state=gateway.store.snapshot())
    for key, item in state.user_inputs.items():
        if key not in gateway.store.snapshot().user_inputs:
            assert gateway.submit_input(item).status == "accepted"
    for key, item in state.authorizations.items():
        if key not in gateway.store.snapshot().authorizations:
            assert gateway.submit_authorization(item).status == "accepted"
    action = action.model_copy(update={"plan_id": "PLAN_" + intent, "node_id": "NODE_" + intent})
    plan = Plan(
        plan_id=action.plan_id,
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=intent,
        goal_input_refs=[action.args.amount_ref],
        ownership_epoch=0,
        nodes=[
            PlanNode(
                node_id=action.node_id,
                tool=action.kind,
                args={key.removeprefix("args."): value for key, value in cert.derivations.items()},
            )
        ],
    )
    action = action.model_copy(update={"plan_hash": H(plan)})
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    assert gateway.submit_plan(plan).status == "registered"
    return action, cert


def test_parallel_600_transfers_require_second_red_approval():
    gateway, device, first_action, first_cert = gateway_case(Fraction(600))
    second_action, second_cert = add_transfer(gateway, Fraction(600), "SECOND")
    cases = [(first_action, first_cert), (second_action, second_cert)]
    tokens = []
    for index, (action, cert) in enumerate(cases):
        proposal = gateway.propose(action, cert, request_id=f"PARALLEL_{index}")
        assert proposal.verdict.tier == "yellow"
        tokens.append(
            device.approve(
                action, cert, proposal.card, now=gateway.store.snapshot().now, sequence=index
            )
        )
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda i: gateway.dispatch(*cases[i], tokens[i]), range(2)))
    assert [result.status for result in results].count("settled") == 1
    losing = next(index for index, result in enumerate(results) if result.status != "settled")
    assert "APR-DRIFT" in results[losing].rule_ids
    assert gateway.bank.execute_count == 1
    assert available(gateway.store.snapshot(), "A_CURRENT") == 9400
    action, cert, _ = recertify(*cases[losing], gateway.store.snapshot())
    proposal = gateway.propose(action, cert, request_id="RED_REAPPROVAL")
    assert proposal.verdict.tier == "red"
    challenge = gateway.request_mfa(action, cert)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.submit_mfa(grant).status == "accepted"
    cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    token = device.approve(
        action, cert, proposal.card, now=gateway.store.snapshot().now, sequence=10
    )
    assert gateway.dispatch(action, cert, token).status == "settled"
    assert gateway.bank.execute_count == 2
    assert available(gateway.store.snapshot(), "A_CURRENT") == 8800
    assert gateway.audit.verify()


def test_process_style_restart_keeps_unknown_and_uses_lookup_only(tmp_path):
    gateway, device, action, cert = gateway_case(path=tmp_path)
    proposal = gateway.propose(action, cert)
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    key = intent_key(action, gateway.store.snapshot())
    gateway.bank.faults[key] = "response_loss"
    assert gateway.dispatch(action, cert, token).status == "unknown"
    # Reopen the persisted journal and audit rather than sharing their memory.
    store = BankStore(gateway.store.snapshot(), path=tmp_path / "state.jsonl")
    recovered = Gateway(
        store,
        gateway.bank,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        mfa=MFAVerifier(signing_key("mfa")),
        evidence_dir=tmp_path / "decisions",
    )
    assert key in recovered.store.snapshot().security.unknown_intent_ids
    assert available(recovered.store.snapshot(), "A_CURRENT") == 9800
    assert recovered.dispatch(action, cert, token).status != "settled"
    assert recovered.reconcile(key).status == "settled"
    assert recovered.bank.execute_count == 1
    assert available(recovered.store.snapshot(), "A_CURRENT") == 9800
    assert key not in recovered.store.snapshot().security.unknown_intent_ids
