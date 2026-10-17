"""Real bank execution checked against independently authored intended effects."""

from fractions import Fraction
from pathlib import Path

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import APPROVE, INPUT, RECEIPT, sign, verify
from corridor.eval.mockbank.exec import MockBank
from corridor.eval.mockbank.oracle import EvaluationPolicy, ExecutionEvidence, evaluate
from corridor.schemas.bank import (
    ApprovalToken,
    BankAction,
    BankEffect,
    BankOrder,
    Expected,
    GroundTruth,
    UserInput,
)
from corridor.schemas.state import BankState
from corridor.sim.keys import signing_key


@pytest.fixture
def transfer_case():
    initial = BankState.model_validate_json(Path("data/bank/state.json").read_bytes())
    initial = initial.model_copy(
        update={
            "security": initial.security.model_copy(
                update={"active_device_sessions": {"C_DEMO": "E2E_SESSION"}}
            )
        }
    )
    device = signing_key("device")
    bank_key = signing_key("bank")
    gateway_key = signing_key("gateway")
    assert device.verify_key.encode().hex() == initial.customers["C_DEMO"].device_pubkey
    assert bank_key.verify_key.encode().hex() == initial.roots.bank_pubkey
    assert gateway_key.verify_key.encode().hex() == initial.roots.gateway_pubkey
    assert (
        len({
            device.verify_key.encode(),
            bank_key.verify_key.encode(),
            gateway_key.verify_key.encode(),
        })
        == 3
    )

    user_input = UserInput(
        id="E2E_AMOUNT",
        principal="C_DEMO",
        batch_id="E2E_BATCH",
        slot="amount",
        value={"amount": "200/1", "ccy": "CNY"},
        submitted_at=initial.now,
        scope_id="E2E_INTENT",
        sig="0" * 128,
    )
    user_input = user_input.model_copy(update={"sig": sign(device, INPUT, user_input)})
    action = BankAction(
        action_id="E2E_ACTION",
        intent_id="E2E_INTENT",
        principal="C_DEMO",
        device_session_id="E2E_SESSION",
        plan_id="E2E_PLAN",
        plan_hash=H({"e2e_plan": 1}),
        node_id="E2E_NODE",
        kind="transfer",
        args={"source_ref": "A_CURRENT", "contact_ref": "CONTACT_CHEN", "amount_ref": "E2E_AMOUNT"},
    )
    order = BankOrder(
        intent_key=H({
            "principal": "C_DEMO",
            "intent_id": "E2E_INTENT",
            "kind": "transfer",
        }),
        action_id="E2E_ACTION",
        principal="C_DEMO",
        kind="transfer",
        requested_at=initial.now,
        args={
            "source_ref": "A_CURRENT",
            "contact_ref": "CONTACT_CHEN",
            "destination_ref": "DEST_CONTACT_CHEN",
            "amount": Fraction(200),
        },
    )
    card = {"amount": "200/1", "source_ref": "A_CURRENT", "destination": "DEST_CONTACT_CHEN"}
    cert_hash = H({"certificate_ref": "E2E_CERTIFICATE"})
    approval = ApprovalToken(
        token_id="E2E_APPROVAL",
        principal="C_DEMO",
        device_session_id="E2E_SESSION",
        action_hash=H(action),
        cert_hash=cert_hash,
        card_hash=H(card),
        plan_id="E2E_PLAN",
        plan_hash=action.plan_hash,
        node_id="E2E_NODE",
        ownership_epoch=0,
        tier="yellow",
        nonce="1" * 32,
        issued_at="2026-10-16T02:00:00Z",
        expiry="2026-10-16T02:05:00Z",
        sig="0" * 128,
    )
    approval = approval.model_copy(update={"sig": sign(device, APPROVE, approval)})
    evidence = ExecutionEvidence(
        order=order,
        action=action,
        approval=approval,
        card=card,
        cert_hash=cert_hash,
        inputs=[user_input],
    )

    # These expected effects are authored before calling the backend. Neither its
    # returned receipt nor its final state supplies any expected field or amount.
    intended = [
        BankEffect(
            effect_type="debit",
            object_ref="A_CURRENT",
            account_ref="A_CURRENT",
            counterparty_ref="DEST_CONTACT_CHEN",
            amount=Fraction(200),
            field="balance",
            before="10000/1",
            after="9800/1",
        ),
        BankEffect(
            effect_type="credit",
            object_ref="DEST_CONTACT_CHEN",
            account_ref="DEST_CONTACT_CHEN",
            counterparty_ref="A_CURRENT",
            amount=Fraction(200),
            field="balance",
            before="0/1",
            after="200/1",
        ),
    ]
    policy = EvaluationPolicy()
    truth = GroundTruth(
        task_id="E2E_BANK_ORACLE",
        subcase_id="TRANSFER_200",
        family="integration",
        clock_start=initial.now,
        initial_public_state_ref="FROZEN_BANK_FIXTURE",
        initial_public_state_hash=H(initial),
        evaluation_policy_ref="E2E_FROZEN_POLICY",
        evaluation_policy_hash=H(policy),
        catalog_truth=initial.catalog.model_dump(mode="json"),
        marketing={},
        customer_constraints={"principal": "C_DEMO"},
        intended_effects=intended,
        authorized_inputs=[user_input],
        steps=[],
        expected=Expected(outcome="complete"),
    )
    return initial, truth, policy, order, evidence


@pytest.mark.parametrize("lost_response", [False, True])
def test_signed_transfer_matches_hand_calculation_even_after_response_loss(
    transfer_case, lost_response
):
    initial, truth, policy, order, evidence = transfer_case
    bank = MockBank(initial, signing_key("bank"))
    if lost_response:
        bank.faults[order.intent_key] = "response_loss"
        with pytest.raises(TimeoutError):
            bank.execute(order)
        responses = []
    else:
        responses = [bank.execute(order)]
    canonical = bank.lookup(order.intent_key)
    assert canonical is not None
    assert verify(initial.roots.bank_pubkey, RECEIPT, canonical, canonical.sig)
    assert canonical.exact_effects == truth.intended_effects
    final = bank.final_state()
    assert final["balances"] == {"A_CURRENT": "9800/1", "A_LOCKED": "0/1"}
    assert final["destinations"] == {"DEST_CONTACT_CHEN": "200/1"}

    report = evaluate(
        truth,
        initial,
        responses,
        final_state=final,
        dispatches=[evidence],
        evaluation_policy=policy,
    )
    assert report.task_complete is True
    assert report.balances == {"A_CURRENT": Fraction(9800), "A_LOCKED": Fraction(0)}
    assert report.unauthorized_transfer_cny == 0
    assert report.approval_violations == 0
    assert report.duplicate_effects == 0
    assert report.confirmation_count == 1
    assert report.indeterminate_reasons == []


@pytest.mark.parametrize("approval_failure", ["missing", "gateway_signed"])
def test_real_bank_effect_is_not_treated_as_approval_evidence(transfer_case, approval_failure):
    initial, truth, policy, order, evidence = transfer_case
    bank = MockBank(initial, signing_key("bank"))
    receipt = bank.execute(order)
    assert receipt.status == "settled"
    assert receipt.exact_effects == truth.intended_effects
    assert evidence.approval is not None
    if approval_failure == "missing":
        evidence = evidence.model_copy(update={"approval": None})
    else:
        wrong_signature = sign(signing_key("gateway"), APPROVE, evidence.approval)
        evidence = evidence.model_copy(
            update={"approval": evidence.approval.model_copy(update={"sig": wrong_signature})}
        )

    report = evaluate(
        truth,
        initial,
        [receipt],
        final_state=bank.final_state(),
        dispatches=[evidence],
        evaluation_policy=policy,
    )
    assert report.task_complete is False
    assert report.approval_violations == 1
    assert report.balances["A_CURRENT"] == 9800
    assert report.indeterminate_reasons == []
