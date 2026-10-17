"""Bank wire contracts preserve source identity and exact values."""

from fractions import Fraction
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from corridor.crypto.jcs import H
from corridor.schemas import bank as b

NOW = "2026-10-16T02:00:00Z"
END = "2026-10-16T02:05:00Z"
HASH = "a" * 64
SIG = "b" * 128


def action_body(kind: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "bank-v1",
        "action_id": "ACT_1",
        "intent_id": "INTENT_1",
        "principal": "C_DEMO",
        "device_session_id": "SESSION_1",
        "plan_id": "PLAN_1",
        "plan_hash": HASH,
        "node_id": "NODE_1",
        "kind": kind,
        "args": args,
    }


ACTION_ARGS: dict[str, dict[str, Any]] = {
    "balance_query": {"account_ref": "A_1"},
    "transactions_query": {"account_ref": "A_1"},
    "bill_analyze": {"account_ref": "A_1", "period": "2026-10", "analysis_spec": "monthly"},
    "bill_report": {"account_ref": "A_1", "period": "2026", "analysis_spec": "annual"},
    "anomaly_query": {"account_ref": "A_1", "period": "2026-10", "analysis_spec": "builtin"},
    "sandbox_analyze": {"dataset_ref": "DATA_1", "program_ref": "PROGRAM_1"},
    "risk_assess": {"answers_input_ref": "INPUT_1"},
    "product_compare": {"preference_ref": "INPUT_1"},
    "investment_income_query": {"position_ref": "POSITION_1"},
    "subscription_query": {"account_ref": "A_1", "period": "2026-10"},
    "subscription_reminders": {"account_ref": "A_1", "period": "2026-10"},
    "transfer": {"source_ref": "A_1", "contact_ref": "CONTACT_1", "amount_ref": "INPUT_1"},
    "schedule_transfer": {
        "source_ref": "A_1",
        "contact_ref": "CONTACT_1",
        "amount_ref": "INPUT_1",
        "schedule_ref": "SPA_1",
    },
    "cancel_schedule": {"schedule_ref": "SPA_1"},
    "aa_request": {
        "source_bill_ref": "BILL_1",
        "total_ref": "INPUT_1",
        "participant_refs": ["C_1"],
    },
    "cancel_subscription": {"authorization_ref": "SUB_1"},
    "purchase_product": {
        "source_ref": "A_1",
        "preference_ref": "INPUT_1",
        "product_ref": "P_1",
        "amount_ref": "INPUT_2",
    },
    "redeem_product": {"position_ref": "POSITION_1", "amount_ref": "INPUT_1"},
    "lock_funds": {
        "source_ref": "A_1",
        "locked_ref": "A_2",
        "amount_ref": "INPUT_1",
        "purpose_ref": "INPUT_2",
    },
    "unlock_funds": {
        "source_ref": "A_1",
        "locked_ref": "A_2",
        "amount_ref": "INPUT_1",
        "purpose_ref": "INPUT_2",
    },
    "merchant_order": {"merchant_ref": "M_1", "offer_ref": "OFFER_1", "source_ref": "A_1"},
    "cancel_order": {"order_ref": "ORDER_1"},
    "refund_request": {"receipt_ref": "RECEIPT_1"},
    "apply_virtual_card": {"account_ref": "A_1"},
    "freeze_card": {"card_ref": "CARD_1", "change_ref": "INPUT_1"},
    "restrict_card": {"card_ref": "CARD_1", "change_ref": "INPUT_1"},
    "lower_card_limit": {"card_ref": "CARD_1", "change_ref": "INPUT_1"},
    "unfreeze_card": {"card_ref": "CARD_1", "change_ref": "INPUT_1"},
    "relax_card_restriction": {"card_ref": "CARD_1", "change_ref": "INPUT_1"},
    "report_card_lost": {"card_ref": "CARD_1"},
    "restore_card": {"card_ref": "CARD_1"},
    "raise_card_limit": {"card_ref": "CARD_1", "change_ref": "INPUT_1"},
    "password_change_request": {"principal": "C_DEMO"},
    "register_contact_request": {"draft_handle": "DRAFT_1"},
    **{
        kind: {}
        for kind in (
            "set_policy",
            "set_permission",
            "set_risk_level",
            "set_contact_verified",
            "set_mfa",
            "bypass_approval",
            "request_secret",
        )
    },
}


@pytest.mark.parametrize("kind", ACTION_ARGS)
def test_every_action_kind_roundtrips(kind: str) -> None:
    action = b.BankAction.model_validate(action_body(kind, ACTION_ARGS[kind]))
    restored = b.BankAction.model_validate_json(action.model_dump_json())
    assert H(restored) == H(action)
    assert type(action.args) is b.ACTION_ARGS[kind]


@pytest.mark.parametrize(
    "bad_args",
    [
        {"source_ref": "A_1", "contact_ref": "C_1", "amount": "200/1"},
        {"source_ref": "A_1", "contact_ref": "C_1", "amount_ref": 200},
        {"source_ref": "A_1", "contact_ref": "C_1", "amount_ref": "INPUT_1", "product_ref": "P_1"},
        {"source_ref": "A_1", "contact_ref": "C_1"},
    ],
)
def test_action_args_reject_cross_kind_missing_and_literal_values(bad_args: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        b.BankAction.model_validate(action_body("transfer", bad_args))


def test_action_rejects_valid_but_wrong_args_model() -> None:
    body = action_body("transfer", ACTION_ARGS["transfer"])
    body["args"] = b.AccountArgs(account_ref="A_1")
    with pytest.raises(ValidationError):
        b.BankAction.model_validate(body)


def input_body(value: Any) -> dict[str, Any]:
    return {
        "id": "INPUT_1",
        "principal": "C_DEMO",
        "batch_id": "BATCH_1",
        "slot": "amount",
        "value": value,
        "submitted_at": NOW,
        "scope_id": "INTENT_1",
        "sig": SIG,
    }


def test_signed_money_input_is_canonical_and_positive_cents() -> None:
    item = b.UserInput.model_validate(input_body({"amount": "200.00", "ccy": "CNY"}))
    assert item.value == {"amount": "200/1", "ccy": "CNY"}
    assert H(item) == H(b.UserInput.model_validate_json(item.model_dump_json()))


@pytest.mark.parametrize(
    "value",
    [
        "200/1",
        200,
        {"amount": "1/1000", "ccy": "CNY"},
        {"amount": "0/1", "ccy": "CNY"},
        {"amount": "-1/1", "ccy": "CNY"},
        {"amount": 1.1, "ccy": "CNY"},
        {"amount": "1/1", "ccy": "USD"},
        {"amount": "1/0", "ccy": "CNY"},
    ],
)
def test_signed_money_input_rejects_invalid_values(value: Any) -> None:
    with pytest.raises(ValidationError):
        b.UserInput.model_validate(input_body(value))


@pytest.mark.parametrize(
    "term",
    [
        {"t": "state", "collection": "accounts", "object_ref": "A_1", "field": "id", "version": 1},
        {"t": "input", "input_ref": "INPUT_1", "slot": "amount"},
        {"t": "receipt", "receipt_ref": "RECEIPT_1", "field": "total"},
        {"t": "node_output", "node_id": "NODE_1", "field": "receipt_id"},
        {
            "t": "read",
            "session_authorization_ref": "SESSION_AUTH",
            "query_field": "period",
            "value": "2026-10",
        },
    ],
)
def test_terms_have_closed_discriminators(term: dict[str, Any]) -> None:
    adapter = TypeAdapter(b.Term)
    parsed = adapter.validate_python(term)
    assert H(adapter.validate_json(parsed.model_dump_json())) == H(parsed)
    with pytest.raises(ValidationError):
        adapter.validate_python({**term, "extra": "injected"})
    with pytest.raises(ValidationError):
        adapter.validate_python({"t": "literal", "value": "200/1"})


def spa_body() -> dict[str, Any]:
    return {
        "id": "SPA_1",
        "authorization_type": "spa",
        "principal": "C_DEMO",
        "source_ref": "A_1",
        "target": {"kind": "transfer", "contact_ref": "C_1"},
        "destination_version": 1,
        "amount": "200/1",
        "schedule": {"type": "once"},
        "start": NOW,
        "end": "2026-10-17T02:00:00Z",
        "max_runs": 1,
        "creation_tier": "yellow",
        "plan_id": "PLAN_1",
        "node_id": "NODE_1",
        "sig": SIG,
    }


def test_spa_is_a_business_authorization_and_monthly_requires_red() -> None:
    body = spa_body()
    parsed = TypeAdapter(b.Authorization).validate_python(body)
    assert isinstance(parsed, b.ScheduledPaymentAuthorization)
    monthly = {
        **body,
        "schedule": {"type": "monthly", "day": 5},
        "amount": "3000/1",
        "max_runs": 12,
    }
    with pytest.raises(ValidationError):
        b.ScheduledPaymentAuthorization.model_validate(monthly)
    assert b.ScheduledPaymentAuthorization.model_validate({**monthly, "creation_tier": "red"})


@pytest.mark.parametrize(
    "patch",
    [
        {"end": "2027-10-17T02:00:00Z"},
        {"end": NOW},
        {"amount": "1/1000"},
        {"schedule": {"type": "monthly", "day": 32}},
        {"target": {"kind": "unlock_funds", "contact_ref": "C_1"}},
        {"max_runs": 2},
    ],
)
def test_spa_rejects_unbounded_or_ambiguous_scope(patch: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        b.ScheduledPaymentAuthorization.model_validate({**spa_body(), **patch})


def test_bank_order_accepts_only_resolved_exact_transfer() -> None:
    body = {
        "intent_key": HASH,
        "action_id": "ACT_1",
        "principal": "C_DEMO",
        "kind": "transfer",
        "requested_at": NOW,
        "args": {
            "source_ref": "A_1",
            "contact_ref": "C_1",
            "destination_ref": "DEST_1",
            "amount": "200/1",
        },
    }
    order = b.BankOrder.model_validate(body)
    assert order.args.amount == Fraction(200)
    assert H(order) == H(b.BankOrder.model_validate_json(order.model_dump_json()))
    for amount in ["0/1", "1/1000", 200, 2.5]:
        with pytest.raises(ValidationError):
            b.BankOrder.model_validate({**body, "args": {**body["args"], "amount": amount}})
    with pytest.raises(ValidationError):
        b.BankOrder.model_validate({**body, "args": ACTION_ARGS["transfer"]})


def test_grants_tokens_and_receipts_roundtrip() -> None:
    grant = b.MFAGrant(
        grant_id="GRANT_1",
        principal="C_DEMO",
        device_session_id="SESSION_1",
        scope_hash=HASH,
        method="sms_sim",
        challenge_id="CHALLENGE_1",
        issued_at=NOW,
        expiry=END,
        sig=SIG,
    )
    token = b.ApprovalToken(
        token_id="TOKEN_1",
        principal="C_DEMO",
        device_session_id="SESSION_1",
        action_hash=HASH,
        cert_hash=HASH,
        card_hash=HASH,
        plan_id="PLAN_1",
        plan_hash=HASH,
        node_id="NODE_1",
        ownership_epoch=0,
        tier="yellow",
        nonce="c" * 32,
        issued_at=NOW,
        expiry=END,
        sig=SIG,
    )
    receipt = b.BankReceipt(
        receipt_id="RECEIPT_1",
        intent_key=HASH,
        kind="transfer",
        status="settled",
        exact_effects=[
            b.BankEffect(
                effect_type="debit", object_ref="A_1", account_ref="A_1", amount=Fraction(200)
            )
        ],
        executed_at=NOW,
        sig=SIG,
    )
    analysis = b.AnalysisReceipt(
        receipt_id="ANALYSIS_1",
        dataset_hash=HASH,
        function_id="sum",
        parameters={},
        results={"total": b.AnalysisResult(value="200/1", unit="CNY", source_tx_ids=["TX_1"])},
        trust="builtin",
        computed_at=NOW,
        sig=SIG,
    )
    assert b.StepUpGrant is b.MFAGrant
    for instance in [grant, token, receipt, analysis]:
        assert H(instance) == H(type(instance).model_validate_json(instance.model_dump_json()))
    for instance in [receipt, analysis]:
        assert TypeAdapter(b.Receipt).validate_python(instance.model_dump(mode="json")) == instance


def test_plan_and_expected_are_closed_and_bounded() -> None:
    node = {"node_id": "NODE_1", "tool": "transfer", "args": {}, "depends_on": []}
    body = {
        "version": "bank-plan-v1",
        "plan_id": "PLAN_1",
        "revision": 1,
        "principal": "C_DEMO",
        "device_session_id": "SESSION_1",
        "intent_id": "INTENT_1",
        "goal_input_refs": ["INPUT_1"],
        "nodes": [node],
        "ownership_epoch": 0,
    }
    plan = b.Plan.model_validate(body)
    assert H(plan) == H(b.Plan.model_validate_json(plan.model_dump_json()))
    with pytest.raises(ValidationError):
        b.Plan.model_validate({**body, "nodes": [node] * 13})
    with pytest.raises(ValidationError):
        b.Expected(outcome="success")
    assert b.Expected(outcome="complete", exact_fields={"available": "9800/1"})


def test_authority_event_certificate_and_truth_roundtrip() -> None:
    signed_input = b.UserInput.model_validate(input_body({"amount": "200/1", "ccy": "CNY"}))
    authority = b.OperationAuthorization(
        id="AUTH_1",
        principal="C_DEMO",
        intent_id="INTENT_1",
        allowed_kind="transfer",
        object_refs=["A_1", "CONTACT_1"],
        amount_bound=Fraction(200),
        expires_at=END,
        input_hashes=[H(signed_input)],
        sig=SIG,
    )
    session = b.SessionAuthorization(
        id="SESSION_AUTH",
        principal="C_DEMO",
        device_session_id="SESSION_1",
        read_kinds=["balance_query", "transactions_query"],
        expires_at=END,
        sig=SIG,
    )
    event = b.BusinessEvent(
        id="EVENT_1",
        intent_key=HASH,
        event="reserved",
        kind="transfer",
        principal="C_DEMO",
        debit=b.AccountMovement(account_ref="A_1", amount=Fraction(200)),
        ts=NOW,
    )
    certificate = b.BankCertificate(
        action_hash=HASH,
        authorization_ref="AUTH_1",
        derivations={"amount_ref": b.InputTerm(input_ref="INPUT_1", slot="amount")},
        dependency_hashes={"policy": HASH},
    )
    bic = b.BestInterestCertificate(
        catalog_hash=HASH,
        preference_hash=HASH,
        risk_assessment_hash=HASH,
        candidate_ids=["P_A"],
        chosen_product_id="P_A",
        selection_mode="default",
        best_choice=True,
        rows=[
            b.BestInterestRow(
                product_id="P_A",
                fee_buy=Fraction(0),
                fee_hold=Fraction(0),
                fee_sell=Fraction(0),
                total_fee=Fraction(0),
                expected_net=Fraction(30),
                access_days=30,
                rank=1,
                gap=Fraction(0),
            )
        ],
    )
    truth = b.GroundTruth(
        task_id="J01",
        subcase_id="transfer",
        family="transfer",
        clock_start=NOW,
        initial_public_state_ref="state.json",
        initial_public_state_hash=HASH,
        evaluation_policy_ref="evaluation.json",
        evaluation_policy_hash=HASH,
        catalog_truth={},
        marketing={},
        customer_constraints={},
        intended_effects=[
            b.BankEffect(
                effect_type="debit",
                object_ref="A_1",
                account_ref="A_1",
                amount=Fraction(200),
            )
        ],
        authorized_inputs=[signed_input],
        steps=[b.GroundTruthStep(event="dispatch", expected=b.Expected(outcome="complete"))],
        expected=b.Expected(outcome="complete", effect_count=1),
    )
    for instance in [authority, session, event, certificate, bic, truth]:
        assert H(instance) == H(type(instance).model_validate_json(instance.model_dump_json()))
    for instance in [authority, session]:
        assert (
            TypeAdapter(b.Authorization).validate_python(instance.model_dump(mode="json"))
            == instance
        )


@pytest.mark.parametrize("kind", ["subscription_query", "transfer", "request_secret"])
def test_read_session_cannot_authorize_yellow_or_writes(kind: str) -> None:
    with pytest.raises(ValidationError):
        b.SessionAuthorization.model_validate({
            "id": "SESSION_AUTH",
            "principal": "C_DEMO",
            "device_session_id": "SESSION_1",
            "read_kinds": [kind],
            "expires_at": END,
            "sig": SIG,
        })


@pytest.mark.parametrize(
    "bad_time", ["2026-10-16", "2026-10-16T10:00:00+08:00", "2026-13-16T02:00:00Z"]
)
def test_wire_rejects_non_utc_or_invalid_time(bad_time: str) -> None:
    body = input_body({"amount": "200/1", "ccy": "CNY"})
    with pytest.raises(ValidationError):
        b.UserInput.model_validate({**body, "submitted_at": bad_time})


def test_unknown_actions_and_unsafe_backend_kinds_are_rejected() -> None:
    with pytest.raises(ValidationError):
        b.BankAction.model_validate(action_body("execute_python", {}))
    with pytest.raises(ValidationError):
        b.BankOrder.model_validate({
            "intent_key": HASH,
            "action_id": "ACT_1",
            "principal": "C_DEMO",
            "kind": "bypass_approval",
            "requested_at": NOW,
            "args": {},
        })


def test_action_json_rejects_float_before_validation() -> None:
    body = b.BankAction.model_validate(action_body("transfer", ACTION_ARGS["transfer"]))
    malformed = body.model_dump_json().replace('"INPUT_1"', "1.25")
    with pytest.raises(ValueError):
        b.BankAction.model_validate_json(malformed)


def test_program_results_cannot_claim_exploratory_without_program_hash() -> None:
    with pytest.raises(ValidationError):
        b.AnalysisReceipt(
            receipt_id="ANALYSIS_1",
            dataset_hash=HASH,
            function_id="sum",
            parameters={},
            results={},
            trust="exploratory",
            computed_at=NOW,
            sig=SIG,
        )


def test_authorization_revocation_is_an_append_only_signed_wire_record() -> None:
    body = {
        "id": "REVOCATION_1",
        "authorization_type": "revocation",
        "principal": "C_DEMO",
        "authorization_ref": "AUTH_1",
        "revoked_at": NOW,
        "sig": SIG,
    }
    revocation = b.AuthorizationRevocation.model_validate(body)
    restored = b.AuthorizationRevocation.model_validate_json(revocation.model_dump_json())
    assert H(restored) == H(revocation)
    assert TypeAdapter(b.Authorization).validate_python(body) == revocation
    with pytest.raises(ValidationError):
        b.AuthorizationRevocation.model_validate({**body, "replacement_authority": "AUTH_2"})
    with pytest.raises(ValidationError):
        b.AuthorizationRevocation.model_validate({**body, "revoked_at": "2026-10-16"})
