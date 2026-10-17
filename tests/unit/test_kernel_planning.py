"""B8 SPA target, immutable-version, exact AA and term-list obligations."""

from fractions import Fraction

import pytest
from pydantic import ValidationError

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT, SPA
from corridor.kernel import check
from corridor.kernel.binding import resolve_amount
from corridor.kernel.planning import compensation_errors
from corridor.kernel.spa import due_at, inspect_spa
from corridor.schemas.bank import BankAction, InputTerm, PlanNode, ScheduleTransferArgs, StateTerm
from corridor.schemas.models import Accept, Reject
from corridor.sim.device import Device
from tests.bank_cases import recertify, signed, spa_case, transfer_case


@pytest.mark.parametrize(
    "target,fields",
    [
        ("merchant_order", {"merchant_ref": "FLOWERS", "offer_ref": "OFFER_FLOWERS"}),
        ("unlock_funds", {"locked_ref": "A_LOCKED", "purpose_ref": "PURPOSE"}),
        ("transfer", {"contact_ref": "CONTACT_CHEN"}),
    ],
)
def test_schedule_creation_supports_exactly_one_bound_target_group(target, fields):
    args = ScheduleTransferArgs(
        source_ref="A_CURRENT", amount_ref="AMOUNT", schedule_ref="SPA", **fields
    )
    assert args.source_ref == "A_CURRENT"
    action, cert, state = spa_case()
    spa = state.authorizations[cert.authorization_ref]
    target_fields = {key: value for key, value in fields.items() if key != "purpose_ref"}
    amount = Fraction(300) if target == "merchant_order" else Fraction(200)
    # Revalidate nested target models before signing the complete scope.
    from corridor.schemas.bank import ScheduledPaymentAuthorization

    spa = signed(
        ScheduledPaymentAuthorization.model_validate({
            **spa.model_dump(mode="python"),
            "target": {"kind": target, **target_fields},
            "amount": amount,
        }),
        SPA,
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "args": {
            "source_ref": "A_CURRENT",
            "amount_ref": "AMOUNT",
            "schedule_ref": spa.id,
            **fields,
        },
    })
    state = state.model_copy(update={"authorizations": {spa.id: spa}})
    assert inspect_spa(action, cert, state, amount).errors == []


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"merchant_ref": "FLOWERS"},
        {"offer_ref": "OFFER_FLOWERS"},
        {"locked_ref": "A_LOCKED"},
        {"purpose_ref": "PURPOSE"},
        {"contact_ref": "CONTACT_CHEN", "merchant_ref": "FLOWERS", "offer_ref": "OFFER_FLOWERS"},
        {"contact_ref": "CONTACT_CHEN", "locked_ref": "A_LOCKED", "purpose_ref": "PURPOSE"},
    ],
)
def test_schedule_creation_rejects_mixed_or_incomplete_target_groups(fields):
    with pytest.raises(ValidationError):
        ScheduleTransferArgs(
            source_ref="A_CURRENT", amount_ref="AMOUNT", schedule_ref="SPA", **fields
        )


@pytest.mark.rule("DOMAIN-SPA")
@pytest.mark.parametrize(
    "field,value",
    [
        ("source_version", None),
        ("source_version", 2),
        ("source_version", True),
        ("destination_version", None),
        ("destination_version", 2),
    ],
)
def test_spa_execution_requires_exact_creation_source_and_target_versions(field, value):
    action, cert, state = spa_case(execution=True)
    event = state.ledger[0]
    delta = {**event.object_delta, "source_version": 1, "destination_version": 1}
    if value is None:
        del delta[field]
    else:
        delta[field] = value
    state = state.model_copy(update={"ledger": [event.model_copy(update={"object_delta": delta})]})
    result = check(*recertify(action, cert, state), phase="dispatch")
    assert isinstance(result, Reject) and "DOMAIN-SPA" in result.rule_ids


def test_spa_source_account_version_change_cannot_be_recertified_into_authority():
    action, cert, state = spa_case(execution=True)
    account = state.accounts["A_CURRENT"].model_copy(update={"version": 2})
    state = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
    terms = {
        **cert.derivations,
        "args.source_ref": cert.derivations["args.source_ref"].model_copy(update={"version": 2}),
    }
    cert = cert.model_copy(update={"derivations": terms})
    result = check(*recertify(action, cert, state), phase="dispatch")
    assert isinstance(result, Reject) and "DOMAIN-SPA" in result.rule_ids


def test_monthly_day_31_skips_missing_months_and_obeys_run_limit():
    _, cert, state = spa_case()
    spa_payload = {
        **state.authorizations[cert.authorization_ref].model_dump(mode="python"),
        "schedule": {"type": "monthly", "day": 31},
        "creation_tier": "red",
        "start": "2026-01-30T16:00:00Z",
        "end": "2026-06-01T16:00:00Z",
        "max_runs": 3,
    }
    from corridor.schemas.bank import ScheduledPaymentAuthorization

    spa = ScheduledPaymentAuthorization.model_validate(spa_payload)
    assert [due_at(spa, index) for index in range(4)] == [
        "2026-01-30T16:00:00Z",
        "2026-03-30T16:00:00Z",
        "2026-05-30T16:00:00Z",
        None,
    ]


def aa_case():
    action, cert, state = transfer_case(Fraction(10))
    total = Device().confirm_input(
        intent_id=action.intent_id,
        slot="total",
        value={"amount": "10/1", "ccy": "CNY"},
        now=state.now,
    )
    participants = ["CONTACT_CHEN", "CONTACT_LIN_A", "CONTACT_LIN_B"]
    authority = state.authorizations[cert.authorization_ref]
    authority = signed(
        authority.model_copy(
            update={
                "allowed_kind": "aa_request",
                "object_refs": participants,
                "input_hashes": [H(total)],
            }
        ),
        CONTROL,
    )
    state = state.model_copy(
        update={"user_inputs": {total.id: total}, "authorizations": {authority.id: authority}}
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "aa_request",
        "args": {
            "source_bill_ref": total.id,
            "total_ref": total.id,
            "participant_refs": participants,
        },
    })
    derivations = {
        "args.source_bill_ref": InputTerm(input_ref=total.id, slot="total"),
        "args.total_ref": InputTerm(input_ref=total.id, slot="total"),
        **{
            f"args.participant_refs.{index}": StateTerm(
                collection="contacts", object_ref=ref, field="id", version=1
            )
            for index, ref in enumerate(participants)
        },
    }
    cert = cert.model_copy(update={"derivations": derivations})
    return recertify(action, cert, state)


def test_aa_signed_total_and_indexed_contact_sources_are_yellow():
    action, cert, state = aa_case()
    result = check(action, cert, state, phase="propose")
    assert isinstance(result, Accept), result
    assert result.tier == "yellow"
    assert resolve_amount(action, state) == 10


@pytest.mark.rule("DOMAIN-AA")
def test_aa_total_cannot_be_less_than_one_cent_per_person():
    action, cert, state = aa_case()
    total = state.user_inputs[action.args.total_ref]
    from corridor.crypto.sign import INPUT

    total = signed(total.model_copy(update={"value": {"amount": "1/100", "ccy": "CNY"}}), INPUT)
    authority = state.authorizations[cert.authorization_ref]
    authority = signed(authority.model_copy(update={"input_hashes": [H(total)]}), CONTROL)
    state = state.model_copy(
        update={"user_inputs": {total.id: total}, "authorizations": {authority.id: authority}}
    )
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject) and "DOMAIN-AA" in result.rule_ids


def test_aa_cannot_swap_bill_reference_or_other_customer_participant():
    action, cert, state = aa_case()
    changed = action.model_copy(
        update={"args": action.args.model_copy(update={"source_bill_ref": "OTHER"})}
    )
    result = check(*recertify(changed, cert, state), phase="propose")
    assert isinstance(result, Reject) and "PROV-COHERENCE" in result.rule_ids
    contact = state.contacts["CONTACT_CHEN"].model_copy(update={"owner": "OTHER"})
    state = state.model_copy(update={"contacts": {**state.contacts, contact.id: contact}})
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject) and "AUTH-PRINCIPAL" in result.rule_ids


def test_plan_term_lists_only_accept_aa_participant_refs():
    contact = StateTerm(collection="contacts", object_ref="CONTACT_CHEN", field="id", version=1)
    node = PlanNode(node_id="AA", tool="aa_request", args={"participant_refs": [contact]})
    assert len(node.args["participant_refs"]) == 1
    for args in (
        {"amount_ref": [contact]},
        {"participant_refs": []},
        {"participant_refs": [contact] * 11},
    ):
        with pytest.raises(ValidationError):
            PlanNode(node_id="AA", tool="aa_request", args=args)


def compensation_case():
    from corridor.crypto.sign import RECEIPT
    from corridor.schemas.bank import BankEffect, BankOrder, BankReceipt, BusinessEvent

    action, cert, state = transfer_case(Fraction(200))
    purpose = Device().confirm_input(
        intent_id=action.intent_id,
        slot="purpose",
        value={"original_receipt_ref": "LOCK_RECEIPT"},
        now=state.now,
    )
    purpose = signed(
        purpose.model_copy(update={"batch_id": state.user_inputs[action.args.amount_ref].batch_id}),
        INPUT,
    )
    order = BankOrder(
        action_id="LOCK_ACTION",
        intent_key=H("LOCK"),
        principal=action.principal,
        kind="lock_funds",
        args={
            "source_ref": "A_CURRENT",
            "locked_ref": "A_LOCKED",
            "amount": "200/1",
            "purpose_ref": "BIRTHDAY",
        },
        requested_at=state.now,
    )
    receipt = signed(
        BankReceipt(
            receipt_id="LOCK_RECEIPT",
            intent_key=order.intent_key,
            kind="lock_funds",
            status="settled",
            executed_at=state.now,
            exact_effects=[
                BankEffect(
                    effect_type="debit",
                    object_ref="A_CURRENT",
                    account_ref="A_CURRENT",
                    amount=Fraction(200),
                    field="balance",
                    before="10000/1",
                    after="9800/1",
                ),
                BankEffect(
                    effect_type="credit",
                    object_ref="A_LOCKED",
                    account_ref="A_LOCKED",
                    amount=Fraction(200),
                    field="balance",
                    before="0/1",
                    after="200/1",
                ),
            ],
            sig="0" * 128,
        ),
        RECEIPT,
        "bank",
    )
    event = BusinessEvent(
        id="LOCK_EVENT",
        intent_key=order.intent_key,
        event="settled",
        kind="lock_funds",
        principal=action.principal,
        debit={"account_ref": "A_CURRENT", "amount": "200/1"},
        credit={"account_ref": "A_LOCKED", "amount": "200/1"},
        object_delta={"order": order.model_dump(mode="json")},
        ts=state.now,
        bank_receipt_id=receipt.id,
    )
    state = state.model_copy(
        update={
            "user_inputs": {**state.user_inputs, purpose.id: purpose},
            "receipts": {receipt.id: receipt},
            "ledger": [event],
        }
    )
    authority = state.authorizations[cert.authorization_ref]
    authority = signed(
        authority.model_copy(
            update={
                "allowed_kind": "unlock_funds",
                "object_refs": ["A_CURRENT", "A_LOCKED"],
                "input_hashes": [*authority.input_hashes, H(purpose)],
            }
        ),
        CONTROL,
    )
    state = state.model_copy(update={"authorizations": {authority.id: authority}})
    args = {
        "source_ref": "A_CURRENT",
        "locked_ref": "A_LOCKED",
        "amount_ref": action.args.amount_ref,
        "purpose_ref": purpose.id,
    }
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "unlock_funds",
        "args": args,
    })
    cert = cert.model_copy(
        update={
            "derivations": {
                "args.source_ref": StateTerm(
                    collection="accounts", object_ref="A_CURRENT", field="id", version=1
                ),
                "args.locked_ref": StateTerm(
                    collection="accounts", object_ref="A_LOCKED", field="id", version=1
                ),
                "args.amount_ref": cert.derivations["args.amount_ref"],
                "args.purpose_ref": InputTerm(input_ref=purpose.id, slot="purpose"),
            }
        }
    )
    return recertify(action, cert, state)


@pytest.mark.rule("DOMAIN-COMPENSATION")
def test_unlock_compensation_is_bound_to_original_settled_bank_receipt():
    action, cert, state = compensation_case()
    assert isinstance(check(action, cert, state, phase="propose"), Accept)
    assert compensation_errors(action, state, Fraction(200)) == []
    assert compensation_errors(action, state, Fraction(201)) == ["DOMAIN-COMPENSATION"]
    receipt = state.receipts["LOCK_RECEIPT"].model_copy(update={"sig": "0" * 128})
    bad = state.model_copy(update={"receipts": {receipt.id: receipt}})
    result = check(*recertify(action, cert, bad), phase="propose")
    assert isinstance(result, Reject) and "DOMAIN-COMPENSATION" in result.rule_ids


@pytest.mark.parametrize(
    "event_status,remaining", [("settled", 50), ("reserved", 50), ("unknown", 50), ("failed", 200)]
)
def test_compensation_cumulative_limit_counts_reserved_and_unknown_but_not_failed(
    event_status, remaining
):
    from corridor.schemas.bank import BusinessEvent

    action, _, state = compensation_case()
    previous = BusinessEvent(
        id="UNDO_EVENT",
        intent_key=H("UNDO"),
        event=event_status,
        kind="unlock_funds",
        principal=action.principal,
        debit={"account_ref": "A_LOCKED", "amount": "150/1"},
        credit={"account_ref": "A_CURRENT", "amount": "150/1"},
        object_delta={"action": action.model_dump(mode="json")},
        ts=state.now,
    )
    state = state.model_copy(update={"ledger": [*state.ledger, previous]})
    assert compensation_errors(action, state, Fraction(remaining)) == []
    assert compensation_errors(action, state, Fraction(remaining + 1)) == ["DOMAIN-COMPENSATION"]


def aa_receipt_case():
    from corridor.gateway.analysis import build_analysis
    from corridor.schemas.bank import BusinessEvent, ReceiptTerm
    from corridor.sim.keys import signing_key
    from tests.billing_cases import report_state

    action, cert, state = aa_case()
    state = state.model_copy(
        update={"transactions": report_state().transactions, "merchants": report_state().merchants}
    )
    report_action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "bill_report",
        "args": {
            "account_ref": "A_CURRENT",
            "period": "2026-09",
            "analysis_spec": "bill_summary_v1",
        },
    })
    receipt = build_analysis(report_action, state, signing_key("gateway"))
    event = BusinessEvent(
        id="REPORT_EVENT",
        intent_key=H("REPORT_EVENT"),
        event="settled",
        kind="bill_report",
        principal=action.principal,
        object_delta={"analysis_receipt_id": receipt.id, "receipt_hash": H(receipt)},
        ts=state.now,
    )
    authority = state.authorizations[cert.authorization_ref]
    authority = signed(
        authority.model_copy(
            update={
                "amount_bound": Fraction(1700),
                "object_refs": [*authority.object_refs, receipt.id],
                "input_hashes": [],
            }
        ),
        CONTROL,
    )
    state = state.model_copy(
        update={
            "receipts": {receipt.id: receipt},
            "ledger": [event],
            "user_inputs": {},
            "authorizations": {authority.id: authority},
        }
    )
    action = action.model_copy(
        update={
            "args": action.args.model_copy(
                update={"source_bill_ref": receipt.id, "total_ref": receipt.id}
            )
        }
    )
    terms = {
        **cert.derivations,
        "args.source_bill_ref": ReceiptTerm(receipt_ref=receipt.id, field="receipt_id"),
        "args.total_ref": ReceiptTerm(receipt_ref=receipt.id, field="net_spend"),
    }
    cert = cert.model_copy(update={"derivations": terms, "analysis_receipt_refs": [receipt.id]})
    return recertify(action, cert, state)


def test_aa_builtin_receipt_requires_registered_owner_bound_exact_total():
    action, cert, state = aa_receipt_case()
    result = check(action, cert, state, phase="propose")
    assert isinstance(result, Accept), result
    assert resolve_amount(action, state) == 1700
    receipt = state.receipts[action.args.source_bill_ref]
    for update in (
        {"trust": "exploratory", "program_hash": "1" * 64},
        {"sig": "0" * 128},
        {"parameters": {**receipt.parameters, "principal": "OTHER"}},
    ):
        changed = receipt.model_copy(update=update)
        altered = state.model_copy(update={"receipts": {receipt.id: changed}})
        result = check(*recertify(action, cert, altered), phase="propose")
        assert isinstance(result, Reject)
        assert "PROV-MISMATCH" in result.rule_ids


def test_verified_new_merchant_spa_requires_red_mfa_and_unverified_still_rejects():
    from corridor.schemas.bank import ScheduledPaymentAuthorization
    from corridor.schemas.domain import Merchant
    from corridor.schemas.models import Escalate
    from tests.bank_cases import with_mfa

    action, cert, state = spa_case(Fraction(300))
    merchant = Merchant.model_validate({
        **state.merchants["FLOWERS"].model_dump(mode="python"),
        "is_new": True,
    })
    spa = state.authorizations[cert.authorization_ref]
    spa = signed(
        ScheduledPaymentAuthorization.model_validate({
            **spa.model_dump(mode="python"),
            "target": {
                "kind": "merchant_order",
                "merchant_ref": "FLOWERS",
                "offer_ref": "OFFER_FLOWERS",
            },
            "creation_tier": "red",
        }),
        SPA,
    )
    args = {
        "source_ref": "A_CURRENT",
        "amount_ref": action.args.amount_ref,
        "schedule_ref": spa.id,
        "merchant_ref": "FLOWERS",
        "offer_ref": "OFFER_FLOWERS",
    }
    action = BankAction.model_validate({**action.model_dump(mode="python"), "args": args})
    terms = {key: value for key, value in cert.derivations.items() if key != "args.contact_ref"}
    terms.update({
        "args.merchant_ref": StateTerm(
            collection="merchants", object_ref="FLOWERS", field="id", version=1
        ),
        "args.offer_ref": StateTerm(
            collection="merchants", object_ref="FLOWERS", field="offers", version=1
        ),
    })
    state = state.model_copy(
        update={
            "merchants": {**state.merchants, merchant.id: merchant},
            "authorizations": {spa.id: spa},
        }
    )
    action, cert, state = recertify(action, cert.model_copy(update={"derivations": terms}), state)
    result = check(action, cert, state, phase="propose")
    assert isinstance(result, Escalate) and result.tier == "red"
    assert isinstance(check(*with_mfa(action, cert, state), phase="dispatch"), Accept)
    state = state.model_copy(
        update={
            "merchants": {
                **state.merchants,
                merchant.id: merchant.model_copy(update={"verified": False}),
            }
        }
    )
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject) and "DOMAIN-SPA" in result.rule_ids


@pytest.mark.rule("DOMAIN-SCHEDULE")
def test_waiting_spa_cannot_drop_mfa_requirement_after_business_day_changes():
    from corridor.schemas.models import Escalate
    from corridor.stores.bank import add_seconds
    from tests.bank_cases import with_mfa

    action, cert, state = spa_case(execution=True)
    task = state.schedules[action.action_id].model_copy(update={"status": "waiting_mfa"})
    state = state.model_copy(
        update={"now": add_seconds(task.due_at, 86399), "schedules": {task.id: task}}
    )
    action, cert, state = recertify(action, cert, state)
    result = check(action, cert, state, phase="dispatch")
    assert isinstance(result, Escalate), result
    assert result.tier == "red" and "DOMAIN-SPA-TIER" in result.rule_ids
    assert isinstance(check(*with_mfa(action, cert, state), phase="dispatch"), Accept)
    expired = state.model_copy(update={"now": task.expires_at})
    result = check(*recertify(action, cert, expired), phase="dispatch")
    assert isinstance(result, Reject) and "DOMAIN-SCHEDULE" in result.rule_ids


def test_new_verified_merchant_immediate_order_is_also_red():
    from corridor.schemas.models import Escalate
    from tests.bank_cases import with_mfa

    action, cert, state = transfer_case(Fraction(300))
    merchant = state.merchants["FLOWERS"].model_copy(update={"is_new": True})
    authority = state.authorizations[cert.authorization_ref]
    authority = signed(
        authority.model_copy(
            update={
                "allowed_kind": "merchant_order",
                "object_refs": ["A_CURRENT", "FLOWERS", "OFFER_FLOWERS"],
            }
        ),
        CONTROL,
    )
    state = state.model_copy(
        update={
            "merchants": {**state.merchants, merchant.id: merchant},
            "authorizations": {authority.id: authority},
        }
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "merchant_order",
        "args": {
            "source_ref": "A_CURRENT",
            "merchant_ref": "FLOWERS",
            "offer_ref": "OFFER_FLOWERS",
        },
    })
    terms = {
        "args.source_ref": cert.derivations["args.source_ref"],
        "args.merchant_ref": StateTerm(
            collection="merchants", object_ref="FLOWERS", field="id", version=1
        ),
        "args.offer_ref": StateTerm(
            collection="merchants", object_ref="FLOWERS", field="offers", version=1
        ),
    }
    action, cert, state = recertify(action, cert.model_copy(update={"derivations": terms}), state)
    result = check(action, cert, state, phase="propose")
    assert isinstance(result, Escalate) and result.tier == "red"
    assert isinstance(check(*with_mfa(action, cert, state), phase="dispatch"), Accept)
