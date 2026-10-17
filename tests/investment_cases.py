"""Independent B7 signed inputs and hand-calculated complete certificates."""

from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL
from corridor.schemas.bank import (
    BankAction,
    BankCertificate,
    BestInterestCertificate,
    InputTerm,
    StateTerm,
)
from corridor.schemas.domain import InvestmentPreference, Position
from corridor.schemas.state import BankState
from corridor.sim.device import Device
from corridor.sim.fixtures import make_state
from corridor.stores.bank import add_seconds
from tests.bank_cases import PRINCIPAL, SESSION, recertify, signed


def preference(**changes):
    return InvestmentPreference.model_validate({
        "id": "PREFERENCE",
        "source_account_ref": "A_CURRENT",
        "amount": "1000/1",
        "horizon_days": 365,
        "max_access_days": 1,
        "allowed_types": ["wealth"],
        "objective": "net_return",
        "selection_mode": "default",
        **changes,
    })


def hand_bic(state: BankState, input_ref: str, chosen: str = "P_A"):
    return BestInterestCertificate.model_validate({
        "catalog_hash": H(state.catalog),
        "preference_hash": H(state.user_inputs[input_ref]),
        "risk_assessment_hash": H(state.risk_assessments["RISK_DEMO"]),
        "candidate_ids": ["P_A", "P_B"],
        "rows": [
            {
                "product_id": "P_A",
                "fee_buy": "0/1",
                "fee_hold": "0/1",
                "fee_sell": "0/1",
                "total_fee": "0/1",
                "expected_net": "30/1",
                "access_days": 30,
                "rank": 1,
                "gap": "0/1",
            },
            {
                "product_id": "P_B",
                "fee_buy": "10/1",
                "fee_hold": "0/1",
                "fee_sell": "0/1",
                "total_fee": "10/1",
                "expected_net": "25/1",
                "access_days": 11,
                "rank": 2,
                "gap": "5/1",
            },
        ],
        "chosen_product_id": chosen,
        "selection_mode": "default",
        "best_choice": chosen == "P_A",
    })


def investment_case(*, kind="product_compare", pref=None, state=None, chosen="P_A"):
    state = state or make_state()
    pref = pref or preference()
    device = Device()
    intent = "INVESTMENT_TEST"
    signed_pref = device.confirm_input(
        intent_id=intent, slot="preference", value=pref.model_dump(mode="json"), now=state.now
    )
    amount = device.confirm_input(
        intent_id=intent,
        slot="amount",
        value={"amount": str(pref.amount), "ccy": "CNY"},
        now=state.now,
    )
    state = state.model_copy(
        update={
            "user_inputs": {**state.user_inputs, signed_pref.id: signed_pref, amount.id: amount},
            "security": state.security.model_copy(
                update={"active_device_sessions": {PRINCIPAL: SESSION}}
            ),
        }
    )
    terms = {"args.preference_ref": InputTerm(input_ref=signed_pref.id, slot="preference")}
    args = {"preference_ref": signed_pref.id}
    if kind == "product_compare":
        auth = device.login(session_id=SESSION, expires_at=add_seconds(state.now, 3600))
        auth = signed(
            auth.model_copy(
                update={"read_kinds": ["product_compare", "risk_assess", "investment_income_query"]}
            ),
            CONTROL,
        )
    else:
        auth = device.authorize({
            "id": "INVESTMENT_AUTH",
            "intent_id": intent,
            "allowed_kind": kind,
            "object_refs": [pref.source_account_ref, chosen],
            "amount_bound": pref.amount,
            "expires_at": add_seconds(state.now, 3600),
            "input_hashes": [H(signed_pref), H(amount)],
        })
        args.update(source_ref=pref.source_account_ref, product_ref=chosen, amount_ref=amount.id)
        terms.update({
            "args.source_ref": StateTerm(
                collection="accounts", object_ref=pref.source_account_ref, field="id", version=1
            ),
            "args.product_ref": StateTerm(
                collection="catalog", object_ref=chosen, field="id", version=1
            ),
            "args.amount_ref": InputTerm(input_ref=amount.id, slot="amount"),
        })
    state = state.model_copy(update={"authorizations": {**state.authorizations, auth.id: auth}})
    action = BankAction.model_validate({
        "action_id": "INVESTMENT_ACTION",
        "intent_id": intent,
        "principal": PRINCIPAL,
        "device_session_id": SESSION,
        "plan_id": "INVESTMENT_PLAN",
        "plan_hash": "1" * 64,
        "node_id": "INVESTMENT_NODE",
        "kind": kind,
        "args": args,
    })
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=auth.id,
        derivations=terms,
        dependency_hashes={},
        best_interest=hand_bic(state, signed_pref.id, chosen),
    )
    return recertify(action, cert, state)


def redemption_case(*, amount=Fraction(1000), state=None, kind="redeem_product"):
    state = state or make_state()
    position = Position(
        id="LOT_A",
        owner=PRINCIPAL,
        product_ref="P_A",
        principal_amount=Fraction(1000),
        units=Fraction(1000),
        reserved_units=Fraction(0),
        nav=Fraction(1),
        acquired_at=add_seconds(state.now, -365 * 86400),
        redeemable_at=add_seconds(state.now, -335 * 86400),
        status="active",
    )
    state = state.model_copy(update={"positions": {position.id: position}})
    action, cert, state = investment_case(state=state)
    device = Device()
    value = device.confirm_input(
        intent_id=action.intent_id,
        slot="amount",
        value={"amount": str(amount), "ccy": "CNY"},
        now=state.now,
    )
    args = {"position_ref": position.id}
    terms = {
        "args.position_ref": StateTerm(
            collection="positions", object_ref=position.id, field="id", version=1
        )
    }
    if kind == "redeem_product":
        args["amount_ref"] = value.id
        terms["args.amount_ref"] = InputTerm(input_ref=value.id, slot="amount")
        auth = device.authorize({
            "id": "REDEEM_AUTH",
            "intent_id": action.intent_id,
            "allowed_kind": kind,
            "object_refs": [position.id],
            "amount_bound": amount,
            "expires_at": add_seconds(state.now, 3600),
            "input_hashes": [H(value)],
        })
    else:
        auth = state.authorizations[cert.authorization_ref]
    state = state.model_copy(
        update={
            "authorizations": {**state.authorizations, auth.id: auth},
            "user_inputs": {**state.user_inputs, value.id: value},
        }
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": kind,
        "args": args,
    })
    cert = cert.model_copy(
        update={"authorization_ref": auth.id, "derivations": terms, "best_interest": None}
    )
    return recertify(action, cert, state)
