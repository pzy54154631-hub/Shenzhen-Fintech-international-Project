"""Permanent regressions for the F1 kernel provenance and authorization review."""

from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT
from corridor.kernel import check
from corridor.kernel.binding import intent_key
from corridor.schemas.bank import (
    BankAction,
    BusinessEvent,
    StateTerm,
    UserInput,
)
from corridor.schemas.models import Accept, Reject
from corridor.stores.bank import add_seconds
from tests.bank_cases import recertify, signed, transfer_case

ZERO = "0" * 128


def _rejected(result, *any_of: str) -> None:
    assert isinstance(result, Reject), f"expected Reject, kernel returned {result!r}"
    if any_of:
        assert set(any_of) & set(result.rule_ids), result.rule_ids


def _with_contacts(state, **updates):
    contacts = dict(state.contacts)
    for cid, change in updates.items():
        contacts[cid] = contacts[cid].model_copy(update=change)
    return state.model_copy(update={"contacts": contacts})


def _settled_transfer(action: BankAction, state, amount: Fraction) -> BusinessEvent:
    return BusinessEvent.model_validate({
        "id": "FIRST_RUN_SETTLED",
        "intent_key": intent_key(action, state),
        "event": "settled",
        "kind": "transfer",
        "principal": action.principal,
        "debit": {"account_ref": "A_CURRENT", "amount": f"{amount.numerator}/1"},
        "object_delta": {"action": action.model_dump(mode="json")},
        "ts": state.now,
        "bank_receipt_id": "RCPT_FIRST",
    })


# --------------------------------------------------------------------------------------
# 1. One signed OperationAuthorization (one user intent, amount_bound=200) must not fund
#    a second transfer just because the planner picked a new node_id / plan_id.
#    DESIGN-BANK 3.2: OperationAuthorization "不是可反复消费的空白授权";
#    4.2: intent_id 来源于设备签名意图，不能由 planner 换 ID 伪造新授权; 用户"再转"必须新 intent.
#    5.3 AUTH-SCOPE: 金额超过该意图签名授权.
# --------------------------------------------------------------------------------------
def test_operation_authorization_cannot_fund_a_second_node_after_settlement() -> None:
    action, cert, state = transfer_case(Fraction(200))
    assert isinstance(check(action, cert, state, phase="dispatch"), Accept)
    state = state.model_copy(update={"ledger": [_settled_transfer(action, state, Fraction(200))]})
    # Planner replays the same signed intent/inputs/authority under a fresh node and action id.
    replay = action.model_copy(
        update={"node_id": "NODE_REPLAY", "action_id": "ACTION_REPLAY", "plan_id": "PLAN_REPLAY"}
    )
    replay, replay_cert, state = recertify(replay, cert, state)
    assert intent_key(replay, state) == intent_key(action, state)
    result = check(replay, replay_cert, state, phase="dispatch")
    _rejected(result, "AUTH-CONSUMED")


def test_operation_authorization_cannot_fund_second_node_while_first_is_unknown() -> None:
    action, cert, state = transfer_case(Fraction(200))
    event = _settled_transfer(action, state, Fraction(200)).model_copy(update={"event": "unknown"})
    state = state.model_copy(update={"ledger": [event]})
    replay = action.model_copy(update={"node_id": "NODE_REPLAY", "action_id": "ACTION_REPLAY"})
    replay, replay_cert, state = recertify(replay, cert, state)
    _rejected(check(replay, replay_cert, state, phase="dispatch"), "AUTH-CONSUMED")


# --------------------------------------------------------------------------------------
# 2. PROV-AMBIGUOUS covers "多手机号匹配或指代歧义" (5.3) and 3.2 says resolution is by
#    name, phone and alias; multiple candidates need a signed unique contact_ref.
# --------------------------------------------------------------------------------------
def test_shared_phone_token_requires_signed_choice() -> None:
    action, cert, state = transfer_case(contact_ref="CONTACT_CHEN")
    # Another of the customer's contacts shares the same (tokenised) phone number.
    state = _with_contacts(state, CONTACT_NEW={"phone_token": "PHONE_CHEN", "is_new": False})
    result = check(*recertify(action, cert, state), phase="propose")
    _rejected(result, "PROV-AMBIGUOUS")


def test_shared_alias_requires_signed_choice() -> None:
    action, cert, state = transfer_case(contact_ref="CONTACT_CHEN")
    state = _with_contacts(state, CONTACT_NEW={"aliases": ["roommate"], "is_new": False})
    result = check(*recertify(action, cert, state), phase="propose")
    _rejected(result, "PROV-AMBIGUOUS")


# Regression guards (expected to pass): same-name contact needs signed selection, and the
# signed selection must name the very contact being paid.
def test_same_name_selection_for_other_contact_does_not_disambiguate() -> None:
    action, cert, state = transfer_case(contact_ref="CONTACT_LIN_B")
    amount = state.user_inputs[action.args.amount_ref]
    selected = signed(
        UserInput(
            id="CONTACT_CHOICE",
            principal=action.principal,
            batch_id=amount.batch_id,
            slot="contact_ref",
            value="CONTACT_LIN_A",
            submitted_at=state.now,
            scope_id=action.intent_id,
            sig=ZERO,
        ),
        INPUT,
    )
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(update={"input_hashes": [*auth.input_hashes, H(selected)]}), CONTROL
    )
    state = state.model_copy(
        update={
            "authorizations": {**state.authorizations, auth.id: auth},
            "user_inputs": {**state.user_inputs, selected.id: selected},
        }
    )
    _rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-AMBIGUOUS")


# --------------------------------------------------------------------------------------
# 3. The user's signed contact selection must agree with the paid contact (5.1:
#    对手与账户不一致 / 混用 → reject). Here the device signed "CONTACT_CHEN" as the payee
#    but the planner pays another contact that also happens to be in object_refs.
# --------------------------------------------------------------------------------------
def test_signed_contact_selection_must_match_paid_contact() -> None:
    action, cert, state = transfer_case(contact_ref="CONTACT_NEW")
    amount = state.user_inputs[action.args.amount_ref]
    selected = signed(
        UserInput(
            id="CONTACT_CHOICE",
            principal=action.principal,
            batch_id=amount.batch_id,
            slot="contact_ref",
            value="CONTACT_CHEN",
            submitted_at=state.now,
            scope_id=action.intent_id,
            sig=ZERO,
        ),
        INPUT,
    )
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(
            update={
                "object_refs": [*auth.object_refs, "CONTACT_CHEN"],
                "input_hashes": [*auth.input_hashes, H(selected)],
            }
        ),
        CONTROL,
    )
    state = _with_contacts(state, CONTACT_NEW={"is_new": False})
    state = state.model_copy(
        update={
            "authorizations": {**state.authorizations, auth.id: auth},
            "user_inputs": {**state.user_inputs, selected.id: selected},
        }
    )
    result = check(*recertify(action, cert, state), phase="propose")
    _rejected(result, "PROV-MISMATCH")


# --------------------------------------------------------------------------------------
# 4. Merchant offer must be inside the signed object scope (AUTH-SCOPE: 对象超过授权).
# --------------------------------------------------------------------------------------
def _merchant_case(object_refs_extra: list[str]):
    action, cert, state = transfer_case(Fraction(300))
    merchants = dict(state.merchants)
    flowers = merchants["FLOWERS"]
    offers = [
        *flowers.offers,
        flowers.offers[0].model_copy(update={"id": "OFFER_FLOWERS_OTHER", "amount": Fraction(250)}),
    ]
    merchants["FLOWERS"] = flowers.model_copy(update={"offers": offers})
    state = state.model_copy(update={"merchants": merchants})
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(
            update={
                "allowed_kind": "merchant_order",
                "object_refs": ["A_CURRENT", "FLOWERS", *object_refs_extra],
                "input_hashes": [],
                "amount_bound": Fraction(300),
            }
        ),
        CONTROL,
    )
    state = state.model_copy(update={"authorizations": {**state.authorizations, auth.id: auth}})
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "merchant_order",
        "args": {
            "merchant_ref": "FLOWERS",
            "offer_ref": "OFFER_FLOWERS_OTHER",
            "source_ref": "A_CURRENT",
        },
    })
    version = state.merchants["FLOWERS"].version
    cert = cert.model_copy(
        update={
            "derivations": {
                "args.merchant_ref": StateTerm(
                    collection="merchants", object_ref="FLOWERS", field="id", version=version
                ),
                "args.offer_ref": StateTerm(
                    collection="merchants", object_ref="FLOWERS", field="offers", version=version
                ),
                "args.source_ref": StateTerm(
                    collection="accounts", object_ref="A_CURRENT", field="id", version=1
                ),
            }
        }
    )
    return recertify(action, cert, state)


def test_merchant_offer_outside_signed_object_refs_is_rejected() -> None:
    # Control: when the offer actually chosen is listed, the order is acceptable.
    assert isinstance(check(*_merchant_case(["OFFER_FLOWERS_OTHER"]), phase="propose"), Accept)
    # User signed authority for FLOWERS / OFFER_FLOWERS only; planner swaps the offer.
    result = check(*_merchant_case(["OFFER_FLOWERS"]), phase="propose")
    _rejected(result, "AUTH-SCOPE")


# --------------------------------------------------------------------------------------
# 5. Cross-principal objects (regression guards).
# --------------------------------------------------------------------------------------
def _with_other_customer_account(state):
    accounts = dict(state.accounts)
    accounts["A_OTHER"] = accounts["A_CURRENT"].model_copy(
        update={"id": "A_OTHER", "owner": "C_OTHER"}
    )
    contacts = dict(state.contacts)
    contacts["CONTACT_OTHER"] = contacts["CONTACT_CHEN"].model_copy(
        update={"id": "CONTACT_OTHER", "owner": "C_OTHER", "name_token": "NAME_OTHER"}
    )
    return state.model_copy(update={"accounts": accounts, "contacts": contacts})


def test_cross_principal_source_or_contact_is_rejected() -> None:
    from corridor.sim.fixtures import make_state

    base = _with_other_customer_account(make_state())
    _rejected(
        check(*transfer_case(source_ref="A_OTHER", state=base), phase="propose"), "AUTH-PRINCIPAL"
    )
    _rejected(
        check(*transfer_case(contact_ref="CONTACT_OTHER", state=base), phase="propose"),
        "AUTH-PRINCIPAL",
    )


# --------------------------------------------------------------------------------------
# 6. Wrong collection / field for a reference (regression guard).
# --------------------------------------------------------------------------------------
def test_contact_ref_derived_from_accounts_collection_is_rejected() -> None:
    action, cert, state = transfer_case()
    cert = cert.model_copy(
        update={
            "derivations": {
                **cert.derivations,
                "args.contact_ref": StateTerm(
                    collection="accounts", object_ref="CONTACT_CHEN", field="id", version=1
                ),
            }
        }
    )
    _rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-FIELD")


# --------------------------------------------------------------------------------------
# 7. SCHEMA-INVALID must be a controlled return; nothing may escape check() (5.3).
# --------------------------------------------------------------------------------------
import pytest  # noqa: E402


@pytest.mark.parametrize("bad_t", [[], {}, ["literal"], {"x": 1}])
def test_unhashable_term_discriminator_does_not_escape_check(bad_t) -> None:
    action, cert, state = transfer_case()
    raw = cert.model_dump(mode="json")
    raw["derivations"]["args.source_ref"]["t"] = bad_t
    try:
        result = check(action, raw, state, phase="dispatch")
    except Exception as exc:  # pragma: no cover - this is the finding
        pytest.fail(f"check() raised {type(exc).__name__}: {exc}")
    _rejected(result, "SCHEMA-INVALID")


# --------------------------------------------------------------------------------------
# 8. Stale schedule objects: an SPA already cancelled cannot be cancelled again as a
#    fresh accepted business action (5.3 DOMAIN-SCHEDULE: 已过期/取消).
# --------------------------------------------------------------------------------------
def _cancel_schedule_case():
    from tests.bank_cases import spa_case

    _, _, state = spa_case(execution=True)
    action, cert, state = transfer_case(intent_id="CANCEL_INTENT", state=state)
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(
            update={
                "allowed_kind": "cancel_schedule",
                "object_refs": ["SPA_TEST"],
                "input_hashes": [],
                "amount_bound": None,
            }
        ),
        CONTROL,
    )
    user_inputs = {k: v for k, v in state.user_inputs.items() if v.scope_id != "CANCEL_INTENT"}
    state = state.model_copy(
        update={
            "authorizations": {**state.authorizations, auth.id: auth},
            "user_inputs": user_inputs,
        }
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "cancel_schedule",
        "args": {"schedule_ref": "SPA_TEST"},
    })
    cert = cert.model_copy(
        update={
            "derivations": {
                "args.schedule_ref": StateTerm(
                    collection="authorizations", object_ref="SPA_TEST", field="id", version=1
                )
            }
        }
    )
    return recertify(action, cert, state)


def test_cancel_of_already_cancelled_schedule_is_rejected() -> None:
    action, cert, state = _cancel_schedule_case()
    assert isinstance(check(action, cert, state, phase="propose"), Accept)
    cancelled = BusinessEvent.model_validate({
        "id": "CANCELLED_BEFORE",
        "intent_key": H("earlier-cancel"),
        "event": "settled",
        "kind": "cancel_schedule",
        "principal": action.principal,
        "object_delta": {"spa_ref": "SPA_TEST"},
        "ts": state.now,
    })
    state = state.model_copy(update={"ledger": [*state.ledger, cancelled]})
    _rejected(check(*recertify(action, cert, state), phase="propose"), "DOMAIN-SCHEDULE")


def test_cancel_of_expired_schedule_is_rejected() -> None:
    action, cert, state = _cancel_schedule_case()
    expired_at = state.authorizations[action.args.schedule_ref].end
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(auth.model_copy(update={"expires_at": add_seconds(expired_at, 3600)}), CONTROL)
    state = state.model_copy(
        update={
            "now": expired_at,
            "authorizations": {**state.authorizations, auth.id: auth},
        }
    )
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject)
    assert result.rule_ids == ["DOMAIN-SCHEDULE"]


# Regression guard: amount and payee from two different batches of the same intent.
def test_amount_and_contact_from_two_batches_are_incoherent() -> None:
    action, cert, state = transfer_case()
    selected = signed(
        UserInput(
            id="CONTACT_CHOICE_OTHER_BATCH",
            principal=action.principal,
            batch_id="SOME_OTHER_BATCH",
            slot="contact_ref",
            value="CONTACT_CHEN",
            submitted_at=state.now,
            scope_id=action.intent_id,
            sig=ZERO,
        ),
        INPUT,
    )
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(update={"input_hashes": [*auth.input_hashes, H(selected)]}), CONTROL
    )
    state = state.model_copy(
        update={
            "authorizations": {**state.authorizations, auth.id: auth},
            "user_inputs": {**state.user_inputs, selected.id: selected},
        }
    )
    _rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-COHERENCE")


# Regression guard backing the test-quality note: a real *paid* order (the scenario the
# golden DOMAIN-COMPENSATION test claims to cover) is rejected by the current code.
def test_really_paid_order_cannot_be_cancelled() -> None:
    action, cert, state = transfer_case()
    from corridor.schemas.domain import MerchantOrder

    order = MerchantOrder.model_validate({
        "id": "ORDER_PAID",
        "owner": action.principal,
        "merchant_ref": "FLOWERS",
        "offer_ref": "OFFER_FLOWERS",
        "amount": "300/1",
        "status": "paid",
    })
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(
            update={
                "allowed_kind": "cancel_order",
                "object_refs": [order.id],
                "input_hashes": [],
                "amount_bound": None,
            }
        ),
        CONTROL,
    )
    state = state.model_copy(
        update={
            "orders": {order.id: order},
            "authorizations": {**state.authorizations, auth.id: auth},
            "user_inputs": {},
        }
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "cancel_order",
        "args": {"order_ref": order.id},
    })
    cert = cert.model_copy(
        update={
            "derivations": {
                "args.order_ref": StateTerm(
                    collection="orders", object_ref=order.id, field="id", version=1
                )
            }
        }
    )
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject), result
    # Only domain rules fire: the paid status is the sole reason for rejection.
    assert set(result.rule_ids) == {"DOMAIN-STATE", "DOMAIN-COMPENSATION"}, result.rule_ids
