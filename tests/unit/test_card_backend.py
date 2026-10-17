"""Independent hand-written card state transitions and bank receipt reconciliation."""

from fractions import Fraction
from hashlib import sha256

import pytest
from nacl.signing import SigningKey
from pydantic import ValidationError

from corridor.crypto.sign import RECEIPT, sign, verify
from corridor.eval.mockbank.exec import MockBank
from corridor.gateway import bank_adapter
from corridor.schemas.bank import BankOrder
from corridor.schemas.state import BankState

NOW = "2026-10-16T02:00:00Z"
KEY = SigningKey(sha256(b"corridor-demo-v0|card-backend-unit|20261016").digest())


@pytest.fixture
def initial() -> BankState:
    return BankState.model_validate({
        "now": NOW,
        "roots": {
            name: KEY.verify_key.encode().hex()
            for name in ("bank_pubkey", "risk_pubkey", "gateway_pubkey")
        },
        "catalog": {
            "id": "catalog",
            "issued_at": NOW,
            "valid_until": "2027-10-16T02:00:00Z",
            "products": [],
            "sig": "0" * 128,
        },
        "accounts": {
            "current": {
                "id": "current",
                "owner": "C",
                "kind": "current",
                "opening_balance": "10000",
                "floor": "0",
                "status": "active",
            }
        },
        "cards": {
            "CARD": {
                "id": "CARD",
                "owner": "C",
                "account_ref": "current",
                "status": "active",
                "limit": "1000",
                "restrictions": ["gambling"],
                "card_token": "CARD_TOKEN_INITIAL",
            }
        },
    })


def order(kind: str, *, key: str = "card-test", **args: object) -> BankOrder:
    return BankOrder.model_validate({
        "intent_key": sha256(key.encode()).hexdigest(),
        "action_id": key,
        "principal": "C",
        "kind": kind,
        "requested_at": NOW,
        "args": args,
    })


def authorize(bank: MockBank, amount: Fraction = Fraction(100), category: str = "food") -> bool:
    return bank_adapter.card_authorize(bank, "CARD", amount, category)


def test_application_creates_one_exact_synthetic_card_per_intent(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    request = order("apply_virtual_card", account_ref="current", limit="1000")
    receipt = bank.execute(request)
    assert receipt.status == "settled"
    assert verify(KEY.verify_key, RECEIPT, receipt, receipt.sig)
    assert len(receipt.exact_effects) == 1
    effect = receipt.exact_effects[0]
    assert effect.effect_type == "state" and effect.field == "card" and effect.before is None
    created = bank.final_state()["cards"][effect.object_ref]
    assert created == {
        "id": effect.object_ref,
        "version": 1,
        "owner": "C",
        "account_ref": "current",
        "kind": "virtual",
        "status": "active",
        "limit": "1000/1",
        "restrictions": [],
        "card_token": "CARD_TOKEN_hpjjjgbbihfdoahf",
    }
    assert bank.execute(request) == receipt
    assert len(bank.final_state()["cards"]) == 2
    assert bank.final_state()["balances"] == {"current": "10000/1"}
    assert bank_adapter.validate_receipt(request, receipt, initial)
    changes = bank_adapter.receipt_updates(request, receipt, initial)
    assert changes["cards"][effect.object_ref].model_dump(mode="json") == created


def test_application_response_loss_recovers_the_same_card(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    request = order("apply_virtual_card", account_ref="current", limit="1000")
    bank.faults[request.intent_key] = "response_loss"
    with pytest.raises(TimeoutError):
        bank.execute(request)
    receipt = bank.lookup(request.intent_key)
    assert receipt is not None and receipt.status == "settled"
    assert bank_adapter.validate_receipt(request, receipt, initial)
    assert bank.execute(request) == receipt
    assert len(bank.final_state()["cards"]) == 2
    assert len(bank.final_state()["events"]) == 1


def test_backend_does_not_enforce_user_authorization(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    request = order("freeze_card", card_ref="CARD").model_copy(update={"principal": "OTHER"})
    receipt = bank.execute(request)
    assert receipt.status == "settled"
    assert bank.final_state()["cards"]["CARD"]["status"] == "frozen"
    assert not bank_adapter.validate_receipt(request, receipt, initial)


@pytest.mark.parametrize(
    "kind,args",
    [
        ("lower_card_limit", {"limit": "200"}),
        ("raise_card_limit", {"limit": "1100"}),
        ("restrict_card", {"restrictions": ["food", "gambling"]}),
        ("relax_card_restriction", {"restrictions": []}),
    ],
)
@pytest.mark.parametrize("status", ["frozen", "lost"])
def test_limit_controls_on_frozen_and_lost_cards(
    initial: BankState, kind: str, args: dict, status: str
) -> None:
    initial = initial.model_copy(
        update={"cards": {"CARD": initial.cards["CARD"].model_copy(update={"status": status})}}
    )
    bank = MockBank(initial, KEY)
    request = order(kind, card_ref="CARD", **args)
    receipt = bank.execute(request)
    assert receipt.status == ("settled" if status == "frozen" else "failed")
    assert bank_adapter.validate_receipt(request, receipt, initial)
    assert not authorize(bank)
    if status == "lost":
        assert receipt.exact_effects == []
        assert bank.final_state()["cards"]["CARD"] == initial.cards["CARD"].model_dump(mode="json")


def test_frozen_lost_and_restored_cards_preserve_other_controls(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    state = initial
    assert authorize(bank)
    for index, (kind, expected) in enumerate([
        ("freeze_card", "frozen"),
        ("report_card_lost", "lost"),
        ("restore_card", "frozen"),
        ("unfreeze_card", "active"),
    ]):
        request = order(kind, key=f"transition-{index}", card_ref="CARD")
        receipt = bank.execute(request)
        assert receipt.status == "settled"
        assert bank_adapter.validate_receipt(request, receipt, state)
        state = state.model_copy(update=bank_adapter.receipt_updates(request, receipt, state))
        card = state.cards["CARD"]
        assert card.status == expected and card.version == index + 2
        assert card.limit == 1000 and card.restrictions == ["gambling"]
        assert authorize(bank) is (expected == "active")
        assert not authorize(bank, category="gambling")
    assert bank.final_state()["cards"]["CARD"] == state.cards["CARD"].model_dump(mode="json")


@pytest.mark.parametrize(
    "status,kind",
    [
        ("active", "unfreeze_card"),
        ("active", "restore_card"),
        ("frozen", "freeze_card"),
        ("frozen", "restore_card"),
        ("lost", "freeze_card"),
        ("lost", "unfreeze_card"),
        ("lost", "report_card_lost"),
    ],
)
def test_invalid_state_transition_has_no_effect(initial: BankState, status: str, kind: str) -> None:
    initial = initial.model_copy(
        update={"cards": {"CARD": initial.cards["CARD"].model_copy(update={"status": status})}}
    )
    bank = MockBank(initial, KEY)
    before = bank.final_state()["cards"]
    receipt = bank.execute(order(kind, card_ref="CARD"))
    assert receipt.status == "failed" and receipt.exact_effects == []
    assert bank.final_state()["cards"] == before


def test_limit_and_category_controls_change_authorization_exactly(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    state = initial
    changes = [
        ("lower_card_limit", {"limit": "200"}),
        ("restrict_card", {"restrictions": ["food", "gambling"]}),
        ("raise_card_limit", {"limit": "1500"}),
        ("relax_card_restriction", {"restrictions": ["gambling"]}),
    ]
    for index, (kind, args) in enumerate(changes):
        request = order(kind, key=f"controls-{index}", card_ref="CARD", **args)
        receipt = bank.execute(request)
        assert receipt.status == "settled"
        assert bank_adapter.validate_receipt(request, receipt, state)
        state = state.model_copy(update=bank_adapter.receipt_updates(request, receipt, state))
        if index == 0:
            assert authorize(bank, Fraction(200))
            assert not authorize(bank, Fraction(20001, 100))
        if index in {1, 2}:
            assert not authorize(bank)
        assert not authorize(bank, category="gambling")
    assert authorize(bank, Fraction(1500))
    assert not authorize(bank, Fraction(150001, 100))
    assert state.cards["CARD"].limit == 1500
    assert state.cards["CARD"].restrictions == ["gambling"]


@pytest.mark.parametrize(
    "kind,args",
    [
        ("lower_card_limit", {"limit": "1000"}),
        ("lower_card_limit", {"limit": "1100"}),
        ("raise_card_limit", {"limit": "1000"}),
        ("raise_card_limit", {"limit": "900"}),
        ("restrict_card", {"restrictions": ["gambling"]}),
        ("restrict_card", {"restrictions": ["food"]}),
        ("relax_card_restriction", {"restrictions": ["gambling"]}),
        ("relax_card_restriction", {"restrictions": ["food"]}),
    ],
)
def test_control_direction_mismatch_has_no_effect(
    initial: BankState, kind: str, args: dict
) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(order(kind, card_ref="CARD", **args))
    assert receipt.status == "failed" and receipt.exact_effects == []
    assert bank.final_state()["cards"]["CARD"] == initial.cards["CARD"].model_dump(mode="json")


@pytest.mark.parametrize("limit", ["0", "-1", "1/1000"])
def test_invalid_limit_is_rejected_at_bank_wire(limit: str) -> None:
    with pytest.raises(ValidationError):
        order("lower_card_limit", card_ref="CARD", limit=limit)


@pytest.mark.parametrize("amount", [Fraction(0), Fraction(-1), Fraction(1, 1000)])
def test_invalid_authorization_amount_has_no_effect(initial: BankState, amount: Fraction) -> None:
    bank = MockBank(initial, KEY)
    before = bank.final_state()
    assert not authorize(bank, amount)
    assert bank.final_state() == before


def test_authorization_probe_is_read_only_and_unknown_cards_fail(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    before = bank.final_state()
    assert authorize(bank)
    assert not bank_adapter.card_authorize(bank, "MISSING", Fraction(1), "food")
    assert bank.final_state() == before
    assert bank.execute_count == 0


@pytest.mark.parametrize("mutation", ["before", "extra", "object", "status", "stale"])
def test_card_receipt_rejects_wrong_shape_or_stale_state(initial: BankState, mutation: str) -> None:
    request = order("freeze_card", card_ref="CARD")
    receipt = MockBank(initial, KEY).execute(request)
    effects = list(receipt.exact_effects)
    if mutation == "before":
        effects[0] = effects[0].model_copy(update={"before": None})
    elif mutation == "extra":
        effects.append(effects[0])
    elif mutation == "object":
        effects[0] = effects[0].model_copy(update={"object_ref": "OTHER"})
    elif mutation == "stale":
        initial = initial.model_copy(
            update={"cards": {"CARD": initial.cards["CARD"].model_copy(update={"version": 2})}}
        )
    changed = receipt.model_copy(
        update={"exact_effects": effects, "status": "failed" if mutation == "status" else "settled"}
    )
    changed = changed.model_copy(update={"sig": sign(KEY, RECEIPT, changed)})
    assert not bank_adapter.validate_receipt(request, changed, initial)


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "active"),
        ("limit", "1001/1"),
        ("owner", "OTHER"),
        ("account_ref", "OTHER"),
        ("restrictions", []),
        ("version", 99),
        ("card_token", "CARD_TOKEN_CHANGED"),
    ],
)
def test_signed_but_wrong_card_effects_are_rejected(initial: BankState, field: str, value) -> None:
    request = order("freeze_card", card_ref="CARD")
    receipt = MockBank(initial, KEY).execute(request)
    effect = receipt.exact_effects[0]
    assert isinstance(effect.after, dict)
    changed = receipt.model_copy(
        update={
            "exact_effects": [effect.model_copy(update={"after": {**effect.after, field: value}})]
        }
    )
    changed = changed.model_copy(update={"sig": sign(KEY, RECEIPT, changed)})
    assert not bank_adapter.validate_receipt(request, changed, initial)
