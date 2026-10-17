"""Hand-calculated backend effects, independent of authorization and recommendation code."""

from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction
from hashlib import sha256

import pytest
from nacl.signing import SigningKey

from corridor.crypto.sign import RECEIPT, verify
from corridor.eval.mockbank.exec import MockBank
from corridor.schemas.bank import BankOrder
from corridor.schemas.state import BankState

NOW = "2026-10-16T02:00:00Z"
KEY = SigningKey(sha256(b"corridor-demo-v0|mockbank-unit|20261016").digest())


@pytest.fixture
def initial() -> BankState:
    return BankState.model_validate({
        "now": NOW,
        "roots": {
            name: KEY.verify_key.encode().hex()
            for name in ("bank_pubkey", "risk_pubkey", "gateway_pubkey")
        },
        "accounts": {
            "current": {
                "id": "current",
                "owner": "C",
                "kind": "current",
                "opening_balance": "10000",
                "floor": "0",
                "status": "active",
            },
            "locked": {
                "id": "locked",
                "owner": "C",
                "kind": "locked",
                "opening_balance": "0",
                "floor": "0",
                "status": "active",
                "parent_ref": "current",
            },
        },
        "contacts": {
            ref: {
                "id": ref,
                "owner": "C",
                "name_token": ref,
                "destination_ref": dest,
                "is_new": ref == "new",
            }
            for ref, dest in [("friend", "DEST_GOOD"), ("wrong", "DEST_WRONG"), ("new", "DEST_NEW")]
        },
        "catalog": {
            "id": "catalog",
            "issued_at": NOW,
            "valid_until": "2027-10-16T02:00:00Z",
            "sig": "0" * 128,
            "products": [
                {
                    "product_id": "P",
                    "type": "wealth",
                    "risk_level": 5,
                    "min_amount": "100",
                    "purchase_open": True,
                    "eligible_customers": ["C"],
                    "min_hold_days": 1,
                    "redeem_delay_days": 1,
                    "expected_annual_rate": "1/10",
                    "purchase_fee_rate": "1/100",
                    "annual_fee_rate": "365/10000",
                    "redemption_fee_rate": "1/100",
                }
            ],
        },
        "merchants": {
            "shop": {
                "id": "shop",
                "display_alias": "Synthetic shop",
                "category_code": "gift",
                "destination_ref": "DEST_SHOP",
                "verified": True,
                "offers": [
                    {"id": "flowers", "amount": "300", "cancel_until": "2026-10-18T02:00:00Z"}
                ],
            }
        },
        "subscriptions": {
            "S1": {
                "id": "S1",
                "owner": "C",
                "merchant_ref": "shop",
                "source_account_ref": "current",
                "amount": "49",
                "period_months": 1,
                "next_due": "2026-10-19T02:00:00Z",
                "status": "active",
                "bank_authorization_ref": "AUTH_S1",
            }
        },
    })


def order(
    kind: str = "transfer", *, key: str = "one", at: str = NOW, principal: str = "C", **args: object
) -> BankOrder:
    if kind == "transfer":
        args = {
            "source_ref": "current",
            "contact_ref": "friend",
            "destination_ref": "DEST_GOOD",
            "amount": "200",
            **args,
        }
    return BankOrder.model_validate({
        "intent_key": sha256(key.encode()).hexdigest(),
        "action_id": key,
        "principal": principal,
        "kind": kind,
        "requested_at": at,
        "args": args,
    })


def amount(bank: MockBank, account: str = "current") -> Fraction:
    return Fraction(bank.final_state()["balances"][account])


def test_transfer_has_exact_effects_and_valid_signature(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(order())
    assert receipt.status == "settled"
    assert amount(bank) == 9800
    assert bank.final_state()["destinations"] == {"DEST_GOOD": "200/1"}
    assert receipt.exact_effects[0].amount == 200
    assert receipt.exact_effects[0].counterparty_ref == "DEST_GOOD"
    assert verify(KEY.verify_key, RECEIPT, receipt, receipt.sig)
    assert initial.accounts["current"].opening_balance == 10000


def test_wrong_recipient_and_absent_authority_are_executed(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(
        order(
            contact_ref="wrong",
            destination_ref="DEST_WRONG",
            amount="201",
            principal="UNAUTHORIZED",
        )
    )
    assert receipt.status == "settled"
    assert amount(bank) == 9799
    assert bank.final_state()["destinations"] == {"DEST_WRONG": "201/1"}


def test_duplicate_key_does_not_repeat_or_replace_effect(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(order())
    assert bank.execute(order(amount="500")) == receipt
    assert bank.lookup(receipt.intent_key) == receipt
    assert amount(bank) == 9800
    assert len(bank.final_state()["events"]) == 1
    assert bank.execute_count == 2


def test_response_loss_commits_once_and_lookup_recovers(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    request = order()
    bank.faults[request.intent_key] = "response_loss"
    with pytest.raises(TimeoutError):
        bank.execute(request)
    receipt = bank.lookup(request.intent_key)
    assert receipt is not None and receipt.status == "settled"
    assert bank.execute(request) == receipt
    assert amount(bank) == 9800
    assert len(bank.final_state()["events"]) == 1


@pytest.mark.parametrize("failure", ["failed", "disk_error"])
def test_injected_precommit_failure_is_stable_and_has_no_effect(
    initial: BankState, failure: str
) -> None:
    bank = MockBank(initial, KEY)
    request = order()
    bank.faults[request.intent_key] = failure
    receipt = bank.execute(request)
    assert receipt.status == "failed" and receipt.exact_effects == []
    assert bank.execute(request) == receipt
    assert amount(bank) == 10000
    del bank.faults[request.intent_key]
    assert bank.execute(request).status == "settled"
    assert amount(bank) == 9800


def test_bad_signature_fault_does_not_hide_real_bank_effect(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    request = order()
    bank.faults[request.intent_key] = "bad_signature"
    receipt = bank.execute(request)
    assert not verify(KEY.verify_key, RECEIPT, receipt, receipt.sig)
    assert amount(bank) == 9800
    canonical = bank.lookup(request.intent_key)
    assert canonical is not None
    assert verify(KEY.verify_key, RECEIPT, canonical, canonical.sig)
    assert canonical.exact_effects == receipt.exact_effects


@pytest.mark.parametrize(
    "changes",
    [
        {"amount": "10000.01"},
        {"source_ref": "missing"},
        {"contact_ref": "missing"},
        {"destination_ref": "UNKNOWN"},
        {"source_ref": "locked"},
    ],
)
def test_database_inconsistent_transfer_has_no_partial_effect(
    initial: BankState, changes: dict[str, str]
) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(order(**changes))
    assert receipt.status == "failed"
    assert amount(bank) == 10000
    assert bank.final_state()["destinations"] == {}


def test_lock_unlock_conserve_money_and_do_not_run_spa(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    args = {
        "source_ref": "current",
        "locked_ref": "locked",
        "amount": "1000",
        "purpose_ref": "birthday",
    }
    assert bank.execute(order("lock_funds", **args)).status == "settled"
    assert (amount(bank), amount(bank, "locked")) == (9000, 1000)
    args["amount"] = "500"
    assert bank.execute(order("unlock_funds", key="unlock", **args)).status == "settled"
    assert (amount(bank), amount(bank, "locked")) == (9500, 500)
    bank.advance_clock("2026-10-18T02:00:00Z")
    assert (amount(bank), amount(bank, "locked")) == (9500, 500)


def test_cancel_subscription_blocks_future_charge_and_preserves_history(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    before = bank.final_state()["transactions"]
    receipt = bank.execute(order("cancel_subscription", authorization_ref="S1"))
    assert receipt.status == "settled"
    assert (
        bank.execute(
            order("cancel_subscription", key="again", authorization_ref="S1")
        ).exact_effects
        == []
    )
    assert bank.advance_clock("2026-12-20T02:00:00Z") == []
    assert amount(bank) == 10000
    assert bank.final_state()["transactions"] == before


def test_monthly_charges_are_once_per_due_date(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    events = bank.advance_clock("2026-12-19T02:00:00Z")
    assert len(events) == 3
    assert amount(bank) == 9853
    assert bank.final_state()["destinations"] == {"DEST_SHOP": "147/1"}
    assert bank.advance_clock("2026-12-19T02:00:00Z") == []
    assert bank.final_state()["subscriptions"]["S1"]["next_due"] == "2027-01-19T02:00:00Z"
    assert all(
        any(
            effect.object_ref == "S1" and effect.field == "next_due"
            for effect in receipt.exact_effects
        )
        for receipt in events
    )


def test_failed_subscription_charge_does_not_overdraw_or_retry_same_due(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    bank.execute(order(amount="9990"))
    events = bank.advance_clock("2026-10-19T02:00:00Z")
    assert len(events) == 1 and events[0].status == "failed"
    assert amount(bank) == 10
    assert bank.advance_clock("2026-10-19T02:00:00Z") == []


def purchase(bank: MockBank, **changes: object):
    args = {
        "source_ref": "current",
        "product_ref": "P",
        "amount": "1000",
        "fee_buy": "10",
        **changes,
    }
    return bank.execute(order("purchase_product", **args))


def test_purchase_books_principal_and_fee_without_applying_suitability(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    receipt = purchase(bank)
    assert receipt.status == "settled"
    assert amount(bank) == 8990
    position = next(iter(bank.final_state()["positions"].values()))
    assert Fraction(position["principal_amount"]) == 1000
    assert Fraction(position["units"]) == 1000
    assert position["redeemable_at"] == "2026-10-17T02:00:00Z"
    assert any(
        e.effect_type == "position" and e.after["product_ref"] == "P" for e in receipt.exact_effects
    )


def test_wrong_purchase_fee_fails_atomically(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    assert purchase(bank, fee_buy="9.99").status == "failed"
    assert amount(bank) == 10000
    assert bank.final_state()["positions"] == {}


def test_redemption_reserves_then_settles_exact_fees_without_expected_yield(
    initial: BankState,
) -> None:
    bank = MockBank(initial, KEY)
    purchase(bank)
    position_ref = next(iter(bank.final_state()["positions"]))
    request = order(
        "redeem_product",
        key="redeem",
        at="2026-10-17T02:00:00Z",
        position_ref=position_ref,
        amount="500",
    )
    assert bank.execute(request).status == "failed"  # The bank clock has not advanced.
    bank.advance_clock("2026-10-17T02:00:00Z")
    request = order(
        "redeem_product",
        key="redeem2",
        at="2026-10-17T02:00:00Z",
        position_ref=position_ref,
        amount="500",
    )
    pending = bank.execute(request)
    assert pending.status == "pending"
    assert amount(bank) == 8990
    assert Fraction(bank.final_state()["positions"][position_ref]["reserved_units"]) == 500
    over = order(
        "redeem_product",
        key="oversell",
        at="2026-10-17T02:00:00Z",
        position_ref=position_ref,
        amount="500.01",
    )
    assert bank.execute(over).status == "failed"
    events = bank.advance_clock("2026-10-18T02:00:00Z")
    assert len(events) == 1 and events[0].status == "settled"
    # 500 principal minus 0.05 management and 5 redemption fee.
    assert amount(bank) == Fraction("9484.95")
    position = bank.final_state()["positions"][position_ref]
    assert Fraction(position["units"]) == 500
    assert Fraction(position["reserved_units"]) == 0
    assert bank.lookup(request.intent_key) == events[0]
    assert bank.advance_clock("2026-10-18T02:00:00Z") == []


def test_paid_merchant_order_only_allows_refund_request(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    paid = bank.execute(
        order(
            "merchant_order",
            source_ref="current",
            merchant_ref="shop",
            offer_ref="flowers",
            destination_ref="DEST_SHOP",
            amount="300",
        )
    )
    order_ref = next(iter(bank.final_state()["orders"]))
    assert paid.status == "settled" and amount(bank) == 9700
    cancel = bank.execute(order("cancel_order", key="cancel", order_ref=order_ref))
    assert cancel.status == "failed" and amount(bank) == 9700
    refund = bank.execute(order("refund_request", key="refund", receipt_ref=paid.receipt_id))
    assert refund.status == "settled" and amount(bank) == 9700
    assert bank.final_state()["orders"][order_ref]["status"] == "refund_pending"
    assert (
        bank.execute(
            order("refund_request", key="repeat", receipt_ref=paid.receipt_id)
        ).exact_effects
        == []
    )


def test_transfer_refund_request_never_reverses_money(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    paid = bank.execute(order())
    request = bank.execute(order("refund_request", key="refund", receipt_ref=paid.receipt_id))
    assert request.status == "settled"
    assert amount(bank) == 9800
    assert bank.final_state()["destinations"] == {"DEST_GOOD": "200/1"}
    assert next(iter(bank.final_state()["refund_requests"].values()))["status"] == "pending"


def test_query_receipt_and_returned_state_do_not_mutate_backend(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(order("balance_query", account_ref="current"))
    assert receipt.status == "settled"
    assert receipt.exact_effects[0].after == "10000/1"
    final = bank.final_state()
    final["balances"]["current"] = "0/1"
    assert amount(bank) == 10000
    with pytest.raises(ValueError, match="backward"):
        bank.advance_clock("2026-10-15T02:00:00Z")


def test_initial_business_events_count_only_latest_and_ignore_display_transactions(
    initial: BankState,
) -> None:
    data = initial.model_dump(mode="python")
    data["ledger"] = [
        {
            "id": f"e{i}",
            "intent_key": sha256(key.encode()).hexdigest(),
            "event": state,
            "kind": "transfer",
            "principal": "C",
            "debit": {"account_ref": "current", "amount": Fraction(value)},
            "ts": NOW,
        }
        for i, (key, state, value) in enumerate([
            ("one", "reserved", 200),
            ("one", "unknown", 200),
            ("two", "reserved", 100),
            ("two", "failed", 100),
            ("three", "settled", 300),
        ])
    ]
    bank = MockBank(BankState.model_validate(data), KEY)
    assert amount(bank) == 9500


def test_non_unique_initial_position_return_account_fails(initial: BankState) -> None:
    data = initial.model_dump(mode="python")
    data["accounts"]["other"] = {**data["accounts"]["current"], "id": "other"}
    data["positions"]["owned"] = {
        "id": "owned",
        "owner": "C",
        "product_ref": "P",
        "principal_amount": "1000",
        "units": "1000",
        "reserved_units": "0",
        "nav": "1",
        "acquired_at": "2026-10-14T02:00:00Z",
        "redeemable_at": "2026-10-15T02:00:00Z",
        "status": "active",
    }
    bank = MockBank(BankState.model_validate(data), KEY)
    request = order("redeem_product", position_ref="owned", amount="100")
    assert bank.execute(request).status == "failed"
    assert bank.final_state()["failures"][request.intent_key] == "REDEMPTION_ACCOUNT_AMBIGUOUS"
    assert amount(bank) == 10000


def test_concurrent_duplicate_requests_have_one_effect(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(lambda _: bank.execute(order()), range(16)))
    assert all(receipt == receipts[0] for receipt in receipts)
    assert amount(bank) == 9800
    assert len(bank.final_state()["events"]) == 1


def test_failed_scope_cannot_be_changed_on_retry(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    failed = bank.execute(order(amount="10001"))
    assert failed.status == "failed"
    assert bank.execute(order(amount="200")) == failed
    assert amount(bank) == 10000


def test_concurrent_distinct_payments_cannot_overdraw(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(
            pool.map(lambda key: bank.execute(order(key=key, amount="6000")), ["first", "second"])
        )
    assert sorted(receipt.status for receipt in receipts) == ["failed", "settled"]
    assert amount(bank) == 4000


def test_new_contact_transition_is_bank_event(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    bank.execute(order(contact_ref="new", destination_ref="DEST_NEW"))
    assert bank.final_state()["contacts"]["new"]["is_new"] is False
    assert initial.contacts["new"].is_new is True


def test_redeem_zero_delay_and_zero_fee_closes_position(initial: BankState) -> None:
    data = initial.model_dump(mode="python")
    product = data["catalog"]["products"][0]
    product.update({
        "min_hold_days": 0,
        "redeem_delay_days": 0,
        "purchase_fee_rate": "0",
        "annual_fee_rate": "0",
        "redemption_fee_rate": "0",
    })
    bank = MockBank(BankState.model_validate(data), KEY)
    purchase(bank, fee_buy="0")
    position_ref = next(iter(bank.final_state()["positions"]))
    receipt = bank.execute(
        order("redeem_product", key="redeem", position_ref=position_ref, amount="1000")
    )
    assert receipt.status == "settled"
    assert amount(bank) == 10000
    assert bank.final_state()["positions"][position_ref]["status"] == "closed"
    assert Fraction(bank.final_state()["positions"][position_ref]["units"]) == 0


def test_rounding_purchase_fee_is_upward_per_charge(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    receipt = purchase(bank, amount="100.01", fee_buy="1.01")
    assert receipt.status == "settled"
    assert amount(bank) == Fraction("9898.98")


def test_lock_failure_rolls_back_both_sides(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(
        order(
            "unlock_funds",
            source_ref="current",
            locked_ref="locked",
            amount="1",
            purpose_ref="purpose",
        )
    )
    assert receipt.status == "failed"
    assert (amount(bank), amount(bank, "locked")) == (10000, 0)


def test_month_end_mandate_uses_calendar_months(initial: BankState) -> None:
    data = initial.model_dump(mode="python")
    data["subscriptions"]["S1"]["next_due"] = "2027-01-31T02:00:00Z"
    bank = MockBank(BankState.model_validate(data), KEY)
    events = bank.advance_clock("2027-02-28T02:00:00Z")
    assert len(events) == 2
    assert [receipt.executed_at for receipt in events] == [
        "2027-01-31T02:00:00Z",
        "2027-02-28T02:00:00Z",
    ]
    assert amount(bank) == 9902


def test_paid_order_mismatch_never_debits(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(
        order(
            "merchant_order",
            source_ref="current",
            merchant_ref="shop",
            offer_ref="flowers",
            destination_ref="DEST_SHOP",
            amount="299",
        )
    )
    assert receipt.status == "failed" and amount(bank) == 10000
    assert bank.final_state()["orders"] == {}


def test_initial_spa_schedule_is_not_dispatched_by_bank_clock(initial: BankState) -> None:
    data = initial.model_dump(mode="python")
    data["schedules"]["schedule"] = {
        "id": "schedule",
        "owner": "C",
        "plan_id": "plan",
        "node_id": "node",
        "spa_ref": "spa",
        "run_index": 0,
        "action_template": {},
        "input_refs": [],
        "due_at": "2026-10-17T02:00:00Z",
        "expires_at": "2026-10-18T02:00:00Z",
        "commitment_id": "commitment",
        "status": "pending",
    }
    bank = MockBank(BankState.model_validate(data), KEY)
    assert bank.advance_clock("2026-10-18T02:00:00Z") == []
    assert amount(bank) == 10000
    assert bank.execute_count == 0


def test_backend_queries_return_raw_bank_objects_without_approval_checks(
    initial: BankState,
) -> None:
    bank = MockBank(initial, KEY)
    receipt = bank.execute(order("subscription_reminders", account_ref="current", period="month"))
    assert receipt.status == "settled"
    assert [item["id"] for item in receipt.exact_effects[0].after] == ["S1"]
    bank.execute(order(key="payment"))
    transactions = bank.execute(order("transactions_query", key="query", account_ref="current"))
    assert len(transactions.exact_effects[0].after) == 1
    assert amount(bank) == 9800


def test_reminder_horizon_includes_exactly_seven_days(initial: BankState) -> None:
    data = initial.model_dump(mode="python")
    data["subscriptions"]["S1"]["next_due"] = "2026-10-23T02:00:00Z"
    data["subscriptions"]["S2"] = {
        **data["subscriptions"]["S1"],
        "id": "S2",
        "next_due": "2026-10-23T02:00:01Z",
    }
    bank = MockBank(BankState.model_validate(data), KEY)
    receipt = bank.execute(order("subscription_reminders", account_ref="current", period="month"))
    assert [item["id"] for item in receipt.exact_effects[0].after] == ["S1"]


def test_non_bank_analysis_contract_returns_unavailable(initial: BankState) -> None:
    bank = MockBank(initial, KEY)
    request = order("product_compare", preference_ref="preference")
    receipt = bank.execute(request)
    assert receipt.status == "failed"
    assert bank.final_state()["failures"][request.intent_key] == "BACKEND_OPERATION_UNAVAILABLE"
    assert bank.final_state()["cards"] == {}
