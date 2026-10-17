"""Independent synthetic bank with exact effects and local fault injection.

This backend enforces object and funds consistency only. It deliberately has no
approval, risk-suitability, recommendation, or intended-recipient policy.
"""

from calendar import monthrange
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import timedelta
from fractions import Fraction
from threading import RLock
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from nacl.signing import SigningKey

from corridor.crypto.jcs import H, json_value
from corridor.crypto.sign import RECEIPT, sign
from corridor.schemas.bank import BankEffect, BankOrder, BankReceipt
from corridor.schemas.domain import Account, Card, MerchantOrder, Position, Transaction
from corridor.schemas.money import fraction_string
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time

_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")


def _id(key: str, kind: str) -> str:
    return str(uuid5(_NAMESPACE, f"{key}:0:{kind}"))


def _days(now: str, count: int) -> str:
    return (parse_time(now) + timedelta(days=count)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _months(now: str, count: int) -> str:
    old = parse_time(now)
    year, month0 = divmod(old.year * 12 + old.month - 1 + count, 12)
    day = min(old.day, monthrange(year, month0 + 1)[1])
    return old.replace(year=year, month=month0 + 1, day=day).strftime("%Y-%m-%dT%H:%M:%SZ")


def _charge(value: Fraction) -> Fraction:
    """Round a nonnegative contractual charge upward to one cent."""
    numerator, denominator = (value * 100).as_integer_ratio()
    return Fraction((numerator + denominator - 1) // denominator, 100)


class _Rejected(ValueError):
    pass


@dataclass
class _Pending:
    order: BankOrder
    position_ref: str
    source_ref: str
    principal: Fraction
    proceeds: Fraction
    settle_at: str


@dataclass
class _Data:
    state: BankState
    balances: dict[str, Fraction]
    destinations: dict[str, Fraction] = field(default_factory=dict)
    receipts: dict[str, BankReceipt] = field(default_factory=dict)
    events: list[BankReceipt] = field(default_factory=list)
    order_inputs: dict[str, BankOrder] = field(default_factory=dict)
    position_sources: dict[str, str] = field(default_factory=dict)
    pending: dict[str, _Pending] = field(default_factory=dict)
    refund_requests: dict[str, dict[str, str]] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)


class MockBank:
    """Local bank initialized from an independent copy of the public fixture.

    ``faults[intent_key]`` accepts ``response_loss``, ``bad_signature``, ``failed``
    or ``disk_error``. Transport faults affect only the returned response; lookup
    always exposes the canonical bank record. Failed requests can be retried with
    the same business scope after a fault or an insufficient balance is resolved.
    ``execute_count`` counts calls, including duplicate requests.
    """

    def __init__(self, initial: BankState, signing_key: SigningKey) -> None:
        state = BankState.model_validate(initial.model_dump(mode="python"))
        balances = {key: account.opening_balance for key, account in state.accounts.items()}
        # Historical display transactions are already reflected in opening balances.
        latest = {event.intent_key: event for event in state.ledger}
        for event in latest.values():
            if event.event in {"reserved", "unknown", "settled"} and event.debit:
                if event.debit.account_ref not in balances:
                    raise ValueError("Initial ledger references a missing debit account")
                balances[event.debit.account_ref] -= event.debit.amount
            if event.event == "settled" and event.credit:
                if event.credit.account_ref not in balances:
                    raise ValueError("Initial ledger references a missing credit account")
                balances[event.credit.account_ref] += event.credit.amount
        if any(balance < 0 for balance in balances.values()):
            raise ValueError("Initial bank balance cannot be negative")
        self._data = _Data(state, balances)
        self._key = signing_key
        self._lock = RLock()
        self.faults: dict[str, str] = {}
        self.execute_count = 0
        for receipt in state.receipts.values():
            if isinstance(receipt, BankReceipt):
                self._data.receipts[receipt.intent_key] = receipt

    def lookup(self, intent_key: str) -> BankReceipt | None:
        with self._lock:
            return deepcopy(self._data.receipts.get(intent_key))

    def card_authorize(self, card_ref: str, amount: Fraction, category: str) -> bool:
        """Read-only test probe for card controls; this never creates a payment."""
        with self._lock:
            card = self._data.state.cards.get(card_ref)
            if (
                card is None
                or card.status != "active"
                or not isinstance(amount, Fraction)
                or amount <= 0
                or (amount * 100).denominator != 1
                or amount > card.limit
                or not isinstance(category, str)
                or not category
                or category in card.restrictions
            ):
                return False
            account = self._data.state.accounts.get(card.account_ref)
            return bool(
                account is not None
                and account.status == "active"
                and account.kind == "current"
                and account.owner == card.owner
            )

    @staticmethod
    def _scope(order: BankOrder) -> str:
        return H({
            "principal": order.principal,
            "kind": order.kind,
            "args": order.args,
            "commitment_id": order.commitment_id,
        })

    def execute(self, order: BankOrder) -> BankReceipt:
        with self._lock:
            self.execute_count += 1
            order = BankOrder.model_validate(order.model_dump(mode="python"))
            previous = self._data.receipts.get(order.intent_key)
            original = self._data.order_inputs.get(order.intent_key)
            if previous is not None and (
                previous.status != "failed"
                or original is None
                or self._scope(original) != self._scope(order)
            ):
                return deepcopy(previous)
            fault = self.faults.get(order.intent_key)
            if previous is not None and fault in {"failed", "disk_error"}:
                return deepcopy(previous)
            before = deepcopy(self._data)
            self._data.order_inputs[order.intent_key] = order
            try:
                if order.requested_at > self._data.state.now:
                    raise _Rejected("REQUEST_FROM_FUTURE")
                if fault in {"failed", "disk_error"}:
                    raise _Rejected(f"INJECTED_{fault.upper()}")
                effects, pending_at = self._apply(order)
                receipt = self._receipt(
                    order.intent_key,
                    order.kind,
                    effects,
                    "pending" if pending_at else "settled",
                    settle_at=pending_at,
                )
                self._data.failures.pop(order.intent_key, None)
            except _Rejected as exc:
                self._data = before
                self._data.order_inputs[order.intent_key] = order
                self._data.failures[order.intent_key] = str(exc)
                receipt = self._receipt(order.intent_key, order.kind, [], "failed")
            self._record(receipt)
            if fault == "response_loss":
                raise TimeoutError("Synthetic bank response lost after committing the operation")
            if fault == "bad_signature":
                return receipt.model_copy(update={"sig": "0" * 128}, deep=True)
            return deepcopy(receipt)

    def _receipt(
        self,
        key: str,
        kind: str,
        effects: list[BankEffect],
        status: str,
        *,
        settle_at: str | None = None,
        executed_at: str | None = None,
    ) -> BankReceipt:
        previous = self._data.receipts.get(key)
        body = {
            "receipt_id": _id(key, "bank_receipt"),
            "intent_key": key,
            "kind": kind,
            "status": status,
            "exact_effects": effects,
            "executed_at": executed_at or self._data.state.now,
            "settle_at": settle_at,
            "version": 1 if previous is None else previous.version + 1,
            "sig": "0" * 128,
        }
        result = BankReceipt.model_validate(body)
        return result.model_copy(update={"sig": sign(self._key, RECEIPT, result)})

    def _record(self, receipt: BankReceipt) -> None:
        self._data.receipts[receipt.intent_key] = receipt
        self._data.events.append(receipt)

    def _account(self, ref: str, *, current: bool = False) -> Account:
        account = self._data.state.accounts.get(ref)
        if account is None or account.status != "active":
            raise _Rejected("ACCOUNT_UNAVAILABLE")
        if current and account.kind != "current":
            raise _Rejected("CURRENT_ACCOUNT_REQUIRED")
        return account

    def _movement(
        self, ref: str, amount: Fraction, debit: bool, counterparty: str | None = None
    ) -> BankEffect:
        self._account(ref)
        previous = self._data.balances[ref]
        updated = previous - amount if debit else previous + amount
        if updated < 0:
            raise _Rejected("INSUFFICIENT_FUNDS")
        self._data.balances[ref] = updated
        return BankEffect(
            effect_type="debit" if debit else "credit",
            object_ref=ref,
            account_ref=ref,
            counterparty_ref=counterparty,
            amount=amount,
            field="balance",
            before=fraction_string(previous),
            after=fraction_string(updated),
        )

    def _destination(self, ref: str, amount: Fraction, source: str) -> BankEffect:
        before = self._data.destinations.get(ref, Fraction(0))
        self._data.destinations[ref] = before + amount
        return BankEffect(
            effect_type="credit",
            object_ref=ref,
            account_ref=ref,
            counterparty_ref=source,
            amount=amount,
            field="balance",
            before=fraction_string(before),
            after=fraction_string(before + amount),
        )

    def _transaction(
        self,
        key: str,
        source: str,
        amount: Fraction,
        kind: str,
        *,
        direction: str = "debit",
        contact: str | None = None,
        merchant: str | None = None,
    ) -> None:
        if amount == 0:
            return
        tx_id = _id(key, f"transaction_{source}_{direction}")
        self._data.state.transactions[tx_id] = Transaction.model_validate({
            "id": tx_id,
            "owner": self._data.state.accounts[source].owner,
            "account_ref": source,
            "amount": amount,
            "direction": direction,
            "kind": kind,
            "contact_ref": contact,
            "merchant_ref": merchant,
            "category_code": self._data.state.merchants[merchant].category_code
            if merchant
            else kind,
            "booked_at": self._data.state.now,
            "bank_ref": tx_id,
            "memo_handle": tx_id,
        })

    def _apply(self, order: BankOrder) -> tuple[list[BankEffect], str | None]:
        args = {name: getattr(order.args, name) for name in type(order.args).model_fields}
        if order.kind == "transfer":
            return self._transfer(order, args), None
        if order.kind in {"lock_funds", "unlock_funds"}:
            return self._funds(order, args), None
        if order.kind == "cancel_subscription":
            ref = args["authorization_ref"]
            subscription = self._data.state.subscriptions.get(ref)
            if subscription is None:
                raise _Rejected("SUBSCRIPTION_NOT_FOUND")
            if subscription.status == "cancelled":
                return [], None
            self._data.state.subscriptions[ref] = subscription.model_copy(
                update={"status": "cancelled", "version": subscription.version + 1}
            )
            return [
                BankEffect(
                    effect_type="state",
                    object_ref=ref,
                    field="status",
                    before="active",
                    after="cancelled",
                )
            ], None
        if order.kind == "purchase_product":
            return self._purchase(order, args), None
        if order.kind == "redeem_product":
            return self._redeem(order, args)
        if order.kind == "merchant_order":
            return self._merchant_order(order, args), None
        if order.kind == "cancel_order":
            return self._cancel_order(args["order_ref"]), None
        if order.kind == "refund_request":
            return self._refund(order, args["receipt_ref"]), None
        if order.kind in {
            "apply_virtual_card",
            "freeze_card",
            "unfreeze_card",
            "report_card_lost",
            "restore_card",
            "lower_card_limit",
            "raise_card_limit",
            "restrict_card",
            "relax_card_restriction",
        }:
            return self._card(order, args), None
        return self._query(order, args), None

    def _card(self, order: BankOrder, args: dict[str, Any]) -> list[BankEffect]:
        if order.kind == "apply_virtual_card":
            account = self._account(args["account_ref"], current=True)
            ref = _id(order.intent_key, "card")
            if ref in self._data.state.cards:
                raise _Rejected("CARD_ALREADY_EXISTS")
            created = Card(
                id=ref,
                owner=account.owner,
                account_ref=account.id,
                status="active",
                limit=args["limit"],
                restrictions=[],
                card_token="CARD_TOKEN_"
                + order.intent_key[:16].translate(
                    str.maketrans("0123456789abcdef", "abcdefghijklmnop")
                ),
            )
            before = None
        else:
            ref = args["card_ref"]
            card = self._data.state.cards.get(ref)
            if card is None:
                raise _Rejected("CARD_NOT_FOUND")
            account = self._account(card.account_ref, current=True)
            if card.owner != account.owner:
                raise _Rejected("CARD_ACCOUNT_MISMATCH")
            changes: dict[str, Any] = {"version": card.version + 1}
            transitions = {
                "freeze_card": ({"active"}, "frozen"),
                "unfreeze_card": ({"frozen"}, "active"),
                "report_card_lost": ({"active", "frozen"}, "lost"),
                "restore_card": ({"lost"}, "frozen"),
            }
            if order.kind in transitions:
                allowed, target = transitions[order.kind]
                if card.status not in allowed:
                    raise _Rejected("CARD_STATE_CONFLICT")
                changes["status"] = target
            elif card.status == "lost":
                raise _Rejected("CARD_STATE_CONFLICT")
            elif order.kind in {"lower_card_limit", "raise_card_limit"}:
                limit = args["limit"]
                if (
                    order.kind == "lower_card_limit"
                    and limit >= card.limit
                    or order.kind == "raise_card_limit"
                    and limit <= card.limit
                ):
                    raise _Rejected("CARD_LIMIT_DIRECTION")
                changes["limit"] = limit
            else:
                restrictions = args["restrictions"]
                previous, target_set = set(card.restrictions), set(restrictions)
                if (
                    order.kind == "restrict_card"
                    and not previous < target_set
                    or order.kind == "relax_card_restriction"
                    and not target_set < previous
                ):
                    raise _Rejected("CARD_RESTRICTION_DIRECTION")
                changes["restrictions"] = restrictions
            before = card.model_dump(mode="json")
            created = card.model_copy(update=changes)
        self._data.state.cards[ref] = created
        return [
            BankEffect(
                effect_type="state",
                object_ref=ref,
                field="card",
                before=before,
                after=created.model_dump(mode="json"),
            )
        ]

    def _transfer(self, order: BankOrder, args: dict[str, Any]) -> list[BankEffect]:
        source, contact_ref, destination, amount = (
            args["source_ref"],
            args["contact_ref"],
            args["destination_ref"],
            args["amount"],
        )
        self._account(source, current=True)
        contact = self._data.state.contacts.get(contact_ref)
        if contact is None or contact.destination_ref != destination:
            raise _Rejected("CONTACT_DESTINATION_MISMATCH")
        effects = [
            self._movement(source, amount, True, destination),
            self._destination(destination, amount, source),
        ]
        self._transaction(order.intent_key, source, amount, "transfer", contact=contact_ref)
        if contact.is_new:
            self._data.state.contacts[contact_ref] = contact.model_copy(
                update={"is_new": False, "version": contact.version + 1}
            )
            effects.append(
                BankEffect(
                    effect_type="state",
                    object_ref=contact_ref,
                    field="is_new",
                    before=True,
                    after=False,
                )
            )
        return effects

    def _funds(self, order: BankOrder, args: dict[str, Any]) -> list[BankEffect]:
        source, locked, amount = args["source_ref"], args["locked_ref"], args["amount"]
        current = self._account(source, current=True)
        child = self._account(locked)
        if child.kind != "locked" or child.parent_ref != source or child.owner != current.owner:
            raise _Rejected("LOCKED_ACCOUNT_MISMATCH")
        debit, credit = (source, locked) if order.kind == "lock_funds" else (locked, source)
        effects = [
            self._movement(debit, amount, True, credit),
            self._movement(credit, amount, False, debit),
        ]
        self._transaction(order.intent_key, debit, amount, "internal")
        self._transaction(order.intent_key, credit, amount, "internal", direction="credit")
        return effects

    def _product(self, ref: str) -> Any:
        product = next((p for p in self._data.state.catalog.products if p.id == ref), None)
        if product is None:
            raise _Rejected("PRODUCT_NOT_FOUND")
        return product

    def _purchase(self, order: BankOrder, args: dict[str, Any]) -> list[BankEffect]:
        source, amount = args["source_ref"], args["amount"]
        account = self._account(source, current=True)
        product = self._product(args["product_ref"])
        if not product.purchase_open:
            raise _Rejected("PRODUCT_CLOSED")
        fee = _charge(amount * product.purchase_fee_rate)
        if fee != args["fee_buy"]:
            raise _Rejected("PURCHASE_FEE_MISMATCH")
        effects = [self._movement(source, amount + fee, True, product.id)]
        ref = _id(order.intent_key, "position")
        position = Position(
            id=ref,
            owner=account.owner,
            product_ref=product.id,
            principal_amount=amount,
            units=amount,
            reserved_units=Fraction(0),
            nav=Fraction(1),
            acquired_at=self._data.state.now,
            redeemable_at=_days(self._data.state.now, product.min_hold_days),
            status="active",
        )
        self._data.state.positions[ref] = position
        self._data.position_sources[ref] = source
        self._transaction(order.intent_key, source, amount + fee, "investment")
        effects.append(
            BankEffect(
                effect_type="position",
                object_ref=ref,
                field="position",
                after=position.model_dump(mode="json"),
            )
        )
        return effects

    def _return_account(self, position: Position) -> str:
        ref = self._data.position_sources.get(position.id)
        if ref is None:
            candidates = [
                account.id
                for account in self._data.state.accounts.values()
                if account.owner == position.owner
                and account.kind == "current"
                and account.status == "active"
            ]
            if len(candidates) != 1:
                raise _Rejected("REDEMPTION_ACCOUNT_AMBIGUOUS")
            ref = candidates[0]
        self._account(ref, current=True)
        return ref

    def _redeem(
        self, order: BankOrder, args: dict[str, Any]
    ) -> tuple[list[BankEffect], str | None]:
        ref, amount = args["position_ref"], args["amount"]
        position = self._data.state.positions.get(ref)
        if position is None or position.status != "active":
            raise _Rejected("POSITION_UNAVAILABLE")
        if position.redeemable_at > self._data.state.now:
            raise _Rejected("POSITION_NOT_REDEEMABLE")
        if amount > min(position.units - position.reserved_units, position.principal_amount):
            raise _Rejected("INSUFFICIENT_POSITION_UNITS")
        source = self._return_account(position)
        product = self._product(position.product_ref)
        held_days = (parse_time(self._data.state.now) - parse_time(position.acquired_at)).days
        fee = _charge(amount * product.annual_fee_rate * held_days / 365) + _charge(
            amount * product.redemption_fee_rate
        )
        if fee > amount:
            raise _Rejected("REDEMPTION_FEES_EXCEED_PRINCIPAL")
        pending = _Pending(
            order,
            ref,
            source,
            amount,
            amount - fee,
            _days(self._data.state.now, product.redeem_delay_days),
        )
        updated = position.model_copy(
            update={
                "reserved_units": position.reserved_units + amount,
                "version": position.version + 1,
            }
        )
        self._data.state.positions[ref] = updated
        if product.redeem_delay_days == 0:
            return self._settle_redemption(pending, original=position), None
        self._data.pending[order.intent_key] = pending
        return [
            BankEffect(
                effect_type="position",
                object_ref=ref,
                field="position",
                before=position.model_dump(mode="json"),
                after=updated.model_dump(mode="json"),
            )
        ], pending.settle_at

    def _settle_redemption(
        self, pending: _Pending, *, original: Position | None = None
    ) -> list[BankEffect]:
        position = self._data.state.positions[pending.position_ref]
        held = position.units - pending.principal
        updated = position.model_copy(
            update={
                "units": held,
                "principal_amount": position.principal_amount - pending.principal,
                "reserved_units": position.reserved_units - pending.principal,
                "status": "closed" if held == 0 else "active",
                "version": position.version + 1,
            }
        )
        effects = [
            self._movement(pending.source_ref, pending.proceeds, False, position.product_ref)
        ]
        self._data.state.positions[position.id] = updated
        self._transaction(
            pending.order.intent_key,
            pending.source_ref,
            pending.proceeds,
            "investment",
            direction="credit",
        )
        effects.append(
            BankEffect(
                effect_type="position",
                object_ref=position.id,
                field="position",
                before=(original or position).model_dump(mode="json"),
                after=updated.model_dump(mode="json"),
            )
        )
        return effects

    def _merchant_order(self, order: BankOrder, args: dict[str, Any]) -> list[BankEffect]:
        source, amount = args["source_ref"], args["amount"]
        account = self._account(source, current=True)
        merchant = self._data.state.merchants.get(args["merchant_ref"])
        if merchant is None or merchant.destination_ref != args["destination_ref"]:
            raise _Rejected("MERCHANT_DESTINATION_MISMATCH")
        offer = next((offer for offer in merchant.offers if offer.id == args["offer_ref"]), None)
        if offer is None or not offer.available or offer.amount != amount:
            raise _Rejected("MERCHANT_OFFER_MISMATCH")
        effects = [
            self._movement(source, amount, True, merchant.destination_ref),
            self._destination(merchant.destination_ref, amount, source),
        ]
        ref = _id(order.intent_key, "merchant_order")
        created = MerchantOrder(
            id=ref,
            owner=account.owner,
            merchant_ref=merchant.id,
            offer_ref=offer.id,
            amount=amount,
            status="paid",
            receipt_ref=_id(order.intent_key, "bank_receipt"),
        )
        self._data.state.orders[ref] = created
        self._transaction(order.intent_key, source, amount, "merchant_debit", merchant=merchant.id)
        effects.append(
            BankEffect(
                effect_type="order",
                object_ref=ref,
                field="order",
                after=created.model_dump(mode="json"),
            )
        )
        return effects

    def _cancel_order(self, ref: str) -> list[BankEffect]:
        order = self._data.state.orders.get(ref)
        if order is None:
            raise _Rejected("ORDER_NOT_FOUND")
        if order.status == "cancelled":
            return []
        if order.status != "draft":
            raise _Rejected("SETTLED_PAYMENT_IRREVERSIBLE")
        merchant = self._data.state.merchants.get(order.merchant_ref)
        offer = (
            next((offer for offer in merchant.offers if offer.id == order.offer_ref), None)
            if merchant
            else None
        )
        if offer is None or self._data.state.now > offer.cancel_until:
            raise _Rejected("ORDER_CANCELLATION_CLOSED")
        updated = order.model_copy(update={"status": "cancelled", "version": order.version + 1})
        self._data.state.orders[ref] = updated
        return [
            BankEffect(
                effect_type="order",
                object_ref=ref,
                field="status",
                before="draft",
                after="cancelled",
            )
        ]

    def _refund(self, order: BankOrder, receipt_ref: str) -> list[BankEffect]:
        original = next((r for r in self._data.receipts.values() if r.id == receipt_ref), None)
        if (
            original is None
            or original.status != "settled"
            or original.kind not in {"transfer", "merchant_order", "subscription_debit"}
        ):
            raise _Rejected("REFUND_SOURCE_UNAVAILABLE")
        if any(
            request["receipt_ref"] == receipt_ref for request in self._data.refund_requests.values()
        ):
            return []
        ref = _id(order.intent_key, "refund_request")
        request = {"receipt_ref": receipt_ref, "principal": order.principal, "status": "pending"}
        self._data.refund_requests[ref] = request
        effects = [
            BankEffect(effect_type="state", object_ref=ref, field="refund_request", after=request)
        ]
        merchant_order = next(
            (item for item in self._data.state.orders.values() if item.receipt_ref == receipt_ref),
            None,
        )
        if merchant_order:
            self._data.state.orders[merchant_order.id] = merchant_order.model_copy(
                update={
                    "status": "refund_pending",
                    "refund_request_ref": ref,
                    "version": merchant_order.version + 1,
                }
            )
            effects.append(
                BankEffect(
                    effect_type="order",
                    object_ref=merchant_order.id,
                    field="status",
                    before="paid",
                    after="refund_pending",
                )
            )
        return effects

    def _query(self, order: BankOrder, args: dict[str, Any]) -> list[BankEffect]:
        ref = args.get("account_ref", args.get("position_ref", ""))
        if order.kind == "balance_query":
            self._account(ref)
            result: Any = fraction_string(self._data.balances[ref])
        elif order.kind == "transactions_query":
            self._account(ref)
            result = [
                tx.model_dump(mode="json")
                for tx in self._data.state.transactions.values()
                if tx.account_ref == ref
            ]
        elif order.kind in {"subscription_query", "subscription_reminders"}:
            self._account(ref)
            result = [
                subscription.model_dump(mode="json")
                for subscription in self._data.state.subscriptions.values()
                if subscription.source_account_ref == ref
                and (
                    order.kind == "subscription_query"
                    or (
                        subscription.status == "active"
                        and self._data.state.now
                        <= subscription.next_due
                        <= _days(self._data.state.now, 7)
                    )
                )
            ]
        elif order.kind == "investment_income_query":
            position = self._data.state.positions.get(ref)
            if position is None:
                raise _Rejected("POSITION_UNAVAILABLE")
            result = position.model_dump(mode="json")
        else:
            # Analysis, recommendation, and P1 card controls are not bank execution.
            raise _Rejected("BACKEND_OPERATION_UNAVAILABLE")
        return [BankEffect(effect_type="query", object_ref=ref, field=order.kind, after=result)]

    def _subscription_charge(self, ref: str) -> BankReceipt:
        subscription = self._data.state.subscriptions[ref]
        due = subscription.next_due
        key = H({"subscription_ref": ref, "due_at": due})
        before = deepcopy(self._data)
        try:
            self._account(subscription.source_account_ref, current=True)
            merchant = self._data.state.merchants.get(subscription.merchant_ref)
            if merchant is None:
                raise _Rejected("MERCHANT_NOT_FOUND")
            effects = [
                self._movement(
                    subscription.source_account_ref,
                    subscription.amount,
                    True,
                    merchant.destination_ref,
                ),
                self._destination(
                    merchant.destination_ref, subscription.amount, subscription.source_account_ref
                ),
            ]
            self._transaction(
                key,
                subscription.source_account_ref,
                subscription.amount,
                "merchant_debit",
                merchant=merchant.id,
            )
            status = "settled"
        except _Rejected as exc:
            self._data = before
            self._data.failures[key] = str(exc)
            effects, status = [], "failed"
        self._data.state.subscriptions[ref] = subscription.model_copy(
            update={
                "next_due": _months(due, subscription.period_months),
                "version": subscription.version + 1,
            }
        )
        effects.append(
            BankEffect(
                effect_type="state",
                object_ref=ref,
                field="next_due",
                before=due,
                after=self._data.state.subscriptions[ref].next_due,
            )
        )
        receipt = self._receipt(key, "subscription_debit", effects, status)
        self._record(receipt)
        return receipt

    def advance_clock(self, now: str) -> list[BankReceipt]:
        """Process only bank maturities and existing debit mandates, never SPA."""
        parse_time(now)
        with self._lock:
            if now < self._data.state.now:
                raise ValueError("The simulated clock cannot move backward")
            emitted: list[BankReceipt] = []
            while True:
                due = [
                    (pending.settle_at, "redemption", key)
                    for key, pending in self._data.pending.items()
                    if pending.settle_at <= now
                ]
                due.extend(
                    (subscription.next_due, "subscription", subscription.id)
                    for subscription in self._data.state.subscriptions.values()
                    if subscription.status == "active" and subscription.next_due <= now
                )
                if not due:
                    break
                when, kind, key = min(due)
                self._data.state = self._data.state.model_copy(update={"now": when})
                if kind == "subscription":
                    emitted.append(self._subscription_charge(key))
                else:
                    pending = self._data.pending[key]
                    effects = self._settle_redemption(pending)
                    receipt = self._receipt(
                        key,
                        pending.order.kind,
                        effects,
                        "settled",
                        settle_at=pending.settle_at,
                        executed_at=self._data.receipts[key].executed_at,
                    )
                    del self._data.pending[key]
                    self._record(receipt)
                    emitted.append(receipt)
            self._data.state = self._data.state.model_copy(update={"now": now})
            return deepcopy(emitted)

    def final_state(self) -> dict[str, Any]:
        """Return a detached JSON-safe public bank projection for the evaluator."""
        with self._lock:
            state = self._data.state
            result = {
                name: getattr(state, name)
                for name in (
                    "accounts",
                    "contacts",
                    "positions",
                    "subscriptions",
                    "cards",
                    "orders",
                    "transactions",
                    "merchants",
                )
            }
            result.update({
                "now": state.now,
                "balances": self._data.balances,
                "destinations": self._data.destinations,
                "receipts": {receipt.id: receipt for receipt in self._data.receipts.values()},
                "intent_receipts": {
                    key: receipt.id for key, receipt in self._data.receipts.items()
                },
                "events": self._data.events,
                "order_inputs": self._data.order_inputs,
                "position_sources": self._data.position_sources,
                "refund_requests": self._data.refund_requests,
                "failures": self._data.failures,
            })
            return json_value(result)
