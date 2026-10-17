"""Compile verified references and reconcile the exact scope of bank receipts."""

from datetime import timedelta
from fractions import Fraction
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from corridor.crypto.sign import RECEIPT, verify
from corridor.eval.mockbank.exec import MockBank
from corridor.kernel.binding import intent_key, resolve_amount
from corridor.kernel.investment import price_redemption, resolve_redemption_account
from corridor.schemas.bank import (
    AccountMovement,
    BankAction,
    BankCertificate,
    BankEffect,
    BankOrder,
    BankReceipt,
    CardChangeRequest,
)
from corridor.schemas.domain import (
    Card,
    MerchantOrder,
    Position,
    Product,
    SubscriptionAuthorization,
    Transaction,
)
from corridor.schemas.money import ceil_minor, fraction_string
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time
from corridor.stores.bank import available, latest_events

_CARD_KINDS = frozenset({
    "apply_virtual_card",
    "freeze_card",
    "unfreeze_card",
    "report_card_lost",
    "restore_card",
    "lower_card_limit",
    "raise_card_limit",
    "restrict_card",
    "relax_card_restriction",
})

_BANK_KINDS = (
    frozenset({
        "transfer",
        "balance_query",
        "transactions_query",
        "subscription_query",
        "subscription_reminders",
        "cancel_subscription",
        "lock_funds",
        "unlock_funds",
        "merchant_order",
        "cancel_order",
        "refund_request",
        "purchase_product",
        "redeem_product",
    })
    | _CARD_KINDS
)


def card_authorize(bank: MockBank, card_ref: str, amount: Fraction, category: str) -> bool:
    """Test adapter for the independent bank's read-only card authorization probe."""
    return bank.card_authorize(card_ref, amount, category)


def compile_order(action: BankAction, cert: BankCertificate, state: BankState) -> BankOrder:
    if action.kind not in _BANK_KINDS:
        raise ValueError("TOOL-UNAVAILABLE")
    args = action.args.model_dump(mode="python")
    amount = resolve_amount(action, state)
    if "amount_ref" in args:
        del args["amount_ref"]
        args["amount"] = amount
    if action.kind == "transfer":
        args["destination_ref"] = state.contacts[args["contact_ref"]].destination_ref
    if action.kind == "merchant_order":
        args["destination_ref"] = state.merchants[args["merchant_ref"]].destination_ref
        args["amount"] = amount
    if action.kind == "purchase_product":
        args.pop("preference_ref", None)
        args.pop("allocation_ref", None)
        args.pop("allocation_item_ref", None)
        if amount is None:
            raise ValueError("PROV-MISMATCH")
        product = _product(state, args["product_ref"])
        args["fee_buy"] = ceil_minor(amount * product.purchase_fee_rate)
    if action.kind == "apply_virtual_card":
        args["limit"] = state.policy.transfer_yellow_limit
    elif action.kind in _CARD_KINDS:
        change_ref = args.pop("change_ref", None)
        if change_ref is not None:
            change = CardChangeRequest.model_validate(state.user_inputs[change_ref].value)
            if change.card_ref != args["card_ref"] or change.kind != action.kind:
                raise ValueError("PROV-MISMATCH")
            if action.kind in {"lower_card_limit", "raise_card_limit"}:
                args["limit"] = change.limit
            elif action.kind in {"restrict_card", "relax_card_restriction"}:
                args["restrictions"] = change.restrictions
    run = state.schedules.get(action.action_id)
    return BankOrder.model_validate({
        "intent_key": intent_key(action, state),
        "action_id": action.action_id,
        "principal": action.principal,
        "kind": action.kind,
        "requested_at": state.now,
        "commitment_id": run.commitment_id if run else None,
        "args": args,
    })


def movements(
    order: BankOrder, state: BankState
) -> tuple[AccountMovement | None, AccountMovement | None]:
    args = order.args.model_dump(mode="python")
    if order.kind == "purchase_product":
        return AccountMovement(
            account_ref=args["source_ref"],
            amount=Fraction(str(args["amount"])) + Fraction(str(args["fee_buy"])),
        ), None
    if order.kind == "redeem_product":
        return None, AccountMovement(
            account_ref=redemption_account(order, state), amount=redemption_proceeds(order, state)
        )
    if order.kind not in {"transfer", "merchant_order", "lock_funds", "unlock_funds"}:
        return None, None
    amount = Fraction(str(args["amount"]))
    debit = args["locked_ref"] if order.kind == "unlock_funds" else args["source_ref"]
    credit = None
    if order.kind in {"lock_funds", "unlock_funds"}:
        credit_ref = args["source_ref"] if order.kind == "unlock_funds" else args["locked_ref"]
        credit = AccountMovement(account_ref=credit_ref, amount=amount)
    return AccountMovement(account_ref=debit, amount=amount), credit


def _product(state: BankState, ref: str) -> Product:
    return next(product for product in state.catalog.products if product.id == ref)


def _original_position(order: BankOrder, state: BankState) -> Position:
    ref = str(order.args.model_dump()["position_ref"])
    event = latest_events(state).get(order.intent_key)
    if event is not None and "original_position" in event.object_delta:
        position = Position.model_validate(event.object_delta["original_position"])
        if event.kind != order.kind or event.principal != order.principal or position.id != ref:
            raise ValueError("BANK-RECEIPT")
        return position
    return state.positions[ref]


def _reserve_position(position: Position, amount: Fraction) -> Position:
    if (
        position.status != "active"
        or amount <= 0
        or amount > min(position.units - position.reserved_units, position.principal_amount)
    ):
        raise ValueError("DOMAIN-POSITION")
    return position.model_copy(
        update={"reserved_units": position.reserved_units + amount, "version": position.version + 1}
    )


def reservation_updates(order: BankOrder, state: BankState) -> dict[str, Any]:
    """Freeze redemption units before contacting the bank, including lost responses."""
    if order.kind != "redeem_product":
        return {}
    args = order.args.model_dump(mode="python")
    position = state.positions[args["position_ref"]]
    if position.owner != order.principal or order.requested_at < position.redeemable_at:
        raise ValueError("DOMAIN-POSITION")
    updated = _reserve_position(position, Fraction(str(args["amount"])))
    return {"positions": {**state.positions, position.id: updated}}


def redemption_account(order: BankOrder, state: BankState) -> str:
    """Use the verified purchase's source, or one unambiguous initial current account."""
    return resolve_redemption_account(_original_position(order, state), order.principal, state)


def redemption_proceeds(order: BankOrder, state: BankState) -> Fraction:
    position = _original_position(order, state)
    product = _product(state, position.product_ref)
    amount = Fraction(str(order.args.model_dump()["amount"]))
    return price_redemption(product, position, amount, order.requested_at).net_proceeds


def _purchase_valid(order: BankOrder, receipt: BankReceipt, state: BankState) -> bool:
    args = order.args.model_dump(mode="python")
    product = _product(state, args["product_ref"])
    account = state.accounts[args["source_ref"]]
    amount = Fraction(str(args["amount"]))
    fee = ceil_minor(amount * product.purchase_fee_rate)
    if (
        receipt.status != "settled"
        or receipt.settle_at is not None
        or receipt.executed_at != order.requested_at
        or len(receipt.exact_effects) != 2
        or account.owner != order.principal
        or account.kind != "current"
        or account.status != "active"
        or fee != Fraction(str(args["fee_buy"]))
    ):
        return False
    if not _money_effect(
        receipt.exact_effects[0],
        order,
        state,
        account=account.id,
        counterparty=product.id,
        amount=amount + fee,
        debit=True,
    ):
        return False
    ref = str(uuid5(uuid5(NAMESPACE_URL, "corridor-demo-v0"), f"{order.intent_key}:0:position"))
    created = Position(
        id=ref,
        owner=order.principal,
        product_ref=product.id,
        principal_amount=amount,
        units=amount,
        reserved_units=Fraction(0),
        nav=Fraction(1),
        acquired_at=receipt.executed_at,
        redeemable_at=(
            parse_time(receipt.executed_at) + timedelta(days=product.min_hold_days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        status="active",
    )
    return ref not in state.positions and receipt.exact_effects[1] == BankEffect(
        effect_type="position",
        object_ref=ref,
        field="position",
        after=created.model_dump(mode="json"),
    )


def _redemption_valid(order: BankOrder, receipt: BankReceipt, state: BankState) -> bool:
    args = order.args.model_dump(mode="python")
    original = _original_position(order, state)
    current = state.positions[original.id]
    product = _product(state, original.product_ref)
    amount = Fraction(str(args["amount"]))
    reserved = _reserve_position(original, amount)
    due = price_redemption(product, original, amount, order.requested_at).settle_at
    if (
        original.owner != order.principal
        or current.owner != order.principal
        or current.product_ref != original.product_ref
        or order.requested_at < original.redeemable_at
        or receipt.executed_at != order.requested_at
    ):
        return False
    if receipt.status == "pending":
        return (
            product.redeem_delay_days > 0
            and receipt.settle_at == due
            and (current == original or current.reserved_units >= amount)
            and receipt.exact_effects
            == [
                BankEffect(
                    effect_type="position",
                    object_ref=original.id,
                    field="position",
                    before=original.model_dump(mode="json"),
                    after=reserved.model_dump(mode="json"),
                )
            ]
        )
    if receipt.status != "settled" or len(receipt.exact_effects) != 2:
        return False
    if product.redeem_delay_days:
        if receipt.settle_at != due or state.now < due:
            return False
        before = current if current != original else reserved
    else:
        if receipt.settle_at is not None or current not in (original, reserved):
            return False
        before = original
    held = current if current != original else reserved
    if held.reserved_units < amount or held.units < amount or held.principal_amount < amount:
        return False
    after = held.model_copy(
        update={
            "units": held.units - amount,
            "principal_amount": held.principal_amount - amount,
            "reserved_units": held.reserved_units - amount,
            "status": "closed" if held.units == amount else "active",
            "version": held.version + 1,
        }
    )
    return _money_effect(
        receipt.exact_effects[0],
        order,
        state,
        account=redemption_account(order, state),
        counterparty=product.id,
        amount=redemption_proceeds(order, state),
        debit=False,
    ) and receipt.exact_effects[1] == BankEffect(
        effect_type="position",
        object_ref=original.id,
        field="position",
        before=before.model_dump(mode="json"),
        after=after.model_dump(mode="json"),
    )


def _before(state: BankState, order: BankOrder, account: str) -> Fraction:
    balance = available(state, account)
    old = latest_events(state).get(order.intent_key)
    if (
        old
        and old.event in {"reserved", "unknown"}
        and old.debit
        and old.debit.account_ref == account
    ):
        balance += old.debit.amount
    return balance


def _money_effect(
    effect: BankEffect,
    order: BankOrder,
    state: BankState,
    *,
    account: str,
    counterparty: str,
    amount: Fraction,
    debit: bool,
    external: bool = False,
) -> bool:
    if (
        effect.effect_type != ("debit" if debit else "credit")
        or effect.object_ref != account
        or effect.account_ref != account
        or effect.counterparty_ref != counterparty
        or effect.amount != amount
        or effect.field != "balance"
        or not isinstance(effect.before, str)
        or not isinstance(effect.after, str)
    ):
        return False
    before, after = Fraction(effect.before), Fraction(effect.after)
    return (
        before >= 0
        and after >= 0
        and after == before + (-amount if debit else amount)
        and (external or before == _before(state, order, account))
    )


def _query_valid(order: BankOrder, receipt: BankReceipt, state: BankState) -> bool:
    args = order.args.model_dump(mode="python")
    account_ref = args["account_ref"]
    if len(receipt.exact_effects) != 1:
        return False
    effect = receipt.exact_effects[0]
    if effect != BankEffect(
        effect_type="query", object_ref=account_ref, field=order.kind, after=effect.after
    ):
        return False
    if order.kind == "balance_query":
        return effect.after == fraction_string(available(state, account_ref))
    if not isinstance(effect.after, list):
        return False
    if order.kind == "transactions_query":
        rows = [Transaction.model_validate(value) for value in effect.after]
        return len({row.id for row in rows}) == len(rows) and all(
            row.account_ref == account_ref
            and row.owner == order.principal
            and row.booked_at <= state.now
            for row in rows
        )
    subscriptions = [SubscriptionAuthorization.model_validate(value) for value in effect.after]
    return len({row.id for row in subscriptions}) == len(subscriptions) and all(
        row.source_account_ref == account_ref
        and row.owner == order.principal
        and state.subscriptions.get(row.id) == row
        for row in subscriptions
    )


def _state_effects_valid(order: BankOrder, receipt: BankReceipt, state: BankState) -> bool:
    args = order.args.model_dump(mode="python")
    effects = receipt.exact_effects
    if order.kind == "cancel_subscription":
        ref = args["authorization_ref"]
        subscription = state.subscriptions[ref]
        return effects == [
            BankEffect(
                effect_type="state",
                object_ref=ref,
                field="status",
                before=subscription.status,
                after="cancelled",
            )
        ]
    if order.kind == "cancel_order":
        ref = args["order_ref"]
        return effects == [
            BankEffect(
                effect_type="order",
                object_ref=ref,
                field="status",
                before=state.orders[ref].status,
                after="cancelled",
            )
        ]
    if order.kind == "refund_request":
        if not effects:
            return False
        first = effects[0]
        expected = BankEffect(
            effect_type="state",
            object_ref=first.object_ref,
            field="refund_request",
            after={
                "receipt_ref": args["receipt_ref"],
                "principal": order.principal,
                "status": "pending",
            },
        )
        if first != expected:
            return False
        original = next(
            (value for value in state.orders.values() if value.receipt_ref == args["receipt_ref"]),
            None,
        )
        remainder = (
            []
            if original is None
            else [
                BankEffect(
                    effect_type="order",
                    object_ref=original.id,
                    field="status",
                    before="paid",
                    after="refund_pending",
                )
            ]
        )
        return effects[1:] == remainder
    return False


def _card_effects_valid(order: BankOrder, receipt: BankReceipt, state: BankState) -> bool:
    args = order.args.model_dump(mode="python")
    if order.kind == "apply_virtual_card":
        account = state.accounts[args["account_ref"]]
        ref = str(uuid5(uuid5(NAMESPACE_URL, "corridor-demo-v0"), f"{order.intent_key}:0:card"))
        if (
            account.owner != order.principal
            or account.kind != "current"
            or account.status != "active"
            or ref in state.cards
            or Fraction(str(args["limit"])) != state.policy.transfer_yellow_limit
        ):
            return False
        card = Card(
            id=ref,
            owner=order.principal,
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
        old = state.cards[ref]
        account = state.accounts[old.account_ref]
        if (
            old.owner != order.principal
            or account.owner != order.principal
            or account.status != "active"
            or account.kind != "current"
        ):
            return False
        changes: dict[str, Any] = {"version": old.version + 1}
        transitions = {
            "freeze_card": ({"active"}, "frozen"),
            "unfreeze_card": ({"frozen"}, "active"),
            "report_card_lost": ({"active", "frozen"}, "lost"),
            "restore_card": ({"lost"}, "frozen"),
        }
        if order.kind in transitions:
            statuses, target = transitions[order.kind]
            if old.status not in statuses:
                return False
            changes["status"] = target
        elif old.status == "lost":
            return False
        elif order.kind in {"lower_card_limit", "raise_card_limit"}:
            limit = Fraction(str(args["limit"]))
            if (
                order.kind == "lower_card_limit"
                and limit >= old.limit
                or order.kind == "raise_card_limit"
                and limit <= old.limit
            ):
                return False
            changes["limit"] = limit
        else:
            restrictions = args["restrictions"]
            if (
                order.kind == "restrict_card"
                and not set(old.restrictions) < set(restrictions)
                or order.kind == "relax_card_restriction"
                and not set(restrictions) < set(old.restrictions)
            ):
                return False
            changes["restrictions"] = restrictions
        before = old.model_dump(mode="json")
        card = old.model_copy(update=changes)
    return receipt.exact_effects == [
        BankEffect(
            effect_type="state",
            object_ref=ref,
            field="card",
            before=before,
            after=card.model_dump(mode="json"),
        )
    ]


def validate_receipt(order: BankOrder, receipt: BankReceipt, state: BankState) -> bool:
    try:
        order = BankOrder.model_validate(order.model_dump(mode="python"))
        receipt = BankReceipt.model_validate(receipt.model_dump(mode="python"))
        if (
            not verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig)
            or receipt.intent_key != order.intent_key
            or receipt.kind != order.kind
            or not order.requested_at <= receipt.executed_at <= state.now
        ):
            return False
        if receipt.status == "failed":
            return not receipt.exact_effects and receipt.settle_at is None
        if order.kind == "purchase_product":
            return _purchase_valid(order, receipt, state)
        if order.kind == "redeem_product":
            return _redemption_valid(order, receipt, state)
        if receipt.status != "settled" or receipt.settle_at is not None:
            return False
        if order.kind in _CARD_KINDS:
            return _card_effects_valid(order, receipt, state)
        if order.kind.endswith("query") or order.kind == "subscription_reminders":
            return _query_valid(order, receipt, state)
        if order.kind in {"cancel_subscription", "cancel_order", "refund_request"}:
            return _state_effects_valid(order, receipt, state)
        args = order.args.model_dump(mode="python")
        debit, credit = movements(order, state)
        if debit is None or len(receipt.exact_effects) < 2:
            return False
        destination = credit.account_ref if credit else args["destination_ref"]
        if not _money_effect(
            receipt.exact_effects[0],
            order,
            state,
            account=debit.account_ref,
            counterparty=destination,
            amount=debit.amount,
            debit=True,
        ):
            return False
        if not _money_effect(
            receipt.exact_effects[1],
            order,
            state,
            account=destination,
            counterparty=debit.account_ref,
            amount=debit.amount,
            debit=False,
            external=credit is None,
        ):
            return False
        extra = receipt.exact_effects[2:]
        if order.kind == "transfer":
            contact = state.contacts[args["contact_ref"]]
            expected = (
                [
                    BankEffect(
                        effect_type="state",
                        object_ref=contact.id,
                        field="is_new",
                        before=True,
                        after=False,
                    )
                ]
                if contact.is_new
                else []
            )
            return extra == expected
        if order.kind == "merchant_order":
            if len(extra) != 1 or extra[0].effect_type != "order" or extra[0].field != "order":
                return False
            created = MerchantOrder.model_validate(extra[0].after)
            return (
                created.id == extra[0].object_ref
                and created.id not in state.orders
                and created.version == 1
                and created.owner == order.principal
                and created.merchant_ref == args["merchant_ref"]
                and created.offer_ref == args["offer_ref"]
                and created.amount == debit.amount
                and created.status == "paid"
                and created.receipt_ref == receipt.receipt_id
                and created.refund_request_ref is None
                and extra[0]
                == BankEffect(
                    effect_type="order",
                    object_ref=created.id,
                    field="order",
                    after=created.model_dump(mode="json"),
                )
            )
        return order.kind in {"lock_funds", "unlock_funds"} and not extra
    except (ValueError, TypeError, KeyError, AttributeError, ArithmeticError, StopIteration):
        return False


def receipt_updates(order: BankOrder, receipt: BankReceipt, state: BankState) -> dict[str, Any]:
    if not validate_receipt(order, receipt, state):
        raise ValueError("BANK-RECEIPT")
    changes: dict[str, Any] = {"receipts": {**state.receipts, receipt.id: receipt}}
    if receipt.status == "failed" and order.kind == "redeem_product":
        original_position = _original_position(order, state)
        amount = Fraction(str(order.args.model_dump()["amount"]))
        current = state.positions[original_position.id]
        if current != original_position:
            if current != _reserve_position(original_position, amount):
                raise ValueError("BANK-RECEIPT")
            changes["positions"] = {**state.positions, original_position.id: original_position}
        return changes
    if receipt.status == "pending" and order.kind == "redeem_product":
        original_position = _original_position(order, state)
        current = state.positions[original_position.id]
        projected = Position.model_validate(receipt.exact_effects[0].after)
        changes["positions"] = {
            **state.positions,
            original_position.id: projected if current == original_position else current,
        }
        return changes
    if receipt.status != "settled":
        return changes
    for effect in receipt.exact_effects:
        if effect.effect_type == "state" and effect.field == "card":
            card = Card.model_validate(effect.after)
            changes["cards"] = {**state.cards, card.id: card}
        elif effect.effect_type == "position" and effect.field == "position":
            position = Position.model_validate(effect.after)
            changes["positions"] = {**state.positions, position.id: position}
        elif effect.effect_type == "state" and effect.field == "is_new":
            contact = state.contacts[effect.object_ref]
            changes["contacts"] = {
                **state.contacts,
                contact.id: contact.model_copy(
                    update={"is_new": False, "version": contact.version + 1}
                ),
            }
        elif effect.effect_type == "state" and effect.field == "status":
            subscription = state.subscriptions[effect.object_ref]
            changes["subscriptions"] = {
                **state.subscriptions,
                subscription.id: subscription.model_copy(
                    update={"status": "cancelled", "version": subscription.version + 1}
                ),
            }
        elif effect.effect_type == "order":
            if effect.field == "order":
                created = MerchantOrder.model_validate(effect.after)
                changes["orders"] = {**state.orders, created.id: created}
            elif effect.field == "status":
                original = state.orders[effect.object_ref]
                update: dict[str, Any] = {"status": effect.after, "version": original.version + 1}
                if effect.after == "refund_pending":
                    update["refund_request_ref"] = receipt.exact_effects[0].object_ref
                changes["orders"] = {
                    **state.orders,
                    original.id: original.model_copy(update=update),
                }
        elif (
            effect.effect_type == "query"
            and effect.field == "transactions_query"
            and isinstance(effect.after, list)
        ):
            rows = [Transaction.model_validate(value) for value in effect.after]
            changes["transactions"] = {**state.transactions, **{row.id: row for row in rows}}
    return changes
