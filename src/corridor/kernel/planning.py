"""Narrow trusted sources for non-debit AA collection requests."""

from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, verify
from corridor.schemas.bank import AnalysisReceipt, BankAction, BankOrder, BankReceipt
from corridor.schemas.money import Money, parse_fraction
from corridor.schemas.state import BankState
from corridor.stores.bank import latest_events


def aa_bill_total(action: BankAction, state: BankState) -> Fraction:
    """Accept only a registered built-in consumption total owned by the caller."""
    args = action.args.model_dump(mode="python")
    receipt = state.receipts.get(str(args["source_bill_ref"]))
    if (
        args["total_ref"] != args["source_bill_ref"]
        or not isinstance(receipt, AnalysisReceipt)
        or receipt.trust != "builtin"
        or receipt.function_id != "bill_summary_v1"
        or receipt.computed_at > state.now
        or receipt.parameters.get("principal") != action.principal
        or not verify(state.roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
    ):
        raise ValueError("PROV-MISMATCH")
    account = state.accounts.get(str(receipt.parameters.get("account_ref", "")))
    field = receipt.results.get("net_spend")
    if (
        account is None
        or account.owner != action.principal
        or field is None
        or field.unit != "CNY"
        or not any(
            event.event == "settled"
            and event.principal == action.principal
            and event.kind in {"bill_analyze", "bill_report"}
            and event.object_delta.get("analysis_receipt_id") == receipt.id
            and event.object_delta.get("receipt_hash") == H(receipt)
            for event in state.ledger
        )
    ):
        raise ValueError("PROV-MISMATCH")
    amount = parse_fraction(field.value)
    if amount <= 0 or (amount * 100).denominator != 1:
        raise ValueError("DOMAIN-AA")
    return amount


def aa_total(action: BankAction, state: BankState) -> Fraction:
    args = action.args.model_dump(mode="python")
    if args["source_bill_ref"] != args["total_ref"]:
        raise ValueError("PROV-COHERENCE")
    value = state.user_inputs.get(str(args["total_ref"]))
    if value is not None:
        if value.slot != "total":
            raise ValueError("PROV-FIELD")
        return Money.model_validate(value.value).amount
    return aa_bill_total(action, state)


def refund_requested(receipt_ref: str, state: BankState) -> bool:
    """Keep settled and unresolved requests reserved against the paid receipt."""
    for event in latest_events(state).values():
        if event.kind != "refund_request" or event.event not in {"reserved", "unknown", "settled"}:
            continue
        if event.object_delta.get("receipt_ref") == receipt_ref:
            return True
        for field in ("action", "order"):
            saved = event.object_delta.get(field)
            if not isinstance(saved, dict):
                continue
            args = saved.get("args")
            if isinstance(args, dict) and args.get("receipt_ref") == receipt_ref:
                return True
    return False


def compensation_errors(action: BankAction, state: BankState, amount: Fraction | None) -> list[str]:
    """Bound a declared lock reversal to the original effect and remaining amount."""
    if action.kind != "unlock_funds":
        return []
    args = action.args.model_dump(mode="python")
    purpose = state.user_inputs.get(str(args.get("purpose_ref", "")))
    if purpose is None or not isinstance(purpose.value, dict):
        return []
    error = ["DOMAIN-COMPENSATION"]
    reference = purpose.value.get("original_receipt_ref")
    if not isinstance(reference, str) or not set(purpose.value) <= {
        "original_receipt_ref",
        "original_plan_id",
        "original_node_id",
    }:
        return error
    receipt = state.receipts.get(reference)
    if (
        not isinstance(receipt, BankReceipt)
        or receipt.kind != "lock_funds"
        or receipt.status != "settled"
        or receipt.executed_at > state.now
        or not verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig)
    ):
        return error
    original = latest_events(state).get(receipt.intent_key)
    if (
        original is None
        or original.event != "settled"
        or original.kind != "lock_funds"
        or original.principal != action.principal
        or original.bank_receipt_id != receipt.id
        or original.debit is None
        or original.credit is None
    ):
        return error
    try:
        order = BankOrder.model_validate(original.object_delta.get("order"))
        original_args = order.args.model_dump(mode="python")
        original_amount = parse_fraction(original_args.get("amount"))
        if (
            order.kind != "lock_funds"
            or order.intent_key != receipt.intent_key
            or order.principal != action.principal
            or original_args.get("source_ref") != args["source_ref"]
            or original_args.get("locked_ref") != args["locked_ref"]
            or original.debit.account_ref != args["source_ref"]
            or original.credit.account_ref != args["locked_ref"]
            or original.debit.amount != original_amount
            or original.credit.amount != original_amount
            or len(receipt.exact_effects) != 2
        ):
            return error
        debit, credit = receipt.exact_effects
        if (
            debit.effect_type != "debit"
            or credit.effect_type != "credit"
            or debit.account_ref != args["source_ref"]
            or credit.account_ref != args["locked_ref"]
            or debit.amount != original_amount
            or credit.amount != original_amount
            or parse_fraction(debit.before) - parse_fraction(debit.after) != original_amount
            or parse_fraction(credit.after) - parse_fraction(credit.before) != original_amount
        ):
            return error
        used = Fraction()
        for event in latest_events(state).values():
            if event.kind != "unlock_funds" or event.event == "failed":
                continue
            old_action = event.object_delta.get("action")
            if not isinstance(old_action, dict):
                continue
            old_args = old_action.get("args")
            if not isinstance(old_args, dict):
                continue
            old_purpose = state.user_inputs.get(str(old_args.get("purpose_ref", "")))
            if old_purpose is None or not isinstance(old_purpose.value, dict):
                continue
            if old_purpose.value.get("original_receipt_ref") != reference:
                continue
            if event.principal != action.principal or event.debit is None:
                return error
            used += event.debit.amount
        return [] if amount is not None and 0 < amount <= original_amount - used else error
    except (ValueError, TypeError, KeyError, AttributeError):
        return error
