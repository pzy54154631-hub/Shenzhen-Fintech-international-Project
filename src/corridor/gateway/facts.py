"""Receipt-authenticated templates are the sole source of displayed bank facts."""

from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, verify
from corridor.gateway.privacy import PIIVault
from corridor.schemas.allocation import BestInterestAllocationCertificate
from corridor.schemas.bank import AnalysisReceipt, BankOrder, BankReceipt, BusinessEvent
from corridor.schemas.domain import Position
from corridor.schemas.models import JsonValue
from corridor.schemas.money import display_amount, fraction_string
from corridor.schemas.narrative import FactRef, Narrative, NarrativeResult, RenderedFact
from corridor.schemas.state import BankState
from corridor.stores.bank import latest_events

_FIELDS = {
    "status",
    "amount",
    "balance_before",
    "balance_after",
    "source_ref",
    "destination_ref",
    "executed_at",
}
_SAFE_NOTES = frozenset({
    "Please review the recipient.",
    "Please tell us if you need help.",
    "Please rely on the verified results.",
    "Please review the verified facts.",
})
_SAFE_NOTE = "Assistant note (unverified): Please rely on the verified bank facts."
_EMPTY = "No verifiable transaction result is available."


def _authorized(receipt: BankReceipt, state: BankState, principal: str) -> BusinessEvent:
    if (
        not verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig)
        or receipt.executed_at > state.now
    ):
        raise ValueError("BANK-RECEIPT")
    event = latest_events(state).get(receipt.intent_key)
    if (
        event is None
        or event.principal != principal
        or event.bank_receipt_id != receipt.id
        or event.kind != receipt.kind
        or event.event != receipt.status
        or receipt.status not in {"settled", "failed"}
    ):
        raise ValueError("RCPT-MISMATCH")
    return event


def _validated_values(
    receipt: BankReceipt, event: BusinessEvent, state: BankState, principal: str
) -> dict[str, JsonValue]:
    order = BankOrder.model_validate(event.object_delta.get("order"))
    if (
        order.intent_key != receipt.intent_key
        or order.principal != principal
        or order.kind != receipt.kind
        or not order.requested_at <= receipt.executed_at <= event.ts <= state.now
    ):
        raise ValueError("BANK-RECEIPT")
    values: dict[str, JsonValue] = {"status": receipt.status, "executed_at": receipt.executed_at}
    if receipt.status == "failed":
        if receipt.exact_effects:
            raise ValueError("BANK-RECEIPT")
        return values
    args = order.args.model_dump(mode="python")
    effects = receipt.exact_effects
    if order.kind == "transfer":
        if len(effects) not in {2, 3}:
            raise ValueError("BANK-RECEIPT")
        debit, credit = effects[:2]
        amount = Fraction(str(args["amount"]))
        source, destination = args["source_ref"], args["destination_ref"]
        if (
            source not in state.accounts
            or state.accounts[source].owner != principal
            or event.debit is None
            or event.debit.account_ref != source
            or event.debit.amount != amount
            or event.credit is not None
            or debit.effect_type != "debit"
            or credit.effect_type != "credit"
            or debit.object_ref != source
            or debit.account_ref != source
            or debit.counterparty_ref != destination
            or credit.object_ref != destination
            or credit.account_ref != destination
            or credit.counterparty_ref != source
            or debit.field != "balance"
            or credit.field != "balance"
            or debit.amount != amount
            or credit.amount != amount
            or not all(
                isinstance(value, str)
                for value in (debit.before, debit.after, credit.before, credit.after)
            )
        ):
            raise ValueError("BANK-RECEIPT")
        before, after = Fraction(str(debit.before)), Fraction(str(debit.after))
        other_before, other_after = Fraction(str(credit.before)), Fraction(str(credit.after))
        if (
            before - after != amount
            or other_after - other_before != amount
            or min(before, after, other_before, other_after) < 0
        ):
            raise ValueError("BANK-RECEIPT")
        if len(effects) == 3:
            extra = effects[2]
            if (
                extra.effect_type != "state"
                or extra.object_ref != args["contact_ref"]
                or extra.field != "is_new"
                or extra.before is not True
                or extra.after is not False
                or extra.amount is not None
                or extra.account_ref is not None
                or extra.counterparty_ref is not None
            ):
                raise ValueError("BANK-RECEIPT")
        values.update(
            amount=fraction_string(amount),
            balance_before=fraction_string(before),
            balance_after=fraction_string(after),
            source_ref=source,
            destination_ref=destination,
        )
    elif order.kind in {"purchase_product", "redeem_product"}:
        amount = Fraction(str(args["amount"]))
        position_effects = [item for item in effects if item.effect_type == "position"]
        movement_effects = [item for item in effects if item.effect_type in {"debit", "credit"}]
        if len(effects) != 2 or len(position_effects) != 1 or len(movement_effects) != 1:
            raise ValueError("BANK-RECEIPT")
        position = Position.model_validate(position_effects[0].after)
        movement = movement_effects[0]
        if position.owner != principal or movement.field != "balance":
            raise ValueError("BANK-RECEIPT")
        before, after = Fraction(str(movement.before)), Fraction(str(movement.after))
        if order.kind == "purchase_product":
            charge = amount + Fraction(str(args["fee_buy"]))
            if (
                event.debit is None
                or event.debit.amount != charge
                or event.credit is not None
                or movement.effect_type != "debit"
                or movement.amount != charge
                or movement.account_ref != args["source_ref"]
                or before - after != charge
                or position.product_ref != args["product_ref"]
                or position.principal_amount != amount
                or position.units != amount
            ):
                raise ValueError("BANK-RECEIPT")
        else:
            original = Position.model_validate(position_effects[0].before)
            if (
                event.credit is None
                or event.credit.amount != movement.amount
                or event.debit is not None
                or movement.effect_type != "credit"
                or movement.account_ref != event.credit.account_ref
                or after - before != movement.amount
                or position.id != args["position_ref"]
                or original.owner != principal
                or original.units - position.units != amount
                or original.principal_amount - position.principal_amount != amount
            ):
                raise ValueError("BANK-RECEIPT")
        values.update(
            amount=fraction_string(amount),
            balance_before=fraction_string(before),
            balance_after=fraction_string(after),
            source_ref=movement.account_ref,
        )
    elif order.kind in {"balance_query", "transactions_query"}:
        account = args["account_ref"]
        if (
            account not in state.accounts
            or state.accounts[account].owner != principal
            or len(effects) != 1
            or effects[0].effect_type != "query"
            or effects[0].object_ref != account
            or effects[0].field != order.kind
            or event.debit is not None
            or event.credit is not None
        ):
            raise ValueError("BANK-RECEIPT")
        values["source_ref"] = account
        if order.kind == "balance_query":
            balance = Fraction(str(effects[0].after))
            if balance < 0:
                raise ValueError("BANK-RECEIPT")
            values["balance_after"] = fraction_string(balance)
    else:
        raise ValueError("RCPT-MISMATCH")
    return values


def _fact(ref: FactRef, receipt: BankReceipt, values: dict[str, JsonValue]) -> RenderedFact:
    if ref.field not in _FIELDS or ref.field not in values:
        raise ValueError("RCPT-MISMATCH")
    value = values[ref.field]
    if "expected" in ref.model_fields_set and ref.expected != value:
        raise ValueError("RCPT-MISMATCH")
    display = str(value)
    if ref.field in {"amount", "balance_before", "balance_after"}:
        display = display_amount(Fraction(str(value)))
    labels = {
        "amount": "Transfer amount",
        "balance_before": "Balance before execution",
        "balance_after": "Verified balance",
        "source_ref": "Account ID",
        "destination_ref": "Recipient destination ID",
        "executed_at": "Bank execution time",
    }
    if receipt.kind in {"purchase_product", "redeem_product"}:
        labels["amount"] = (
            "Purchase principal" if receipt.kind == "purchase_product" else "Redemption principal"
        )
    if ref.field == "status":
        display = (
            "Transfer settled"
            if receipt.kind == "transfer" and value == "settled"
            else "Purchase settled"
            if receipt.kind == "purchase_product" and value == "settled"
            else "Redemption settled"
            if receipt.kind == "redeem_product" and value == "settled"
            else "Query completed"
            if value == "settled"
            else "Bank confirmation incomplete"
        )
        text = display + "."
    else:
        unit = " CNY" if ref.field in {"amount", "balance_before", "balance_after"} else ""
        text = f"{labels[ref.field]}: {display}{unit}."
    return RenderedFact(
        receipt_ref=ref.receipt_ref,
        field=ref.field,
        exact_value=value,
        display_value=display,
        text=text,
    )


def _positional_value(value: JsonValue, path: str, labels: list[str]) -> JsonValue:
    """Keep every planner-controlled key outside the authenticated fact projection."""
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for index, key in enumerate(sorted(value), start=1):
            field = f"r{index}"
            child_path = f"{path}.{field}"
            labels.append(f"{child_path} = {key}")
            result[field] = _positional_value(value[key], child_path, labels)
        return result
    if isinstance(value, list):
        return [
            _positional_value(item, f"{path}[{index}]", labels)
            for index, item in enumerate(value, start=1)
        ]
    return value


def _analysis_fact(
    ref: FactRef, receipt: AnalysisReceipt, state: BankState, principal: str
) -> tuple[RenderedFact, list[str]]:
    account_ref = receipt.parameters.get("account_ref")
    account = state.accounts.get(str(account_ref))
    investment = receipt.function_id in {
        "product_compare_v1",
        "investment_income_v1",
        "risk_assess_v1",
        "allocation_compare_v1",
    }
    allocation = receipt.function_id == "allocation_compare_v1"
    aa_request = receipt.function_id == "aa_split_v1"
    exploratory = receipt.function_id == "restricted_analysis_v1" and receipt.trust == "exploratory"
    position = state.positions.get(str(receipt.parameters.get("position_ref")))
    owned = account is not None and account.owner == principal
    if receipt.function_id == "investment_income_v1":
        owned = position is not None and position.owner == principal
    elif receipt.function_id == "risk_assess_v1":
        owned = principal in state.customers
    elif aa_request:
        owned = principal in state.customers
    if (
        (receipt.trust != "builtin" and not exploratory)
        or (
            not investment
            and not aa_request
            and not exploratory
            and receipt.function_id not in {"bill_summary_v1", "anomaly_v1", "subscriptions_v1"}
        )
        or receipt.parameters.get("principal") != principal
        or not owned
        or receipt.computed_at > state.now
        or not verify(state.roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
        or not any(
            event.principal == principal
            and event.event == "settled"
            and (not aa_request or event.kind == "aa_request")
            and (not allocation or event.kind == "allocation_compare")
            and event.object_delta.get("analysis_receipt_id") == receipt.id
            and event.object_delta.get("action_hash") == receipt.parameters.get("action_hash")
            and event.object_delta.get("receipt_hash") == H(receipt)
            and event.ts == receipt.computed_at
            for event in state.ledger
        )
    ):
        raise ValueError("RCPT-MISMATCH")
    if aa_request:
        _validate_aa_results(receipt, state, principal)
    if allocation:
        _validate_allocation_results(receipt)
    if exploratory:
        from corridor.gateway.sandbox_monitor import validate_results

        if (
            not receipt.program_hash
            or not validate_results({key: value.value for key, value in receipt.results.items()})
            or any(value.unit != "number" for value in receipt.results.values())
        ):
            raise ValueError("RCPT-MISMATCH")
    item = receipt.results.get(ref.field)
    if item is None or any(
        tx_id not in state.transactions
        or state.transactions[tx_id].owner != principal
        or state.transactions[tx_id].account_ref != account_ref
        for tx_id in item.source_tx_ids
    ):
        raise ValueError("RCPT-MISMATCH")
    if "expected" in ref.model_fields_set and ref.expected != item.value:
        raise ValueError("RCPT-MISMATCH")
    field, value = ref.field, item.value
    labels: list[str] = []
    if exploratory:
        # Sort the signed result keys so IDs survive canonical JSON persistence and
        # do not depend on the planner's chosen fact-reference ordering.
        field = f"r{sorted(receipt.results).index(ref.field) + 1}"
        path = f"{receipt.id}/{field}"
        labels.append(f"{path} = {ref.field}")
        value = _positional_value(value, path, labels)
    display = display_amount(Fraction(str(value))) if item.unit == "CNY" else str(value)
    qualifier = (
        "performance benchmark (not guaranteed); "
        if ref.field.endswith("expected_net") or ref.field == "projected_income"
        else ""
    )
    text = f"Verified analysis {ref.field}: {display} ({item.unit}; {qualifier})."
    if allocation:
        qualifier = (
            " Performance benchmark (not guaranteed)." if ref.field == "projected_net" else ""
        )
        text = f"Verified allocation {ref.field}: {display} ({item.unit}).{qualifier}"
    if aa_request:
        if ref.field == "status":
            display = "Request created; collection not yet confirmed"
        text = f"Split-bill collection request {ref.field}: {display}."
    if exploratory:
        text = (
            f"Exploratory analysis {field}: {display}; period {receipt.parameters.get('period')}, "
            f"{receipt.parameters.get('row_count')} rows; program {receipt.program_hash}. "
            "Question semantics are unverified; this cannot authorize a payment."
        )
    return RenderedFact(
        receipt_ref=receipt.id,
        field=field,
        exact_value=value,
        display_value=display,
        text=text,
    ), labels


def _validate_allocation_results(receipt: AnalysisReceipt) -> None:
    """Check the display projection against the same authenticated full BIAC."""
    raw = receipt.results.get("allocation")
    if raw is None or raw.unit != "allocation_fact":
        raise ValueError("RCPT-MISMATCH")
    biac = BestInterestAllocationCertificate.model_validate(raw.value)
    expected = {
        "total_principal": (fraction_string(biac.totals.principal), "CNY"),
        "total_buy_fees": (fraction_string(biac.totals.fee_buy), "CNY"),
        "total_debit": (fraction_string(biac.totals.total_debit), "CNY"),
        "projected_net": (fraction_string(biac.totals.projected_net), "CNY"),
        "liquid_principal": (fraction_string(biac.totals.liquid_net_principal), "CNY"),
        "biac_hash": (H(biac), "allocation_hash"),
        "projection_notice": (
            "Projected, not guaranteed. Synthetic new-money allocation.",
            "notice",
        ),
    }
    if (
        receipt.parameters.get("account_ref") != biac.source_account_ref
        or receipt.parameters.get("principal") != biac.principal
        or set(receipt.results) != {"allocation", *expected}
        or any(item.source_tx_ids for item in receipt.results.values())
        or any(
            receipt.results[name].value != value or receipt.results[name].unit != unit
            for name, (value, unit) in expected.items()
        )
    ):
        raise ValueError("RCPT-MISMATCH")


def _validate_aa_results(receipt: AnalysisReceipt, state: BankState, principal: str) -> None:
    """A collection request cannot be presented as completed payment evidence."""
    shares = sorted(
        field.removeprefix("shares.") for field in receipt.results if field.startswith("shares.")
    )
    if (
        not 1 <= len(shares) <= 10
        or set(receipt.results)
        != {"total", "status", "request_ids", *(f"shares.{ref}" for ref in shares)}
        or any(
            ref not in state.contacts or state.contacts[ref].owner != principal or not ref.isascii()
            for ref in shares
        )
        or any(item.source_tx_ids for item in receipt.results.values())
    ):
        raise ValueError("RCPT-MISMATCH")
    total = receipt.results["total"]
    status = receipt.results["status"]
    requests = receipt.results["request_ids"]
    if (
        total.unit != "CNY"
        or not isinstance(total.value, str)
        or status.unit != "request_status"
        or status.value != "requested"
        or requests.unit != "request_ids"
        or not isinstance(requests.value, list)
        or len(requests.value) != len(shares)
        or any(not isinstance(value, str) or not value for value in requests.value)
        or len(set(str(value) for value in requests.value)) != len(shares)
    ):
        raise ValueError("RCPT-MISMATCH")
    amount = Fraction(total.value)
    if amount <= 0 or (amount * 100).denominator != 1 or amount * 100 < len(shares):
        raise ValueError("RCPT-MISMATCH")
    quotient, remainder = divmod(int(amount * 100), len(shares))
    for index, contact in enumerate(shares):
        item = receipt.results[f"shares.{contact}"]
        expected = Fraction(quotient + (index < remainder), 100)
        if item.unit != "CNY" or item.value != fraction_string(expected):
            raise ValueError("RCPT-MISMATCH")


def render_narrative(
    narrative: Narrative, state: BankState, principal: str, vault: PIIVault
) -> NarrativeResult:
    rules: list[str] = []
    facts: list[RenderedFact] = []
    exploratory_labels: list[str] = []
    note = ""
    fallback = _EMPTY
    try:
        state = BankState.model_validate(state.model_dump(mode="python"))
        pending = any(
            event.event in {"reserved", "unknown"} and event.principal == principal
            for event in latest_events(state).values()
        )
        fallback = "Results awaiting reconciliation." if pending else _EMPTY
        # exclude_unset preserves the distinction between omitted and explicit expected=null.
        narrative = Narrative.model_validate(
            narrative.model_dump(mode="python", exclude_unset=True, warnings=False)
        )
        for ref in narrative.fact_refs:
            receipt = state.receipts.get(ref.receipt_ref)
            if isinstance(receipt, AnalysisReceipt):
                fact, labels = _analysis_fact(ref, receipt, state, principal)
                facts.append(fact)
                exploratory_labels.extend(labels)
                continue
            if not isinstance(receipt, BankReceipt):
                raise ValueError("RCPT-MISMATCH")
            event = _authorized(receipt, state, principal)
            facts.append(_fact(ref, receipt, _validated_values(receipt, event, state, principal)))
    except (ValueError, TypeError, AttributeError, KeyError, ArithmeticError) as exc:
        rules.append(str(exc) if str(exc) in {"BANK-RECEIPT", "RCPT-MISMATCH"} else "RCPT-MISMATCH")
        facts = []
        exploratory_labels = []
    raw_note = getattr(narrative, "note", "")
    if not isinstance(raw_note, str):
        rules.append("RCPT-MISMATCH")
        raw_note = ""
    if raw_note:
        try:
            vault.ensure_safe(raw_note, rule="PII-OUT")
            if raw_note not in _SAFE_NOTES:
                raise ValueError("RCPT-MISMATCH")
            note = "Assistant note (unverified): " + raw_note
        except ValueError as exc:
            rules.append(str(exc))
            note = _SAFE_NOTE
    if exploratory_labels:
        label_note = (
            "Assistant note (unverified): Program label semantics are unverified; "
            + "; ".join(dict.fromkeys(exploratory_labels))
        )
        note = "\n".join(part for part in (note, label_note) if part)
    text = "\n".join([*(item.text for item in facts)] or [fallback])
    if note:
        text += "\n" + note
    try:
        vault.ensure_safe({"facts": facts, "note": note, "text": text}, rule="PII-OUT")
    except ValueError:
        rules.append("PII-OUT")
        facts, note, text = [], _SAFE_NOTE, fallback + "\n" + _SAFE_NOTE
    return NarrativeResult(
        status="rejected" if rules else "rendered",
        rule_ids=list(dict.fromkeys(rules)),
        facts=facts,
        note=note,
        text=text,
    )
