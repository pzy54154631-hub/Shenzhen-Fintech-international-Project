"""Exact, deterministic built-in billing and subscription calculations.

These functions consume trusted bank rows. Memos and merchant display names do
not participate in classification, recurrence, or authorization matching.
"""

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime, time, timedelta
from fractions import Fraction
from uuid import NAMESPACE_URL, uuid5

from nacl.signing import SigningKey

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, sign
from corridor.schemas.bank import AnalysisArgs, AnalysisReceipt, AnalysisResult, BankAction
from corridor.schemas.domain import Merchant, SubscriptionAuthorization, Transaction
from corridor.schemas.models import JsonValue
from corridor.schemas.money import fraction_string
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time

BILL_FUNCTION = "bill_summary_v1"
ANOMALY_FUNCTION = "anomaly_v1"
SUBSCRIPTION_FUNCTION = "subscriptions_v1"
_CHINA_OFFSET = timedelta(hours=8)
_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")
_CATEGORY_CODES = frozenset({
    "dining",
    "transport",
    "shopping",
    "services",
    "gifts",
    "groceries",
    "housing",
    "utilities",
    "healthcare",
    "education",
    "entertainment",
    "travel",
    "uncategorized",
})
Period = str | Mapping[str, str]


def _local_midnight(day: date) -> str:
    return (datetime.combine(day, time(), tzinfo=UTC) - _CHINA_OFFSET).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def period_bounds(period: Period) -> tuple[str, str]:
    """Convert a China year/month/day or explicit date range to UTC bounds."""
    if isinstance(period, str):
        if re.fullmatch(r"[0-9]{4}", period):
            start = date(int(period), 1, 1)
            end = date(start.year + 1, 1, 1)
        elif re.fullmatch(r"[0-9]{4}-[0-9]{2}", period):
            start = date.fromisoformat(period + "-01")
            end = date(start.year + (start.month == 12), start.month % 12 + 1, 1)
        elif re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", period):
            start = date.fromisoformat(period)
            end = start + timedelta(days=1)
        else:
            raise ValueError("Invalid analysis period")
    else:
        if set(period) != {"start_inclusive", "end_exclusive"}:
            raise ValueError("Invalid analysis period")
        start = date.fromisoformat(period["start_inclusive"])
        end = date.fromisoformat(period["end_exclusive"])
    if start >= end:
        raise ValueError("Analysis period must be nonempty")
    return _local_midnight(start), _local_midnight(end)


def _unique(rows: Iterable[Transaction]) -> list[Transaction]:
    unique: dict[str, Transaction] = {}
    for row in rows:
        if row.id in unique and unique[row.id] != row:
            raise ValueError("Conflicting transaction ID")
        unique[row.id] = row
    return sorted(unique.values(), key=lambda row: (row.booked_at, row.id))


def _in_period(row: Transaction, bounds: tuple[str, str]) -> bool:
    return row.status == "settled" and bounds[0] <= row.booked_at < bounds[1]


def _debit(row: Transaction) -> bool:
    return row.status == "settled" and row.kind == "merchant_debit" and row.direction == "debit"


def _refund(row: Transaction) -> bool:
    return row.status == "settled" and row.kind == "refund" and row.direction == "credit"


def _original(row: Transaction, by_id: Mapping[str, Transaction]) -> Transaction | None:
    original = by_id.get(row.refund_of or "")
    if (
        original is not None
        and _debit(original)
        and original.owner == row.owner
        and original.account_ref == row.account_ref
        and original.booked_at <= row.booked_at
    ):
        return original
    return None


def _category(row: Transaction, merchants: Mapping[str, Merchant]) -> str:
    merchant = merchants.get(row.merchant_ref or "")
    if merchant is None or merchant.category_code not in _CATEGORY_CODES:
        return "uncategorized"
    return merchant.category_code


def _result(value: JsonValue, unit: str, sources: Iterable[str]) -> AnalysisResult:
    return AnalysisResult(value=value, unit=unit, source_tx_ids=sorted(set(sources)))


def billing_results(
    rows: Iterable[Transaction], merchants: Mapping[str, Merchant], period: Period
) -> dict[str, AnalysisResult]:
    """Aggregate exact settled consumption; refund timing determines its period."""
    transactions = _unique(rows)
    by_id = {row.id: row for row in transactions}
    bounds = period_bounds(period)
    gross, refunds = Fraction(), Fraction()
    debit_ids: list[str] = []
    refund_ids: list[str] = []
    totals: dict[str, Fraction] = defaultdict(Fraction)
    sources: dict[str, list[str]] = defaultdict(list)
    for row in transactions:
        if not _in_period(row, bounds):
            continue
        if _debit(row):
            gross += row.amount
            debit_ids.append(row.id)
            category, amount = _category(row, merchants), row.amount
        elif _refund(row):
            refunds += row.amount
            refund_ids.append(row.id)
            original = _original(row, by_id)
            category = _category(original, merchants) if original else "unmatched_refund"
            amount = -row.amount
        else:
            continue
        totals[category] += amount
        sources[category].append(row.id)
    net = gross - refunds
    if sum(totals.values(), Fraction()) != net:
        raise ValueError("Analysis category totals do not reconcile")
    results = {
        "gross_spend": _result(fraction_string(gross), "CNY", debit_ids),
        "refunds": _result(fraction_string(refunds), "CNY", refund_ids),
        "net_spend": _result(fraction_string(net), "CNY", [*debit_ids, *refund_ids]),
    }
    for category in sorted(totals):
        results[f"category_totals.{category}"] = _result(
            fraction_string(totals[category]), "CNY", sources[category]
        )
    return results


def anomaly_results(rows: Iterable[Transaction], period: Period) -> dict[str, AnalysisResult]:
    """Flag suspicious charges without claiming fraud or changing account state."""
    bounds = period_bounds(period)
    transactions = [row for row in _unique(rows) if _in_period(row, bounds) and _debit(row)]
    reasons: dict[str, set[str]] = defaultdict(set)
    sources: dict[str, set[str]] = defaultdict(set)
    groups: dict[tuple[str, str, str, Fraction], list[Transaction]] = defaultdict(list)
    for row in transactions:
        if row.amount >= 2000:
            reasons[row.id].add("large_expense")
            sources[row.id].add(row.id)
        if row.merchant_ref is not None:
            groups[(row.owner, row.account_ref, row.merchant_ref, row.amount)].append(row)
    for group in groups.values():
        for index, row in enumerate(group):
            for other in group[index + 1 :]:
                if parse_time(other.booked_at) - parse_time(row.booked_at) > timedelta(minutes=10):
                    break
                if row.bank_ref == other.bank_ref:
                    continue
                for candidate in (row, other):
                    reasons[candidate.id].add("duplicate_candidate")
                    sources[candidate.id].update((row.id, other.id))
    results = {"anomaly_tx_ids": _result(list(sorted(reasons)), "tx_ids", reasons)}
    for tx_id in sorted(reasons):
        results[f"anomalies.{tx_id}"] = _result(
            list(sorted(reasons[tx_id])), "reason_codes", sources[tx_id]
        )
    return results


def _china_date(timestamp: str) -> date:
    return (parse_time(timestamp) + _CHINA_OFFSET).date()


def subscription_results(
    rows: Iterable[Transaction],
    subscriptions: Iterable[SubscriptionAuthorization],
    period: Period,
    *,
    now: str,
    principal: str,
    account_ref: str,
) -> dict[str, AnalysisResult]:
    """Recognize recurring charges and match only unique active bank authority."""
    transactions = [
        row
        for row in _unique(rows)
        if row.owner == principal and row.account_ref == account_ref and row.booked_at <= now
    ]
    by_id = {row.id: row for row in transactions}
    refunded = {
        original.id
        for row in transactions
        if _refund(row)
        if (original := _original(row, by_id)) is not None
    }
    bounds = period_bounds(period)
    groups: dict[tuple[str, str, Fraction], list[Transaction]] = defaultdict(list)
    for row in transactions:
        if _debit(row) and _in_period(row, bounds) and row.id not in refunded and row.merchant_ref:
            groups[(row.merchant_ref, row.account_ref, row.amount)].append(row)
    authorities = sorted(subscriptions, key=lambda item: item.id)
    results: dict[str, AnalysisResult] = {}
    merchants: set[str] = set()
    cancellable: dict[str, list[str]] = {}
    reminders: dict[str, list[str]] = {}
    all_sources: list[str] = []
    candidate_index = 0
    for (merchant, account, amount), group in sorted(groups.items()):
        gaps = [
            (_china_date(right.booked_at) - _china_date(left.booked_at)).days
            for left, right in zip(group, group[1:], strict=False)
        ]
        if len(group) < 3 or not all(25 <= gap <= 35 for gap in gaps):
            continue
        sources = sorted(row.id for row in group)
        all_sources.extend(sources)
        merchants.add(merchant)
        matching = [
            authorization
            for authorization in authorities
            if authorization.owner == principal
            and authorization.status == "active"
            and authorization.source_account_ref == account
            and authorization.merchant_ref == merchant
            and authorization.amount == amount
            and authorization.period_months == 1
        ]
        authorization = matching[0] if len(matching) == 1 else None
        prefix = f"candidates.{candidate_index}"
        candidate_index += 1
        results.update({
            f"{prefix}.merchant_ref": _result(merchant, "merchant_ref", sources),
            f"{prefix}.account_ref": _result(account, "account_ref", sources),
            f"{prefix}.amount": _result(fraction_string(amount), "CNY", sources),
            f"{prefix}.cancellable": _result(authorization is not None, "boolean", sources),
            f"{prefix}.authorization_ref": _result(
                authorization.id if authorization else None, "authorization_ref", sources
            ),
        })
        if authorization is not None:
            cancellable[authorization.id] = sources
            results[f"next_due.{authorization.id}"] = _result(
                authorization.next_due, "UTC", sources
            )
            if 0 <= (_china_date(authorization.next_due) - _china_date(now)).days <= 7:
                reminders[authorization.id] = sources
    results.update({
        "candidate_merchants": _result(list(sorted(merchants)), "merchant_refs", all_sources),
        "cancellable_authorizations": _result(
            list(sorted(cancellable)),
            "authorization_refs",
            (s for ids in cancellable.values() for s in ids),
        ),
        "reminder_authorizations": _result(
            list(sorted(reminders)),
            "authorization_refs",
            (s for ids in reminders.values() for s in ids),
        ),
    })
    return results


def build_analysis(
    action: BankAction, state: BankState, signing_key: SigningKey
) -> AnalysisReceipt:
    """Build a signed result after the gateway has checked action authorization."""
    if bytes(signing_key.verify_key).hex() != state.roots.gateway_pubkey:
        raise ValueError("Analysis signer does not match the trusted gateway")
    if action.kind not in {
        "bill_analyze",
        "bill_report",
        "anomaly_query",
        "subscription_query",
        "subscription_reminders",
    }:
        raise ValueError("Unsupported built-in analysis")
    args = action.args.model_dump(mode="python")
    account_ref, period = str(args["account_ref"]), str(args["period"])
    account = state.accounts.get(account_ref)
    if account is None or account.owner != action.principal:
        raise ValueError("Analysis account is not owned by the principal")
    start, end = period_bounds(period)
    rows = [
        row
        for row in state.transactions.values()
        if row.owner == action.principal
        and row.account_ref == account_ref
        and row.booked_at <= state.now
    ]
    if action.kind in {"bill_analyze", "bill_report"}:
        function_id = BILL_FUNCTION
        results = billing_results(rows, state.merchants, period)
    elif action.kind == "anomaly_query":
        function_id = ANOMALY_FUNCTION
        results = anomaly_results(rows, period)
    else:
        function_id = SUBSCRIPTION_FUNCTION
        results = subscription_results(
            rows,
            state.subscriptions.values(),
            period,
            now=state.now,
            principal=action.principal,
            account_ref=account_ref,
        )
    if isinstance(action.args, AnalysisArgs) and action.args.analysis_spec != function_id:
        raise ValueError("Unsupported built-in analysis specification")
    dataset_hash = H({
        "transactions": _unique(rows),
        "merchant_categories": {
            key: value.category_code for key, value in sorted(state.merchants.items())
        },
        "subscriptions": [
            value
            for key, value in sorted(state.subscriptions.items())
            if value.owner == action.principal and value.source_account_ref == account_ref
        ],
    })
    parameters: dict[str, JsonValue] = {
        "principal": action.principal,
        "account_ref": account_ref,
        "period": {"start_inclusive": start, "end_exclusive": end},
        "action_hash": H(action),
    }
    receipt = AnalysisReceipt(
        receipt_id=str(uuid5(_NAMESPACE, f"{action.intent_id}:{action.node_id}:analysis")),
        dataset_hash=dataset_hash,
        function_id=function_id,
        parameters=parameters,
        results=results,
        trust="builtin",
        computed_at=state.now,
        sig="0" * 128,
    )
    return receipt.model_copy(update={"sig": sign(signing_key, RECEIPT, receipt)})
