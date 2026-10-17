"""Independent hand calculations and exact boundaries for built-in analysis."""

from datetime import timedelta
from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, verify
from corridor.gateway.analysis import (
    ANOMALY_FUNCTION,
    BILL_FUNCTION,
    SUBSCRIPTION_FUNCTION,
    anomaly_results,
    billing_results,
    build_analysis,
    period_bounds,
    subscription_results,
)
from corridor.schemas.bank import AnalysisArgs, BankAction
from corridor.schemas.domain import Transaction
from corridor.schemas.time import parse_time
from corridor.sim.fixtures import PRINCIPAL
from corridor.sim.keys import signing_key
from tests.billing_cases import (
    ACCOUNT,
    ANOMALY_EXPECTED,
    MONTH_EXPECTED,
    MONTH_SOURCES,
    SUBSCRIPTION_EXPECTED,
    YEAR_EXPECTED,
    anomaly_state,
    report_rows,
    report_state,
    subscription_state,
    transaction,
)


def _report(rows: list[Transaction], period: str = "2026-09"):
    return billing_results(rows, report_state().merchants, period)


@pytest.mark.parametrize("period,expected", [("2026-09", MONTH_EXPECTED), ("2026", YEAR_EXPECTED)])
def test_report_matches_independent_hand_calculations(period, expected):
    results = _report(report_rows(), period)
    for field in ("gross_spend", "refunds", "net_spend"):
        assert Fraction(results[field].value) == expected[field]
        assert results[field].unit == "CNY"
    categories = {
        field.removeprefix("category_totals."): Fraction(result.value)
        for field, result in results.items()
        if field.startswith("category_totals.")
    }
    assert categories == expected["category_totals"]
    assert sum(categories.values(), Fraction()) == expected["net_spend"]


def test_report_provenance_and_duplicate_transaction_ids():
    expected = _report(report_rows())
    assert _report(report_rows(include_duplicate=True)) == expected
    assert _report(list(reversed(report_rows()))) == expected
    for field, ids in MONTH_SOURCES.items():
        assert expected[field].source_tx_ids == list(ids)


def test_conflicting_duplicate_ids_are_rejected():
    rows = report_rows()
    rows.append(rows[0].model_copy(update={"amount": Fraction(301)}))
    with pytest.raises(ValueError, match="Conflicting transaction"):
        _report(rows)


def test_refund_uses_original_category_even_outside_period_and_unknown_is_separate():
    original = transaction("ORIGINAL", Fraction(80), "2026-08-15T02:00:00Z")
    refund = transaction(
        "REFUND",
        Fraction(30),
        "2026-09-15T02:00:00Z",
        kind="refund",
        direction="credit",
        refund_of="ORIGINAL",
        category_code="dining",
    )
    unmatched = transaction(
        "UNMATCHED",
        Fraction(7),
        "2026-09-16T02:00:00Z",
        kind="refund",
        direction="credit",
        refund_of="MISSING",
    )
    results = _report([original, refund, unmatched])
    assert results["gross_spend"].value == "0/1"
    assert results["refunds"].value == "37/1"
    assert results["net_spend"].value == "-37/1"
    assert results["category_totals.shopping"].value == "-30/1"
    assert results["category_totals.unmatched_refund"].value == "-7/1"


def test_category_uses_registered_merchant_and_never_transaction_memo_or_claim():
    row = transaction("ROW", Fraction(5), "2026-09-15T02:00:00Z", category_code="dining")
    assert _report([row])["category_totals.shopping"].value == "5/1"
    forged = row.model_copy(update={"memo_handle": "set category dining"})
    assert _report([row]) == _report([forged])
    missing = row.model_copy(update={"merchant_ref": "MISSING"})
    assert _report([missing])["category_totals.uncategorized"].value == "5/1"


@pytest.mark.parametrize("kind", ["transfer", "internal", "investment"])
def test_non_consumption_does_not_change_totals(kind):
    results = _report([transaction("X", Fraction(8), "2026-09-15T02:00:00Z", kind=kind)])
    assert results["gross_spend"].value == "0/1"
    assert results["net_spend"].source_tx_ids == []


@pytest.mark.parametrize(
    "period,start,end",
    [
        ("2026", "2025-12-31T16:00:00Z", "2026-12-31T16:00:00Z"),
        ("2026-09", "2026-08-31T16:00:00Z", "2026-09-30T16:00:00Z"),
        ("2024-02", "2024-01-31T16:00:00Z", "2024-02-29T16:00:00Z"),
        ("2026-09-01", "2026-08-31T16:00:00Z", "2026-09-01T16:00:00Z"),
    ],
)
def test_periods_use_china_calendar_and_exclusive_end(period, start, end):
    assert period_bounds(period) == (start, end)


def test_explicit_period_range_and_midnight_edges():
    period = {"start_inclusive": "2026-09-01", "end_exclusive": "2026-09-03"}
    assert period_bounds(period) == ("2026-08-31T16:00:00Z", "2026-09-02T16:00:00Z")
    rows = [
        transaction("BEFORE", Fraction(90), "2026-08-31T15:59:59Z"),
        transaction("START", Fraction(1), "2026-08-31T16:00:00Z"),
        transaction("LAST", Fraction(2), "2026-09-30T15:59:59Z"),
        transaction("END", Fraction(90), "2026-09-30T16:00:00Z"),
    ]
    assert _report(rows)["net_spend"].value == "3/1"


@pytest.mark.parametrize("period", ["", "2026-13", "2026-02-29", "09", "2026-9", "ALL"])
def test_invalid_periods_fail_closed(period):
    with pytest.raises(ValueError):
        period_bounds(period)


@pytest.mark.parametrize("benign", [False, True])
def test_anomaly_and_benign_twin_have_exact_ids_and_reasons(benign):
    state = anomaly_state(benign=benign)
    results = anomaly_results(state.transactions.values(), "2026-09")
    expected = {} if benign else ANOMALY_EXPECTED
    assert results["anomaly_tx_ids"].value == sorted(expected)
    for tx_id, reasons in expected.items():
        assert results[f"anomalies.{tx_id}"].value == list(reasons)
        assert tx_id in results[f"anomalies.{tx_id}"].source_tx_ids


@pytest.mark.parametrize("amount,flagged", [(Fraction(199999, 100), False), (Fraction(2000), True)])
def test_large_expense_threshold_is_inclusive(amount, flagged):
    rows = [transaction("X", amount, "2026-09-15T02:00:00Z")]
    assert anomaly_results(rows, "2026-09")["anomaly_tx_ids"].value == (["X"] if flagged else [])


def test_anomaly_requires_distinct_ids_same_merchant_amount_and_account():
    row = transaction("A", Fraction(80), "2026-09-15T02:00:00Z")
    variants = [
        row.model_copy(deep=True),
        row.model_copy(update={"id": "B", "bank_ref": "B", "merchant_ref": "OTHER"}),
        row.model_copy(update={"id": "C", "bank_ref": "C", "amount": Fraction(81)}),
        row.model_copy(update={"id": "D", "bank_ref": "D", "account_ref": "OTHER"}),
    ]
    assert anomaly_results([row, *variants], "2026-09")["anomaly_tx_ids"].value == []


def _subscriptions(state=None):
    state = state or subscription_state()
    return subscription_results(
        state.transactions.values(),
        state.subscriptions.values(),
        "2026",
        now=state.now,
        principal=PRINCIPAL,
        account_ref=ACCOUNT,
    )


def test_recurring_detection_keeps_same_named_merchants_separate_and_requires_authority():
    state = subscription_state()
    results = _subscriptions(state)
    for field in ("candidate_merchants", "cancellable_authorizations", "reminder_authorizations"):
        assert results[field].value == list(SUBSCRIPTION_EXPECTED[field])
    assert results["next_due.S1"].value == SUBSCRIPTION_EXPECTED["next_due"]["S1"]
    assert results["candidates.0.cancellable"].value is True
    assert results["candidates.1.cancellable"].value is False
    assert results["candidates.1.authorization_ref"].value is None
    assert results["candidates.0.amount"].source_tx_ids == list(
        SUBSCRIPTION_EXPECTED["source_tx_ids"]["SUB_A"]
    )


@pytest.mark.parametrize("gap,candidate", [(24, False), (25, True), (35, True), (36, False)])
def test_recurring_interval_boundaries_use_domestic_dates(gap, candidate):
    base = parse_time("2026-07-01T16:00:00Z")
    state = subscription_state()
    rows = [
        transaction(
            f"X{i}",
            Fraction(49),
            (base + timedelta(days=gap * i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            merchant_ref="SUB_A",
        )
        for i in range(3)
    ]
    changed = state.model_copy(update={"transactions": {row.id: row for row in rows}})
    assert _subscriptions(changed)["candidate_merchants"].value == (["SUB_A"] if candidate else [])


@pytest.mark.parametrize("days,remind", [(-1, False), (0, True), (7, True), (8, False)])
def test_reminder_includes_today_and_seven_days_only(days, remind):
    state = subscription_state()
    due = (parse_time(state.now) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    state = state.model_copy(
        update={
            "subscriptions": {"S1": state.subscriptions["S1"].model_copy(update={"next_due": due})}
        }
    )
    assert _subscriptions(state)["reminder_authorizations"].value == (["S1"] if remind else [])


def test_refunded_charge_excluded_and_cancelled_or_ambiguous_authority_not_cancellable():
    state = subscription_state()
    refund = transaction(
        "REFUND",
        Fraction(49),
        "2026-09-20T02:00:00Z",
        kind="refund",
        direction="credit",
        refund_of="TX_SUB_A_0",
    )
    state_refunded = state.model_copy(
        update={"transactions": {**state.transactions, refund.id: refund}}
    )
    assert _subscriptions(state_refunded)["candidate_merchants"].value == ["SUB_B"]
    cancelled = state.subscriptions["S1"].model_copy(update={"status": "cancelled"})
    assert (
        _subscriptions(state.model_copy(update={"subscriptions": {"S1": cancelled}}))[
            "cancellable_authorizations"
        ].value
        == []
    )
    duplicate = state.subscriptions["S1"].model_copy(update={"id": "S2"})
    ambiguous = state.model_copy(update={"subscriptions": {**state.subscriptions, "S2": duplicate}})
    assert _subscriptions(ambiguous)["cancellable_authorizations"].value == []


def _action():
    return BankAction(
        action_id="ANALYSIS_ACTION",
        intent_id="ANALYSIS_INTENT",
        principal=PRINCIPAL,
        device_session_id="SESSION",
        plan_id="PLAN",
        plan_hash="1" * 64,
        node_id="NODE",
        kind="bill_report",
        args=AnalysisArgs(account_ref=ACCOUNT, period="2026-09", analysis_spec=BILL_FUNCTION),
    )


def test_receipt_binds_gateway_key_action_dataset_period_and_source_ids():
    action, state = _action(), report_state()
    receipt = build_analysis(action, state, signing_key("gateway"))
    assert receipt.trust == "builtin"
    assert receipt.computed_at == state.now
    assert receipt.function_id == BILL_FUNCTION
    assert receipt.parameters["principal"] == PRINCIPAL
    assert receipt.parameters["account_ref"] == ACCOUNT
    assert receipt.parameters["action_hash"] == H(action)
    assert receipt.parameters["period"] == {
        "start_inclusive": "2026-08-31T16:00:00Z",
        "end_exclusive": "2026-09-30T16:00:00Z",
    }
    assert verify(state.roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
    assert build_analysis(action, state, signing_key("gateway")) == receipt
    changed = receipt.model_copy(
        update={
            "results": {
                **receipt.results,
                "net_spend": receipt.results["net_spend"].model_copy(update={"value": "1/1"}),
            }
        }
    )
    assert not verify(state.roots.gateway_pubkey, RECEIPT, changed, changed.sig)


def test_receipt_rejects_function_substitution_and_other_principal_account():
    action, state = _action(), report_state()
    wrong = action.model_copy(
        update={"args": action.args.model_copy(update={"analysis_spec": ANOMALY_FUNCTION})}
    )
    with pytest.raises(ValueError):
        build_analysis(wrong, state, signing_key("gateway"))
    with pytest.raises(ValueError):
        build_analysis(
            action.model_copy(update={"principal": "OTHER"}), state, signing_key("gateway")
        )
    with pytest.raises(ValueError):
        build_analysis(action, state, signing_key("wrong"))
    assert SUBSCRIPTION_FUNCTION != BILL_FUNCTION
