"""Hand-authored B6 billing fixtures, independent of the analysis implementation.

Monthly reporting, anomaly detection and subscription recognition use separate
datasets. Expected totals and identifiers are literals, never calculated by the
production functions being tested. All persons, merchants and transactions are
synthetic; transaction memos are untrusted handles rather than display facts.
"""

from fractions import Fraction
from typing import Literal

from corridor.schemas.domain import Merchant, SubscriptionAuthorization, Transaction
from corridor.schemas.state import BankState
from corridor.sim.fixtures import PRINCIPAL, make_state

ACCOUNT = "A_CURRENT"
REPORT_MONTH = "2026-09"
REPORT_YEAR = "2026"

MONTH_EXPECTED = {
    "gross_spend": Fraction(1800),
    "refunds": Fraction(100),
    "net_spend": Fraction(1700),
    "category_totals": {
        "dining": Fraction(300),
        "transport": Fraction(100),
        "shopping": Fraction(1300),
    },
}
YEAR_EXPECTED = {
    "gross_spend": Fraction(1875),
    "refunds": Fraction(100),
    "net_spend": Fraction(1775),
    "category_totals": {
        "dining": Fraction(375),
        "transport": Fraction(100),
        "shopping": Fraction(1300),
    },
}
MONTH_SOURCES = {
    "gross_spend": ("TX_DINING", "TX_SHOPPING", "TX_TRANSPORT"),
    "refunds": ("TX_SHOPPING_REFUND",),
    "net_spend": ("TX_DINING", "TX_SHOPPING", "TX_SHOPPING_REFUND", "TX_TRANSPORT"),
    "category_totals.dining": ("TX_DINING",),
    "category_totals.transport": ("TX_TRANSPORT",),
    "category_totals.shopping": ("TX_SHOPPING", "TX_SHOPPING_REFUND"),
}
ANOMALY_EXPECTED = {
    "TX_DUPLICATE_A": ("duplicate_candidate",),
    "TX_DUPLICATE_B": ("duplicate_candidate",),
    "TX_LARGE": ("large_expense",),
}
BENIGN_ANOMALY_EXPECTED: dict[str, tuple[str, ...]] = {}
SUBSCRIPTION_EXPECTED = {
    "candidate_merchants": ("SUB_A", "SUB_B"),
    "cancellable_authorizations": ("S1",),
    "reminder_authorizations": ("S1",),
    "next_due": {"S1": "2026-10-19T02:00:00Z"},
    "source_tx_ids": {
        "SUB_A": ("TX_SUB_A_0", "TX_SUB_A_1", "TX_SUB_A_2"),
        "SUB_B": ("TX_SUB_B_0", "TX_SUB_B_1", "TX_SUB_B_2"),
    },
}


def transaction(
    tx_id: str,
    amount: Fraction,
    booked_at: str,
    *,
    merchant_ref: str | None = "M_SHOPPING",
    category_code: str = "shopping",
    kind: Literal["merchant_debit", "refund", "transfer", "internal", "investment"] = (
        "merchant_debit"
    ),
    direction: Literal["debit", "credit"] = "debit",
    refund_of: str | None = None,
    account_ref: str = ACCOUNT,
) -> Transaction:
    """Build a validated row for exact boundary and duplicate-ID tests."""
    return Transaction(
        id=tx_id,
        owner=PRINCIPAL,
        account_ref=account_ref,
        amount=amount,
        direction=direction,
        kind=kind,
        merchant_ref=merchant_ref,
        category_code=category_code,
        booked_at=booked_at,
        bank_ref=tx_id,
        memo_handle="UNTRUSTED_MEMO",
        refund_of=refund_of,
    )


def _merchant(merchant_id: str, category: str, *, alias: str | None = None) -> Merchant:
    return Merchant(
        id=merchant_id,
        display_alias=alias or f"Synthetic {merchant_id}",
        category_code=category,
        destination_ref=f"DEST_{merchant_id}",
        verified=True,
        offers=[],
    )


def _state(
    rows: list[Transaction],
    merchants: list[Merchant],
    subscriptions: list[SubscriptionAuthorization] | None = None,
) -> BankState:
    payload = make_state().model_dump(mode="python")
    payload.update(
        transactions={row.id: row for row in rows},
        merchants={merchant.id: merchant for merchant in merchants},
        subscriptions={item.id: item for item in subscriptions or []},
    )
    return BankState.model_validate(payload)


def report_rows(*, include_duplicate: bool = False) -> list[Transaction]:
    """September costs are 1800 - 100; the year also includes January dining 75.

    The 500 transfer must be excluded. The refund's own category deliberately
    differs from its source: analysis must recover the original shopping class.
    Duplicates remain in this list, since BankState is keyed by transaction ID.
    """
    rows = [
        transaction(
            "TX_DINING",
            Fraction(300),
            "2026-09-02T02:00:00Z",
            merchant_ref="M_DINING",
            category_code="dining",
        ),
        transaction(
            "TX_TRANSPORT",
            Fraction(100),
            "2026-09-03T02:00:00Z",
            merchant_ref="M_TRANSPORT",
            category_code="transport",
        ),
        transaction("TX_SHOPPING", Fraction(1400), "2026-09-04T02:00:00Z"),
        transaction(
            "TX_SHOPPING_REFUND",
            Fraction(100),
            "2026-09-05T02:00:00Z",
            category_code="uncategorized",
            kind="refund",
            direction="credit",
            refund_of="TX_SHOPPING",
        ),
        transaction(
            "TX_TRANSFER",
            Fraction(500),
            "2026-09-06T02:00:00Z",
            merchant_ref=None,
            category_code="uncategorized",
            kind="transfer",
        ),
        transaction(
            "TX_YEAR_DINING",
            Fraction(75),
            "2026-01-09T02:00:00Z",
            merchant_ref="M_DINING",
            category_code="dining",
        ),
    ]
    if include_duplicate:
        rows.append(rows[0].model_copy(deep=True))
    return rows


def report_state() -> BankState:
    """Return the isolated J07 month/year fixture with no subscriptions."""
    return _state(
        report_rows(),
        [
            _merchant("M_DINING", "dining"),
            _merchant("M_TRANSPORT", "transport"),
            _merchant("M_SHOPPING", "shopping"),
        ],
    )


def anomaly_state(*, benign: bool = False) -> BankState:
    """The benign twin changes only the gap to 601s and the large charge to 1999.99."""
    return _state(
        [
            transaction("TX_DUPLICATE_A", Fraction(80), "2026-09-08T02:00:00Z"),
            transaction(
                "TX_DUPLICATE_B",
                Fraction(80),
                "2026-09-08T02:10:01Z" if benign else "2026-09-08T02:10:00Z",
            ),
            transaction(
                "TX_LARGE",
                Fraction(199999, 100) if benign else Fraction(2300),
                "2026-09-09T02:00:00Z",
                merchant_ref="M_DINING",
                category_code="dining",
            ),
        ],
        [_merchant("M_SHOPPING", "shopping"), _merchant("M_DINING", "dining")],
    )


def subscription_state() -> BankState:
    """J10 has two recurring groups but only S1 authorizes a cancellation.

    SUB_A and SUB_B share a display name to test grouping by merchant identity.
    SUB_C has only two 99 CNY charges and must never become a candidate.
    """
    rows = [
        transaction(
            f"TX_{merchant_ref}_{index}",
            amount,
            day + "T02:00:00Z",
            merchant_ref=merchant_ref,
            category_code="services",
        )
        for merchant_ref, amount, days in (
            ("SUB_A", Fraction(49), ("2026-07-20", "2026-08-19", "2026-09-18")),
            ("SUB_B", Fraction(29), ("2026-07-20", "2026-08-19", "2026-09-18")),
            ("SUB_C", Fraction(99), ("2026-08-19", "2026-09-18")),
        )
        for index, day in enumerate(days)
    ]
    authorization = SubscriptionAuthorization(
        id="S1",
        owner=PRINCIPAL,
        merchant_ref="SUB_A",
        source_account_ref=ACCOUNT,
        amount=Fraction(49),
        period_months=1,
        next_due="2026-10-19T02:00:00Z",
        status="active",
        bank_authorization_ref="BANK_S1",
    )
    return _state(
        rows,
        [
            _merchant("SUB_A", "services", alias="Synthetic recurring service"),
            _merchant("SUB_B", "services", alias="Synthetic recurring service"),
            _merchant("SUB_C", "services"),
        ],
        [authorization],
    )
