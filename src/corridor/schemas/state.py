"""Public trusted snapshots, excluding private values and marketing metadata."""

from collections.abc import Mapping
from fractions import Fraction
from typing import Annotated, Self

from pydantic import Field, model_validator

from corridor.schemas.allocation import AllocationPlan, AllocationPolicy
from corridor.schemas.bank import (
    AnalysisReceipt,
    Authorization,
    BankReceipt,
    BusinessEvent,
    MFAGrant,
    Receipt,
    UserInput,
)
from corridor.schemas.base import Model
from corridor.schemas.domain import (
    Account,
    Amount,
    CalendarEvent,
    Card,
    Contact,
    Customer,
    Merchant,
    MerchantOrder,
    Position,
    ProductCatalog,
    RiskAssessment,
    ScheduledTask,
    SubscriptionAuthorization,
    Transaction,
    Versioned,
)
from corridor.schemas.models import Hash, Identifier, NonnegativeInt, PositiveInt
from corridor.schemas.time import Timestamp

DEFAULT_TOOLS = (
    "balance_query",
    "transactions_query",
    "bill_analyze",
    "bill_report",
    "anomaly_query",
    "sandbox_analyze",
    "risk_assess",
    "product_compare",
    "investment_income_query",
    "subscription_query",
    "subscription_reminders",
    "transfer",
    "schedule_transfer",
    "cancel_schedule",
    "aa_request",
    "cancel_subscription",
    "purchase_product",
    "redeem_product",
    "lock_funds",
    "unlock_funds",
    "merchant_order",
    "cancel_order",
    "refund_request",
    "apply_virtual_card",
    "freeze_card",
    "restrict_card",
    "lower_card_limit",
    "unfreeze_card",
    "relax_card_restriction",
    "report_card_lost",
    "restore_card",
    "raise_card_limit",
    "password_change_request",
    "register_contact_request",
)


class Policy(Model):
    version: PositiveInt = 1
    transfer_yellow_limit: Amount = Fraction(1000)
    approval_ttl_seconds: PositiveInt = 300
    mfa_ttl_seconds: PositiveInt = 120
    mfa_max_attempts: PositiveInt = 3
    reject_limit: PositiveInt = 3
    approval_limit: PositiveInt = 6
    approval_window_seconds: PositiveInt = 600
    unlock_cooldown_seconds: PositiveInt = 1800
    spa_wait_seconds: PositiveInt = 86400
    spa_max_days: PositiveInt = 365
    risk_valid_days: PositiveInt = 365
    risk_answers_ttl_seconds: PositiveInt = 1800
    tool_whitelist: list[Identifier] = Field(default_factory=lambda: list(DEFAULT_TOOLS))
    risk_questions: Annotated[list[str], Field(min_length=5, max_length=5)] = Field(
        default_factory=lambda: [
            "Investment experience",
            "Loss tolerance",
            "Income stability",
            "Liquidity needs",
            "Investment horizon",
        ]
    )
    risk_answer_scores: list[Annotated[int, Field(ge=0, le=4)]] = Field(
        default_factory=lambda: [0, 1, 2, 3, 4]
    )


class TrustRoots(Model):
    bank_pubkey: Hash
    risk_pubkey: Hash
    gateway_pubkey: Hash


class ApprovalRequest(Model):
    request_id: Identifier
    ts: Timestamp
    action_hash: Hash | None = Field(default=None, exclude_if=lambda value: value is None)
    card_hash: Hash | None = Field(default=None, exclude_if=lambda value: value is None)


class Security(Model):
    active_device_sessions: dict[str, Identifier] = Field(default_factory=dict)
    mfa_grants: dict[str, MFAGrant] = Field(default_factory=dict)
    consumed_grant_ids: list[Identifier] = Field(default_factory=list)
    consumed_nonces: list[Identifier] = Field(default_factory=list)
    void_token_ids: list[Identifier] = Field(default_factory=list)
    reject_streak: dict[str, NonnegativeInt] = Field(default_factory=dict)
    approval_requests: dict[str, list[ApprovalRequest]] = Field(default_factory=dict)
    locked_at: dict[str, Timestamp] = Field(default_factory=dict)
    lock_reason: dict[str, str] = Field(default_factory=dict)
    unknown_intent_ids: list[Identifier] = Field(default_factory=list)

    @model_validator(mode="after")
    def grant_identity(self) -> Self:
        if any(key != grant.grant_id for key, grant in self.mfa_grants.items()):
            raise ValueError("MFA grant key must match its identity")
        return self


class BankState(Model):
    now: Timestamp
    policy: Policy = Field(default_factory=Policy)
    roots: TrustRoots
    customers: dict[str, Customer] = Field(default_factory=dict)
    risk_assessments: dict[str, RiskAssessment] = Field(default_factory=dict)
    accounts: dict[str, Account] = Field(default_factory=dict)
    contacts: dict[str, Contact] = Field(default_factory=dict)
    transactions: dict[str, Transaction] = Field(default_factory=dict)
    cards: dict[str, Card] = Field(default_factory=dict)
    subscriptions: dict[str, SubscriptionAuthorization] = Field(default_factory=dict)
    catalog: ProductCatalog
    allocation_policies: dict[str, AllocationPolicy] = Field(
        default_factory=dict, exclude_if=lambda value: not value
    )
    allocation_plans: dict[str, AllocationPlan] = Field(
        default_factory=dict, exclude_if=lambda value: not value
    )
    positions: dict[str, Position] = Field(default_factory=dict)
    schedules: dict[str, ScheduledTask] = Field(default_factory=dict)
    orders: dict[str, MerchantOrder] = Field(default_factory=dict)
    merchants: dict[str, Merchant] = Field(default_factory=dict)
    calendar: dict[str, CalendarEvent] = Field(default_factory=dict)
    user_inputs: dict[str, UserInput] = Field(default_factory=dict)
    authorizations: dict[str, Authorization] = Field(default_factory=dict)
    ledger: list[BusinessEvent] = Field(default_factory=list)
    receipts: dict[str, Receipt] = Field(default_factory=dict)
    security: Security = Field(default_factory=Security)

    @model_validator(mode="after")
    def collection_identity(self) -> Self:
        collections: tuple[Mapping[str, Versioned | BankReceipt | AnalysisReceipt], ...] = (
            self.customers,
            self.risk_assessments,
            self.allocation_policies,
            self.allocation_plans,
            self.accounts,
            self.contacts,
            self.transactions,
            self.cards,
            self.subscriptions,
            self.positions,
            self.schedules,
            self.orders,
            self.merchants,
            self.calendar,
            self.user_inputs,
            self.authorizations,
            self.receipts,
        )
        for collection in collections:
            if any(key != value.id for key, value in collection.items()):
                raise ValueError("Collection key must match object identity")
        return self
