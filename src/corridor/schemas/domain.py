"""Exact, versioned domain objects for the synthetic domestic bank."""

from datetime import date
from fractions import Fraction
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, Field, model_validator

from corridor.schemas.base import Model
from corridor.schemas.models import (
    Hash,
    Identifier,
    JsonValue,
    NonnegativeInt,
    PositiveInt,
    Signature,
)
from corridor.schemas.money import NonnegativeRational, PositiveRational, Rational
from corridor.schemas.time import Timestamp


def _minor_units(value: Fraction) -> Fraction:
    if (value * 100).denominator != 1:
        raise ValueError("Amounts must be exact multiples of 0.01 CNY")
    return value


def _calendar_date(value: str) -> str:
    parsed = date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise ValueError("Expected YYYY-MM-DD")
    return value


Amount = Annotated[NonnegativeRational, AfterValidator(_minor_units)]
PositiveAmount = Annotated[PositiveRational, AfterValidator(_minor_units)]
CalendarDate = Annotated[str, AfterValidator(_calendar_date)]
RiskLevel = Annotated[int, Field(ge=1, le=5)]


class Versioned(Model):
    id: Identifier
    version: PositiveInt = 1


class Customer(Versioned):
    principal: Identifier
    display_alias: str
    device_pubkey: Hash
    mfa_pubkey: Hash
    risk_profile_ref: Identifier | None = None
    account_refs: list[Identifier]
    credential_version: PositiveInt = 1

    @model_validator(mode="after")
    def principal_identity(self) -> Self:
        if self.principal != self.id:
            raise ValueError("Customer principal must match its identity")
        return self


class Account(Versioned):
    owner: Identifier
    kind: Literal["current", "locked"]
    ccy: Literal["CNY"] = "CNY"
    opening_balance: Amount
    floor: Amount
    status: Literal["active", "closed"]
    parent_ref: Identifier | None = None

    @model_validator(mode="after")
    def parent_kind(self) -> Self:
        if (self.kind == "locked") != (self.parent_ref is not None):
            raise ValueError("Only locked accounts require a parent account")
        if self.parent_ref == self.id:
            raise ValueError("An account cannot be its own parent")
        return self


class Contact(Versioned):
    owner: Identifier
    name_token: Identifier
    phone_token: Identifier | None = None
    aliases: list[str] = Field(default_factory=list)
    destination_ref: Identifier
    destination_version: PositiveInt = 1
    verified_at: Timestamp | None = None
    verification_ref: Identifier | None = None
    is_new: bool = True

    @model_validator(mode="after")
    def consistent_verification(self) -> Self:
        if (self.verified_at is None) != (self.verification_ref is None):
            raise ValueError("Verification reference and time must be present together")
        return self


class Transaction(Versioned):
    owner: Identifier
    account_ref: Identifier
    amount: PositiveAmount
    direction: Literal["debit", "credit"]
    kind: Literal["merchant_debit", "refund", "transfer", "internal", "investment"]
    status: Literal["settled"] = "settled"
    refund_of: Identifier | None = None
    merchant_ref: Identifier | None = None
    contact_ref: Identifier | None = None
    category_code: Identifier
    booked_at: Timestamp
    bank_ref: Identifier
    memo_handle: Identifier


class Card(Versioned):
    owner: Identifier
    account_ref: Identifier
    kind: Literal["virtual"] = "virtual"
    status: Literal["active", "frozen", "lost"]
    limit: PositiveAmount
    restrictions: list[str] = Field(default_factory=list)
    card_token: Identifier


class SubscriptionAuthorization(Versioned):
    owner: Identifier
    merchant_ref: Identifier
    source_account_ref: Identifier
    amount: PositiveAmount
    period_months: PositiveInt
    next_due: Timestamp
    status: Literal["active", "cancelled"]
    bank_authorization_ref: Identifier


class Position(Versioned):
    owner: Identifier
    product_ref: Identifier
    principal_amount: Amount
    units: NonnegativeRational
    reserved_units: NonnegativeRational
    nav: PositiveRational
    acquired_at: Timestamp
    redeemable_at: Timestamp
    status: Literal["active", "closed"]

    @model_validator(mode="after")
    def available_units(self) -> Self:
        if self.reserved_units > self.units:
            raise ValueError("Reserved units cannot exceed held units")
        if self.redeemable_at < self.acquired_at:
            raise ValueError("Redemption cannot precede acquisition")
        if self.nav != 1:
            raise ValueError("The synthetic pricing model requires NAV equal to one")
        return self


class ScheduledTask(Versioned):
    owner: Identifier
    plan_id: Identifier
    node_id: Identifier
    spa_ref: Identifier
    run_index: NonnegativeInt
    action_template: dict[str, JsonValue]
    input_refs: list[Identifier]
    due_at: Timestamp
    expires_at: Timestamp
    commitment_id: Identifier
    status: Literal["pending", "due", "waiting_mfa", "executed", "skipped", "cancelled", "expired"]

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if self.expires_at <= self.due_at:
            raise ValueError("Scheduled execution must have a positive expiry window")
        return self


class MerchantOffer(Versioned):
    amount: PositiveAmount
    cancel_until: Timestamp
    available: bool = True


class Merchant(Versioned):
    display_alias: str
    category_code: Identifier
    destination_ref: Identifier
    verified: bool
    is_new: bool = False
    offers: list[MerchantOffer]

    @model_validator(mode="after")
    def unique_offers(self) -> Self:
        if len({offer.id for offer in self.offers}) != len(self.offers):
            raise ValueError("Merchant offer identifiers must be unique")
        return self


class MerchantOrder(Versioned):
    owner: Identifier
    merchant_ref: Identifier
    offer_ref: Identifier
    amount: PositiveAmount
    status: Literal["draft", "paid", "cancelled", "refund_pending"]
    receipt_ref: Identifier | None = None
    refund_request_ref: Identifier | None = None


class CalendarEvent(Versioned):
    owner: Identifier
    event_type: Literal["birthday"]
    event_date: CalendarDate
    person_contact_ref: Identifier
    source_ref: Identifier


class RiskAssessment(Versioned):
    owner: Identifier
    answers_hash: Hash
    answers: Annotated[list[Annotated[int, Field(ge=0, le=4)]], Field(min_length=5, max_length=5)]
    score: Annotated[int, Field(ge=0, le=20)]
    level: RiskLevel
    issued_at: Timestamp
    expires_at: Timestamp
    sig: Signature

    @model_validator(mode="after")
    def assessment_window(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("Risk assessment expiry must follow issuance")
        return self


class Product(Model):
    product_id: Identifier
    version: PositiveInt = 1
    type: Literal["deposit", "wealth"]
    risk_level: RiskLevel
    min_amount: Amount
    max_amount: Amount | None = None
    purchase_open: bool
    eligible_customers: list[Identifier]
    min_hold_days: NonnegativeInt
    redeem_delay_days: NonnegativeInt
    expected_annual_rate: Rational
    purchase_fee_rate: NonnegativeRational
    annual_fee_rate: NonnegativeRational
    redemption_fee_rate: NonnegativeRational
    pricing_model: Literal["simple_365_v1"] = "simple_365_v1"

    @property
    def id(self) -> str:
        return self.product_id

    @model_validator(mode="after")
    def amount_range(self) -> Self:
        if self.max_amount is not None and self.max_amount < self.min_amount:
            raise ValueError("Maximum purchase amount is below minimum")
        return self


class ProductCatalog(Versioned):
    issued_at: Timestamp
    valid_until: Timestamp
    products: list[Product]
    sig: Signature

    @model_validator(mode="after")
    def valid_catalog(self) -> Self:
        if self.valid_until <= self.issued_at:
            raise ValueError("Catalog expiry must follow issuance")
        if len({product.product_id for product in self.products}) != len(self.products):
            raise ValueError("Product identifiers must be unique")
        return self


class InvestmentPreference(Versioned):
    source_account_ref: Identifier
    amount: PositiveAmount
    horizon_days: PositiveInt
    max_access_days: NonnegativeInt
    allowed_types: Annotated[list[Literal["deposit", "wealth"]], Field(min_length=1)]
    objective: Literal["net_return", "total_fee", "liquidity"]
    selection_mode: Literal["default", "explicit"]
    selected_product_ref: Identifier | None = None
    reason_code: Identifier | None = None

    @model_validator(mode="after")
    def explicit_choice(self) -> Self:
        if self.selection_mode == "explicit" and (
            self.selected_product_ref is None or self.reason_code is None
        ):
            raise ValueError("Explicit selection requires a product and a reason")
        if self.selection_mode == "default" and (
            self.selected_product_ref is not None or self.reason_code is not None
        ):
            raise ValueError("Default selection cannot contain an explicit override")
        if len(set(self.allowed_types)) != len(self.allowed_types):
            raise ValueError("Allowed product types must be unique")
        return self


class MarketingMetadata(Model):
    product_id: Identifier
    sponsored: bool
    campaign_text_handle: Identifier
