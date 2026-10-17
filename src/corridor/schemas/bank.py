"""Closed bank actions, signed authority, execution messages and evaluation wire types."""

from datetime import timedelta
from fractions import Fraction
from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, Field, model_validator

from corridor.schemas.allocation import BestInterestAllocationCertificate
from corridor.schemas.base import Model
from corridor.schemas.domain import Versioned
from corridor.schemas.models import (
    Hash,
    Identifier,
    JsonValue,
    NonnegativeInt,
    PositiveInt,
    Signature,
)
from corridor.schemas.money import Money, NonnegativeRational, PositiveRational, Rational
from corridor.schemas.time import Timestamp, parse_time


def _whole_cents(value: Fraction) -> Fraction:
    if (value * 100).denominator != 1:
        raise ValueError("Business amounts must be exact multiples of one cent")
    return value


Cents = Annotated[NonnegativeRational, AfterValidator(_whole_cents)]
PositiveCents = Annotated[PositiveRational, AfterValidator(_whole_cents)]
Tier = Literal["green", "yellow", "red", "black"]
ActionKind = Literal[
    "balance_query",
    "transactions_query",
    "bill_analyze",
    "bill_report",
    "anomaly_query",
    "sandbox_analyze",
    "risk_assess",
    "product_compare",
    "allocation_compare",
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
    "set_policy",
    "set_permission",
    "set_risk_level",
    "set_contact_verified",
    "set_mfa",
    "bypass_approval",
    "request_secret",
]


class AccountArgs(Model):
    account_ref: Identifier
    period: Identifier | None = None


class AnalysisArgs(Model):
    account_ref: Identifier
    period: Identifier
    analysis_spec: Identifier


class SubscriptionQueryArgs(Model):
    account_ref: Identifier
    period: Identifier


class SandboxArgs(Model):
    dataset_ref: Identifier
    program_ref: Identifier


class RiskAssessArgs(Model):
    answers_input_ref: Identifier


class PreferenceArgs(Model):
    preference_ref: Identifier


class AllocationArgs(Model):
    request_ref: Identifier


class PositionArgs(Model):
    position_ref: Identifier


class TransferArgs(Model):
    source_ref: Identifier
    contact_ref: Identifier
    amount_ref: Identifier


class ScheduleTransferArgs(Model):
    source_ref: Identifier
    amount_ref: Identifier
    schedule_ref: Identifier
    contact_ref: Identifier | None = None
    merchant_ref: Identifier | None = None
    offer_ref: Identifier | None = None
    locked_ref: Identifier | None = None
    purpose_ref: Identifier | None = None

    @model_validator(mode="after")
    def one_spa_target(self) -> Self:
        present = {
            name
            for name in ("contact_ref", "merchant_ref", "offer_ref", "locked_ref", "purpose_ref")
            if getattr(self, name) is not None
        }
        if present not in (
            {"contact_ref"},
            {"merchant_ref", "offer_ref"},
            {"locked_ref", "purpose_ref"},
        ):
            raise ValueError("SPA creation requires exactly one complete target group")
        return self


class ScheduleArgs(Model):
    schedule_ref: Identifier


class AARequestArgs(Model):
    source_bill_ref: Identifier
    total_ref: Identifier
    participant_refs: Annotated[list[Identifier], Field(min_length=1, max_length=10)]

    @model_validator(mode="after")
    def distinct_participants(self) -> Self:
        if len(set(self.participant_refs)) != len(self.participant_refs):
            raise ValueError("AA participants must be unique")
        return self


class SubscriptionArgs(Model):
    authorization_ref: Identifier


class PurchaseArgs(Model):
    source_ref: Identifier
    preference_ref: Identifier | None = Field(default=None, exclude_if=lambda value: value is None)
    product_ref: Identifier
    amount_ref: Identifier
    allocation_ref: Identifier | None = Field(default=None, exclude_if=lambda value: value is None)
    allocation_item_ref: Identifier | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def exact_investment_branch(self) -> Self:
        legacy = self.preference_ref is not None
        allocation = self.allocation_ref is not None and self.allocation_item_ref is not None
        partial = (self.allocation_ref is None) != (self.allocation_item_ref is None)
        if partial or legacy == allocation:
            raise ValueError("Purchase requires exactly one complete BIC or BIAC branch")
        return self


class RedeemArgs(Model):
    position_ref: Identifier
    amount_ref: Identifier


class FundsArgs(Model):
    source_ref: Identifier
    locked_ref: Identifier
    amount_ref: Identifier
    purpose_ref: Identifier


class MerchantArgs(Model):
    merchant_ref: Identifier
    offer_ref: Identifier
    source_ref: Identifier


class OrderArgs(Model):
    order_ref: Identifier


class ReceiptArgs(Model):
    receipt_ref: Identifier


class ApplyCardArgs(Model):
    account_ref: Identifier


class CardChangeArgs(Model):
    card_ref: Identifier
    change_ref: Identifier


class CardStateArgs(Model):
    card_ref: Identifier
    change_ref: Identifier | None = None


CardCategory = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]


def _card_restrictions(value: list[str]) -> list[str]:
    if value != sorted(set(value)):
        raise ValueError("Card restrictions must be unique and sorted")
    return value


CardRestrictions = Annotated[
    list[CardCategory], Field(max_length=32), AfterValidator(_card_restrictions)
]


class CardChangeRequest(Model):
    """One exact device-signed change, bound to its card and operation kind."""

    card_ref: Identifier
    kind: Literal[
        "freeze_card",
        "unfreeze_card",
        "report_card_lost",
        "restore_card",
        "lower_card_limit",
        "raise_card_limit",
        "restrict_card",
        "relax_card_restriction",
    ]
    status: Literal["active", "frozen", "lost"] | None = None
    limit: PositiveCents | None = None
    restrictions: CardRestrictions | None = None

    @model_validator(mode="after")
    def exact_change(self) -> Self:
        states = {
            "freeze_card": "frozen",
            "unfreeze_card": "active",
            "report_card_lost": "lost",
            "restore_card": "frozen",
        }
        present = {
            name for name in ("status", "limit", "restrictions") if getattr(self, name) is not None
        }
        if self.kind in states:
            valid = present == {"status"} and self.status == states[self.kind]
        elif self.kind in {"lower_card_limit", "raise_card_limit"}:
            valid = present == {"limit"}
        else:
            valid = present == {"restrictions"}
        if not valid:
            raise ValueError("Card change must specify exactly its operation's resulting value")
        return self


class PasswordChangeArgs(Model):
    principal: Identifier


class RegisterContactArgs(Model):
    draft_handle: Identifier


class EmptyArgs(Model):
    pass


ActionArgs = (
    AccountArgs
    | AnalysisArgs
    | SubscriptionQueryArgs
    | SandboxArgs
    | RiskAssessArgs
    | PreferenceArgs
    | AllocationArgs
    | PositionArgs
    | TransferArgs
    | ScheduleTransferArgs
    | ScheduleArgs
    | AARequestArgs
    | SubscriptionArgs
    | PurchaseArgs
    | RedeemArgs
    | FundsArgs
    | MerchantArgs
    | OrderArgs
    | ReceiptArgs
    | ApplyCardArgs
    | CardChangeArgs
    | CardStateArgs
    | PasswordChangeArgs
    | RegisterContactArgs
    | EmptyArgs
)

ACTION_ARGS: dict[str, type[Model]] = {
    "balance_query": AccountArgs,
    "transactions_query": AccountArgs,
    "bill_analyze": AnalysisArgs,
    "bill_report": AnalysisArgs,
    "anomaly_query": AnalysisArgs,
    "sandbox_analyze": SandboxArgs,
    "risk_assess": RiskAssessArgs,
    "product_compare": PreferenceArgs,
    "allocation_compare": AllocationArgs,
    "investment_income_query": PositionArgs,
    "subscription_query": SubscriptionQueryArgs,
    "subscription_reminders": SubscriptionQueryArgs,
    "transfer": TransferArgs,
    "schedule_transfer": ScheduleTransferArgs,
    "cancel_schedule": ScheduleArgs,
    "aa_request": AARequestArgs,
    "cancel_subscription": SubscriptionArgs,
    "purchase_product": PurchaseArgs,
    "redeem_product": RedeemArgs,
    "lock_funds": FundsArgs,
    "unlock_funds": FundsArgs,
    "merchant_order": MerchantArgs,
    "cancel_order": OrderArgs,
    "refund_request": ReceiptArgs,
    "apply_virtual_card": ApplyCardArgs,
    "freeze_card": CardChangeArgs,
    "restrict_card": CardChangeArgs,
    "lower_card_limit": CardChangeArgs,
    "unfreeze_card": CardChangeArgs,
    "relax_card_restriction": CardChangeArgs,
    "report_card_lost": CardStateArgs,
    "restore_card": CardStateArgs,
    "raise_card_limit": CardChangeArgs,
    "password_change_request": PasswordChangeArgs,
    "register_contact_request": RegisterContactArgs,
    "set_policy": EmptyArgs,
    "set_permission": EmptyArgs,
    "set_risk_level": EmptyArgs,
    "set_contact_verified": EmptyArgs,
    "set_mfa": EmptyArgs,
    "bypass_approval": EmptyArgs,
    "request_secret": EmptyArgs,
}


def _validate_args(value: Any, mapping: dict[str, type[Model]]) -> Any:
    if isinstance(value, Model):
        value = value.model_dump(mode="python")
    if not isinstance(value, dict):
        return value
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in mapping:
        raise ValueError("Unknown business action kind")
    expected = mapping[kind]
    args = value.get("args")
    if isinstance(args, Model):
        if type(args) is not expected:
            raise ValueError("Argument model does not match action kind")
        args = args.model_dump(mode="python")
    return {**value, "args": expected.model_validate(args)}


class BankAction(Model):
    schema_version: Literal["bank-v1"] = "bank-v1"
    action_id: Identifier
    intent_id: Identifier
    principal: Identifier
    device_session_id: Identifier
    plan_id: Identifier
    plan_hash: Hash
    node_id: Identifier
    kind: ActionKind
    args: ActionArgs

    @model_validator(mode="before")
    @classmethod
    def args_for_kind(cls, value: Any) -> Any:
        return _validate_args(value, ACTION_ARGS)


class StateTerm(Model):
    t: Literal["state"] = "state"
    collection: Literal[
        "customers",
        "risk_assessments",
        "accounts",
        "contacts",
        "transactions",
        "cards",
        "subscriptions",
        "catalog",
        "positions",
        "schedules",
        "orders",
        "merchants",
        "calendar",
        "authorizations",
    ]
    object_ref: Identifier
    field: Identifier
    version: PositiveInt


class InputTerm(Model):
    t: Literal["input"] = "input"
    input_ref: Identifier
    slot: Identifier


class ReceiptTerm(Model):
    t: Literal["receipt"] = "receipt"
    receipt_ref: Identifier
    field: Identifier


class NodeOutputTerm(Model):
    t: Literal["node_output"] = "node_output"
    node_id: Identifier
    field: Identifier


class ReadTerm(Model):
    t: Literal["read"] = "read"
    session_authorization_ref: Identifier
    query_field: Identifier
    value: JsonValue


Term = Annotated[
    StateTerm | InputTerm | ReceiptTerm | NodeOutputTerm | ReadTerm,
    Field(discriminator="t"),
]


class UserInput(Versioned):
    principal: Identifier
    batch_id: Identifier
    slot: Identifier
    value: JsonValue
    submitted_at: Timestamp
    scope_id: Identifier
    supersedes: Identifier | None = None
    sig: Signature

    @model_validator(mode="before")
    @classmethod
    def monetary_input(cls, value: Any) -> Any:
        if isinstance(value, Model):
            value = value.model_dump(mode="python")
        if isinstance(value, dict) and value.get("slot") in {"amount", "total"}:
            money = Money.model_validate(value.get("value"))
            if money.amount <= 0 or not money.is_minor_unit():
                raise ValueError("Signed payment inputs require positive whole cents")
            return {**value, "value": money.model_dump(mode="json")}
        return value


class OperationAuthorization(Versioned):
    authorization_type: Literal["operation"] = "operation"
    principal: Identifier
    intent_id: Identifier
    allowed_kind: ActionKind
    object_refs: list[Identifier]
    amount_bound: Cents | None = None
    expires_at: Timestamp
    input_hashes: list[Hash]
    sig: Signature


class SessionAuthorization(Versioned):
    authorization_type: Literal["session"] = "session"
    principal: Identifier
    device_session_id: Identifier
    read_kinds: list[ActionKind]
    expires_at: Timestamp
    sig: Signature

    @model_validator(mode="after")
    def green_queries_only(self) -> Self:
        green = {
            "balance_query",
            "transactions_query",
            "bill_analyze",
            "bill_report",
            "anomaly_query",
            "sandbox_analyze",
            "risk_assess",
            "product_compare",
            "allocation_compare",
            "investment_income_query",
        }
        if not self.read_kinds or len(set(self.read_kinds)) != len(self.read_kinds):
            raise ValueError("Read authority requires distinct query kinds")
        if not set(self.read_kinds) <= green:
            raise ValueError("Session authority only covers green queries")
        return self


class TransferTarget(Model):
    kind: Literal["transfer"] = "transfer"
    contact_ref: Identifier


class MerchantTarget(Model):
    kind: Literal["merchant_order"] = "merchant_order"
    merchant_ref: Identifier
    offer_ref: Identifier


class UnlockTarget(Model):
    kind: Literal["unlock_funds"] = "unlock_funds"
    locked_ref: Identifier


SPATarget = Annotated[TransferTarget | MerchantTarget | UnlockTarget, Field(discriminator="kind")]


class OnceSchedule(Model):
    type: Literal["once"] = "once"


class MonthlySchedule(Model):
    type: Literal["monthly"] = "monthly"
    day: Annotated[int, Field(ge=1, le=31)]


Schedule = Annotated[OnceSchedule | MonthlySchedule, Field(discriminator="type")]


class ScheduledPaymentAuthorization(Versioned):
    authorization_type: Literal["spa"] = "spa"
    principal: Identifier
    source_ref: Identifier
    target: SPATarget
    destination_version: PositiveInt
    amount: PositiveCents
    schedule: Schedule
    start: Timestamp
    end: Timestamp
    max_runs: PositiveInt
    creation_tier: Literal["yellow", "red"]
    plan_id: Identifier
    node_id: Identifier
    sig: Signature

    @model_validator(mode="after")
    def limited_scope(self) -> Self:
        duration = parse_time(self.end) - parse_time(self.start)
        if duration <= timedelta(0) or duration > timedelta(days=365):
            raise ValueError("SPA validity must be positive and at most 365 days")
        if isinstance(self.schedule, OnceSchedule) and self.max_runs != 1:
            raise ValueError("A one-time SPA permits exactly one run")
        if self.creation_tier == "yellow" and (
            self.amount > 1000 or isinstance(self.schedule, MonthlySchedule)
        ):
            raise ValueError("Large or recurring SPA creation requires red tier")
        if isinstance(self.target, UnlockTarget) and self.target.locked_ref == self.source_ref:
            raise ValueError("An unlock SPA needs distinct source and locked accounts")
        return self


class AuthorizationRevocation(Versioned):
    authorization_type: Literal["revocation"] = "revocation"
    principal: Identifier
    authorization_ref: Identifier
    revoked_at: Timestamp
    sig: Signature


Authorization = Annotated[
    OperationAuthorization
    | SessionAuthorization
    | ScheduledPaymentAuthorization
    | AuthorizationRevocation,
    Field(discriminator="authorization_type"),
]


class BestInterestRow(Model):
    product_id: Identifier
    fee_buy: Cents
    fee_hold: Cents
    fee_sell: Cents
    total_fee: Cents
    expected_net: Rational
    access_days: NonnegativeInt
    rank: PositiveInt
    gap: NonnegativeRational


class BestInterestCertificate(Model):
    catalog_hash: Hash
    preference_hash: Hash
    risk_assessment_hash: Hash
    candidate_ids: list[Identifier]
    rows: list[BestInterestRow]
    chosen_product_id: Identifier
    selection_mode: Literal["default", "explicit"]
    best_choice: bool


class BankCertificate(Model):
    version: Literal["bank-v1"] = "bank-v1"
    action_hash: Hash
    authorization_ref: Identifier
    derivations: dict[str, Term]
    dependency_hashes: dict[str, Hash]
    analysis_receipt_refs: list[Identifier] = Field(default_factory=list)
    best_interest: BestInterestCertificate | None = None
    allocation: BestInterestAllocationCertificate | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    mfa_grant_refs: list[Identifier] = Field(default_factory=list)


class MFAGrant(Model):
    grant_id: Identifier
    principal: Identifier
    device_session_id: Identifier
    scope_hash: Hash
    method: Literal["sms_sim"]
    challenge_id: Identifier
    issued_at: Timestamp
    expiry: Timestamp
    sig: Signature

    @model_validator(mode="after")
    def ordered_times(self) -> Self:
        if self.expiry <= self.issued_at:
            raise ValueError("MFA expiry must follow issue time")
        return self


StepUpGrant = MFAGrant


class ApprovalToken(Model):
    token_id: Identifier
    principal: Identifier
    device_session_id: Identifier
    action_hash: Hash
    cert_hash: Hash
    card_hash: Hash
    plan_id: Identifier
    plan_hash: Hash
    node_id: Identifier
    ownership_epoch: NonnegativeInt
    tier: Literal["yellow", "red"]
    nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    issued_at: Timestamp
    expiry: Timestamp
    sig: Signature

    @model_validator(mode="after")
    def ordered_times(self) -> Self:
        if self.expiry <= self.issued_at:
            raise ValueError("Approval expiry must follow issue time")
        return self


BankEventKind = ActionKind | Literal["subscription_debit"]


class AccountMovement(Model):
    account_ref: Identifier
    amount: Cents


class BusinessEvent(Versioned):
    intent_key: Hash
    event: Literal["reserved", "settled", "failed", "unknown"]
    kind: BankEventKind
    principal: Identifier
    commitment_id: Identifier | None = None
    debit: AccountMovement | None = None
    credit: AccountMovement | None = None
    object_delta: dict[str, JsonValue] = Field(default_factory=dict)
    ts: Timestamp
    bank_receipt_id: Identifier | None = None


class BankEffect(Model):
    effect_type: Literal["debit", "credit", "state", "position", "order", "query"]
    object_ref: Identifier
    account_ref: Identifier | None = None
    counterparty_ref: Identifier | None = None
    amount: Cents | None = None
    field: Identifier | None = None
    before: JsonValue = None
    after: JsonValue = None

    @model_validator(mode="after")
    def monetary_effect(self) -> Self:
        if self.effect_type in {"debit", "credit"} and (
            self.account_ref is None or self.amount is None
        ):
            raise ValueError("Account effects need an account and exact amount")
        return self


class BankReceipt(Model):
    receipt_type: Literal["bank"] = "bank"
    receipt_id: Identifier
    version: PositiveInt = 1
    intent_key: Hash
    kind: BankEventKind
    status: Literal["pending", "settled", "failed", "unknown"]
    exact_effects: list[BankEffect]
    executed_at: Timestamp
    settle_at: Timestamp | None = None
    sig: Signature

    @property
    def id(self) -> str:
        return self.receipt_id

    @model_validator(mode="after")
    def settlement_time(self) -> Self:
        if self.settle_at is not None and self.settle_at < self.executed_at:
            raise ValueError("Settlement cannot precede execution")
        return self


class AnalysisResult(Model):
    value: JsonValue
    unit: Identifier
    source_tx_ids: list[Identifier]


class AnalysisReceipt(Model):
    receipt_type: Literal["analysis"] = "analysis"
    receipt_id: Identifier
    version: PositiveInt = 1
    dataset_hash: Hash
    function_id: Identifier
    parameters: dict[str, JsonValue]
    results: dict[str, AnalysisResult]
    program_hash: Hash | None = None
    trust: Literal["builtin", "exploratory"]
    computed_at: Timestamp
    sig: Signature

    @property
    def id(self) -> str:
        return self.receipt_id

    @model_validator(mode="after")
    def exploratory_provenance(self) -> Self:
        if self.trust == "exploratory" and self.program_hash is None:
            raise ValueError("Exploratory results require a program hash")
        return self


Receipt = Annotated[BankReceipt | AnalysisReceipt, Field(discriminator="receipt_type")]


class TransferOrderArgs(Model):
    source_ref: Identifier
    contact_ref: Identifier
    destination_ref: Identifier
    amount: PositiveCents


class FundsOrderArgs(Model):
    source_ref: Identifier
    locked_ref: Identifier
    amount: PositiveCents
    purpose_ref: Identifier


class MerchantOrderArgs(Model):
    source_ref: Identifier
    merchant_ref: Identifier
    offer_ref: Identifier
    destination_ref: Identifier
    amount: PositiveCents


class PurchaseOrderArgs(Model):
    source_ref: Identifier
    product_ref: Identifier
    amount: PositiveCents
    fee_buy: Cents


class RedeemOrderArgs(Model):
    position_ref: Identifier
    amount: PositiveCents


class ApplyCardOrderArgs(Model):
    account_ref: Identifier
    limit: PositiveCents


class CardStateOrderArgs(Model):
    card_ref: Identifier


class CardLimitOrderArgs(Model):
    card_ref: Identifier
    limit: PositiveCents


class CardRestrictionOrderArgs(Model):
    card_ref: Identifier
    restrictions: CardRestrictions


BankOrderArgs = (
    TransferOrderArgs
    | FundsOrderArgs
    | MerchantOrderArgs
    | PurchaseOrderArgs
    | RedeemOrderArgs
    | SubscriptionArgs
    | OrderArgs
    | ReceiptArgs
    | ApplyCardOrderArgs
    | CardStateOrderArgs
    | CardLimitOrderArgs
    | CardRestrictionOrderArgs
    | AccountArgs
    | AnalysisArgs
    | SubscriptionQueryArgs
    | PreferenceArgs
    | PositionArgs
)

BANK_ORDER_ARGS: dict[str, type[Model]] = {
    "transfer": TransferOrderArgs,
    "lock_funds": FundsOrderArgs,
    "unlock_funds": FundsOrderArgs,
    "merchant_order": MerchantOrderArgs,
    "purchase_product": PurchaseOrderArgs,
    "redeem_product": RedeemOrderArgs,
    "cancel_subscription": SubscriptionArgs,
    "cancel_order": OrderArgs,
    "refund_request": ReceiptArgs,
    "apply_virtual_card": ApplyCardOrderArgs,
    "freeze_card": CardStateOrderArgs,
    "restrict_card": CardRestrictionOrderArgs,
    "lower_card_limit": CardLimitOrderArgs,
    "unfreeze_card": CardStateOrderArgs,
    "relax_card_restriction": CardRestrictionOrderArgs,
    "report_card_lost": CardStateOrderArgs,
    "restore_card": CardStateOrderArgs,
    "raise_card_limit": CardLimitOrderArgs,
    "balance_query": AccountArgs,
    "transactions_query": AccountArgs,
    "bill_analyze": AnalysisArgs,
    "bill_report": AnalysisArgs,
    "anomaly_query": AnalysisArgs,
    "subscription_query": SubscriptionQueryArgs,
    "subscription_reminders": SubscriptionQueryArgs,
    "product_compare": PreferenceArgs,
    "investment_income_query": PositionArgs,
}


class BankOrder(Model):
    intent_key: Hash
    action_id: Identifier
    principal: Identifier
    kind: ActionKind
    requested_at: Timestamp
    commitment_id: Identifier | None = None
    args: BankOrderArgs

    @model_validator(mode="before")
    @classmethod
    def args_for_kind(cls, value: Any) -> Any:
        return _validate_args(value, BANK_ORDER_ARGS)


class Handle(Model):
    handle_type: Literal["state", "input", "receipt", "program", "dataset"]
    ref: Identifier


class Compensation(Model):
    tool: ActionKind
    original_node_ref: Identifier


class PlanNode(Model):
    node_id: Identifier
    tool: ActionKind
    args: dict[str, Term | Handle | list[Term]]
    depends_on: Annotated[list[Identifier], Field(max_length=12)] = Field(default_factory=list)
    compensation: Compensation | None = None
    due_at_ref: Identifier | None = None

    @model_validator(mode="after")
    def limited_term_lists(self) -> Self:
        for name, value in self.args.items():
            if isinstance(value, list) and (
                self.tool != "aa_request" or name != "participant_refs" or not 1 <= len(value) <= 10
            ):
                raise ValueError("Only AA participant_refs accepts a list of one to ten terms")
        return self


class Plan(Model):
    version: Literal["bank-plan-v1"] = "bank-plan-v1"
    plan_id: Identifier
    revision: PositiveInt
    principal: Identifier
    device_session_id: Identifier
    intent_id: Identifier
    goal_input_refs: list[Identifier]
    nodes: Annotated[list[PlanNode], Field(min_length=1, max_length=12)]
    ownership_epoch: NonnegativeInt

    @model_validator(mode="after")
    def edge_limit(self) -> Self:
        if sum(len(node.depends_on) for node in self.nodes) > 24:
            raise ValueError("Plans contain at most 24 dependency edges")
        return self


class Expected(Model):
    outcome: Literal["complete", "refuse", "clarify", "waiting", "handoff"]
    rule_ids_all: list[Identifier] = Field(default_factory=list)
    rule_ids_any: list[Identifier] = Field(default_factory=list)
    tier: Tier | None = None
    effect_count: NonnegativeInt | None = None
    exact_fields: dict[str, JsonValue] = Field(default_factory=dict)


class GroundTruthStep(Model):
    event: Identifier
    advance_to: Timestamp | None = None
    user_response: JsonValue = None
    fault: Identifier | None = None
    expected: Expected


class GroundTruth(Model):
    task_id: Identifier
    subcase_id: Identifier
    family: Identifier
    twin_of: Identifier | None = None
    clock_start: Timestamp
    initial_public_state_ref: Identifier
    initial_public_state_hash: Hash
    evaluation_policy_ref: Identifier
    evaluation_policy_hash: Hash
    catalog_truth: dict[str, JsonValue]
    marketing: dict[str, JsonValue]
    customer_constraints: dict[str, JsonValue]
    intended_effects: list[BankEffect]
    authorized_inputs: list[UserInput]
    steps: list[GroundTruthStep]
    expected: Expected
