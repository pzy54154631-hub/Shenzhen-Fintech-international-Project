"""Bounded exact wire contracts for synthetic policy-checked allocations."""

from fractions import Fraction
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BeforeValidator, Field, field_validator, model_validator

from corridor.schemas.base import Model
from corridor.schemas.domain import Versioned
from corridor.schemas.models import Hash, PositiveInt, Signature
from corridor.schemas.models import Identifier as BaseIdentifier
from corridor.schemas.money import Rational
from corridor.schemas.time import Timestamp

MAX_PRINCIPAL = 1_000_000_000
MAX_RATIONAL_BITS = 127
Identifier = Annotated[BaseIdentifier, Field(max_length=128)]
Sleeve = Literal["R1", "R2", "R3", "R4", "R5"]
ClientProfile = Literal["C1", "C2", "C3", "C4", "C5"]
SLEEVES: tuple[Sleeve, ...] = ("R1", "R2", "R3", "R4", "R5")


def _bounded_text(value: object) -> object:
    if isinstance(value, str) and len(value) > 128:
        raise ValueError("Allocation rational text exceeds its resource bound")
    return value


def _bounded_fraction(value: Fraction) -> Fraction:
    if max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > MAX_RATIONAL_BITS:
        raise ValueError("Allocation rational exceeds its resource bound")
    return value


def _nonnegative(value: Fraction) -> Fraction:
    if value < 0:
        raise ValueError("Allocation value must be nonnegative")
    return value


def _weight(value: Fraction) -> Fraction:
    if not 0 <= value <= 1:
        raise ValueError("Allocation weight must be between zero and one")
    return value


def _cents(value: Fraction) -> Fraction:
    if value < 0 or (value * 100).denominator != 1:
        raise ValueError("Allocation amount requires nonnegative exact cents")
    return value


def _principal(value: Fraction) -> Fraction:
    if not 0 < value <= MAX_PRINCIPAL:
        raise ValueError("Allocation principal is outside its resource bound")
    return value


AllocationRational = Annotated[
    Rational, BeforeValidator(_bounded_text), AfterValidator(_bounded_fraction)
]
AllocationNonnegative = Annotated[AllocationRational, AfterValidator(_nonnegative)]
AllocationWeight = Annotated[AllocationRational, AfterValidator(_weight)]
AllocationCents = Annotated[AllocationRational, AfterValidator(_cents)]
AllocationPrincipal = Annotated[AllocationCents, AfterValidator(_principal)]
SelectionMode = Literal["default", "explicit_weights", "explicit_items"]
Weights = Annotated[dict[Sleeve, AllocationWeight], Field(min_length=5, max_length=5)]
ProductIds = Annotated[list[Identifier], Field(max_length=12)]


class AllocationRequestItem(Model):
    product_id: Identifier
    principal: AllocationPrincipal


class AllocationRequest(Versioned):
    id: Identifier
    source_account_ref: Identifier
    amount: AllocationPrincipal
    horizon_days: Annotated[int, Field(ge=1, le=365)]
    liquidity_days: Annotated[int, Field(ge=0, le=365)]
    liquidity_amount: AllocationCents
    allowed_types: Annotated[list[Literal["deposit", "wealth"]], Field(min_length=1, max_length=2)]
    objective: Literal["net_return", "total_fee", "liquidity"]
    allocation_policy_ref: Identifier
    selection_mode: SelectionMode = "default"
    target_weights: Weights | None = None
    items: Annotated[list[AllocationRequestItem], Field(min_length=1, max_length=12)] | None = None
    model_biac_hash: Hash | None = None
    reason_code: Literal["user_adjustment", "liquidity_preference", "product_preference"] | None = (
        None
    )

    @field_validator("allowed_types")
    @classmethod
    def canonical_types(
        cls, value: list[Literal["deposit", "wealth"]]
    ) -> list[Literal["deposit", "wealth"]]:
        if len(set(value)) != len(value):
            raise ValueError("Allowed product types must be unique")
        return sorted(set(value))

    @model_validator(mode="after")
    def bounded_request(self) -> Self:
        if self.liquidity_days > self.horizon_days or self.liquidity_amount > self.amount:
            raise ValueError("Liquidity requirement exceeds the signed investment scope")
        present = (self.target_weights is not None, self.items is not None)
        expected = {
            "default": (False, False),
            "explicit_weights": (True, False),
            "explicit_items": (False, True),
        }[self.selection_mode]
        if present != expected:
            raise ValueError("Selection mode requires exactly its signed adjustment")
        explicit = self.selection_mode != "default"
        if explicit != (self.model_biac_hash is not None) or explicit != (
            self.reason_code is not None
        ):
            raise ValueError("Explicit adjustments require a model hash and reason")
        if self.target_weights is not None and sum(self.target_weights.values(), Fraction()) != 1:
            raise ValueError("Explicit weights must sum exactly to one")
        if self.items is not None and len({item.product_id for item in self.items}) != len(
            self.items
        ):
            raise ValueError("Explicit product amounts must be aggregated by product")
        return self


class AllocationBand(Model):
    sleeve: Sleeve
    lower: AllocationWeight
    upper: AllocationWeight

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.lower > self.upper:
            raise ValueError("Allocation lower band exceeds upper band")
        return self


class AllocationGroupBound(Model):
    sleeves: Annotated[list[Sleeve], Field(min_length=1, max_length=5)]
    lower: AllocationWeight
    upper: AllocationWeight

    @model_validator(mode="after")
    def valid_group(self) -> Self:
        if self.lower > self.upper or self.sleeves != sorted(set(self.sleeves)):
            raise ValueError("Group bounds require ordered limits and unique sorted sleeves")
        return self


class AllocationProfile(Model):
    bands: Annotated[list[AllocationBand], Field(min_length=5, max_length=5)]
    group_bounds: Annotated[list[AllocationGroupBound], Field(max_length=31)]
    model_weights: Weights

    @model_validator(mode="after")
    def valid_model(self) -> Self:
        if [band.sleeve for band in self.bands] != list(SLEEVES):
            raise ValueError("All five policy sleeves must appear in canonical order")
        if sum(self.model_weights.values(), Fraction()) != 1:
            raise ValueError("Signed model weights must sum exactly to one")
        for band in self.bands:
            if not band.lower <= self.model_weights[band.sleeve] <= band.upper:
                raise ValueError("Signed model weights violate a sleeve band")
        groups = [tuple(group.sleeves) for group in self.group_bounds]
        if len(set(groups)) != len(groups):
            raise ValueError("Policy groups must be unique")
        for group in self.group_bounds:
            actual = sum((self.model_weights[sleeve] for sleeve in group.sleeves), Fraction())
            if not group.lower <= actual <= group.upper:
                raise ValueError("Signed model weights violate a group bound")
        return self


class RiskRetakeLimits(Model):
    daily: Annotated[int, Field(ge=1, le=2)] = 2
    trailing_twelve_months: Annotated[int, Field(ge=1, le=8)] = 8


class AllocationPolicy(Versioned):
    id: Identifier
    schema_version: Literal["allocation-policy-v1"] = "allocation-policy-v1"
    issued_at: Timestamp
    valid_until: Timestamp
    catalog_id: Identifier
    catalog_version: PositiveInt
    currency: Literal["CNY"] = "CNY"
    selector_version: Literal["greedy-sleeves-v1"] = "greedy-sleeves-v1"
    ranking_basis: Literal["request_principal"] = "request_principal"
    concentration_cap: AllocationWeight
    max_products: Annotated[int, Field(ge=1, le=12)]
    profiles: Annotated[dict[ClientProfile, AllocationProfile], Field(min_length=5, max_length=5)]
    risk_retake_limits: RiskRetakeLimits | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    sig: Signature

    @model_validator(mode="after")
    def valid_policy(self) -> Self:
        if self.issued_at >= self.valid_until or self.concentration_cap != Fraction(1, 2):
            raise ValueError("Policy requires a valid lifetime and a one-half concentration cap")
        for client, profile in self.profiles.items():
            level = int(client[1:])
            if any(profile.model_weights[sleeve] != 0 for sleeve in SLEEVES[level:]):
                raise ValueError("Model weights may not exceed client suitability")
            if any(band.lower != 0 or band.upper != 0 for band in profile.bands[level:]):
                raise ValueError("Risk budget bands may not exceed client suitability")
        return self


ExclusionReason = Literal[
    "purchase_closed",
    "customer_ineligible",
    "risk",
    "product_type",
    "holding_period",
    "minimum_amount",
    "maximum_amount",
    "concentration",
    "available_balance",
]


class AllocationExclusion(Model):
    product_id: Identifier
    reason_codes: Annotated[list[ExclusionReason], Field(min_length=1, max_length=9)]


class AllocationRankingRow(Model):
    product_id: Identifier
    fee_buy: AllocationCents
    fee_hold: AllocationCents
    fee_sell: AllocationCents
    total_fee: AllocationCents
    expected_net: AllocationRational
    access_days: Annotated[int, Field(ge=0, le=2**31 - 1)]
    rank: Annotated[int, Field(ge=1, le=12)]
    gap: AllocationNonnegative
    reference_amount: AllocationPrincipal
    comparison_only: Literal[True] = True


class AllocationSleeve(Model):
    sleeve: Sleeve
    model_weight: AllocationWeight
    target_cents: Annotated[int, Field(ge=0, le=MAX_PRINCIPAL * 100)]
    actual_cents: Annotated[int, Field(ge=0, le=MAX_PRINCIPAL * 100)]
    candidate_ids: ProductIds
    ranking_rows: Annotated[list[AllocationRankingRow], Field(max_length=12)]


class AllocationItem(Model):
    product_id: Identifier
    sleeve: Sleeve
    principal: AllocationPrincipal
    weight: AllocationWeight
    fee_buy: AllocationCents
    fee_hold: AllocationCents
    fee_sell: AllocationCents
    expected_net: AllocationRational
    access_days: Annotated[int, Field(ge=0, le=2**31 - 1)]
    liquid_net_principal: AllocationCents
    selection_reason: Literal[
        "objective_rank", "liquidity_requirement", "sleeve_fill", "explicit_item"
    ]


class AllocationTotals(Model):
    principal: AllocationPrincipal
    fee_buy: AllocationCents
    total_debit: AllocationCents
    projected_fees: AllocationCents
    projected_net: AllocationRational
    liquid_net_principal: AllocationCents


ConstraintId = Literal[
    "principal_sum",
    "total_debit",
    "product_minimum",
    "product_maximum",
    "concentration",
    "sleeve_lower",
    "sleeve_upper",
    "group_lower",
    "group_upper",
    "liquidity",
    "nonnegative_liquid_principal",
]


class AllocationCheck(Model):
    constraint_id: ConstraintId
    subject_ref: Identifier | None = None
    lhs: AllocationRational
    comparator: Literal["<=", "=", ">="]
    rhs: AllocationRational
    satisfied: bool


class AllocationProductDelta(Model):
    product_id: Identifier
    principal_delta: AllocationRational
    weight_delta: AllocationRational


class AllocationSleeveDelta(Model):
    sleeve: Sleeve
    principal_delta: AllocationRational
    weight_delta: AllocationRational


class AllocationDeviations(Model):
    products: Annotated[list[AllocationProductDelta], Field(max_length=12)]
    sleeves: Annotated[list[AllocationSleeveDelta], Field(min_length=5, max_length=5)]
    projected_fees_delta: AllocationRational
    projected_net_delta: AllocationRational
    liquid_net_principal_delta: AllocationRational
    total_debit_delta: AllocationRational


class AllocationFactReason(Model):
    template_id: Literal[
        "complete_catalogue",
        "reference_ranking",
        "policy_constraints",
        "liquidity_requirement",
        "model_deviation",
        "heuristic_allocation",
    ]
    fact_refs: Annotated[list[Identifier], Field(max_length=128)]


class BestInterestAllocationCertificate(Model):
    schema_version: Literal["biac-v1"] = "biac-v1"
    selector_version: Literal["greedy-sleeves-v1"] = "greedy-sleeves-v1"
    request_hash: Hash
    policy_hash: Hash
    catalog_hash: Hash
    risk_assessment_hash: Hash
    principal: Identifier
    source_account_ref: Identifier
    base_context_hash: Hash
    candidate_ids: ProductIds
    exclusions: Annotated[list[AllocationExclusion], Field(max_length=12)]
    sleeves: Annotated[list[AllocationSleeve], Field(min_length=5, max_length=5)]
    allocation: Annotated[list[AllocationItem], Field(min_length=1, max_length=12)]
    totals: AllocationTotals
    checks: Annotated[list[AllocationCheck], Field(max_length=128)]
    selection_mode: SelectionMode
    model_biac_hash: Hash | None = None
    deviations: AllocationDeviations | None = None
    fact_reasons: Annotated[list[AllocationFactReason], Field(max_length=12)]


FailureReason = Literal[
    "target_rounding_conflict",
    "capacity_shortfall",
    "minimum_amount",
    "available_balance",
    "liquidity_shortfall",
    "constraint_violation",
    "model_target_conflict",
    "invalid_request",
    "invalid_policy",
    "no_candidates",
    "sleeve_capacity",
    "product_capacity",
]


class AllocationConstructionStep(Model):
    product_id: Identifier
    stage: Literal["liquidity", "fill"]
    allocated_cents: Annotated[int, Field(ge=0, le=MAX_PRINCIPAL * 100)]
    skipped_reason: FailureReason | None = None


class AllocationFailure(Model):
    input_hashes: Annotated[dict[Identifier, Hash], Field(max_length=8)]
    candidate_ids: ProductIds
    exclusions: Annotated[list[AllocationExclusion], Field(max_length=12)]
    stage: Literal["input", "policy", "eligibility", "rounding", "liquidity", "fill", "validation"]
    reason_codes: Annotated[list[FailureReason], Field(min_length=1, max_length=12)]
    residual_cents: Annotated[int, Field(ge=0, le=MAX_PRINCIPAL * 100)]
    unmet_constraints: Annotated[list[AllocationCheck], Field(max_length=128)]
    trace: Annotated[list[AllocationConstructionStep], Field(max_length=24)] = Field(
        default_factory=list
    )


class AllocationPlanItem(Model):
    item_ref: Identifier
    product_ref: Identifier
    principal: AllocationPrincipal
    fee_buy: AllocationCents
    child_intent_id: Identifier
    input_refs: Annotated[list[Identifier], Field(min_length=1, max_length=8)]
    authorization_ref: Identifier
    child_plan_id: Identifier
    child_plan_hash: Hash
    child_node_id: Identifier


class AllocationPlan(Versioned):
    id: Identifier
    principal: Identifier
    parent_intent_id: Identifier
    request_ref: Identifier
    biac_hash: Hash
    policy_hash: Hash
    catalog_hash: Hash
    risk_assessment_hash: Hash
    initial_budget: AllocationCents
    items: Annotated[list[AllocationPlanItem], Field(min_length=1, max_length=12)]
    plan_hash: Hash
    selection_input_ref: Identifier | None = None

    @model_validator(mode="after")
    def unique_children(self) -> Self:
        for name in ("item_ref", "product_ref", "child_intent_id", "child_plan_id"):
            values = [getattr(item, name) for item in self.items]
            if len(set(values)) != len(values):
                raise ValueError("Allocation plan child mappings must be unique")
        if [item.product_ref for item in self.items] != sorted(
            item.product_ref for item in self.items
        ):
            raise ValueError("Allocation plan items must be ordered by product")
        return self
