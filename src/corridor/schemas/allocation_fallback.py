"""Non-executable economic previews for explicitly confirmed allocation corrections."""

from typing import Annotated, Literal

from pydantic import Field

from corridor.schemas.allocation import (
    AllocationCheck,
    AllocationExclusion,
    AllocationFailure,
    AllocationItem,
    AllocationRational,
    AllocationRequest,
    AllocationSleeve,
    AllocationTotals,
    Identifier,
    ProductIds,
    Sleeve,
)
from corridor.schemas.base import Model
from corridor.schemas.models import Hash, JsonValue


class AllocationProjection(Model):
    base_context_hash: Hash
    policy_hash: Hash
    catalog_hash: Hash
    risk_assessment_hash: Hash
    effective_risk_level: Annotated[int, Field(ge=1, le=5)]
    candidate_ids: ProductIds
    exclusions: Annotated[list[AllocationExclusion], Field(max_length=12)]
    sleeves: Annotated[list[AllocationSleeve], Field(min_length=5, max_length=5)]
    allocation: Annotated[list[AllocationItem], Field(min_length=1, max_length=12)]
    totals: AllocationTotals
    checks: Annotated[list[AllocationCheck], Field(max_length=128)]


class AllocationFieldChange(Model):
    field: Literal["target_weights", "liquidity_amount", "horizon_days", "allowed_types", "amount"]
    before: JsonValue
    after: JsonValue
    delta: AllocationRational | None = None
    unit: Literal["weight", "CNY", "days", "product_types"]


class AllocationProductChange(Model):
    product_id: Identifier
    principal_delta: AllocationRational
    percentage_points_delta: AllocationRational
    fee_buy_delta: AllocationRational
    fee_hold_delta: AllocationRational
    fee_sell_delta: AllocationRational
    benchmark_net_delta: AllocationRational
    liquid_net_principal_delta: AllocationRational


class AllocationWeightChange(Model):
    sleeve: Sleeve
    before: AllocationRational
    after: AllocationRational
    percentage_points_delta: AllocationRational


class AllocationFallbackDiff(Model):
    basis: Literal["historical_default_baseline", "no_constructed_baseline"]
    baseline_biac_hash: Hash | None = None
    products: Annotated[list[AllocationProductChange], Field(max_length=12)]
    requested_weights: Annotated[list[AllocationWeightChange], Field(max_length=5)]
    benchmark_net_delta: AllocationRational | None = None
    projected_fees_delta: AllocationRational | None = None
    liquid_net_principal_delta: AllocationRational | None = None
    total_debit_delta: AllocationRational | None = None
    liquidity_days: Annotated[int, Field(ge=0, le=365)]


class AllocationAlternative(Model):
    alternative_id: Hash
    kind: Literal[
        "weights_clipped", "lower_liquidity", "extend_horizon", "allow_deposit", "lower_amount"
    ]
    proposed_request: AllocationRequest
    projection: AllocationProjection
    changes: Annotated[list[AllocationFieldChange], Field(min_length=1, max_length=1)]
    diff: AllocationFallbackDiff
    requires_confirmation: Literal[True] = True


class AllocationFallbackPreview(Model):
    status: Literal["unsigned_preview"] = "unsigned_preview"
    source_request_ref: Identifier
    source_request_hash: Hash | None
    source_errors: Annotated[list[str], Field(max_length=32)]
    failure: AllocationFailure | None
    alternatives: Annotated[list[AllocationAlternative], Field(max_length=3)]
    binding_constraints: Annotated[list[AllocationCheck], Field(max_length=128)]
    requires_confirmation: Literal[True] = True
    notice: str = (
        "No allocation was constructed for the rejected request. These unsigned alternatives "
        "are policy-checked heuristic previews. Select and sign a new request on the device; "
        "current constraints will be checked again. Performance benchmark (not guaranteed)."
    )
    limitation: str = (
        "The fixed menu is bounded and may miss other allowed allocations. Amount reductions "
        "use capacity candidates; they do not establish the largest possible investment."
    )


class AllocationCorrectionDiff(Model):
    status: Literal["read_only_comparison"] = "read_only_comparison"
    basis: Literal["signed_requests_under_current_context"] = (
        "signed_requests_under_current_context"
    )
    principal: Identifier
    parent_intent_id: Identifier
    before_request_ref: Identifier
    after_request_ref: Identifier
    before_request_hash: Hash
    after_request_hash: Hash
    before_request: AllocationRequest
    after_request: AllocationRequest
    before_projection: AllocationProjection
    after_projection: AllocationProjection
    products: Annotated[list[AllocationProductChange], Field(max_length=12)]
    principal_delta: AllocationRational
    fee_buy_delta: AllocationRational
    projected_fees_delta: AllocationRational
    benchmark_net_delta: AllocationRational
    liquid_net_principal_delta: AllocationRational
    total_debit_delta: AllocationRational
    notice: str = (
        "Read-only comparison of signed requests recomputed under current trusted facts. "
        "The previous input gives no execution authority. Liquid net principal uses each "
        "request's stated day. Performance benchmark (not guaranteed)."
    )
