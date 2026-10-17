"""Bounded, read-only alternatives; only a new device signature can authorize one."""

from fractions import Fraction
from typing import Literal

from corridor.crypto.jcs import H
from corridor.kernel.allocation import (
    CENT,
    ZERO,
    _checks,
    _construct,
    _Context,
    _context,
    _context_for_request,
    _default,
    _floor_cents,
    _projection,
    _signed_input,
    _targets,
    _totals,
    _weights_valid,
    evaluate_allocation,
)
from corridor.schemas.allocation import (
    SLEEVES,
    AllocationItem,
    AllocationRequest,
    BestInterestAllocationCertificate,
)
from corridor.schemas.allocation_fallback import (
    AllocationAlternative,
    AllocationCorrectionDiff,
    AllocationFallbackDiff,
    AllocationFallbackPreview,
    AllocationFieldChange,
    AllocationProductChange,
    AllocationProjection,
    AllocationWeightChange,
)
from corridor.schemas.state import BankState

_COMMON_FIELDS = (
    "source_account_ref",
    "amount",
    "horizon_days",
    "liquidity_days",
    "liquidity_amount",
    "allowed_types",
    "objective",
    "allocation_policy_ref",
)


def _request(context: _Context, **changes: object) -> AllocationRequest:
    return AllocationRequest.model_validate({
        **context.request.model_dump(mode="python"),
        **changes,
    })


def _candidate_context(
    original: _Context, request: AllocationRequest, state: BankState
) -> _Context:
    # The retained signature identifies the source only. No certificate is emitted.
    return _context_for_request(
        original.principal, original.parent_intent_id, original.user_input, request, state
    )


def _model(context: _Context, state: BankState) -> BestInterestAllocationCertificate | None:
    """Recover only a real signed default in exactly the explicit request's context."""
    for ref in sorted(state.user_inputs):
        try:
            value, request = _signed_input(
                context.principal, context.parent_intent_id, ref, state, historical=True
            )
        except ValueError:
            continue
        if request.selection_mode != "default" or any(
            getattr(request, field) != getattr(context.request, field) for field in _COMMON_FIELDS
        ):
            continue
        previous = _context_for_request(
            context.principal, context.parent_intent_id, value, request, state
        )
        baseline = _default(previous, state).certificate
        if baseline is not None and H(baseline) == context.request.model_biac_hash:
            return baseline
    return None


def _preview_projection(context: _Context, state: BankState) -> AllocationProjection | None:
    if not context.candidates:
        return None
    request = context.request
    if request.selection_mode != "default" and _model(context, state) is None:
        return None
    if request.selection_mode == "explicit_items":
        amounts = {item.product_id: int(item.principal * 100) for item in request.items or []}
        reasons = dict.fromkeys(amounts, "explicit_item")
        targets = {
            str(s): sum(
                amounts.get(p.id, 0) for p in context.candidates if SLEEVES[p.risk_level - 1] == s
            )
            for s in SLEEVES
        }
    else:
        raw_weights = (
            request.target_weights or {}
            if request.selection_mode == "explicit_weights"
            else context.profile.model_weights
        )
        weights = {str(k): v for k, v in raw_weights.items()}
        if not _weights_valid(weights, context.profile, context.effective_level):
            return None
        computed_targets = _targets(context, weights)
        if computed_targets is None:
            return None
        targets = computed_targets
        amounts, reasons, _ = _construct(context, targets)
    if set(amounts) - {p.id for p in context.candidates} or not all(
        check.satisfied for check in _checks(context, amounts)
    ):
        return None
    return AllocationProjection.model_validate({
        **_projection(context, targets, amounts, reasons),
        "base_context_hash": context.base_hash,
        "policy_hash": H(context.policy),
        "catalog_hash": H(state.catalog),
        "risk_assessment_hash": H(context.risk),
        "effective_risk_level": context.effective_level,
    })


def allocation_projection_diff(
    original: AllocationRequest,
    proposed: AllocationRequest,
    projection: AllocationProjection,
    baseline: BestInterestAllocationCertificate | None,
) -> AllocationFallbackDiff:
    """Exact deltas against a named real model; a rejected request has no portfolio."""
    weight_changes: list[AllocationWeightChange] = []
    if original.target_weights is not None and proposed.target_weights is not None:
        weight_changes = [
            AllocationWeightChange(
                sleeve=sleeve,
                before=original.target_weights[sleeve],
                after=proposed.target_weights[sleeve],
                percentage_points_delta=100
                * (proposed.target_weights[sleeve] - original.target_weights[sleeve]),
            )
            for sleeve in SLEEVES
        ]
    common = {
        "requested_weights": weight_changes,
        "liquidity_days": proposed.liquidity_days,
    }
    if baseline is None:
        return AllocationFallbackDiff.model_validate({
            **common,
            "basis": "no_constructed_baseline",
            "products": [],
        })
    return AllocationFallbackDiff.model_validate({
        **common,
        "basis": "historical_default_baseline",
        "baseline_biac_hash": H(baseline),
        "products": _product_changes(baseline.allocation, projection.allocation),
        "benchmark_net_delta": projection.totals.projected_net - baseline.totals.projected_net,
        "projected_fees_delta": projection.totals.projected_fees - baseline.totals.projected_fees,
        "liquid_net_principal_delta": projection.totals.liquid_net_principal
        - baseline.totals.liquid_net_principal,
        "total_debit_delta": projection.totals.total_debit - baseline.totals.total_debit,
    })


def _product_changes(
    before_rows: list[AllocationItem], after_rows: list[AllocationItem]
) -> list[AllocationProductChange]:
    before = {item.product_id: item for item in before_rows}
    after = {item.product_id: item for item in after_rows}
    deltas: list[AllocationProductChange] = []
    for product_id in sorted(set(before) | set(after)):
        old, new = before.get(product_id), after.get(product_id)

        def delta(field: str) -> Fraction:
            old_value = getattr(old, field) if old is not None else ZERO
            new_value = getattr(new, field) if new is not None else ZERO
            return Fraction(new_value - old_value)

        deltas.append(
            AllocationProductChange(
                product_id=product_id,
                principal_delta=delta("principal"),
                percentage_points_delta=100 * delta("weight"),
                fee_buy_delta=delta("fee_buy"),
                fee_hold_delta=delta("fee_hold"),
                fee_sell_delta=delta("fee_sell"),
                benchmark_net_delta=delta("expected_net"),
                liquid_net_principal_delta=delta("liquid_net_principal"),
            )
        )
    return deltas


def compare_allocation_requests(
    principal: str, before_request_ref: str, after_request_ref: str, state: BankState
) -> AllocationCorrectionDiff:
    """Recompute a historical/current signed pair without restoring old authority."""
    after_input = state.user_inputs.get(after_request_ref)
    if after_input is None:
        raise ValueError("BIC-PREFERENCE")
    parent = after_input.scope_id
    current = _context(principal, parent, after_request_ref, state, None)
    evaluation = evaluate_allocation(principal, parent, after_request_ref, state)
    if evaluation.errors or evaluation.certificate is None:
        raise ValueError(evaluation.errors[0] if evaluation.errors else "ALLOC-SELECT")
    before_input, before_request = _signed_input(
        principal, parent, before_request_ref, state, historical=True
    )
    previous = _context_for_request(principal, parent, before_input, before_request, state)
    before_projection = _preview_projection(previous, state)
    after_projection = _preview_projection(current, state)
    if before_projection is None or after_projection is None:
        raise ValueError("ALLOC-SELECT")
    before, after = before_projection.totals, after_projection.totals
    return AllocationCorrectionDiff(
        principal=principal,
        parent_intent_id=parent,
        before_request_ref=before_request_ref,
        after_request_ref=after_request_ref,
        before_request_hash=H(before_input),
        after_request_hash=H(after_input),
        before_request=before_request,
        after_request=current.request,
        before_projection=before_projection,
        after_projection=after_projection,
        products=_product_changes(before_projection.allocation, after_projection.allocation),
        principal_delta=after.principal - before.principal,
        fee_buy_delta=after.fee_buy - before.fee_buy,
        projected_fees_delta=after.projected_fees - before.projected_fees,
        benchmark_net_delta=after.projected_net - before.projected_net,
        liquid_net_principal_delta=after.liquid_net_principal - before.liquid_net_principal,
        total_debit_delta=after.total_debit - before.total_debit,
    )


def _alternative(
    original: _Context,
    request: AllocationRequest,
    state: BankState,
    kind: Literal[
        "weights_clipped", "lower_liquidity", "extend_horizon", "allow_deposit", "lower_amount"
    ],
    baseline: BestInterestAllocationCertificate | None = None,
) -> AllocationAlternative | None:
    context = _candidate_context(original, request, state)
    projection = _preview_projection(context, state)
    if projection is None:
        return None
    field, unit = {
        "weights_clipped": ("target_weights", "weight"),
        "lower_liquidity": ("liquidity_amount", "CNY"),
        "extend_horizon": ("horizon_days", "days"),
        "allow_deposit": ("allowed_types", "product_types"),
        "lower_amount": ("amount", "CNY"),
    }[kind]
    old_value, new_value = getattr(original.request, field), getattr(request, field)
    changes = [
        AllocationFieldChange.model_validate({
            "field": field,
            "before": original.request.model_dump(mode="json")[field],
            "after": request.model_dump(mode="json")[field],
            "delta": Fraction(new_value - old_value)
            if isinstance(new_value, (Fraction, int))
            else None,
            "unit": unit,
        })
    ]
    return AllocationAlternative(
        alternative_id=H({
            "source": H(original.user_input),
            "request": request,
            "projection": projection,
        }),
        kind=kind,
        proposed_request=request,
        projection=projection,
        changes=changes,
        diff=allocation_projection_diff(original.request, request, projection, baseline),
    )


def _clip_weights(context: _Context) -> dict[str, Fraction] | None:
    requested = context.request.target_weights
    if requested is None:
        return None
    bands = {band.sleeve: band for band in context.profile.bands}
    clipped = {str(s): min(bands[s].upper, max(bands[s].lower, requested[s])) for s in SLEEVES}
    remaining = 1 - sum(clipped.values(), ZERO)
    for sleeve in SLEEVES:
        if remaining > 0:
            step = min(remaining, bands[sleeve].upper - clipped[sleeve])
        else:
            step = max(remaining, bands[sleeve].lower - clipped[sleeve])
        clipped[sleeve] += step
        remaining -= step
    return clipped if _weights_valid(clipped, context.profile, context.effective_level) else None


def _liquidity_thresholds(context: _Context, state: BankState) -> list[Fraction]:
    """Enumerate the finitely many greedy liquidity-prefix stop thresholds."""
    largest = _candidate_context(
        context, _request(context, liquidity_amount=context.request.amount), state
    )
    targets = _targets(largest, {str(k): v for k, v in largest.profile.model_weights.items()})
    if targets is None:
        return []
    _, _, trace = _construct(largest, targets)
    amounts: dict[str, int] = {}
    thresholds = {ZERO}
    for step in trace:
        if step["stage"] != "liquidity":
            continue
        product_id = str(step["product_id"])
        increment = step["allocated_cents"]
        if not isinstance(increment, int):
            raise ValueError("ALLOC-SUM")
        amounts[product_id] = amounts.get(product_id, 0) + increment
        liquid = _totals(largest, amounts)["liquid_net_principal"]
        if ZERO <= liquid < context.request.liquidity_amount:
            thresholds.add(liquid)
    return sorted(thresholds, reverse=True)


def _amount_candidates(context: _Context) -> list[Fraction]:
    """Conservative capacity candidates, never a monotonicity or maximality claim."""
    ceiling = min(context.request.amount - CENT, context.budget)
    for sleeve in SLEEVES:
        weight = context.profile.model_weights[sleeve]
        if weight <= 0:
            continue
        capacity = sum(
            (
                Fraction(context.intervals[p.id][1], 100)
                for p in context.candidates
                if SLEEVES[p.risk_level - 1] == sleeve
            ),
            ZERO,
        )
        ceiling = min(ceiling, capacity / weight)
    ceilings = {Fraction(_floor_cents(ceiling), 100)}
    if context.candidates:
        fee = max(p.purchase_fee_rate for p in context.candidates)
        if fee > 0:
            conservative = (context.budget - len(context.candidates) * CENT) / (1 + fee)
            ceilings.add(Fraction(_floor_cents(min(ceiling, conservative)), 100))
    # A small fixed neighbourhood may avoid cent-rounding conflicts; it is not exhaustive.
    return sorted(
        {
            candidate - offset * CENT
            for candidate in ceilings
            for offset in range(5)
            if context.request.liquidity_amount <= candidate - offset * CENT
            and ZERO < candidate - offset * CENT < context.request.amount
        },
        reverse=True,
    )


def preview_allocation_alternatives(
    principal: str, parent_intent_id: str, request_ref: str, state: BankState
) -> AllocationFallbackPreview:
    """Return up to three checked projections without a signature or state mutation."""
    evaluation = evaluate_allocation(principal, parent_intent_id, request_ref, state)
    result = AllocationFallbackPreview(
        source_request_ref=request_ref,
        source_request_hash=None,
        source_errors=list(evaluation.errors),
        failure=evaluation.failure,
        alternatives=[],
        binding_constraints=evaluation.failure.unmet_constraints if evaluation.failure else [],
    )
    try:
        original = _context(principal, parent_intent_id, request_ref, state, None)
        result = result.model_copy(update={"source_request_hash": H(original.user_input)})
        if not evaluation.errors:
            return result.model_copy(
                update={
                    "notice": (
                        "The signed request already constructs an allocation; "
                        "no fallback is needed."
                    )
                }
            )
        if set(evaluation.errors) - {
            "ALLOC-BAND",
            "ALLOC-SELECT",
            "ALLOC-SUM",
            "ALLOC-CONC",
            "ALLOC-LIQ",
            "BIC-NOFEASIBLE",
            "BIC-RISK",
        }:
            return result
        if original.request.selection_mode == "explicit_weights":
            baseline = _model(original, state)
            clipped = _clip_weights(original)
            if baseline is not None and clipped is not None and "ALLOC-BAND" in evaluation.errors:
                alternative = _alternative(
                    original,
                    _request(original, target_weights=clipped),
                    state,
                    "weights_clipped",
                    baseline,
                )
                if alternative is not None:
                    result.alternatives.append(alternative)
            return result
        if original.request.selection_mode != "default":
            return result
        if original.request.liquidity_amount > 0:
            for threshold in _liquidity_thresholds(original, state):
                alternative = _alternative(
                    original,
                    _request(original, liquidity_amount=threshold),
                    state,
                    "lower_liquidity",
                )
                if alternative is not None:
                    result.alternatives.append(alternative)
                    break
        horizons = sorted({
            product.min_hold_days
            for product in state.catalog.products
            if original.request.horizon_days < product.min_hold_days <= 365
        })
        if horizons:
            alternative = _alternative(
                original, _request(original, horizon_days=horizons[0]), state, "extend_horizon"
            )
            if alternative is not None:
                result.alternatives.append(alternative)
        if "deposit" not in original.request.allowed_types:
            alternative = _alternative(
                original,
                _request(
                    original, allowed_types=sorted([*original.request.allowed_types, "deposit"])
                ),
                state,
                "allow_deposit",
            )
            if alternative is not None:
                result.alternatives.append(alternative)
        if len(result.alternatives) < 3:
            for amount in _amount_candidates(original):
                alternative = _alternative(
                    original, _request(original, amount=amount), state, "lower_amount"
                )
                if alternative is not None:
                    result.alternatives.append(alternative)
                    break
    except (ValueError, KeyError):
        # Invalid signatures, absent context and bounded-wire overflow never enable fallback.
        return result
    return result
