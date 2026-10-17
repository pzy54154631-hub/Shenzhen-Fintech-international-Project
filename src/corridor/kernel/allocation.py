"""Exact, bounded policy allocation construction and independent witness checks.

The constructor is deliberately greedy. A failure proves only that this bounded
procedure did not construct a portfolio, never general infeasibility.
"""

from dataclasses import dataclass
from datetime import timedelta
from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.crypto.sign import ALLOCATION_POLICY, INPUT, RISK, verify
from corridor.kernel.investment import _valid_catalog, price_product, risk_score, suitability
from corridor.schemas.allocation import (
    MAX_RATIONAL_BITS,
    SLEEVES,
    AllocationCheck,
    AllocationFailure,
    AllocationPolicy,
    AllocationProfile,
    AllocationRequest,
    BestInterestAllocationCertificate,
)
from corridor.schemas.bank import BankAction, BankCertificate, UserInput
from corridor.schemas.domain import Product, RiskAssessment
from corridor.schemas.money import ceil_minor
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time
from corridor.stores.bank import available

ZERO = Fraction()
CENT = Fraction(1, 100)


@dataclass(frozen=True)
class AllocationEvaluation:
    request: AllocationRequest | None
    certificate: BestInterestAllocationCertificate | None
    failure: AllocationFailure | None
    errors: tuple[str, ...]


@dataclass(frozen=True)
class _Context:
    principal: str
    parent_intent_id: str
    request: AllocationRequest
    user_input: UserInput
    policy: AllocationPolicy
    profile: AllocationProfile
    risk: RiskAssessment
    effective_level: int
    budget: Fraction
    candidates: tuple[Product, ...]
    exclusions: tuple[dict[str, object], ...]
    intervals: dict[str, tuple[int, int]]
    base_hash: str


def _floor_cents(amount: Fraction) -> int:
    return (amount * 100).numerator // (amount * 100).denominator


def _signed_input(
    principal: str, parent: str, ref: str, state: BankState, *, historical: bool = False
) -> tuple[UserInput, AllocationRequest]:
    value = state.user_inputs.get(ref)
    customer = state.customers.get(principal)
    if (
        value is None
        or customer is None
        or value.principal != principal
        or value.slot != "allocation"
        or value.scope_id != parent
        or value.submitted_at > state.now
        or (not historical and any(v.supersedes == value.id for v in state.user_inputs.values()))
        or not verify(customer.device_pubkey, INPUT, value, value.sig)
    ):
        raise ValueError("BIC-PREFERENCE")
    try:
        request = AllocationRequest.model_validate(value.value)
    except ValueError as exc:
        raise ValueError("BIC-PREFERENCE") from exc
    account = state.accounts.get(request.source_account_ref)
    if (
        account is None
        or account.owner != principal
        or account.kind != "current"
        or account.status != "active"
        or account.ccy != "CNY"
    ):
        raise ValueError("BIC-PREFERENCE")
    return value, request


def get_allocation_request(
    principal: str, parent_intent_id: str, request_ref: str, state: BankState
) -> AllocationRequest:
    """Resolve a current device-signed request in its exact parent scope."""
    return _signed_input(principal, parent_intent_id, request_ref, state)[1]


def _risk(principal: str, state: BankState) -> RiskAssessment:
    customer = state.customers.get(principal)
    risk = state.risk_assessments.get(customer.risk_profile_ref or "") if customer else None
    if risk is None:
        raise ValueError("BIC-RISK")
    score, level = risk_score(risk.answers, state)
    if (
        risk.owner != principal
        or not verify(state.roots.risk_pubkey, RISK, risk, risk.sig)
        or not risk.issued_at <= state.now < risk.expires_at
        or parse_time(risk.expires_at) > parse_time(risk.issued_at) + timedelta(days=365)
        or parse_time(state.now)
        >= parse_time(risk.issued_at) + timedelta(days=min(365, state.policy.risk_valid_days))
        or risk.answers_hash != H(risk.answers)
        or risk.score != score
        or risk.level != level
    ):
        raise ValueError("BIC-RISK")
    return risk


def _weights_valid(weights: dict[str, Fraction], profile: AllocationProfile, level: int) -> bool:
    return (
        set(weights) == set(SLEEVES)
        and sum(weights.values(), ZERO) == 1
        and all(0 <= value <= 1 for value in weights.values())
        and all(weights[sleeve] == 0 for sleeve in SLEEVES[level:])
        and all(band.lower <= weights[band.sleeve] <= band.upper for band in profile.bands)
        and all(
            group.lower <= sum((weights[s] for s in group.sleeves), ZERO) <= group.upper
            for group in profile.group_bounds
        )
    )


def _policy(request: AllocationRequest, state: BankState) -> AllocationPolicy:
    if len(state.allocation_policies) != 1:
        raise ValueError("ALLOC-POLICY")
    stored = next(iter(state.allocation_policies.values()))
    try:
        policy = AllocationPolicy.model_validate(stored.model_dump(mode="python"))
    except ValueError as exc:
        raise ValueError("ALLOC-POLICY") from exc
    if (
        request.allocation_policy_ref != policy.id
        or state.allocation_policies.get(policy.id) != stored
        or not verify(state.roots.bank_pubkey, ALLOCATION_POLICY, policy, policy.sig)
        or not policy.issued_at <= state.now < policy.valid_until
        or policy.catalog_id != state.catalog.id
        or policy.catalog_version != state.catalog.version
        or len(state.catalog.products) > policy.max_products
        or any(
            not _weights_valid(
                {str(k): v for k, v in profile.model_weights.items()}, profile, level
            )
            for level, profile in ((int(key[1:]), value) for key, value in policy.profiles.items())
        )
    ):
        raise ValueError("ALLOC-POLICY")
    return policy


def _context(
    principal: str,
    parent: str,
    request_ref: str,
    state: BankState,
    budget_override: Fraction | None,
) -> _Context:
    value, request = _signed_input(principal, parent, request_ref, state)
    return _context_for_request(principal, parent, value, request, state, budget_override)


def _context_for_request(
    principal: str,
    parent: str,
    value: UserInput,
    request: AllocationRequest,
    state: BankState,
    budget_override: Fraction | None = None,
) -> _Context:
    """Derive economic facts after input verification; also used by unsigned previews.

    This private helper never verifies or creates authority. Executable callers must
    pass through _signed_input; preview callers must not issue a certificate.
    """
    if (
        not _valid_catalog(state)
        or any(
            max(abs(value.numerator).bit_length(), value.denominator.bit_length())
            > MAX_RATIONAL_BITS
            for product in state.catalog.products
            for value in (
                product.min_amount,
                product.max_amount or ZERO,
                product.expected_annual_rate,
                product.purchase_fee_rate,
                product.annual_fee_rate,
                product.redemption_fee_rate,
            )
        )
        or any(p.min_hold_days + p.redeem_delay_days > 2**31 - 1 for p in state.catalog.products)
    ):
        raise ValueError("BIC-CATALOG")
    risk = _risk(principal, state)
    effective_level = suitability(
        principal, state, risk, horizon_days=request.horizon_days, objective=request.objective
    ).effective_level
    policy = _policy(request, state)
    profile = next(value for key, value in policy.profiles.items() if key == f"C{effective_level}")
    account = state.accounts[request.source_account_ref]
    budget = available(state, account.id) - account.floor
    if budget_override is not None:
        if not isinstance(budget_override, Fraction) or (budget_override * 100).denominator != 1:
            raise ValueError("ALLOC-SUM")
        budget = budget_override
    if (
        budget < 0
        or max(abs(budget.numerator).bit_length(), budget.denominator.bit_length())
        > MAX_RATIONAL_BITS
    ):
        raise ValueError("BAL-AVAILABLE")
    intervals: dict[str, tuple[int, int]] = {}
    candidates: list[Product] = []
    exclusions: list[dict[str, object]] = []
    for product in sorted(state.catalog.products, key=lambda p: p.id):
        minimum = max(CENT, ceil_minor(product.min_amount))
        maximum = min(request.amount, request.amount * policy.concentration_cap)
        if product.max_amount is not None:
            maximum = min(maximum, product.max_amount)
        upper_cents = _floor_cents(maximum)
        checks = (
            (product.purchase_open, "purchase_closed"),
            (principal in product.eligible_customers, "customer_ineligible"),
            (product.risk_level <= effective_level, "risk"),
            (product.type in request.allowed_types, "product_type"),
            (product.min_hold_days <= request.horizon_days, "holding_period"),
            (minimum <= request.amount, "minimum_amount"),
            (minimum <= request.amount * policy.concentration_cap, "concentration"),
            (product.max_amount is None or minimum <= product.max_amount, "maximum_amount"),
            (
                minimum + ceil_minor(minimum * product.purchase_fee_rate) <= budget,
                "available_balance",
            ),
        )
        reasons = sorted(reason for valid, reason in checks if not valid)
        if int(minimum * 100) > upper_cents and not reasons:
            reasons.append("minimum_amount")
        if reasons:
            exclusions.append({"product_id": product.id, "reason_codes": reasons})
        else:
            candidates.append(product)
            intervals[product.id] = (int(minimum * 100), upper_cents)
    base_hash = H({
        "principal": principal,
        "parent_intent_id": parent,
        "source_account_ref": account.id,
        "amount": request.amount,
        "horizon_days": request.horizon_days,
        "liquidity_days": request.liquidity_days,
        "liquidity_amount": request.liquidity_amount,
        "allowed_types": sorted(set(request.allowed_types)),
        "objective": request.objective,
        "policy_hash": H(policy),
        "catalog_hash": H(state.catalog),
        "risk_assessment_hash": H(risk),
        "effective_risk_level": effective_level,
        "account": account,
        "initial_budget": budget,
    })
    return _Context(
        principal,
        parent,
        request,
        value,
        policy,
        profile,
        risk,
        effective_level,
        budget,
        tuple(candidates),
        tuple(exclusions),
        intervals,
        base_hash,
    )


def _scalar(product: Product, request: AllocationRequest) -> Fraction:
    row = price_product(product, request.amount, request.horizon_days)
    if request.objective == "net_return":
        return -row.expected_net
    if request.objective == "total_fee":
        return row.total_fee
    return Fraction(row.access_days)


def _ordered(context: _Context) -> list[Product]:
    return sorted(context.candidates, key=lambda p: (_scalar(p, context.request), p.id))


def _liquid(product: Product, amount: Fraction) -> Fraction:
    return (
        amount
        - ceil_minor(amount * product.annual_fee_rate * product.min_hold_days / 365)
        - ceil_minor(amount * product.redemption_fee_rate)
    )


def _totals(context: _Context, amounts: dict[str, int]) -> dict[str, Fraction]:
    principal = buy = fees = projected = liquid = ZERO
    for product in context.candidates:
        amount = Fraction(amounts.get(product.id, 0), 100)
        if amount <= 0:
            continue
        row = price_product(product, amount, context.request.horizon_days)
        principal += amount
        buy += row.fee_buy
        fees += row.total_fee
        projected += row.expected_net
        if row.access_days <= context.request.liquidity_days:
            liquid += _liquid(product, amount)
    return {
        "principal": principal,
        "fee_buy": buy,
        "total_debit": principal + buy,
        "projected_fees": fees,
        "projected_net": projected,
        "liquid_net_principal": liquid,
    }


def _checks(context: _Context, amounts: dict[str, int]) -> list[AllocationCheck]:
    request = context.request
    totals = _totals(context, amounts)
    checks: list[AllocationCheck] = []

    def add(
        kind: str, lhs: Fraction, comparator: str, rhs: Fraction, subject: str | None = None
    ) -> None:
        satisfied = (
            lhs == rhs if comparator == "=" else lhs <= rhs if comparator == "<=" else lhs >= rhs
        )
        checks.append(
            AllocationCheck.model_validate({
                "constraint_id": kind,
                "lhs": lhs,
                "comparator": comparator,
                "rhs": rhs,
                "satisfied": satisfied,
                "subject_ref": subject,
            })
        )

    add(
        "principal_sum",
        sum((Fraction(v, 100) for v in amounts.values()), ZERO),
        "=",
        request.amount,
    )
    add("total_debit", totals["total_debit"], "<=", context.budget)
    add("liquidity", totals["liquid_net_principal"], ">=", request.liquidity_amount)
    sleeve_amounts = {sleeve: ZERO for sleeve in SLEEVES}
    for product in context.candidates:
        amount = Fraction(amounts.get(product.id, 0), 100)
        sleeve_amounts[SLEEVES[product.risk_level - 1]] += amount
        if amount <= 0:
            continue
        lower, upper = context.intervals[product.id]
        add("product_minimum", amount, ">=", Fraction(lower, 100), product.id)
        add("product_maximum", amount, "<=", Fraction(upper, 100), product.id)
        add(
            "concentration",
            amount,
            "<=",
            request.amount * context.policy.concentration_cap,
            product.id,
        )
        add("nonnegative_liquid_principal", _liquid(product, amount), ">=", ZERO, product.id)
    for band in context.profile.bands:
        add(
            "sleeve_lower",
            sleeve_amounts[band.sleeve] / request.amount,
            ">=",
            band.lower,
            band.sleeve,
        )
        add(
            "sleeve_upper",
            sleeve_amounts[band.sleeve] / request.amount,
            "<=",
            band.upper,
            band.sleeve,
        )
    for group in context.profile.group_bounds:
        weight = sum((sleeve_amounts[s] for s in group.sleeves), ZERO) / request.amount
        subject = "_".join(sorted(group.sleeves))
        add("group_lower", weight, ">=", group.lower, subject)
        add("group_upper", weight, "<=", group.upper, subject)
    return sorted(checks, key=lambda item: (item.constraint_id, item.subject_ref or ""))


def _constraint_errors(checks: list[AllocationCheck]) -> list[str]:
    rules = {
        "principal_sum": "ALLOC-SUM",
        "total_debit": "ALLOC-SUM",
        "product_minimum": "ALLOC-SUM",
        "product_maximum": "ALLOC-SUM",
        "concentration": "ALLOC-CONC",
        "sleeve_lower": "ALLOC-BAND",
        "sleeve_upper": "ALLOC-BAND",
        "group_lower": "ALLOC-BAND",
        "group_upper": "ALLOC-BAND",
        "liquidity": "ALLOC-LIQ",
        "nonnegative_liquid_principal": "ALLOC-LIQ",
    }
    return sorted({rules[item.constraint_id] for item in checks if not item.satisfied})


def _targets(context: _Context, weights: dict[str, Fraction]) -> dict[str, int] | None:
    amount = context.request.amount
    targets: dict[str, int] = {s: _floor_cents(amount * weights[s]) for s in SLEEVES}
    remaining = int(amount * 100) - sum(targets.values())

    def allowed(values: dict[str, int], *, lower: bool = False) -> bool:
        fractions = {s: Fraction(v, 100) / amount for s, v in values.items()}
        return all(
            (not lower or fractions[b.sleeve] >= b.lower) and fractions[b.sleeve] <= b.upper
            for b in context.profile.bands
        ) and all(
            (not lower or sum((fractions[s] for s in group.sleeves), ZERO) >= group.lower)
            and sum((fractions[s] for s in group.sleeves), ZERO) <= group.upper
            for group in context.profile.group_bounds
        )

    while remaining:
        changed = False
        for sleeve in SLEEVES:
            trial = {**targets, sleeve: targets[sleeve] + 1}
            if weights[sleeve] > 0 and allowed(trial):
                targets = trial
                remaining -= 1
                changed = True
                if not remaining:
                    break
        if not changed:
            return None
    return targets if allowed(targets, lower=True) else None


def _construct(
    context: _Context, targets: dict[str, int]
) -> tuple[dict[str, int], dict[str, str], list[dict[str, object]]]:
    amounts: dict[str, int] = {}
    reasons: dict[str, str] = {}
    trace: list[dict[str, object]] = []
    by_id = {p.id: p for p in context.candidates}

    def add(product: Product, reason: str) -> None:
        current = amounts.get(product.id, 0)
        sleeve = SLEEVES[product.risk_level - 1]
        used = sum(
            value for key, value in amounts.items() if by_id[key].risk_level == product.risk_level
        )
        lower, upper = context.intervals[product.id]
        high = min(
            upper - current,
            targets[sleeve] - used,
            int(context.request.amount * 100) - sum(amounts.values()),
        )
        low = 0
        fixed = sum(
            (
                Fraction(v, 100) + ceil_minor(Fraction(v, 100) * by_id[k].purchase_fee_rate)
                for k, v in amounts.items()
                if k != product.id
            ),
            ZERO,
        )
        while low < high:
            middle = (low + high + 1) // 2
            total = Fraction(current + middle, 100)
            if fixed + total + ceil_minor(total * product.purchase_fee_rate) <= context.budget:
                low = middle
            else:
                high = middle - 1
        if low > 0 and current + low >= lower:
            amounts[product.id] = current + low
            reasons.setdefault(product.id, reason)
            skipped = None
        else:
            low = 0
            skipped = (
                "product_capacity"
                if upper <= current
                else "sleeve_capacity"
                if targets[sleeve] <= used
                else "minimum_amount"
                if current + high < lower
                else "available_balance"
            )
        trace.append({
            "product_id": product.id,
            "stage": "liquidity" if reason == "liquidity_requirement" else "fill",
            "allocated_cents": low,
            "skipped_reason": skipped,
        })

    ordered = _ordered(context)
    for product in ordered:
        if _totals(context, amounts)["liquid_net_principal"] >= context.request.liquidity_amount:
            break
        if product.min_hold_days + product.redeem_delay_days <= context.request.liquidity_days:
            add(product, "liquidity_requirement")
    for sleeve in SLEEVES:
        ranked = [p for p in ordered if SLEEVES[p.risk_level - 1] == sleeve]
        for index, product in enumerate(ranked):
            add(product, "objective_rank" if index == 0 else "sleeve_fill")
    return amounts, reasons, trace


def _failure(
    context: _Context,
    state: BankState,
    stage: str,
    reason: str,
    amounts: dict[str, int] | None = None,
    trace: list[dict[str, object]] | None = None,
) -> AllocationFailure:
    amounts = amounts or {}
    return AllocationFailure.model_validate({
        "input_hashes": {
            "request": H(context.user_input),
            "policy": H(context.policy),
            "catalog": H(state.catalog),
            "risk_assessment": H(context.risk),
        },
        "candidate_ids": sorted(p.id for p in context.candidates),
        "exclusions": list(context.exclusions),
        "stage": stage,
        "reason_codes": [reason],
        "residual_cents": max(0, int(context.request.amount * 100) - sum(amounts.values())),
        "unmet_constraints": [item for item in _checks(context, amounts) if not item.satisfied],
        "trace": trace or [],
    })


def _projection(
    context: _Context,
    targets: dict[str, int],
    amounts: dict[str, int],
    reasons: dict[str, str],
) -> dict[str, object]:
    """Economic rows only: no signed request binding or executable witness."""
    request = context.request
    sleeves: list[dict[str, object]] = []
    items: list[dict[str, object]] = []
    for sleeve in SLEEVES:
        ranked = [p for p in _ordered(context) if SLEEVES[p.risk_level - 1] == sleeve]
        rows = []
        for index, product in enumerate(ranked, 1):
            row = price_product(product, request.amount, request.horizon_days)
            rows.append({
                **row.model_dump(mode="python"),
                "rank": index,
                "gap": _scalar(product, request) - _scalar(ranked[0], request),
                "reference_amount": request.amount,
                "comparison_only": True,
            })
        sleeves.append({
            "sleeve": sleeve,
            "model_weight": context.profile.model_weights[sleeve],
            "target_cents": targets[sleeve],
            "actual_cents": sum(amounts.get(p.id, 0) for p in ranked),
            "candidate_ids": sorted(p.id for p in ranked),
            "ranking_rows": rows,
        })
    for product in context.candidates:
        amount = Fraction(amounts.get(product.id, 0), 100)
        if amount <= 0:
            continue
        row = price_product(product, amount, request.horizon_days)
        items.append({
            "product_id": product.id,
            "sleeve": SLEEVES[product.risk_level - 1],
            "principal": amount,
            "weight": amount / request.amount,
            "fee_buy": row.fee_buy,
            "fee_hold": row.fee_hold,
            "fee_sell": row.fee_sell,
            "expected_net": row.expected_net,
            "access_days": row.access_days,
            "liquid_net_principal": _liquid(product, amount)
            if row.access_days <= request.liquidity_days
            else ZERO,
            "selection_reason": reasons[product.id],
        })
    totals = _totals(context, amounts)
    return {
        "candidate_ids": sorted(p.id for p in context.candidates),
        "exclusions": list(context.exclusions),
        "sleeves": sleeves,
        "allocation": items,
        "totals": totals,
        "checks": _checks(context, amounts),
    }


def _certificate(
    context: _Context,
    state: BankState,
    targets: dict[str, int],
    amounts: dict[str, int],
    reasons: dict[str, str],
    model: BestInterestAllocationCertificate | None = None,
) -> BestInterestAllocationCertificate:
    request = context.request
    totals = _totals(context, amounts)
    deviations: dict[str, object] | None = None
    if model is not None:
        original = {item.product_id: item.principal for item in model.allocation}
        ids = sorted(set(original) | set(amounts))
        actual_sleeve_cents = {
            s: sum(
                amounts.get(p.id, 0) for p in context.candidates if SLEEVES[p.risk_level - 1] == s
            )
            for s in SLEEVES
        }
        deviations = {
            "products": [
                {
                    "product_id": key,
                    "principal_delta": Fraction(amounts.get(key, 0), 100) - original.get(key, ZERO),
                    "weight_delta": (Fraction(amounts.get(key, 0), 100) - original.get(key, ZERO))
                    / request.amount,
                }
                for key in ids
            ],
            "sleeves": [
                {
                    "sleeve": sleeve,
                    "principal_delta": Fraction(
                        actual_sleeve_cents[sleeve] - model.sleeves[i].actual_cents, 100
                    ),
                    "weight_delta": Fraction(
                        actual_sleeve_cents[sleeve] - model.sleeves[i].actual_cents, 100
                    )
                    / request.amount,
                }
                for i, sleeve in enumerate(SLEEVES)
            ],
            "projected_fees_delta": totals["projected_fees"] - model.totals.projected_fees,
            "projected_net_delta": totals["projected_net"] - model.totals.projected_net,
            "liquid_net_principal_delta": totals["liquid_net_principal"]
            - model.totals.liquid_net_principal,
            "total_debit_delta": totals["total_debit"] - model.totals.total_debit,
        }
    facts = [
        {"template_id": "complete_catalogue", "fact_refs": ["candidate_ids", "exclusions"]},
        {"template_id": "reference_ranking", "fact_refs": ["sleeves"]},
        {"template_id": "policy_constraints", "fact_refs": ["checks"]},
        {"template_id": "heuristic_allocation", "fact_refs": ["allocation"]},
        {"template_id": "liquidity_requirement", "fact_refs": ["totals.liquid_net_principal"]},
    ]
    if model is not None:
        facts.append({
            "template_id": "model_deviation",
            "fact_refs": ["model_biac_hash", "deviations"],
        })
    return BestInterestAllocationCertificate.model_validate({
        "schema_version": "biac-v1",
        "selector_version": context.policy.selector_version,
        "request_hash": H(context.user_input),
        "policy_hash": H(context.policy),
        "catalog_hash": H(state.catalog),
        "risk_assessment_hash": H(context.risk),
        "principal": context.principal,
        "source_account_ref": request.source_account_ref,
        "base_context_hash": context.base_hash,
        **_projection(context, targets, amounts, reasons),
        "selection_mode": request.selection_mode,
        "model_biac_hash": H(model) if model is not None else None,
        "deviations": deviations,
        "fact_reasons": sorted(facts, key=lambda f: f["template_id"]),
    })


def _default(context: _Context, state: BankState) -> AllocationEvaluation:
    if not context.candidates:
        return AllocationEvaluation(
            context.request,
            None,
            _failure(context, state, "eligibility", "no_candidates"),
            ("BIC-NOFEASIBLE",),
        )
    targets = _targets(context, {str(k): v for k, v in context.profile.model_weights.items()})
    if targets is None:
        return AllocationEvaluation(
            context.request,
            None,
            _failure(context, state, "rounding", "target_rounding_conflict"),
            ("ALLOC-SELECT",),
        )
    amounts, reasons, trace = _construct(context, targets)
    errors = _constraint_errors(_checks(context, amounts))
    if errors:
        return AllocationEvaluation(
            context.request,
            None,
            _failure(context, state, "fill", "constraint_violation", amounts, trace),
            tuple(["ALLOC-SELECT", *errors]),
        )
    return AllocationEvaluation(
        context.request, _certificate(context, state, targets, amounts, reasons), None, ()
    )


def _evaluate_allocation(
    principal: str,
    parent_intent_id: str,
    request_ref: str,
    state: BankState,
    *,
    budget_override: Fraction | None = None,
) -> AllocationEvaluation:
    """Reconstruct only from trusted state; budget overrides belong to parent-plan verification."""
    try:
        context = _context(principal, parent_intent_id, request_ref, state, budget_override)
    except ValueError as exc:
        rule = str(exc)
        if rule not in {
            "BIC-PREFERENCE",
            "BIC-CATALOG",
            "BIC-RISK",
            "ALLOC-POLICY",
            "ALLOC-SUM",
            "BAL-AVAILABLE",
        }:
            rule = "ALLOC-SUM"
        return AllocationEvaluation(None, None, None, (rule,))
    request = context.request
    if request.selection_mode == "default":
        return _default(context, state)
    model: BestInterestAllocationCertificate | None = None
    for value in state.user_inputs.values():
        if (
            value.scope_id != parent_intent_id
            or value.principal != principal
            or value.slot != "allocation"
        ):
            continue
        try:
            old, old_request = _signed_input(
                principal, parent_intent_id, value.id, state, historical=True
            )
        except ValueError:
            continue
        if old_request.selection_mode != "default":
            continue
        try:
            old_context = _context_for_request(
                principal, parent_intent_id, old, old_request, state, budget_override
            )
        except ValueError:
            continue
        if old_context.base_hash != context.base_hash:
            continue
        candidate = _default(old_context, state).certificate
        if candidate is not None and H(candidate) == request.model_biac_hash:
            model = candidate
            break
    if model is None:
        return AllocationEvaluation(
            request,
            None,
            _failure(context, state, "validation", "constraint_violation"),
            ("ALLOC-SELECT",),
        )
    if request.selection_mode == "explicit_weights":
        weights = {str(k): v for k, v in (request.target_weights or {}).items()}
        if not _weights_valid(weights, context.profile, context.effective_level):
            errors = ["ALLOC-BAND"]
            if any(weights.get(s, ZERO) > 0 for s in SLEEVES[context.effective_level :]):
                errors.append("BIC-RISK")
            return AllocationEvaluation(
                request,
                None,
                _failure(context, state, "validation", "constraint_violation"),
                tuple(errors),
            )
        targets = _targets(context, weights)
        if targets is None:
            return AllocationEvaluation(
                request,
                None,
                _failure(context, state, "rounding", "target_rounding_conflict"),
                ("ALLOC-SELECT",),
            )
        amounts, reasons, trace = _construct(context, targets)
    else:
        trace = []
        amounts = {item.product_id: int(item.principal * 100) for item in request.items or []}
        missing = set(amounts) - {p.id for p in context.candidates}
        if missing:
            errors = ["BIC-COMPLETE"]
            if any(
                p.id in missing and p.risk_level > context.effective_level
                for p in state.catalog.products
            ):
                errors.append("BIC-RISK")
            return AllocationEvaluation(
                request,
                None,
                _failure(context, state, "validation", "constraint_violation", amounts),
                tuple(errors),
            )
        reasons = dict.fromkeys(amounts, "explicit_item")
        targets = {
            s: sum(
                amounts.get(p.id, 0) for p in context.candidates if SLEEVES[p.risk_level - 1] == s
            )
            for s in SLEEVES
        }
    errors = _constraint_errors(_checks(context, amounts))
    if errors:
        return AllocationEvaluation(
            request,
            None,
            _failure(context, state, "validation", "constraint_violation", amounts, trace),
            tuple(["ALLOC-SELECT", *errors]),
        )
    return AllocationEvaluation(
        request, _certificate(context, state, targets, amounts, reasons, model), None, ()
    )


def evaluate_allocation(
    principal: str,
    parent_intent_id: str,
    request_ref: str,
    state: BankState,
    *,
    budget_override: Fraction | None = None,
) -> AllocationEvaluation:
    """Return a controlled refusal if exact arithmetic exceeds the bounded output wire."""
    try:
        return _evaluate_allocation(
            principal, parent_intent_id, request_ref, state, budget_override=budget_override
        )
    except ValueError:
        return AllocationEvaluation(None, None, None, ("ALLOC-SUM",))


def build_allocation(
    principal: str,
    parent_intent_id: str,
    request_ref: str,
    state: BankState,
    *,
    budget_override: Fraction | None = None,
) -> BestInterestAllocationCertificate:
    evaluation = evaluate_allocation(
        principal, parent_intent_id, request_ref, state, budget_override=budget_override
    )
    if evaluation.certificate is None or evaluation.errors:
        raise ValueError(evaluation.errors[0] if evaluation.errors else "ALLOC-SELECT")
    return evaluation.certificate


def verify_allocation(
    actual: BestInterestAllocationCertificate | None,
    evaluation: AllocationEvaluation,
    state: BankState,
) -> list[str]:
    """Check the supplied vector independently before enforcing exact canonical equality."""
    errors = list(evaluation.errors)
    expected, request = evaluation.certificate, evaluation.request
    if expected is None or request is None:
        return errors
    if actual is None:
        return [*errors, "BIC-COMPLETE"]
    if actual.catalog_hash != expected.catalog_hash:
        errors.append("BIC-CATALOG")
    if actual.policy_hash != expected.policy_hash:
        errors.append("ALLOC-POLICY")
    if actual.risk_assessment_hash != expected.risk_assessment_hash:
        errors.append("BIC-RISK")
    if (
        actual.request_hash != expected.request_hash
        or actual.principal != expected.principal
        or actual.source_account_ref != expected.source_account_ref
        or actual.base_context_hash != expected.base_context_hash
    ):
        errors.append("BIC-PREFERENCE")
    if (
        actual.candidate_ids != expected.candidate_ids
        or actual.exclusions != expected.exclusions
        or [s.candidate_ids for s in actual.sleeves] != [s.candidate_ids for s in expected.sleeves]
        or [s.sleeve for s in actual.sleeves] != [s.sleeve for s in expected.sleeves]
        or [sorted(row.product_id for row in s.ranking_rows) for s in actual.sleeves]
        != [s.candidate_ids for s in expected.sleeves]
        or len({item.product_id for item in actual.allocation}) != len(actual.allocation)
        or any(item.product_id not in expected.candidate_ids for item in actual.allocation)
    ):
        errors.append("BIC-COMPLETE")
    if [s.ranking_rows for s in actual.sleeves] != [s.ranking_rows for s in expected.sleeves]:
        errors.append("BIC-SCORE")
    value = next((v for v in state.user_inputs.values() if H(v) == expected.request_hash), None)
    if value is None:
        return [*errors, "BIC-PREFERENCE"]
    try:
        # The expected debit check carries the trusted initial budget during parent dispatch.
        budget = next(c.rhs for c in expected.checks if c.constraint_id == "total_debit")
        context = _context(expected.principal, value.scope_id, value.id, state, budget)
    except (ValueError, StopIteration):
        return [*errors, "ALLOC-SELECT"]
    claimed_targets = {
        s.sleeve: Fraction(s.target_cents, 100) / request.amount for s in actual.sleeves
    }
    if (
        set(claimed_targets) != set(SLEEVES)
        or any(
            not band.lower <= claimed_targets.get(band.sleeve, ZERO) <= band.upper
            for band in context.profile.bands
        )
        or any(
            not group.lower
            <= sum((claimed_targets.get(s, ZERO) for s in group.sleeves), ZERO)
            <= group.upper
            for group in context.profile.group_bounds
        )
    ):
        errors.append("ALLOC-BAND")
    amounts: dict[str, int] = {}
    for item in actual.allocation:
        if item.principal <= 0 or (item.principal * 100).denominator != 1:
            errors.append("ALLOC-SUM")
        amounts[item.product_id] = amounts.get(item.product_id, 0) + int(item.principal * 100)
    checks = _checks(context, amounts)
    errors.extend(_constraint_errors(checks))
    by_id = {p.id: p for p in state.catalog.products}
    for item in actual.allocation:
        product = by_id.get(item.product_id)
        if product is None:
            continue
        if product.risk_level > context.effective_level:
            errors.append("BIC-RISK")
        if item.principal <= 0:
            continue
        row = price_product(product, item.principal, request.horizon_days)
        net = (
            _liquid(product, item.principal) if row.access_days <= request.liquidity_days else ZERO
        )
        if (item.fee_buy, item.fee_hold, item.fee_sell, item.expected_net) != (
            row.fee_buy,
            row.fee_hold,
            row.fee_sell,
            row.expected_net,
        ):
            errors.extend(["BIC-SCORE", "ALLOC-SUM"])
        if item.access_days != row.access_days or item.liquid_net_principal != net:
            errors.append("ALLOC-LIQ")
        if (
            item.weight != item.principal / request.amount
            or item.sleeve != SLEEVES[product.risk_level - 1]
        ):
            errors.extend(["BIC-SCORE", "ALLOC-BAND"])
    totals = _totals(context, amounts)
    if any(getattr(actual.totals, key) != value for key, value in totals.items()):
        errors.append("ALLOC-SUM")
        if (
            actual.totals.projected_fees != totals["projected_fees"]
            or actual.totals.projected_net != totals["projected_net"]
        ):
            errors.append("BIC-SCORE")
        if actual.totals.liquid_net_principal != totals["liquid_net_principal"]:
            errors.append("ALLOC-LIQ")
    if actual != expected:
        errors.append("ALLOC-SELECT")
    return list(dict.fromkeys(errors))


def allocation_errors(action: BankAction, cert: BankCertificate, state: BankState) -> list[str]:
    if action.kind == "allocation_compare":
        args = action.args.model_dump(mode="python")
        evaluation = evaluate_allocation(
            action.principal, action.intent_id, str(args["request_ref"]), state
        )
        errors = verify_allocation(cert.allocation, evaluation, state)
        if cert.best_interest is not None:
            errors.append("ALLOC-SELECT")
        return errors
    if action.kind == "purchase_product" and action.args.model_dump().get("allocation_ref"):
        from corridor.kernel.allocation_execution import allocation_purchase_errors

        return allocation_purchase_errors(action, cert, state)
    if action.kind == "purchase_product" and any(
        action.intent_id == item.child_intent_id
        for plan in state.allocation_plans.values()
        for item in plan.items
    ):
        return ["PLAN-SCOPE"]
    return ["ALLOC-SELECT"] if cert.allocation is not None else []
