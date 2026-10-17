"""Independent Topic B arithmetic and signed-effect oracle.

Implemented from DESIGN-WEALTH sections 2-8, ADR-012 and public wire contracts.
No trusted selector, state-store helper or gateway verdict is used. The pure
calculation accepts an unsigned request for comparison fixtures; ``verify_biac``
additionally checks the device-signed request. This is a bounded heuristic
reference, not an optimiser or a proof that a failed construction is impossible.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

from pydantic import ValidationError

from corridor.crypto.jcs import H
from corridor.crypto.sign import ALLOCATION_POLICY, CATALOG, CONTROL, INPUT, RECEIPT, RISK, verify
from corridor.schemas.allocation import (
    AllocationPolicy,
    AllocationProfile,
    AllocationRequest,
    BestInterestAllocationCertificate,
)
from corridor.schemas.bank import BankOrder, BankReceipt, OperationAuthorization, UserInput
from corridor.schemas.domain import Position, Product, RiskAssessment
from corridor.schemas.state import BankState

SLEEVES = ("R1", "R2", "R3", "R4", "R5")
FAILURE_MESSAGE = "No allocation was constructed under this policy and these inputs."


@dataclass
class WealthOracleResult:
    candidate_ids: tuple[str, ...] = ()
    exclusions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    rankings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    allocation: dict[str, Fraction] = field(default_factory=dict)
    totals: dict[str, Fraction] = field(default_factory=dict)
    target_cents: dict[str, int] = field(default_factory=dict)
    selection_reasons: dict[str, str] = field(default_factory=dict)
    violations: tuple[str, ...] = ()
    constructed: bool = False
    message: str = FAILURE_MESSAGE


@dataclass
class WealthExecutionResult:
    status: str
    completed: bool
    allocation: dict[str, Fraction]
    debit: Fraction
    remaining_cash: Fraction
    settled_count: int
    violations: tuple[str, ...]
    projected_net_delta: Fraction | None = None
    projected_fees_delta: Fraction | None = None
    liquidity_shortfall: Fraction = Fraction()
    authorization_checked: bool = True


def ceilcent(value: Fraction) -> Fraction:
    scaled = value * 100
    return Fraction(-(-scaled.numerator // scaled.denominator), 100)


def _floor_cents(value: Fraction) -> int:
    scaled = value * 100
    return scaled.numerator // scaled.denominator


def price(product: Product, amount: Fraction, horizon_days: int) -> dict[str, Fraction | int]:
    """Charge each fee independently; never round the performance benchmark."""
    buy = ceilcent(amount * product.purchase_fee_rate)
    hold = ceilcent(amount * product.annual_fee_rate * horizon_days / 365)
    sell = ceilcent(amount * product.redemption_fee_rate)
    return {
        "fee_buy": buy,
        "fee_hold": hold,
        "fee_sell": sell,
        "total_fee": buy + hold + sell,
        "expected_net": amount * product.expected_annual_rate * horizon_days / 365
        - buy
        - hold
        - sell,
        "access_days": product.min_hold_days + product.redeem_delay_days,
    }


def _liquid(product: Product, amount: Fraction) -> Fraction:
    return (
        amount
        - ceilcent(amount * product.annual_fee_rate * product.min_hold_days / 365)
        - ceilcent(amount * product.redemption_fee_rate)
    )


def available_budget(state: BankState, source: str) -> Fraction:
    """Reconstruct the public latest-event account projection, less its floor."""
    account = state.accounts[source]
    balance = account.opening_balance - account.floor
    latest = {event.intent_key: event for event in state.ledger}
    for event in latest.values():
        if event.event in {"reserved", "unknown", "settled"}:
            if event.debit is not None and event.debit.account_ref == source:
                balance -= event.debit.amount
        if event.event == "settled" and event.credit is not None:
            if event.credit.account_ref == source:
                balance += event.credit.amount
    return balance


def _risk(state: BankState, principal: str) -> RiskAssessment | None:
    customer = state.customers.get(principal)
    if customer is None or customer.risk_profile_ref is None:
        return None
    assessment = state.risk_assessments.get(customer.risk_profile_ref)
    if assessment is None:
        return None
    score = sum(assessment.answers)
    if (
        assessment.owner != principal
        or assessment.score != score
        or assessment.level != max(1, (score + 3) // 4)
        or not assessment.issued_at <= state.now < assessment.expires_at
        or not verify(state.roots.risk_pubkey, RISK, assessment, assessment.sig)
    ):
        return None
    return assessment


def _inputs(
    state: BankState,
    request: AllocationRequest,
    principal: str,
) -> tuple[AllocationPolicy | None, AllocationProfile | None, tuple[str, ...]]:
    errors: set[str] = set()
    try:
        AllocationRequest.model_validate(request.model_dump(mode="python"))
    except (ValidationError, ValueError):
        errors.add("BIC-PREFERENCE")
    account = state.accounts.get(request.source_account_ref)
    if account is None or (
        account.owner != principal
        or account.kind != "current"
        or account.status != "active"
        or account.ccy != "CNY"
    ):
        errors.add("BIC-PREFERENCE")
    catalog = state.catalog
    if (
        not catalog.issued_at <= state.now < catalog.valid_until
        or not verify(state.roots.bank_pubkey, CATALOG, catalog, catalog.sig)
        or len({product.id for product in catalog.products}) != len(catalog.products)
    ):
        errors.add("BIC-CATALOG")
    assessment = _risk(state, principal)
    if assessment is None:
        errors.add("BIC-RISK")
    policy = state.allocation_policies.get(request.allocation_policy_ref)
    if policy is None or len(state.allocation_policies) != 1:
        return policy, None, tuple(sorted(errors | {"ALLOC-POLICY"}))
    try:
        AllocationPolicy.model_validate(policy.model_dump(mode="python"))
    except (ValidationError, ValueError):
        errors.add("ALLOC-POLICY")
    if (
        not verify(state.roots.bank_pubkey, ALLOCATION_POLICY, policy, policy.sig)
        or not policy.issued_at <= state.now < policy.valid_until
        or policy.catalog_id != catalog.id
        or policy.catalog_version != catalog.version
        or len(catalog.products) > policy.max_products
        or policy.concentration_cap != Fraction(1, 2)
        or policy.selector_version != "greedy-sleeves-v1"
    ):
        errors.add("ALLOC-POLICY")
    profile = policy.profiles.get(f"C{assessment.level}") if assessment else None
    if assessment and profile is None:
        errors.add("ALLOC-POLICY")
    return policy, profile, tuple(sorted(errors))


def _bounds(
    product: Product, request: AllocationRequest, policy: AllocationPolicy
) -> tuple[int, int]:
    lower = max(1, _floor_cents(ceilcent(product.min_amount)))
    upper = min(request.amount, request.amount * policy.concentration_cap)
    if product.max_amount is not None:
        upper = min(upper, product.max_amount)
    return lower, _floor_cents(upper)


def _candidates(
    state: BankState,
    request: AllocationRequest,
    policy: AllocationPolicy,
    principal: str,
    budget: Fraction,
) -> tuple[list[Product], dict[str, tuple[str, ...]]]:
    assessment = _risk(state, principal)
    assert assessment is not None
    eligible: list[Product] = []
    excluded: dict[str, tuple[str, ...]] = {}
    for product in sorted(state.catalog.products, key=lambda p: p.id):
        minimum, _ = _bounds(product, request, policy)
        amount = Fraction(minimum, 100)
        reasons = {
            "purchase_closed": not product.purchase_open,
            "customer_ineligible": principal not in product.eligible_customers,
            "risk": product.risk_level > assessment.level,
            "product_type": product.type not in request.allowed_types,
            "holding_period": product.min_hold_days > request.horizon_days,
            "minimum_amount": amount > request.amount,
            "maximum_amount": product.max_amount is not None and amount > product.max_amount,
            "concentration": amount > request.amount * policy.concentration_cap,
            "available_balance": amount + ceilcent(amount * product.purchase_fee_rate) > budget,
        }
        codes = tuple(sorted(name for name, failed in reasons.items() if failed))
        if codes:
            excluded[product.id] = codes
        else:
            eligible.append(product)
    return eligible, excluded


def _score(product: Product, request: AllocationRequest) -> Fraction:
    numbers = price(product, request.amount, request.horizon_days)
    if request.objective == "net_return":
        return -Fraction(numbers["expected_net"])
    if request.objective == "total_fee":
        return Fraction(numbers["total_fee"])
    return Fraction(numbers["access_days"])


def _rankings(
    products: list[Product], request: AllocationRequest
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for level, sleeve in enumerate(SLEEVES, start=1):
        ordered = sorted(
            (p for p in products if p.risk_level == level),
            key=lambda p: (_score(p, request), p.id),
        )
        result[sleeve] = [
            {
                "product_id": p.id,
                **price(p, request.amount, request.horizon_days),
                "rank": i,
                "gap": _score(p, request) - _score(ordered[0], request),
                "reference_amount": request.amount,
                "comparison_only": True,
            }
            for i, p in enumerate(ordered, start=1)
        ]
    return result


def _within_bands(profile: AllocationProfile, weights: Mapping[str, Fraction]) -> bool:
    return all(b.lower <= weights[b.sleeve] <= b.upper for b in profile.bands) and all(
        g.lower <= sum((weights[s] for s in g.sleeves), Fraction()) <= g.upper
        for g in profile.group_bounds
    )


def _targets(
    profile: AllocationProfile,
    request: AllocationRequest,
    weights: Mapping[str, Fraction],
) -> dict[str, int] | None:
    if set(weights) != set(SLEEVES) or sum(weights.values(), Fraction()) != 1:
        return None
    if not _within_bands(profile, weights):
        return None
    cents = _floor_cents(request.amount)
    target = {s: _floor_cents(request.amount * weights[s]) for s in SLEEVES}
    left = cents - sum(target.values())
    while left:
        progress = False
        for sleeve in SLEEVES:
            if weights[sleeve] <= 0:
                continue
            trial = {s: Fraction(n + (s == sleeve), cents) for s, n in target.items()}
            if any(trial[b.sleeve] > b.upper for b in profile.bands) or any(
                sum(trial[s] for s in g.sleeves) > g.upper for g in profile.group_bounds
            ):
                continue
            target[sleeve] += 1
            left -= 1
            progress = True
            if not left:
                break
        if not progress:
            return None
    return (
        target
        if _within_bands(profile, {s: Fraction(n, cents) for s, n in target.items()})
        else None
    )


def _totals(
    products: Mapping[str, Product],
    request: AllocationRequest,
    allocation: Mapping[str, Fraction],
) -> dict[str, Fraction]:
    totals = dict.fromkeys(
        (
            "principal",
            "fee_buy",
            "total_debit",
            "projected_fees",
            "projected_net",
            "liquid_net_principal",
        ),
        Fraction(),
    )
    for product_id, amount in allocation.items():
        if product_id not in products or amount <= 0:
            continue
        product = products[product_id]
        numbers = price(product, amount, request.horizon_days)
        totals["principal"] += amount
        totals["fee_buy"] += Fraction(numbers["fee_buy"])
        totals["projected_fees"] += Fraction(numbers["total_fee"])
        totals["projected_net"] += Fraction(numbers["expected_net"])
        if numbers["access_days"] <= request.liquidity_days:
            totals["liquid_net_principal"] += _liquid(product, amount)
    totals["total_debit"] = totals["principal"] + totals["fee_buy"]
    return totals


def allocation_constraints(
    state: BankState,
    request: AllocationRequest,
    allocation: Mapping[str, Fraction],
    *,
    principal: str,
    budget: Fraction | None = None,
    require_full: bool = True,
) -> tuple[str, ...]:
    """Check actual amounts directly, independently of both selector and BIAC claims.

    A legal execution prefix need not meet the full plan's lower bands or liquidity.
    Upper limits, suitability and product limits still apply to a prefix.
    """
    policy, profile, initial = _inputs(state, request, principal)
    errors = set(initial)
    if initial or policy is None or profile is None:
        return tuple(sorted(errors))
    budget = available_budget(state, request.source_account_ref) if budget is None else budget
    products = {p.id: p for p in state.catalog.products}
    eligible, _ = _candidates(state, request, policy, principal, budget)
    eligible_ids = {p.id for p in eligible}
    sleeve_amounts = dict.fromkeys(SLEEVES, Fraction())
    for product_id, amount in allocation.items():
        if amount <= 0 or (amount * 100).denominator != 1:
            errors.add("ALLOC-SUM")
        product = products.get(product_id)
        if product is None:
            errors.add("BIC-COMPLETE")
            continue
        assessment = _risk(state, principal)
        if assessment and product.risk_level > assessment.level:
            errors.add("BIC-RISK")
        if product_id not in eligible_ids:
            errors.add("BIC-COMPLETE")
        lower, upper = _bounds(product, request, policy)
        if amount * 100 < lower or amount * 100 > upper:
            errors.add("ALLOC-SUM")
        if amount > request.amount * policy.concentration_cap:
            errors.add("ALLOC-CONC")
        if _liquid(product, amount) < 0:
            errors.add("ALLOC-LIQ")
        sleeve_amounts[f"R{product.risk_level}"] += amount
    total = sum(allocation.values(), Fraction())
    if total > request.amount or (require_full and total != request.amount):
        errors.add("ALLOC-SUM")
    weights = {s: amount / request.amount for s, amount in sleeve_amounts.items()}
    for band in profile.bands:
        if weights[band.sleeve] > band.upper or (
            require_full and weights[band.sleeve] < band.lower
        ):
            errors.add("ALLOC-BAND")
    for group in profile.group_bounds:
        weight = sum(weights[s] for s in group.sleeves)
        if weight > group.upper or (require_full and weight < group.lower):
            errors.add("ALLOC-BAND")
    totals = _totals(products, request, allocation)
    if totals["total_debit"] > budget:
        errors.add("BAL-AVAILABLE")
    if require_full and totals["liquid_net_principal"] < request.liquidity_amount:
        errors.add("ALLOC-LIQ")
    return tuple(sorted(errors))


def _construct(
    products: list[Product],
    request: AllocationRequest,
    policy: AllocationPolicy,
    targets: Mapping[str, int],
    budget: Fraction,
) -> tuple[dict[str, Fraction], dict[str, str]]:
    amounts = dict.fromkeys((p.id for p in products), 0)
    by_id = {p.id: p for p in products}
    reasons: dict[str, str] = {}
    ranked = sorted(products, key=lambda p: (_score(p, request), p.id))

    def debit(changed: str, cents: int) -> Fraction:
        return sum(
            (
                Fraction(cents if pid == changed else n, 100)
                + ceilcent(
                    Fraction(cents if pid == changed else n, 100) * by_id[pid].purchase_fee_rate
                )
                for pid, n in amounts.items()
            ),
            Fraction(),
        )

    def fill(product: Product, reason: str) -> None:
        current = amounts[product.id]
        sleeve_used = sum(
            n for pid, n in amounts.items() if by_id[pid].risk_level == product.risk_level
        )
        minimum, maximum = _bounds(product, request, policy)
        ceiling = current + min(
            maximum - current,
            targets[f"R{product.risk_level}"] - sleeve_used,
            _floor_cents(request.amount) - sum(amounts.values()),
        )
        low, high = current, ceiling
        while low < high:
            middle = (low + high + 1) // 2
            if debit(product.id, middle) <= budget:
                low = middle
            else:
                high = middle - 1
        if low > current and low >= minimum:
            amounts[product.id] = low
            reasons.setdefault(product.id, reason)

    for product in ranked:
        liquid = sum(
            (
                _liquid(by_id[pid], Fraction(n, 100))
                for pid, n in amounts.items()
                if by_id[pid].min_hold_days + by_id[pid].redeem_delay_days <= request.liquidity_days
            ),
            Fraction(),
        )
        if liquid >= request.liquidity_amount:
            break
        if product.min_hold_days + product.redeem_delay_days <= request.liquidity_days:
            fill(product, "liquidity_requirement")
    for level in range(1, 6):
        sleeve_products = [p for p in ranked if p.risk_level == level]
        for index, product in enumerate(sleeve_products):
            fill(product, "objective_rank" if index == 0 else "sleeve_fill")
    return {pid: Fraction(n, 100) for pid, n in sorted(amounts.items()) if n}, reasons


def evaluate_allocation(
    state: BankState,
    request: AllocationRequest,
    *,
    principal: str,
    budget: Fraction | None = None,
) -> WealthOracleResult:
    policy, profile, errors = _inputs(state, request, principal)
    result = WealthOracleResult(violations=errors)
    if errors or policy is None or profile is None:
        return result
    budget = available_budget(state, request.source_account_ref) if budget is None else budget
    products, result.exclusions = _candidates(state, request, policy, principal, budget)
    result.candidate_ids = tuple(p.id for p in products)
    result.rankings = _rankings(products, request)
    if not products:
        result.violations = ("BIC-NOFEASIBLE",)
        return result
    # ADR-012 freezes signed model weights; it explicitly supersedes midpoint recomputation.
    weights = (
        request.target_weights
        if request.selection_mode == "explicit_weights"
        else profile.model_weights
    )
    assert weights is not None
    if request.selection_mode != "default":
        default_request = request.model_copy(
            update={
                "selection_mode": "default",
                "target_weights": None,
                "items": None,
                "model_biac_hash": None,
                "reason_code": None,
            }
        )
        if not evaluate_allocation(
            state, default_request, principal=principal, budget=budget
        ).constructed:
            result.violations = ("ALLOC-SELECT",)
            return result
    targets = _targets(profile, request, weights)
    if targets is None:
        result.violations = ("ALLOC-BAND", "ALLOC-SELECT")
        return result
    result.target_cents = targets
    if request.selection_mode == "explicit_items":
        result.allocation = {item.product_id: item.principal for item in request.items or []}
        result.selection_reasons = dict.fromkeys(result.allocation, "explicit_item")
    else:
        result.allocation, result.selection_reasons = _construct(
            products,
            request,
            policy,
            targets,
            budget,
        )
    result.totals = _totals({p.id: p for p in state.catalog.products}, request, result.allocation)
    violations = allocation_constraints(
        state,
        request,
        result.allocation,
        principal=principal,
        budget=budget,
    )
    result.violations = tuple(sorted(set(violations) | ({"ALLOC-SELECT"} if violations else set())))
    result.constructed = not result.violations
    if result.constructed:
        result.message = "Policy-checked heuristic allocation constructed."
    return result


def verify_biac(
    state: BankState,
    request: AllocationRequest,
    biac: BestInterestAllocationCertificate,
    *,
    principal: str,
    budget: Fraction | None = None,
    require_signed_request: bool = True,
    request_scope_id: str | None = None,
) -> tuple[str, ...]:
    """Compare economic witness fields with independently recomputed facts.

    Opaque base-context hashes and gateway fact-template identifiers are not
    asserted to be verified by this arithmetic oracle. Approval/MFA evidence is a
    separate gateway obligation. Certificate constraint booleans are never read.
    """
    expected = evaluate_allocation(state, request, principal=principal, budget=budget)
    errors = set(expected.violations)
    policy = state.allocation_policies.get(request.allocation_policy_ref)
    risk = _risk(state, principal)
    if biac.catalog_hash != H(state.catalog):
        errors.add("BIC-CATALOG")
    if policy is None or biac.policy_hash != H(policy):
        errors.add("ALLOC-POLICY")
    if risk is None or biac.risk_assessment_hash != H(risk):
        errors.add("BIC-RISK")
    if biac.principal != principal or biac.source_account_ref != request.source_account_ref:
        errors.add("BIC-PREFERENCE")
    if biac.selector_version != "greedy-sleeves-v1" or biac.schema_version != "biac-v1":
        errors.add("ALLOC-POLICY")
    matching = [
        i
        for i in state.user_inputs.values()
        if i.slot == "allocation" and i.value == request.model_dump(mode="json")
    ]
    customer = state.customers.get(principal)
    signed = [
        i
        for i in matching
        if customer is not None
        and i.principal == principal
        and i.submitted_at <= state.now
        and (request_scope_id is None or i.scope_id == request_scope_id)
        and verify(customer.device_pubkey, INPUT, i, i.sig)
        and not any(other.supersedes == i.id for other in state.user_inputs.values())
    ]
    if require_signed_request and not any(H(i) == biac.request_hash for i in signed):
        errors.add("BIC-PREFERENCE")
    if tuple(biac.candidate_ids) != expected.candidate_ids:
        errors.add("BIC-COMPLETE")
    exclusions = [(item.product_id, tuple(item.reason_codes)) for item in biac.exclusions]
    if exclusions != sorted(expected.exclusions.items()):
        errors.add("BIC-COMPLETE")
    if [s.sleeve for s in biac.sleeves] != list(SLEEVES):
        errors.add("BIC-COMPLETE")
    products = {p.id: p for p in state.catalog.products}
    allocation: dict[str, Fraction] = {}
    if [item.product_id for item in biac.allocation] != sorted({
        i.product_id for i in biac.allocation
    }):
        errors.add("BIC-COMPLETE")
    for item in biac.allocation:
        allocation[item.product_id] = allocation.get(item.product_id, Fraction()) + item.principal
        product = products.get(item.product_id)
        if product is None:
            errors.add("BIC-COMPLETE")
            continue
        numbers = price(product, item.principal, request.horizon_days)
        if any(
            getattr(item, name) != numbers[name]
            for name in ("fee_buy", "fee_hold", "fee_sell", "expected_net", "access_days")
        ):
            errors.add("BIC-SCORE")
        liquid = (
            _liquid(product, item.principal)
            if numbers["access_days"] <= request.liquidity_days
            else Fraction()
        )
        if item.liquid_net_principal != liquid:
            errors.add("ALLOC-LIQ")
        if (
            item.sleeve != f"R{product.risk_level}"
            or item.weight != item.principal / request.amount
        ):
            errors.add("BIC-SCORE")
        if item.selection_reason != expected.selection_reasons.get(item.product_id):
            errors.add("ALLOC-SELECT")
    if allocation != expected.allocation or biac.selection_mode != request.selection_mode:
        errors.add("ALLOC-SELECT")
    errors.update(
        allocation_constraints(state, request, allocation, principal=principal, budget=budget)
    )
    computed_totals = _totals(products, request, allocation)
    if any(getattr(biac.totals, name) != value for name, value in computed_totals.items()):
        errors.add("BIC-SCORE")
    for sleeve in biac.sleeves:
        rows = expected.rankings.get(sleeve.sleeve, [])
        if sleeve.candidate_ids != sorted(row["product_id"] for row in rows):
            errors.add("BIC-COMPLETE")
        if len(sleeve.ranking_rows) != len(rows) or any(
            any(getattr(given, name) != value for name, value in row.items())
            for given, row in zip(sleeve.ranking_rows, rows, strict=False)
        ):
            errors.add("BIC-SCORE")
        actual = sum(
            (
                a
                for pid, a in allocation.items()
                if pid in products and f"R{products[pid].risk_level}" == sleeve.sleeve
            ),
            Fraction(),
        )
        if sleeve.actual_cents != actual * 100:
            errors.add("BIC-SCORE")
        if sleeve.target_cents != expected.target_cents.get(sleeve.sleeve):
            errors.add("ALLOC-SELECT")
        if policy is not None and risk is not None:
            model_weight = policy.profiles[f"C{risk.level}"].model_weights[sleeve.sleeve]
            if sleeve.model_weight != model_weight:
                errors.add("ALLOC-SELECT")
    if biac.model_biac_hash != request.model_biac_hash:
        errors.add("ALLOC-SELECT")
    if request.selection_mode == "default":
        if biac.deviations is not None:
            errors.add("ALLOC-SELECT")
    else:
        default = evaluate_allocation(
            state,
            request.model_copy(
                update={
                    "selection_mode": "default",
                    "target_weights": None,
                    "items": None,
                    "model_biac_hash": None,
                    "reason_code": None,
                }
            ),
            principal=principal,
            budget=budget,
        )
        if biac.deviations is None or not default.constructed:
            errors.add("ALLOC-SELECT")
        else:
            deviations = biac.deviations
            product_deltas = {
                pid: allocation.get(pid, Fraction()) - default.allocation.get(pid, Fraction())
                for pid in set(allocation) | set(default.allocation)
            }
            # Zero product deltas may be omitted; nonzero changes must all be present.
            declared = {d.product_id: d.principal_delta for d in deviations.products}
            if (
                len(declared) != len(deviations.products)
                or any(
                    declared.get(pid, Fraction()) != delta for pid, delta in product_deltas.items()
                )
                or any(pid not in product_deltas for pid in declared)
            ):
                errors.add("ALLOC-SELECT")
            if any(
                d.weight_delta != d.principal_delta / request.amount for d in deviations.products
            ):
                errors.add("ALLOC-SELECT")
            if [d.sleeve for d in deviations.sleeves] != list(SLEEVES):
                errors.add("ALLOC-SELECT")
            for delta in deviations.sleeves:
                actual_delta = sum(
                    (
                        amount
                        for pid, amount in product_deltas.items()
                        if pid in products and f"R{products[pid].risk_level}" == delta.sleeve
                    ),
                    Fraction(),
                )
                if (
                    delta.principal_delta != actual_delta
                    or delta.weight_delta != actual_delta / request.amount
                ):
                    errors.add("ALLOC-SELECT")
            for name in ("projected_fees", "projected_net", "liquid_net_principal", "total_debit"):
                if (
                    getattr(deviations, name + "_delta")
                    != computed_totals[name] - default.totals[name]
                ):
                    errors.add("ALLOC-SELECT")
    return tuple(sorted(errors))


def _authorized(
    state: BankState,
    receipt: BankReceipt,
    principal: str,
    product: str,
    amount: Fraction,
    debit: Fraction,
    source: str,
    authorizations: Iterable[OperationAuthorization],
    inputs: Iterable[UserInput],
) -> bool:
    customer = state.customers.get(principal)
    if customer is None:
        return False
    evidence = list(inputs)
    for auth in authorizations:
        key = H({"principal": principal, "intent_id": auth.intent_id, "kind": "purchase_product"})
        if (
            key != receipt.intent_key
            or auth.principal != principal
            or auth.allowed_kind != "purchase_product"
            or auth.expires_at <= receipt.executed_at
            or auth.amount_bound is None
            or auth.amount_bound < debit
            or not {source, product} <= set(auth.object_refs)
            or not verify(customer.device_pubkey, CONTROL, auth, auth.sig)
        ):
            continue
        bound = [i for i in evidence if H(i) in auth.input_hashes]
        if len({H(i) for i in bound}) != len(set(auth.input_hashes)):
            continue
        if any(
            i.principal != principal
            or i.scope_id != auth.intent_id
            or i.submitted_at > receipt.executed_at
            or not verify(customer.device_pubkey, INPUT, i, i.sig)
            for i in bound
        ):
            continue
        amounts = [i for i in bound if i.slot == "amount" and isinstance(i.value, dict)]
        if any(
            i.value == {"amount": f"{amount.numerator}/{amount.denominator}", "ccy": "CNY"}
            for i in amounts
        ):
            return True
    return False


def verify_execution(
    state: BankState,
    request: AllocationRequest,
    receipts: Iterable[BankReceipt],
    *,
    principal: str,
    expected_allocation: Mapping[str, Fraction] | None = None,
    authorizations: Iterable[OperationAuthorization] = (),
    inputs: Iterable[UserInput] = (),
    orders: Iterable[BankOrder] = (),
    require_complete: bool = False,
    check_authorization: bool = True,
) -> WealthExecutionResult:
    """Inspect actual signed bank effects using the *initial* public snapshot.

    Missing authority is a failure by default. Pure receipt arithmetic tests may
    explicitly disable it; that fact remains visible in ``authorization_checked``.
    Supplying orders additionally binds each receipt to its exact proposed debit.
    No receipt means no measured return delta, never zero regret.
    """
    errors: set[str] = set()
    allocation: dict[str, Fraction] = {}
    seen: set[str] = set()
    debit = Fraction()
    source_debit = Fraction()
    settled = 0
    has_unknown = False
    products = {p.id: p for p in state.catalog.products}
    orders_by_key = {o.intent_key: o for o in orders}
    auths = list(authorizations)
    signed_inputs = list(inputs)
    for receipt in receipts:
        if not verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig):
            errors.add("BANK-RECEIPT")
            continue
        if receipt.intent_key in seen:
            errors.add("IDEM-DUP")
            continue
        seen.add(receipt.intent_key)
        if receipt.status != "settled":
            has_unknown |= receipt.status in {"unknown", "pending"}
            if receipt.exact_effects:
                errors.add("BANK-RECEIPT")
            continue
        # A malformed but bank-signed settled receipt must not hide a debit.
        # Count every confirmed money movement even when its position shape fails.
        receipt_debits = [e for e in receipt.exact_effects if e.effect_type == "debit"]
        debit += sum((e.amount or Fraction() for e in receipt_debits), Fraction())
        source_debit += sum(
            (
                e.amount or Fraction()
                for e in receipt_debits
                if e.account_ref == request.source_account_ref
            ),
            Fraction(),
        )
        if receipt.kind != "purchase_product":
            if receipt.exact_effects:
                errors.add("AUTH-SCOPE")
            continue
        settled += 1
        debits = [e for e in receipt.exact_effects if e.effect_type == "debit"]
        positions = [e for e in receipt.exact_effects if e.effect_type == "position"]
        if len(debits) != 1 or len(positions) != 1 or len(receipt.exact_effects) != 2:
            errors.add("BANK-RECEIPT")
            continue
        try:
            position = Position.model_validate(positions[0].after)
        except (ValidationError, ValueError):
            errors.add("BANK-RECEIPT")
            continue
        product_id = position.product_ref
        amount = position.principal_amount
        movement = debits[0]
        charged = movement.amount or Fraction()
        product = products.get(product_id)
        if (
            position.owner != principal
            or position.id != positions[0].object_ref
            or movement.account_ref != request.source_account_ref
            or movement.counterparty_ref != product_id
            or product is None
            or amount <= 0
        ):
            errors.add("BANK-RECEIPT")
        if product is not None and charged != amount + ceilcent(amount * product.purchase_fee_rate):
            errors.add("BIC-SCORE")
        if product_id in allocation:
            errors.add("IDEM-DUP")
        allocation[product_id] = allocation.get(product_id, Fraction()) + amount
        errors.update(
            allocation_constraints(
                state.model_copy(update={"now": receipt.executed_at}),
                request,
                {product_id: amount},
                principal=principal,
                require_full=False,
            )
        )
        if orders_by_key:
            order = orders_by_key.get(receipt.intent_key)
            args = (
                {
                    name: getattr(order.args, name, None)
                    for name in ("source_ref", "product_ref", "amount", "fee_buy")
                }
                if order
                else {}
            )
            if (
                order is None
                or order.principal != principal
                or order.kind != receipt.kind
                or args
                != {
                    "source_ref": request.source_account_ref,
                    "product_ref": product_id,
                    "amount": amount,
                    "fee_buy": charged - amount,
                }
            ):
                errors.add("BANK-RECEIPT")
        if check_authorization and not _authorized(
            state,
            receipt,
            principal,
            product_id,
            amount,
            charged,
            request.source_account_ref,
            auths,
            signed_inputs,
        ):
            errors.add("AUTH-SCOPE")
        if expected_allocation is not None and (
            product_id not in expected_allocation
            or allocation[product_id] > expected_allocation[product_id]
        ):
            errors.add("ALLOC-SELECT")
    full = sum(allocation.values(), Fraction()) == request.amount
    if allocation:
        errors.update(
            allocation_constraints(
                state,
                request,
                allocation,
                principal=principal,
                require_full=full,
            )
        )
    if require_complete and (not full or has_unknown):
        errors.add("ALLOC-SUM")
    if full and expected_allocation is not None and allocation != dict(expected_allocation):
        errors.add("ALLOC-SELECT")
    totals = _totals(products, request, allocation)
    benchmark = evaluate_allocation(state, request, principal=principal)
    if benchmark.constructed:
        if any(
            amount > benchmark.allocation.get(pid, Fraction()) for pid, amount in allocation.items()
        ):
            errors.add("ALLOC-SELECT")
    elif allocation:
        errors.add("ALLOC-SELECT")
    if source_debit > available_budget(state, request.source_account_ref):
        errors.add("BAL-AVAILABLE")
    net_delta = fee_delta = None
    if full and benchmark.constructed:
        net_delta = totals["projected_net"] - benchmark.totals["projected_net"]
        fee_delta = totals["projected_fees"] - benchmark.totals["projected_fees"]
    complete = full and not errors and not has_unknown
    status = (
        "unknown"
        if has_unknown
        else "completed"
        if complete
        else "executed_with_violations"
        if full
        else "partially_executed"
        if settled
        else "not_executed"
    )
    account = state.accounts[request.source_account_ref]
    return WealthExecutionResult(
        status=status,
        completed=complete,
        allocation=allocation,
        debit=debit,
        remaining_cash=available_budget(state, request.source_account_ref)
        + account.floor
        - source_debit,
        settled_count=settled,
        violations=tuple(sorted(errors)),
        projected_net_delta=net_delta,
        projected_fees_delta=fee_delta,
        liquidity_shortfall=max(
            Fraction(), request.liquidity_amount - totals["liquid_net_principal"]
        ),
        authorization_checked=check_authorization,
    )
