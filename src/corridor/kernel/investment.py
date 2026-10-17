"""Trusted complete-set investment selection, pricing and certificate checking."""

from dataclasses import dataclass
from datetime import timedelta
from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.crypto.sign import ALLOCATION_POLICY, CATALOG, INPUT, RECEIPT, RISK, verify
from corridor.schemas.allocation import AllocationPolicy
from corridor.schemas.bank import (
    AnalysisReceipt,
    BankAction,
    BankCertificate,
    BankOrder,
    BankReceipt,
    BestInterestCertificate,
    BestInterestRow,
)
from corridor.schemas.domain import InvestmentPreference, Position, Product, RiskAssessment
from corridor.schemas.money import Money, ceil_minor
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time
from corridor.stores.bank import available, latest_events


@dataclass(frozen=True)
class InvestmentEvaluation:
    preference: InvestmentPreference | None
    certificate: BestInterestCertificate | None
    exclusions: dict[str, list[str]]
    errors: tuple[str, ...]


def risk_score(answers: list[int], state: BankState) -> tuple[int, int]:
    """The synthetic five-question assessment is not a regulatory risk model."""
    if (
        len(answers) != 5
        or any(type(answer) is not int or not 0 <= answer <= 4 for answer in answers)
        or state.policy.risk_answer_scores != [0, 1, 2, 3, 4]
    ):
        raise ValueError("BIC-RISK")
    score = sum(state.policy.risk_answer_scores[answer] for answer in answers)
    return score, max(1, (score + 3) // 4)


def risk_answers_errors(action: BankAction, state: BankState) -> list[str]:
    """A new assessment requires a fresh, previously unused device submission."""
    ref = str(action.args.model_dump()["answers_input_ref"])
    value = state.user_inputs.get(ref)
    if value is None:
        return ["BIC-RISK"]
    errors: list[str] = []
    if any(
        event.kind == "risk_assess"
        and event.principal == action.principal
        and event.event != "failed"
        and event.object_delta.get("answers_input_ref") == ref
        for event in state.ledger
    ):
        errors.append("RISK-ANSWERS-CONSUMED")
    customer = state.customers.get(action.principal)
    current = state.risk_assessments.get(customer.risk_profile_ref or "") if customer else None
    age = parse_time(state.now) - parse_time(value.submitted_at)
    if (
        age < timedelta()
        or age > timedelta(seconds=state.policy.risk_answers_ttl_seconds)
        or (current is not None and value.submitted_at <= current.issued_at)
    ):
        errors.append("RISK-ANSWERS-STALE")
    if errors:
        return errors
    return risk_retake_errors(action.principal, state)


def risk_retake_errors(principal: str, state: BankState) -> list[str]:
    """Count completed or unresolved attempts on UTC+8 calendar business dates."""
    daily_limit, year_limit = 2, 8
    for stored in state.allocation_policies.values():
        try:
            policy = AllocationPolicy.model_validate(stored.model_dump(mode="python"))
        except ValueError:
            return ["ALLOC-POLICY"]
        if (
            not verify(state.roots.bank_pubkey, ALLOCATION_POLICY, policy, policy.sig)
            or not policy.issued_at <= state.now < policy.valid_until
            or policy.catalog_id != state.catalog.id
            or policy.catalog_version != state.catalog.version
        ):
            return ["ALLOC-POLICY"]
        if policy.risk_retake_limits is not None:
            daily_limit = min(daily_limit, policy.risk_retake_limits.daily)
            year_limit = min(year_limit, policy.risk_retake_limits.trailing_twelve_months)
    today = (parse_time(state.now) + timedelta(hours=8)).date()
    try:
        cutoff = today.replace(year=today.year - 1)
    except ValueError:
        cutoff = today.replace(year=today.year - 1, day=28)
    assessments = {
        ref: risk
        for ref, risk in state.risk_assessments.items()
        if _risk_valid(risk, principal, state, current=False)
    }
    days = [
        (parse_time(risk.issued_at) + timedelta(hours=8)).date() for risk in assessments.values()
    ]
    for event in latest_events(state).values():
        if event.kind != "risk_assess" or event.principal != principal or event.event == "failed":
            continue
        ref = event.object_delta.get("risk_assessment_ref")
        receipt = state.receipts.get(str(event.object_delta.get("analysis_receipt_id")))
        if ref is None and isinstance(receipt, AnalysisReceipt):
            result = receipt.results.get("risk_assessment_ref")
            if result is not None:
                ref = result.value
        if isinstance(ref, str) and ref in assessments:
            continue
        days.append((parse_time(event.ts) + timedelta(hours=8)).date())
    if (
        sum(day == today for day in days) >= daily_limit
        or sum(cutoff <= day <= today for day in days) >= year_limit
    ):
        return ["RISK-RETAKE-LIMIT"]
    return []


@dataclass(frozen=True)
class Suitability:
    raw_level: int
    effective_level: int
    reason_codes: tuple[str, ...]
    clarification: str | None


def risk_session_cap(
    principal: str, state: BankState, *, device_session_id: str | None = None
) -> int:
    """Trusted session evidence can lower suitability and never raise it."""
    session = device_session_id or state.security.active_device_sessions.get(principal)
    cap = 5
    if session is None:
        return cap
    for event in state.ledger:
        if (
            event.principal != principal
            or event.event != "settled"
            or event.ts > state.now
            or event.object_delta.get("device_session_id") != session
        ):
            continue
        value = event.object_delta.get("effective_level_cap")
        if type(value) is int and 1 <= value <= 5:
            cap = min(cap, value)
        if event.kind == "risk_assess":
            risk = state.risk_assessments.get(str(event.object_delta.get("risk_assessment_ref")))
            if risk is not None and _risk_valid(risk, principal, state, current=False):
                cap = min(cap, risk.level, 1 if risk.answers[1] == 0 else 5)
    return cap


def suitability(
    principal: str,
    state: BankState,
    risk: RiskAssessment,
    *,
    device_session_id: str | None = None,
    horizon_days: int | None = None,
    objective: str | None = None,
) -> Suitability:
    """Deterministic synthetic conflicts affect effective limits, never signed raw scores."""
    reasons: list[str] = []
    candidates = [
        risk.level,
        risk_session_cap(principal, state, device_session_id=device_session_id),
    ]
    if candidates[-1] < risk.level:
        reasons.append("session_risk_cap")
    if risk.answers[1] == 0:
        candidates.append(1)
        if risk.level > 1 or objective == "net_return":
            reasons.append("loss_tolerance_conflict")
    if objective == "net_return" and horizon_days is not None and horizon_days < 365:
        candidates.append(2)
        reasons.append("short_horizon_growth")
    clarification = None
    if reasons:
        clarification = (
            "Please confirm your loss tolerance and investment horizon on the device. "
            "The lowest suitability level recorded in this session remains in effect."
        )
    return Suitability(risk.level, min(candidates), tuple(reasons), clarification)


def effective_risk_level(
    principal: str,
    state: BankState,
    *,
    horizon_days: int | None = None,
    objective: str | None = None,
) -> int:
    customer = state.customers.get(principal)
    risk = state.risk_assessments.get(customer.risk_profile_ref or "") if customer else None
    if risk is None or not _risk_valid(risk, principal, state):
        raise ValueError("BIC-RISK")
    return suitability(
        principal, state, risk, horizon_days=horizon_days, objective=objective
    ).effective_level


def risk_upgrade_review(action: BankAction, state: BankState) -> bool:
    """A refused purchase cannot be unlocked by raising the raw assessment in-session."""
    if action.kind != "risk_assess":
        return False
    refused = any(
        event.principal == action.principal
        and event.event == "settled"
        and event.ts <= state.now
        and event.object_delta.get("device_session_id") == action.device_session_id
        and event.object_delta.get("suitability_signal") == "purchase_refused"
        for event in state.ledger
    )
    if not refused:
        return False
    value = state.user_inputs.get(str(action.args.model_dump()["answers_input_ref"]))
    if value is None or not isinstance(value.value, list):
        return False
    answers = [answer for answer in value.value if type(answer) is int]
    _, level = risk_score(answers, state)
    return level > risk_session_cap(
        action.principal, state, device_session_id=action.device_session_id
    )


def get_preference(action: BankAction, state: BankState) -> InvestmentPreference:
    args = action.args.model_dump(mode="python")
    value = state.user_inputs.get(str(args.get("preference_ref", "")))
    customer = state.customers.get(action.principal)
    if (
        value is None
        or customer is None
        or value.principal != action.principal
        or value.slot != "preference"
        or value.scope_id != action.intent_id
        or value.submitted_at > state.now
        or any(item.supersedes == value.id for item in state.user_inputs.values())
        or not verify(customer.device_pubkey, INPUT, value, value.sig)
    ):
        raise ValueError("BIC-PREFERENCE")
    try:
        preference = InvestmentPreference.model_validate(value.value)
    except ValueError as exc:
        raise ValueError("BIC-PREFERENCE") from exc
    account = state.accounts.get(preference.source_account_ref)
    if (
        account is None
        or account.owner != action.principal
        or account.kind != "current"
        or account.status != "active"
        or (preference.amount * 100).denominator != 1
    ):
        raise ValueError("BIC-PREFERENCE")
    return preference


def _valid_catalog(state: BankState, *, current: bool = True) -> bool:
    catalog = state.catalog
    return (
        verify(state.roots.bank_pubkey, CATALOG, catalog, catalog.sig)
        and len({p.id for p in catalog.products}) == len(catalog.products)
        and all(p.id.isascii() and p.pricing_model == "simple_365_v1" for p in catalog.products)
        and (not current or catalog.issued_at <= state.now < catalog.valid_until)
    )


def _risk_valid(
    risk: RiskAssessment, principal: str, state: BankState, *, current: bool = True
) -> bool:
    try:
        score, level = risk_score(risk.answers, state)
    except ValueError:
        return False
    if (
        risk.owner != principal
        or not verify(state.roots.risk_pubkey, RISK, risk, risk.sig)
        or risk.issued_at > state.now
        or (current and not risk.issued_at <= state.now < risk.expires_at)
        or parse_time(risk.expires_at) > parse_time(risk.issued_at) + timedelta(days=365)
        or (
            current
            and parse_time(state.now)
            >= parse_time(risk.issued_at) + timedelta(days=min(365, state.policy.risk_valid_days))
        )
        or risk.answers_hash != H(risk.answers)
        or risk.score != score
        or risk.level != level
    ):
        return False
    return True


def _risk(action: BankAction, state: BankState) -> RiskAssessment | None:
    customer = state.customers.get(action.principal)
    risk = state.risk_assessments.get(customer.risk_profile_ref or "") if customer else None
    if risk is None or not _risk_valid(risk, action.principal, state):
        return None
    return risk


def price_product(product: Product, amount: Fraction, horizon_days: int) -> BestInterestRow:
    """Round only contractual charges; projected return remains an exact fraction."""
    if amount <= 0 or horizon_days <= 0 or product.pricing_model != "simple_365_v1":
        raise ValueError("BIC-SCORE")
    buy = ceil_minor(amount * product.purchase_fee_rate)
    hold = ceil_minor(amount * product.annual_fee_rate * horizon_days / 365)
    sell = ceil_minor(amount * product.redemption_fee_rate)
    total = buy + hold + sell
    return BestInterestRow(
        product_id=product.id,
        fee_buy=buy,
        fee_hold=hold,
        fee_sell=sell,
        total_fee=total,
        expected_net=amount * product.expected_annual_rate * horizon_days / 365 - total,
        access_days=product.min_hold_days + product.redeem_delay_days,
        rank=1,
        gap=Fraction(),
    )


@dataclass(frozen=True)
class RedemptionCalculation:
    fee_hold: Fraction
    fee_sell: Fraction
    net_proceeds: Fraction
    settle_at: str

    @property
    def fees(self) -> Fraction:
        return self.fee_hold + self.fee_sell


def price_redemption(
    product: Product, position: Position, amount: Fraction, requested_at: str
) -> RedemptionCalculation:
    """Use the same exact charges and settlement time for checking, cards and receipts."""
    held_days = (parse_time(requested_at) - parse_time(position.acquired_at)).days
    if held_days < 0 or amount <= 0 or product.pricing_model != "simple_365_v1":
        raise ValueError("DOMAIN-STATE")
    hold = ceil_minor(amount * product.annual_fee_rate * held_days / 365)
    sell = ceil_minor(amount * product.redemption_fee_rate)
    if hold + sell > amount:
        raise ValueError("DOMAIN-STATE")
    due = (parse_time(requested_at) + timedelta(days=product.redeem_delay_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return RedemptionCalculation(hold, sell, amount - hold - sell, due)


def resolve_redemption_account(position: Position, principal: str, state: BankState) -> str:
    """Return the verified purchase source, or the unique active initial current account."""
    sources: set[str] = set()
    for event in latest_events(state).values():
        if event.kind != "purchase_product" or event.event != "settled":
            continue
        receipt = state.receipts.get(event.bank_receipt_id or "")
        if not isinstance(receipt, BankReceipt):
            continue
        if any(
            effect.effect_type == "position" and effect.object_ref == position.id
            for effect in receipt.exact_effects
        ):
            purchase = BankOrder.model_validate(event.object_delta.get("order"))
            if (
                purchase.kind != "purchase_product"
                or purchase.principal != position.owner
                or event.principal != position.owner
                or purchase.intent_key != receipt.intent_key
                or not verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig)
            ):
                raise ValueError("BANK-RECEIPT")
            sources.add(str(purchase.args.model_dump()["source_ref"]))
    if not sources:
        sources = {
            account.id
            for account in state.accounts.values()
            if account.owner == position.owner
            and account.kind == "current"
            and account.status == "active"
        }
    if len(sources) != 1:
        raise ValueError("DOMAIN-STATE")
    ref = next(iter(sources))
    account = state.accounts.get(ref)
    if (
        account is None
        or account.owner != principal
        or account.kind != "current"
        or account.status != "active"
    ):
        raise ValueError("DOMAIN-STATE")
    return ref


def evaluate_investment(action: BankAction, state: BankState) -> InvestmentEvaluation:
    """Rebuild every eligible row without receiving a proposed candidate list."""
    errors: list[str] = []
    try:
        preference = get_preference(action, state)
    except ValueError:
        preference = None
        errors.append("BIC-PREFERENCE")
    if not _valid_catalog(state):
        errors.append("BIC-CATALOG")
    risk = _risk(action, state)
    if risk is None:
        errors.append("BIC-RISK")
    if errors or preference is None or risk is None:
        return InvestmentEvaluation(preference, None, {}, tuple(errors))
    effective_level = suitability(
        action.principal,
        state,
        risk,
        device_session_id=action.device_session_id,
        horizon_days=preference.horizon_days,
        objective=preference.objective,
    ).effective_level
    account = state.accounts[preference.source_account_ref]
    available_amount = available(state, account.id) - account.floor
    exclusions: dict[str, list[str]] = {}
    rows: list[BestInterestRow] = []
    for product in state.catalog.products:
        row = price_product(product, preference.amount, preference.horizon_days)
        reasons: list[str] = []
        checks = (
            (product.purchase_open, "purchase_closed"),
            (action.principal in product.eligible_customers, "customer_ineligible"),
            (product.risk_level <= effective_level, "risk"),
            (product.min_amount <= preference.amount, "minimum_amount"),
            (
                product.max_amount is None or preference.amount <= product.max_amount,
                "maximum_amount",
            ),
            (product.type in preference.allowed_types, "product_type"),
            (product.min_hold_days <= preference.horizon_days, "holding_period"),
            (product.redeem_delay_days <= preference.max_access_days, "access_delay"),
            (preference.amount + row.fee_buy <= available_amount, "available_balance"),
        )
        for valid, reason in checks:
            if not valid:
                reasons.append(reason)
        if reasons:
            exclusions[product.id] = reasons
        else:
            rows.append(row)
    if not rows:
        return InvestmentEvaluation(preference, None, exclusions, ("BIC-NOFEASIBLE",))

    def scalar(row: BestInterestRow) -> Fraction:
        if preference.objective == "net_return":
            return -row.expected_net
        if preference.objective == "total_fee":
            return row.total_fee
        return Fraction(row.access_days)

    rows.sort(key=lambda row: (scalar(row), row.product_id))
    best = scalar(rows[0])
    rows = [
        row.model_copy(update={"rank": index, "gap": scalar(row) - best})
        for index, row in enumerate(rows, 1)
    ]
    chosen = (
        preference.selected_product_ref
        if preference.selection_mode == "explicit"
        else rows[0].product_id
    )
    if chosen not in {row.product_id for row in rows}:
        errors.append("BIC-CHOICE")
        if "risk" in exclusions.get(chosen or "", []):
            errors.append("BIC-RISK")
    args = action.args.model_dump(mode="python")
    certificate = BestInterestCertificate(
        catalog_hash=H(state.catalog),
        preference_hash=H(state.user_inputs[args["preference_ref"]]),
        risk_assessment_hash=H(risk),
        candidate_ids=sorted(row.product_id for row in rows),
        rows=rows,
        chosen_product_id=chosen or rows[0].product_id,
        selection_mode=preference.selection_mode,
        best_choice=chosen == rows[0].product_id,
    )
    return InvestmentEvaluation(preference, certificate, exclusions, tuple(errors))


def build_best_interest(action: BankAction, state: BankState) -> BestInterestCertificate:
    evaluation = evaluate_investment(action, state)
    if evaluation.errors or evaluation.certificate is None:
        raise ValueError(evaluation.errors[0] if evaluation.errors else "BIC-NOFEASIBLE")
    return evaluation.certificate


def _redemption_errors(action: BankAction, state: BankState) -> list[str]:
    args = action.args.model_dump(mode="python")
    position = state.positions.get(str(args.get("position_ref", "")))
    if position is None or position.owner != action.principal:
        return ["DOMAIN-STATE"]
    errors: list[str] = []
    product = next((p for p in state.catalog.products if p.id == position.product_ref), None)
    if not _valid_catalog(state, current=False) or product is None:
        errors.append("BIC-CATALOG")
    if action.kind == "investment_income_query":
        return errors
    if position.status != "active" or position.nav != 1 or position.redeemable_at > state.now:
        errors.append("DOMAIN-STATE")
    try:
        amount = Money.model_validate(state.user_inputs[args["amount_ref"]].value).amount
    except (ValueError, KeyError):
        return [*errors, "PROV-MISMATCH"]
    if amount > position.units - position.reserved_units or amount > position.principal_amount:
        errors.append("BAL-AVAILABLE")
    if product is not None:
        if parse_time(position.acquired_at) + timedelta(days=product.min_hold_days) > parse_time(
            state.now
        ):
            errors.append("DOMAIN-STATE")
        try:
            price_redemption(product, position, amount, state.now)
            resolve_redemption_account(position, action.principal, state)
        except (ValueError, KeyError):
            errors.append("DOMAIN-STATE")
    return errors


def investment_errors(action: BankAction, cert: BankCertificate, state: BankState) -> list[str]:
    if action.kind in {"redeem_product", "investment_income_query"}:
        return _redemption_errors(action, state)
    if action.kind == "risk_assess":
        args = action.args.model_dump(mode="python")
        value = state.user_inputs.get(str(args["answers_input_ref"]))
        try:
            if value is None or not isinstance(value.value, list):
                raise ValueError("BIC-RISK")
            answers = value.value
            if any(type(answer) is not int for answer in answers):
                raise ValueError("BIC-RISK")
            risk_score([int(answer) for answer in answers if isinstance(answer, int)], state)
        except ValueError:
            return ["BIC-RISK"]
        return risk_answers_errors(action, state)
    if action.kind not in {"product_compare", "purchase_product"}:
        return []
    evaluation = evaluate_investment(action, state)
    errors = list(evaluation.errors)
    expected, actual = evaluation.certificate, cert.best_interest
    args = action.args.model_dump(mode="python")
    preference = evaluation.preference
    if action.kind == "purchase_product" and preference is not None:
        try:
            amount = Money.model_validate(state.user_inputs[args["amount_ref"]].value).amount
        except (ValueError, KeyError):
            amount = None
        if amount != preference.amount or args["source_ref"] != preference.source_account_ref:
            errors.append("BIC-PREFERENCE")
    if expected is None:
        return errors
    if actual is None:
        return [*errors, "BIC-COMPLETE"]
    if actual.catalog_hash != expected.catalog_hash:
        errors.append("BIC-CATALOG")
    if actual.preference_hash != expected.preference_hash:
        errors.append("BIC-PREFERENCE")
    if actual.risk_assessment_hash != expected.risk_assessment_hash:
        errors.append("BIC-RISK")
    if (
        actual.candidate_ids != expected.candidate_ids
        or sorted(row.product_id for row in actual.rows) != expected.candidate_ids
    ):
        errors.append("BIC-COMPLETE")
    elif actual.rows != expected.rows:
        errors.append("BIC-SCORE")
    if (
        actual.chosen_product_id != expected.chosen_product_id
        or actual.selection_mode != expected.selection_mode
        or actual.best_choice != expected.best_choice
        or (action.kind == "purchase_product" and args["product_ref"] != expected.chosen_product_id)
    ):
        errors.append("BIC-CHOICE")
    chosen = str(args.get("product_ref", actual.chosen_product_id))
    if "risk" in evaluation.exclusions.get(chosen, []):
        errors.append("BIC-RISK")
    return errors
