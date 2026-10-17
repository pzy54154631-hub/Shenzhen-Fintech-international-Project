"""Signed deterministic investment comparisons, questionnaires and income facts."""

from fractions import Fraction
from typing import Any, cast
from uuid import NAMESPACE_URL, uuid5

from nacl.signing import SigningKey

from corridor.crypto.jcs import H
from corridor.crypto.sign import INPUT, RECEIPT, RISK, sign, verify
from corridor.kernel.allocation import evaluate_allocation
from corridor.kernel.allocation_fallback import (
    compare_allocation_requests,
    preview_allocation_alternatives,
)
from corridor.kernel.investment import (
    _risk,
    evaluate_investment,
    risk_answers_errors,
    risk_score,
    risk_upgrade_review,
    suitability,
)
from corridor.schemas.allocation_fallback import AllocationCorrectionDiff, AllocationFallbackPreview
from corridor.schemas.bank import AnalysisReceipt, AnalysisResult, BankAction, BankOrder
from corridor.schemas.domain import RiskAssessment
from corridor.schemas.models import JsonValue
from corridor.schemas.money import fraction_string
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time
from corridor.stores.bank import add_seconds, latest_events

_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")


def build_allocation_alternatives(
    principal: str, parent_intent_id: str, request_ref: str, state: BankState
) -> AllocationFallbackPreview:
    """Read-only previews; device confirmation and ordinary kernel checks remain mandatory."""
    return preview_allocation_alternatives(principal, parent_intent_id, request_ref, state)


def build_allocation_correction_diff(
    principal: str, before_request_ref: str, after_request_ref: str, state: BankState
) -> AllocationCorrectionDiff:
    """Compare signed revisions under current facts; never restore historical authority."""
    return compare_allocation_requests(principal, before_request_ref, after_request_ref, state)


def build_risk_assessment(action: BankAction, state: BankState, key: SigningKey) -> RiskAssessment:
    ref = action.args.model_dump()["answers_input_ref"]
    item = state.user_inputs[ref]
    customer = state.customers[action.principal]
    if (
        key.verify_key.encode().hex() != state.roots.risk_pubkey
        or item.slot != "answers"
        or item.principal != action.principal
        or item.scope_id != action.intent_id
        or item.submitted_at > state.now
        or any(value.supersedes == item.id for value in state.user_inputs.values())
        or not verify(customer.device_pubkey, INPUT, item, item.sig)
    ):
        raise ValueError("AUTH-SIG")
    answers = item.value
    if (
        not isinstance(answers, list)
        or len(answers) != 5
        or any(type(answer) is not int or not 0 <= answer <= 4 for answer in answers)
    ):
        raise ValueError("BIC-RISK")
    exact_answers = cast(list[int], answers)
    errors = risk_answers_errors(action, state)
    if errors:
        raise ValueError(errors[0])
    if risk_upgrade_review(action, state):
        raise ValueError("RISK-UPGRADE-REVIEW")
    score, level = risk_score(exact_answers, state)
    assessment = RiskAssessment(
        id=str(uuid5(_NAMESPACE, f"{action.intent_id}:{action.node_id}:risk")),
        owner=action.principal,
        answers=exact_answers,
        answers_hash=H(answers),
        score=score,
        level=level,
        issued_at=state.now,
        expires_at=add_seconds(state.now, 365 * 86400),
        sig="0" * 128,
    )
    return assessment.model_copy(update={"sig": sign(key, RISK, assessment)})


def _value(value: JsonValue, unit: str) -> AnalysisResult:
    return AnalysisResult(value=value, unit=unit, source_tx_ids=[])


def _ceilcent(value: Fraction) -> Fraction:
    scaled = value * 100
    return Fraction(-(-scaled.numerator // scaled.denominator), 100)


def build_investment_analysis(
    action: BankAction, state: BankState, gateway_key: SigningKey, risk_key: SigningKey | None
) -> tuple[AnalysisReceipt, dict[str, Any]]:
    changes: dict[str, Any] = {}
    parameters: dict[str, JsonValue] = {"principal": action.principal, "action_hash": H(action)}
    results: dict[str, AnalysisResult] = {}
    args = action.args.model_dump(mode="python")
    suitability_risk = None
    suitability_horizon = None
    suitability_objective = None
    if action.kind == "risk_assess":
        if risk_key is None:
            raise ValueError("TOOL-UNAVAILABLE")
        assessment = build_risk_assessment(action, state, risk_key)
        suitability_risk = assessment
        customer = state.customers[action.principal]
        changes = {
            "risk_assessments": {**state.risk_assessments, assessment.id: assessment},
            "customers": {
                **state.customers,
                customer.id: customer.model_copy(
                    update={"risk_profile_ref": assessment.id, "version": customer.version + 1}
                ),
            },
        }
        for name in ("score", "level", "issued_at", "expires_at"):
            results[name] = _value(assessment.model_dump(mode="json")[name], "risk_fact")
        results["risk_assessment_ref"] = _value(assessment.id, "risk_ref")
        dataset_hash = assessment.answers_hash
        function_id = "risk_assess_v1"
    elif action.kind == "product_compare":
        evaluation = evaluate_investment(action, state)
        bic = evaluation.certificate
        if evaluation.errors or bic is None or evaluation.preference is None:
            raise ValueError(evaluation.errors[0] if evaluation.errors else "BIC-NOFEASIBLE")
        parameters["account_ref"] = evaluation.preference.source_account_ref
        suitability_risk = _risk(action, state)
        suitability_horizon = evaluation.preference.horizon_days
        suitability_objective = evaluation.preference.objective
        raw = bic.model_dump(mode="json")
        for name in ("candidate_ids", "chosen_product_id", "selection_mode", "best_choice"):
            results[name] = _value(raw[name], "comparison_fact")
        results["exclusions"] = _value(cast(JsonValue, evaluation.exclusions), "exclusion_reasons")
        for row in raw["rows"]:
            for name, value in row.items():
                if name == "product_id":
                    continue
                unit = "rank" if name == "rank" else "days" if name == "access_days" else "CNY"
                if name == "gap" and evaluation.preference.objective == "liquidity":
                    unit = "days"
                results[f"rows.{row['product_id']}.{name}"] = _value(value, unit)
        dataset_hash = H({
            "catalog": state.catalog,
            "risk": bic.risk_assessment_hash,
            "preference": bic.preference_hash,
        })
        function_id = "product_compare_v1"
    elif action.kind == "allocation_compare":
        evaluation_allocation = evaluate_allocation(
            action.principal, action.intent_id, str(args["request_ref"]), state
        )
        biac = evaluation_allocation.certificate
        if evaluation_allocation.errors or biac is None or evaluation_allocation.request is None:
            raise ValueError(
                evaluation_allocation.errors[0] if evaluation_allocation.errors else "ALLOC-SELECT"
            )
        parameters["account_ref"] = biac.source_account_ref
        suitability_risk = _risk(action, state)
        suitability_horizon = evaluation_allocation.request.horizon_days
        suitability_objective = evaluation_allocation.request.objective
        parameters["request_ref"] = str(args["request_ref"])
        results["allocation"] = _value(biac.model_dump(mode="json"), "allocation_fact")
        results["biac_hash"] = _value(H(biac), "allocation_hash")
        results["projection_notice"] = _value(
            "Projected, not guaranteed. Synthetic new-money allocation.", "notice"
        )
        for name, value in {
            "total_principal": biac.totals.principal,
            "total_buy_fees": biac.totals.fee_buy,
            "total_debit": biac.totals.total_debit,
            "projected_net": biac.totals.projected_net,
            "liquid_principal": biac.totals.liquid_net_principal,
        }.items():
            results[name] = _value(fraction_string(value), "CNY")
        dataset_hash = H({
            "request_hash": biac.request_hash,
            "policy_hash": biac.policy_hash,
            "catalog_hash": biac.catalog_hash,
            "risk_assessment_hash": biac.risk_assessment_hash,
        })
        function_id = "allocation_compare_v1"
    elif action.kind == "investment_income_query":
        position = state.positions[args["position_ref"]]
        if position.owner != action.principal:
            raise ValueError("AUTH-PRINCIPAL")
        product = next(item for item in state.catalog.products if item.id == position.product_ref)
        realized = Fraction()
        for event in latest_events(state).values():
            if (
                event.event != "settled"
                or event.kind != "redeem_product"
                or event.principal != action.principal
            ):
                continue
            order = BankOrder.model_validate(event.object_delta["order"])
            data = order.args.model_dump(mode="python")
            if data["position_ref"] == position.id and event.credit is not None:
                realized += event.credit.amount - Fraction(data["amount"])
        held_days = max(0, (parse_time(state.now) - parse_time(position.acquired_at)).days)
        principal = position.principal_amount
        projected = (
            principal * product.expected_annual_rate * held_days / 365
            - _ceilcent(principal * product.annual_fee_rate * held_days / 365)
            - _ceilcent(principal * product.redemption_fee_rate)
        )
        results = {
            name: _value(fraction_string(value), "CNY")
            for name, value in {
                "realized_income": realized,
                "projected_income": projected,
                "principal_amount": principal,
                "units": position.units,
                "reserved_units": position.reserved_units,
            }.items()
        }
        parameters["position_ref"] = position.id
        dataset_hash = H({"position": position, "product": product, "ledger": state.ledger})
        function_id = "investment_income_v1"
    else:
        raise ValueError("TOOL-UNAVAILABLE")
    if suitability_risk is not None:
        facts = suitability(
            action.principal,
            state,
            suitability_risk,
            device_session_id=action.device_session_id,
            horizon_days=suitability_horizon,
            objective=suitability_objective,
        )
        if action.kind == "allocation_compare":
            # Keep the allocation scalar-fact contract exact; these signed inputs
            # support the canonical card and the append-only session restriction.
            parameters["suitability"] = {
                "raw_level": facts.raw_level,
                "effective_level": facts.effective_level,
                "reasons": list(facts.reason_codes),
                "clarification": facts.clarification,
            }
        else:
            results["effective_level"] = _value(facts.effective_level, "risk_fact")
            results["suitability_reasons"] = _value(list(facts.reason_codes), "risk_fact")
            results["suitability_clarification"] = _value(facts.clarification, "notice")
    receipt = AnalysisReceipt(
        receipt_id=str(uuid5(_NAMESPACE, f"{action.intent_id}:{action.node_id}:analysis")),
        dataset_hash=dataset_hash,
        function_id=function_id,
        parameters=parameters,
        results=results,
        trust="builtin",
        computed_at=state.now,
        sig="0" * 128,
    )
    return receipt.model_copy(update={"sig": sign(gateway_key, RECEIPT, receipt)}), changes
