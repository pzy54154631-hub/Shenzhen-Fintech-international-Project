"""Pure business projections shared by certificate checking and canonical cards.

Authentication bookkeeping is deliberately absent from the business digest.
These helpers calculate facts; they do not authorize an action on their own.
"""

from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Literal, cast

from corridor.crypto.jcs import H
from corridor.kernel.allocation import evaluate_allocation, get_allocation_request
from corridor.kernel.cards import CARD_KINDS, card_account_ref, card_facts
from corridor.kernel.investment import (
    _risk,
    evaluate_investment,
    get_preference,
    price_redemption,
    resolve_redemption_account,
    suitability,
)
from corridor.kernel.planning import aa_total
from corridor.kernel.spa import due_at
from corridor.schemas.bank import (
    AuthorizationRevocation,
    BankAction,
    BankCertificate,
    InputTerm,
    OperationAuthorization,
    ReceiptTerm,
    ScheduledPaymentAuthorization,
    SessionAuthorization,
    StateTerm,
)
from corridor.schemas.models import JsonValue
from corridor.schemas.money import Money
from corridor.schemas.state import BankState
from corridor.stores.bank import available, business_date, commitments, financial_version

GREEN = frozenset({
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
})
RED = frozenset({
    "purchase_product",
    "password_change_request",
    "register_contact_request",
    "unfreeze_card",
    "relax_card_restriction",
    "report_card_lost",
    "restore_card",
    "raise_card_limit",
})
OUTGOING = frozenset({"transfer", "merchant_order"})


def rational(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def intent_key(action: BankAction, state: BankState) -> str:
    run = state.schedules.get(action.action_id)
    if run is not None and action.kind != "schedule_transfer":
        return H({"spa_id": run.spa_ref, "run_index": run.run_index})
    key = {
        "principal": action.principal,
        "intent_id": action.intent_id,
        "kind": action.kind,
    }
    spa = state.authorizations.get(action.intent_id)
    if action.kind == "schedule_transfer" and isinstance(spa, ScheduledPaymentAuthorization):
        # SPA creation is explicitly bound to a device-signed node. Immediate
        # operation authorizations carry no such planner identifier binding.
        key["node_id"] = spa.node_id
    elif (
        action.kind in GREEN - {"risk_assess"}
        and not any(
            isinstance(auth, OperationAuthorization)
            and auth.principal == action.principal
            and auth.intent_id == action.intent_id
            and auth.allowed_kind == action.kind
            for auth in state.authorizations.values()
        )
        and any(
            isinstance(auth, SessionAuthorization)
            and auth.principal == action.principal
            and auth.device_session_id == action.device_session_id
            and action.kind in auth.read_kinds
            for auth in state.authorizations.values()
        )
    ):
        # Reusable read sessions must allow independent DAG query nodes. An
        # operation intent always keeps the single-use key, including queries.
        key["node_id"] = action.node_id
    return H(key)


def mfa_scope(action: BankAction, card_hash: str, ownership_epoch: int = 0) -> str:
    return H({
        "action_hash": H(action),
        "card_hash": card_hash,
        "plan_hash": action.plan_hash,
        "node_id": action.node_id,
        "ownership_epoch": ownership_epoch,
        "device_session_id": action.device_session_id,
    })


def resolve_amount(action: BankAction, state: BankState) -> Fraction | None:
    args = action.args.model_dump(mode="python")
    if action.kind == "aa_request":
        return aa_total(action, state)
    amount_ref = args.get("amount_ref") or args.get("total_ref")
    if amount_ref is not None:
        return Money.model_validate(state.user_inputs[amount_ref].value).amount
    if action.kind == "merchant_order":
        merchant = state.merchants[args["merchant_ref"]]
        return next(offer.amount for offer in merchant.offers if offer.id == args["offer_ref"])
    if action.kind == "product_compare":
        return get_preference(action, state).amount
    if action.kind == "allocation_compare":
        evaluation = evaluate_allocation(
            action.principal, action.intent_id, str(args["request_ref"]), state
        )
        return evaluation.request.amount if evaluation.request is not None else None
    return None


def _approval_account_ref(action: BankAction, state: BankState) -> str | None:
    if action.kind == "redeem_product":
        ref = str(action.args.model_dump()["position_ref"])
        try:
            return resolve_redemption_account(state.positions[ref], action.principal, state)
        except (ValueError, KeyError):
            # Invalid destinations are rejected by the investment domain check.
            return None
    return card_account_ref(action, state)


def _suitability_projection(action: BankAction, state: BankState) -> dict[str, JsonValue] | None:
    if action.kind not in {"product_compare", "purchase_product", "allocation_compare"}:
        return None
    risk = _risk(action, state)
    if risk is None:
        return None
    args = action.args.model_dump()
    try:
        if action.kind == "allocation_compare":
            goal = get_allocation_request(
                action.principal, action.intent_id, str(args["request_ref"]), state
            )
            horizon, objective = goal.horizon_days, goal.objective
        elif args.get("allocation_ref"):
            parent = state.allocation_plans[str(args["allocation_ref"])]
            goal = get_allocation_request(
                action.principal, parent.parent_intent_id, parent.request_ref, state
            )
            horizon, objective = goal.horizon_days, goal.objective
        else:
            preference = get_preference(action, state)
            horizon, objective = preference.horizon_days, preference.objective
    except (ValueError, KeyError):
        return None
    facts = suitability(
        action.principal,
        state,
        risk,
        device_session_id=action.device_session_id,
        horizon_days=horizon,
        objective=objective,
    )
    return {
        "assessment_ref": risk.id,
        "level": facts.effective_level,
        "raw_level": facts.raw_level,
        "effective_level": facts.effective_level,
        "expires_at": risk.expires_at,
        "reason_codes": list(facts.reason_codes),
        "clarification": facts.clarification,
    }


def dependency_hashes(
    action: BankAction,
    cert: BankCertificate,
    state: BankState,
) -> dict[str, str]:
    objects: dict[str, Any] = {}
    for term in cert.derivations.values():
        if isinstance(term, StateTerm):
            collection = getattr(state, term.collection)
            if term.collection == "catalog":
                obj = next((p for p in state.catalog.products if p.id == term.object_ref), None)
            else:
                obj = collection.get(term.object_ref)
            objects[f"{term.collection}:{term.object_ref}"] = obj
        elif isinstance(term, ReceiptTerm):
            objects[f"receipts:{term.receipt_ref}"] = state.receipts.get(term.receipt_ref)
    account_ref = _approval_account_ref(action, state)
    if account_ref is not None:
        objects[f"accounts:{account_ref}"] = state.accounts.get(account_ref)
    refs = {term.input_ref for term in cert.derivations.values() if isinstance(term, InputTerm)}
    inputs = {
        key: value
        for key, value in state.user_inputs.items()
        if key in refs
        or (value.principal == action.principal and value.scope_id == action.intent_id)
    }
    auth = state.authorizations.get(cert.authorization_ref)
    result = {
        "policy": H(state.policy),
        "customer": H(state.customers.get(action.principal)),
        "authorization": H(auth),
        "revocations": H([
            value
            for value in state.authorizations.values()
            if isinstance(value, AuthorizationRevocation)
            and value.authorization_ref == cert.authorization_ref
        ]),
        "inputs": H(inputs),
        "objects": H(objects),
        "financial": financial_version(state, action.principal),
        "business_date": H(business_date(state.now)),
    }
    if not isinstance(auth, ScheduledPaymentAuthorization) or action.kind == "schedule_transfer":
        result["session"] = H(state.security.active_device_sessions.get(action.principal))
    if action.kind in {
        "purchase_product",
        "redeem_product",
        "product_compare",
        "allocation_compare",
        "investment_income_query",
    }:
        result["catalog"] = H(state.catalog)
        customer = state.customers.get(action.principal)
        result["risk"] = H(
            state.risk_assessments.get(customer.risk_profile_ref or "") if customer else None
        )
        if action.kind in {"product_compare", "purchase_product", "allocation_compare"}:
            result["suitability"] = H(_suitability_projection(action, state))
    if action.kind == "allocation_compare" or action.args.model_dump().get("allocation_ref"):
        result["allocation_policies"] = H(state.allocation_policies)
        parent = state.allocation_plans.get(str(action.args.model_dump().get("allocation_ref")))
        parent_intent_id = (
            action.intent_id
            if action.kind == "allocation_compare"
            else parent.parent_intent_id
            if parent is not None and parent.principal == action.principal
            else None
        )
        result["allocation_plans"] = H({
            key: plan
            for key, plan in state.allocation_plans.items()
            if plan.principal == action.principal and plan.parent_intent_id == parent_intent_id
        })
    if action.args.model_dump().get("allocation_ref"):
        from corridor.kernel.allocation_execution import allocation_dependency_projection

        result["allocation_context"] = H(allocation_dependency_projection(action, state))
    if action.kind in {
        "bill_analyze",
        "bill_report",
        "anomaly_query",
        "subscription_query",
        "subscription_reminders",
    }:
        account_ref = action.args.model_dump().get("account_ref")
        result["analysis_data"] = H({
            "transactions": [
                tx
                for tx in state.transactions.values()
                if tx.owner == action.principal and tx.account_ref == account_ref
            ],
            "subscriptions": [
                sub
                for sub in state.subscriptions.values()
                if sub.owner == action.principal and sub.source_account_ref == account_ref
            ],
            "merchants": state.merchants,
        })
    return result


@dataclass(frozen=True)
class Binding:
    tier: Literal["green", "yellow", "red"]
    tier_basis: dict[str, JsonValue]
    card_core: dict[str, JsonValue]
    dependency_hash: str
    verified_facts: dict[str, JsonValue]
    amount: Fraction | None
    intent_key: str


def business_context_hash(action: BankAction, cert: BankCertificate, state: BankState) -> str:
    """Bind trusted business objects without draft/signature bookkeeping.

    Each object is hashed separately so a nested draft signature cannot change
    the digest when the device signs the identical business object on a click.
    """
    objects: dict[str, str] = {}
    for term in cert.derivations.values():
        if isinstance(term, StateTerm):
            collection = getattr(state, term.collection)
            obj = (
                next((item for item in state.catalog.products if item.id == term.object_ref), None)
                if term.collection == "catalog"
                else collection.get(term.object_ref)
            )
            objects[f"{term.collection}:{term.object_ref}"] = H(obj)
        elif isinstance(term, ReceiptTerm):
            objects[f"receipts:{term.receipt_ref}"] = H(state.receipts.get(term.receipt_ref))
    account_ref = _approval_account_ref(action, state)
    if account_ref is not None:
        objects[f"accounts:{account_ref}"] = H(state.accounts.get(account_ref))
    refs = {term.input_ref for term in cert.derivations.values() if isinstance(term, InputTerm)}
    context: dict[str, Any] = {
        "policy": H(state.policy),
        "customer": H(state.customers.get(action.principal)),
        "objects": objects,
        "inputs": {
            key: H(value)
            for key, value in state.user_inputs.items()
            if key in refs
            or (value.principal == action.principal and value.scope_id == action.intent_id)
        },
        "authorization": H(state.authorizations.get(cert.authorization_ref)),
    }
    if action.args.model_dump().get("allocation_ref"):
        from corridor.kernel.allocation_execution import allocation_dependency_projection

        context["allocation"] = allocation_dependency_projection(action, state)
    return H(context)


def binding(action: BankAction, cert: BankCertificate, state: BankState) -> Binding:
    args = action.args.model_dump(mode="json")
    amount = resolve_amount(action, state)
    auth = state.authorizations.get(cert.authorization_ref)
    spa = auth if isinstance(auth, ScheduledPaymentAuthorization) else None
    creation = action.kind == "schedule_transfer" and spa is not None
    key = intent_key(action, state)
    when = (due_at(spa, 0) or spa.start) if creation and spa is not None else state.now
    obligations = commitments(state, action.principal, when)
    before = sum(obligations.values(), Fraction(0))
    candidate = (
        amount
        if action.kind in OUTGOING or (creation and spa is not None and spa.target.kind in OUTGOING)
        else Fraction(0)
    )
    current = obligations.get(key, Fraction(0))
    after = before - current + (candidate or Fraction(0))
    tier: Literal["green", "yellow", "red"] = "green" if action.kind in GREEN else "yellow"
    reasons: list[JsonValue] = []
    contact = state.contacts.get(str(args.get("contact_ref", "")))
    new_target = contact.is_new if contact is not None else False
    merchant = state.merchants.get(str(args.get("merchant_ref", "")))
    if merchant is not None:
        new_target = not merchant.verified or merchant.is_new
    if action.kind in RED:
        tier = "red"
        reasons.append("sensitive_operation")
    if action.kind in OUTGOING and after > state.policy.transfer_yellow_limit:
        tier = "red"
        reasons.append("daily_limit")
    if action.kind in OUTGOING and new_target:
        tier = "red"
        reasons.append("new_recipient")
    if creation and spa is not None:
        tier = (
            "red"
            if (
                spa.schedule.type == "monthly"
                or spa.amount > state.policy.transfer_yellow_limit
                or new_target
            )
            else "yellow"
        )
        reasons = ["spa_creation"]
    if spa is not None and not creation and spa.creation_tier == "red":
        tier = "red"
        reasons.append("red_spa_creation")
    run = state.schedules.get(action.action_id)
    if spa is not None and not creation and run is not None and run.status == "waiting_mfa":
        tier = "red"
        reasons.append("awaiting_run_verification")
    source_ref = str(args.get("source_ref", args.get("account_ref", "")))
    debit_ref = str(args.get("locked_ref", "")) if action.kind == "unlock_funds" else source_ref
    balance = available(state, debit_ref) if debit_ref in state.accounts else None
    tier_basis: dict[str, JsonValue] = {
        "business_date": business_date(when),
        "total_before": rational(before),
        "total_after": rational(after),
        "commitment_ids": cast(list[JsonValue], sorted(obligations)),
        "principal_financial_version": financial_version(state, action.principal),
    }
    digest = H(dependency_hashes(action, cert, state))
    card: dict[str, JsonValue] = {
        "principal_token": "CUSTOMER_" + H(action.principal)[:16],
        "kind": action.kind,
        "objects": cast(dict[str, JsonValue], args),
        "amount": rational(amount) if amount is not None else None,
        "ccy": "CNY",
        "fees": None,
        "tier": tier,
        "tier_reasons": reasons,
        "total_before": rational(before),
        "total_after": rational(after),
        "available": rational(balance) if balance is not None else None,
        "business_date": business_date(when),
        "execution_window": {"start": spa.start, "end": spa.end} if spa else None,
        "risk": None,
        "best_interest": None,
        "irreversible": action.kind in OUTGOING,
        "dependency_hash": digest,
        "business_context_hash": business_context_hash(action, cert, state),
        "action_hash": H(action),
        "intent_id": action.intent_id,
        "plan_hash": action.plan_hash,
        "node_id": action.node_id,
        "device_session_id": action.device_session_id,
        "spa_hash": H(spa) if spa else None,
        "spa": {
            "source_ref": spa.source_ref,
            "target": cast(dict[str, JsonValue], spa.target.model_dump(mode="json")),
            "destination_version": spa.destination_version,
            "amount": rational(spa.amount),
            "schedule": cast(dict[str, JsonValue], spa.schedule.model_dump(mode="json")),
            "start": spa.start,
            "expiry": spa.end,
            "max_runs": spa.max_runs,
            "creation_tier": spa.creation_tier,
        }
        if spa
        else None,
    }
    if action.kind in CARD_KINDS:
        card["card_change"] = card_facts(action, state)
    if action.kind == "redeem_product":
        position = state.positions[str(args["position_ref"])]
        product = next(item for item in state.catalog.products if item.id == position.product_ref)
        if amount is None:
            raise ValueError("PROV-MISMATCH")
        redemption = price_redemption(product, position, amount, state.now)
        account_ref = resolve_redemption_account(position, action.principal, state)
        card.update(
            fees=rational(redemption.fees),
            fee_breakdown={
                "fee_hold": rational(redemption.fee_hold),
                "fee_sell": rational(redemption.fee_sell),
            },
            net_proceeds=rational(redemption.net_proceeds),
            return_account_ref=account_ref,
            settlement_date=business_date(redemption.settle_at),
            available=rational(available(state, account_ref)),
        )
    if action.kind == "allocation_compare":
        allocation_evaluation = evaluate_allocation(
            action.principal, action.intent_id, str(args["request_ref"]), state
        )
        if allocation_evaluation.certificate is not None:
            card["allocation"] = allocation_evaluation.certificate.model_dump(mode="json")
            if allocation_evaluation.certificate.selection_mode != "default":
                card["deviation_notice"] = "Deviation from model allocation"
                deviations = allocation_evaluation.certificate.deviations
                if deviations is not None:
                    card["deviation_percentage_points"] = {
                        item.sleeve: rational(item.weight_delta * 100)
                        for item in deviations.sleeves
                    }
        if allocation_evaluation.failure is not None:
            card["allocation_failure"] = allocation_evaluation.failure.model_dump(mode="json")
        if allocation_evaluation.request is not None:
            source_ref = allocation_evaluation.request.source_account_ref
            card["available"] = rational(available(state, source_ref))
        card["projection_notice"] = "Projected, not guaranteed. Synthetic new-money allocation."
        card["allocation_claim"] = "Sponsor-independent within the declared catalogue and policy."
    if action.kind == "purchase_product" and args.get("allocation_ref"):
        from corridor.kernel.allocation_execution import inspect_allocation_plan

        execution = inspect_allocation_plan(str(args["allocation_ref"]), state, require_ready=False)
        if execution.plan is not None:
            parent = execution.plan
            item = next(
                (
                    entry
                    for entry in parent.items
                    if entry.item_ref == args.get("allocation_item_ref")
                ),
                None,
            )
            card["allocation_execution"] = {
                "allocation_ref": parent.id,
                "parent_intent_id": parent.parent_intent_id,
                "parent_plan_hash": parent.plan_hash,
                "biac_hash": parent.biac_hash,
                "allocation_item_ref": str(args["allocation_item_ref"]),
                "initial_budget": rational(parent.initial_budget),
                "current_budget": rational(execution.current_budget),
                "settled_debit": rational(execution.settled_debit),
                "remaining_debit": rational(execution.remaining_debit),
                "settled_item_refs": list(execution.settled_item_refs),
                "remaining_item_refs": list(execution.remaining_item_refs),
                "control_status": execution.control_status,
            }
            if item is not None:
                card["fees"] = rational(item.fee_buy)
                card["total_debit"] = rational(item.principal + item.fee_buy)
        if execution.certificate is not None:
            biac = execution.certificate
            card["allocation"] = biac.model_dump(mode="json")
            if biac.selection_mode != "default":
                card["deviation_notice"] = "Deviation from model allocation"
                if biac.deviations is not None:
                    card["deviation_percentage_points"] = {
                        entry.sleeve: rational(entry.weight_delta * 100)
                        for entry in biac.deviations.sleeves
                    }
        card["projection_notice"] = "Projected, not guaranteed. Synthetic new-money allocation."
        card["execution_notice"] = (
            "Each purchase requires approval and MFA. "
            "Partial execution cannot be rolled back automatically."
        )
    if action.kind in {"product_compare", "purchase_product"} and not args.get("allocation_ref"):
        evaluation = evaluate_investment(action, state)
        bic = evaluation.certificate
        details: dict[str, JsonValue] = {
            "exclusions": cast(dict[str, JsonValue], evaluation.exclusions),
            "projection_notice": "Expected return is a synthetic projection, not a guarantee.",
        }
        if bic is not None:
            details.update(bic.model_dump(mode="json"))
            chosen = next(
                (row for row in bic.rows if row.product_id == bic.chosen_product_id), None
            )
            if chosen is not None:
                details.update(chosen_rank=chosen.rank, chosen_gap=rational(chosen.gap))
                card["fees"] = rational(chosen.fee_buy)
            preference = evaluation.preference
            if preference is not None:
                details["gap_unit"] = "days" if preference.objective == "liquidity" else "CNY"
                details["reason_code"] = preference.reason_code
                if action.kind == "product_compare":
                    source_ref = preference.source_account_ref
                    card["available"] = rational(available(state, source_ref))
                details["choice_notice"] = (
                    "Non-leading product explicitly selected by the user."
                    if not bic.best_choice
                    else "First under the declared objective."
                )
        card["best_interest"] = details
    if action.kind in {"product_compare", "purchase_product", "allocation_compare"}:
        card["risk"] = _suitability_projection(action, state)
    facts: dict[str, JsonValue] = {
        "amount": card["amount"],
        "source_ref": source_ref or None,
        "destination_ref": contact.destination_ref
        if contact
        else (merchant.destination_ref if merchant else None),
        "intent_key": key,
        "card_core": card,
    }
    return Binding(tier, tier_basis, card, digest, facts, amount, key)
