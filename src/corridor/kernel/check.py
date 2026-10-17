"""Pure bank authorization, source, state and execution-tier checking."""

import re
from datetime import date, timedelta
from fractions import Fraction
from typing import Any, Literal

from pydantic import ValidationError

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT, MFA, RECEIPT, SPA, verify
from corridor.kernel.allocation import allocation_errors
from corridor.kernel.binding import Binding, binding, dependency_hashes, mfa_scope, resolve_amount
from corridor.kernel.cards import CARD_KINDS, card_errors, card_request
from corridor.kernel.investment import investment_errors, risk_upgrade_review
from corridor.kernel.planning import aa_bill_total, compensation_errors, refund_requested
from corridor.kernel.rules import RULES
from corridor.kernel.spa import inspect_spa, is_cancelled
from corridor.schemas.bank import (
    AuthorizationRevocation,
    BankAction,
    BankCertificate,
    BankReceipt,
    BusinessEvent,
    InputTerm,
    NodeOutputTerm,
    OperationAuthorization,
    ReadTerm,
    ReceiptTerm,
    ScheduledPaymentAuthorization,
    SessionAuthorization,
    StateTerm,
    UserInput,
)
from corridor.schemas.base import Model, loads_exact
from corridor.schemas.models import Accept, Escalate, Reject
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time
from corridor.stores.bank import available, latest_events

_GREEN = frozenset({
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
_ANALYSIS_FUNCTIONS = {
    "bill_analyze": "bill_summary_v1",
    "bill_report": "bill_summary_v1",
    "anomaly_query": "anomaly_v1",
}
_SUPPORTED = (
    _GREEN
    | CARD_KINDS
    | {
        "subscription_query",
        "subscription_reminders",
        "transfer",
        "schedule_transfer",
        "cancel_schedule",
        "cancel_subscription",
        "lock_funds",
        "unlock_funds",
        "merchant_order",
        "cancel_order",
        "refund_request",
        "password_change_request",
        "register_contact_request",
        "purchase_product",
        "redeem_product",
        "aa_request",
    }
)
_BLACK = frozenset({
    "set_policy",
    "set_permission",
    "set_risk_level",
    "set_contact_verified",
    "set_mfa",
    "bypass_approval",
    "request_secret",
})
_COLLECTIONS = {
    "account_ref": "accounts",
    "source_ref": "accounts",
    "locked_ref": "accounts",
    "contact_ref": "contacts",
    "merchant_ref": "merchants",
    "offer_ref": "merchants",
    "authorization_ref": "subscriptions",
    "order_ref": "orders",
    "schedule_ref": "authorizations",
    "principal": "customers",
    "product_ref": "catalog",
    "position_ref": "positions",
    "participant_refs": "contacts",
    "card_ref": "cards",
}
_GROUPS = {
    name: index
    for index, name in enumerate((
        "SCHEMA",
        "CERT",
        "BLACK",
        "AUTH",
        "PROV",
        "IDEM",
        "BAL",
        "DOMAIN",
        "BIC",
        "ALLOC",
        "TIER",
        "MFA",
    ))
}


def _sort_rules(errors: list[str]) -> list[str]:
    def order(rule: str) -> tuple[int, int]:
        group = "BLACK" if rule == "TIER-BLACK-KIND" else rule.split("-")[0]
        return _GROUPS.get(group, 99), list(RULES).index(rule)

    return sorted(set(errors), key=order)


def _reject(errors: list[str], facts: Binding | None = None) -> Reject:
    rules = _sort_rules(errors)
    return Reject(
        rule_ids=rules,
        first=rules[0],
        obligation=RULES[rules[0]].obligation,
        counterexample_code="bank_obligation_failed",
        **_details(facts),
    )


def _details(facts: Binding | None) -> dict[str, Any]:
    if facts is None:
        return {}
    return {
        "tier": facts.tier,
        "required_factors": []
        if facts.tier == "green"
        else (["device", "sms_sim"] if facts.tier == "red" else ["device"]),
        "dependency_hash": facts.dependency_hash,
        "tier_basis": facts.tier_basis,
        "verified_facts": facts.verified_facts,
    }


def _plain(value: Any) -> Any:
    if isinstance(value, Model):
        return value.model_dump(mode="python")
    if isinstance(value, (str, bytes, bytearray)):
        return loads_exact(value)
    return value


def _period(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9]{4}(?:-[0-9]{2}(?:-[0-9]{2})?)?", value) is None
    ):
        return False
    try:
        date.fromisoformat(
            value + ("-01-01" if len(value) == 4 else "-01" if len(value) == 7 else "")
        )
    except ValueError:
        return False
    return True


def _schema_rules(exc: ValueError, raw_cert: Any = None) -> list[str]:
    rules = ["SCHEMA-INVALID"]
    if isinstance(exc, ValidationError):
        locations = {str(item["loc"][0]) for item in exc.errors() if item["loc"]}
        if "catalog" in locations:
            rules.append("BIC-CATALOG")
        if "risk_assessments" in locations:
            rules.append("BIC-RISK")
        if "allocation_policies" in locations:
            rules.append("ALLOC-POLICY")
    text = str(exc).lower()
    if any(
        word in text
        for word in (
            "timestamp",
            "yyyy-mm-dd",
            "does not match format",
            "unconverted data",
            "time data",
        )
    ):
        rules.append("SCHEMA-TIME")
    if any(
        word in text
        for word in (
            "whole cents",
            "one cent",
            "positive whole",
            "ccy",
            "nonnegative",
            "must be positive",
        )
    ):
        rules.append("SCHEMA-UNIT")
    if isinstance(raw_cert, dict):
        derivations = raw_cert.get("derivations")
        if isinstance(derivations, dict) and any(
            not isinstance(term, (dict, Model))
            or (
                isinstance(term, dict)
                and isinstance(term.get("t"), str)
                and term.get("t") in {"literal", "const", "expression"}
            )
            for term in derivations.values()
        ):
            rules.append("PROV-LITERAL")
    return rules


def _revoked(state: BankState, authorization_ref: str, errors: list[str]) -> bool:
    result = False
    for auth in state.authorizations.values():
        if (
            not isinstance(auth, AuthorizationRevocation)
            or auth.authorization_ref != authorization_ref
        ):
            continue
        customer = state.customers.get(auth.principal)
        if customer is None or not verify(customer.device_pubkey, CONTROL, auth, auth.sig):
            errors.append("AUTH-SIG")
        if auth.revoked_at <= state.now:
            result = True
    return result


def _authority(
    action: BankAction, cert: BankCertificate, state: BankState, errors: list[str]
) -> None:
    customer = state.customers.get(action.principal)
    auth = state.authorizations.get(cert.authorization_ref)
    if customer is None or customer.principal != action.principal:
        errors.append("AUTH-PRINCIPAL")
    if auth is None or isinstance(auth, AuthorizationRevocation):
        errors.append("AUTH-SCOPE")
        return
    spa_run = isinstance(auth, ScheduledPaymentAuthorization) and action.kind != "schedule_transfer"
    if (
        not spa_run
        and state.security.active_device_sessions.get(action.principal) != action.device_session_id
    ):
        errors.append("AUTH-PRINCIPAL")
    if auth.principal != action.principal:
        errors.append("AUTH-PRINCIPAL")
    if customer is not None:
        ctx = SPA if isinstance(auth, ScheduledPaymentAuthorization) else CONTROL
        if not verify(customer.device_pubkey, ctx, auth, auth.sig):
            errors.append("AUTH-SIG")
    if _revoked(state, auth.id, errors):
        errors.append("AUTH-SCOPE")
    if isinstance(auth, OperationAuthorization):
        if auth.allowed_kind != action.kind or auth.expires_at <= state.now:
            errors.append("AUTH-SCOPE")
        if auth.intent_id != action.intent_id:
            errors.extend(["AUTH-SCOPE", "IDEM-KEY"])
        if _authorization_uses(auth, state):
            errors.append("AUTH-CONSUMED")
    elif isinstance(auth, SessionAuthorization):
        if (
            action.kind not in _GREEN
            or action.kind not in auth.read_kinds
            or auth.expires_at <= state.now
            or auth.device_session_id != action.device_session_id
        ):
            errors.append("AUTH-SCOPE")


def _authorization_uses(auth: OperationAuthorization, state: BankState) -> list[BusinessEvent]:
    """Find effective uses, preserving references across appended terminal events.

    A failed terminal event releases its reservation. Legacy events may carry
    only the signed intent or the immediate key rather than the certificate.
    """
    matching_keys: set[str] = set()
    immediate_key = H({
        "principal": auth.principal,
        "intent_id": auth.intent_id,
        "kind": auth.allowed_kind,
    })
    for event in state.ledger:
        if event.principal != auth.principal:
            continue
        delta = event.object_delta
        recorded_cert = delta.get("cert")
        recorded_action = delta.get("action")
        if (
            delta.get("authorization_ref") == auth.id
            or isinstance(recorded_cert, dict)
            and recorded_cert.get("authorization_ref") == auth.id
            or isinstance(recorded_action, dict)
            and recorded_action.get("intent_id") == auth.intent_id
            and recorded_action.get("kind") == auth.allowed_kind
            or event.intent_key == immediate_key
        ):
            matching_keys.add(event.intent_key)
    return [
        event
        for key, event in latest_events(state).items()
        if key in matching_keys and event.event != "failed"
    ]


def _input(
    input_ref: str, action: BankAction, cert: BankCertificate, state: BankState, errors: list[str]
) -> UserInput | None:
    value = state.user_inputs.get(input_ref)
    if value is None:
        errors.append("PROV-MISMATCH")
        return None
    customer = state.customers.get(action.principal)
    if value.principal != action.principal:
        errors.append("AUTH-PRINCIPAL")
    if customer is None or not verify(customer.device_pubkey, INPUT, value, value.sig):
        errors.append("AUTH-SIG")
    if value.scope_id != action.intent_id:
        errors.append("PROV-COHERENCE")
    if value.submitted_at > state.now or any(
        item.supersedes == value.id for item in state.user_inputs.values()
    ):
        errors.append("PROV-STALE")
    auth = state.authorizations.get(cert.authorization_ref)
    if isinstance(auth, OperationAuthorization) and H(value) not in auth.input_hashes:
        errors.append("AUTH-SCOPE")
    return value


def _state_term(
    field: str,
    argument: Any,
    term: StateTerm,
    action: BankAction,
    cert: BankCertificate,
    state: BankState,
    errors: list[str],
) -> None:
    expected = _COLLECTIONS.get(field.split(".")[0])
    if term.collection != expected:
        errors.append("PROV-FIELD")
        return
    collection = getattr(state, term.collection)
    obj: Any = (
        next((product for product in state.catalog.products if product.id == term.object_ref), None)
        if term.collection == "catalog"
        else collection.get(term.object_ref)
    )
    if obj is None:
        errors.append("PROV-MISMATCH")
        return
    if obj.version != term.version:
        errors.append("PROV-STALE")
    owner = getattr(obj, "owner", getattr(obj, "principal", action.principal))
    if owner != action.principal:
        errors.append("AUTH-PRINCIPAL")
    auth = state.authorizations.get(cert.authorization_ref)
    if isinstance(auth, OperationAuthorization) and term.object_ref not in auth.object_refs:
        errors.append("AUTH-SCOPE")
    if field == "offer_ref":
        if isinstance(auth, OperationAuthorization) and argument not in auth.object_refs:
            errors.append("AUTH-SCOPE")
        args = action.args.model_dump(mode="python")
        if term.field != "offers":
            errors.append("PROV-FIELD")
        if term.object_ref != args.get("merchant_ref") or not any(
            offer.id == argument for offer in obj.offers
        ):
            errors.append("PROV-MISMATCH")
    else:
        if term.field != "id":
            errors.append("PROV-FIELD")
        if term.object_ref != argument or obj.id != argument:
            errors.append("PROV-MISMATCH")
    if field == "schedule_ref" and not isinstance(obj, ScheduledPaymentAuthorization):
        errors.append("PROV-FIELD")


def _card_origin(
    action: BankAction, cert: BankCertificate, state: BankState, errors: list[str]
) -> None:
    """Card controls require an exact signed request, never an agent assertion."""
    if action.kind not in CARD_KINDS or action.kind == "apply_virtual_card":
        return
    args = action.args.model_dump(mode="python")
    auth = state.authorizations.get(cert.authorization_ref)
    customer = state.customers.get(action.principal)
    if (
        not isinstance(auth, OperationAuthorization)
        or customer is None
        or auth.principal != action.principal
        or auth.intent_id != action.intent_id
        or auth.allowed_kind != action.kind
        or args["card_ref"] not in auth.object_refs
        or auth.expires_at <= state.now
        or not verify(customer.device_pubkey, CONTROL, auth, auth.sig)
    ):
        errors.append("TIER-BLACK-KIND")
    ref = args.get("change_ref")
    if ref is None and action.kind in {"report_card_lost", "restore_card"}:
        return
    term = cert.derivations.get("args.change_ref")
    if not isinstance(term, InputTerm) or term.input_ref != ref or term.slot != "card_change":
        errors.extend(["TIER-BLACK-KIND", "PROV-FIELD"])
    origin_errors: list[str] = []
    value = _input(str(ref), action, cert, state, origin_errors)
    if value is None or value.slot != "card_change":
        origin_errors.append("PROV-FIELD")
    try:
        request = card_request(action, state)
        if request is None or request.kind != action.kind or request.card_ref != args["card_ref"]:
            origin_errors.append("PROV-COHERENCE")
    except (KeyError, ValueError) as exc:
        origin_errors.extend(
            _schema_rules(exc) if isinstance(exc, ValueError) else ["PROV-MISSING"]
        )
    if origin_errors:
        errors.extend(["TIER-BLACK-KIND", *origin_errors])


def _receipt_term(
    field: str,
    argument: Any,
    term: ReceiptTerm,
    action: BankAction,
    cert: BankCertificate,
    state: BankState,
    errors: list[str],
) -> None:
    if action.kind == "aa_request" and field in {"source_bill_ref", "total_ref"}:
        expected_field = "net_spend" if field == "total_ref" else "receipt_id"
        if term.field != expected_field or term.receipt_ref != argument:
            errors.append("PROV-FIELD")
            return
        try:
            aa_bill_total(action, state)
        except ValueError as exc:
            errors.append(str(exc) if str(exc) == "DOMAIN-AA" else "PROV-MISMATCH")
        if term.receipt_ref not in cert.analysis_receipt_refs:
            errors.append("PROV-MISSING")
        auth = state.authorizations.get(cert.authorization_ref)
        if isinstance(auth, OperationAuthorization) and term.receipt_ref not in auth.object_refs:
            errors.append("AUTH-SCOPE")
        return
    if action.kind != "refund_request" or field != "receipt_ref" or term.field != "receipt_id":
        errors.append("PROV-FIELD")
        return
    receipt = state.receipts.get(term.receipt_ref)
    if not isinstance(receipt, BankReceipt) or receipt.receipt_id != argument:
        errors.append("PROV-MISMATCH")
        return
    if not verify(state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig):
        errors.append("AUTH-SIG")
    if not any(
        event.principal == action.principal and event.bank_receipt_id == receipt.receipt_id
        for event in state.ledger
    ):
        errors.append("AUTH-PRINCIPAL")
    auth = state.authorizations.get(cert.authorization_ref)
    if isinstance(auth, OperationAuthorization) and receipt.receipt_id not in auth.object_refs:
        errors.append("AUTH-SCOPE")


def _provenance(
    action: BankAction, cert: BankCertificate, state: BankState, errors: list[str]
) -> None:
    args = action.args.model_dump(mode="python")
    fields = {name: value for name, value in args.items() if name != "participant_refs"}
    if "participant_refs" in args:
        fields.update({
            f"participant_refs.{index}": value
            for index, value in enumerate(args["participant_refs"])
        })
    required = {f"args.{name}" for name, value in fields.items() if value is not None}
    if required - cert.derivations.keys():
        errors.append("PROV-MISSING")
    if cert.derivations.keys() - required:
        errors.append("PROV-FIELD")
    inputs: list[UserInput] = []
    for field, argument in fields.items():
        if argument is None:
            continue
        term = cert.derivations.get(f"args.{field}")
        if term is None:
            continue
        if isinstance(term, StateTerm):
            _state_term(field, argument, term, action, cert, state, errors)
        elif isinstance(term, InputTerm):
            if field not in {
                "amount_ref",
                "total_ref",
                "purpose_ref",
                "period",
                "draft_handle",
                "preference_ref",
                "request_ref",
                "allocation_ref",
                "allocation_item_ref",
                "answers_input_ref",
                "source_bill_ref",
                "change_ref",
            }:
                errors.append("PROV-FIELD")
                continue
            value = _input(term.input_ref, action, cert, state, errors)
            if value is None:
                continue
            inputs.append(value)
            expected_slot = {
                "amount_ref": "amount",
                "total_ref": "total",
                "purpose_ref": "purpose",
                "period": "period",
                "draft_handle": "draft_handle",
                "preference_ref": "preference",
                "request_ref": "allocation",
                "allocation_ref": "allocation_binding",
                "allocation_item_ref": "allocation_binding",
                "answers_input_ref": "answers",
                "source_bill_ref": "total",
                "change_ref": "card_change",
            }[field]
            if term.slot != value.slot or value.slot != expected_slot:
                errors.append("PROV-FIELD")
            if field in {"allocation_ref", "allocation_item_ref"}:
                if (
                    action.kind != "purchase_product"
                    or not isinstance(value.value, dict)
                    or argument != value.value.get(field)
                ):
                    errors.append("PROV-MISMATCH")
            elif field.endswith("_ref"):
                if argument != term.input_ref:
                    errors.append("PROV-MISMATCH")
            elif argument != value.value:
                errors.append("PROV-MISMATCH")
        elif isinstance(term, ReadTerm):
            auth = state.authorizations.get(cert.authorization_ref)
            if (
                action.kind not in _GREEN
                or not isinstance(auth, SessionAuthorization)
                or term.session_authorization_ref != cert.authorization_ref
                or field
                not in (
                    {"dataset_ref", "program_ref"}
                    if action.kind == "sandbox_analyze"
                    else {"period", "analysis_spec"}
                )
                or term.query_field != field
                or term.value != argument
                or (
                    not isinstance(argument, str)
                    or re.fullmatch(
                        ("DSET_" if field == "dataset_ref" else "PROG_") + "[a-p]{64}", argument
                    )
                    is None
                    if action.kind == "sandbox_analyze"
                    else not _period(argument)
                    if field == "period"
                    else argument != _ANALYSIS_FUNCTIONS.get(action.kind)
                )
            ):
                errors.append("PROV-FIELD")
        elif isinstance(term, ReceiptTerm):
            _receipt_term(field, argument, term, action, cert, state, errors)
        elif isinstance(term, NodeOutputTerm):
            errors.append("PROV-FIELD")
    auth = state.authorizations.get(cert.authorization_ref)
    if isinstance(auth, OperationAuthorization):
        referenced_hashes = set(auth.input_hashes)
        authorized = [
            value for value in state.user_inputs.values() if H(value) in referenced_hashes
        ]
        if len({H(value) for value in authorized}) != len(referenced_hashes):
            errors.append("AUTH-SCOPE")
        for value in authorized:
            checked = _input(value.id, action, cert, state, errors)
            if checked is not None:
                inputs.append(checked)
    elif isinstance(auth, ScheduledPaymentAuthorization):
        batch_ids = {item.batch_id for item in inputs}
        for value in state.user_inputs.values():
            if (
                value.principal == action.principal
                and value.scope_id == auth.id
                and value.batch_id in batch_ids
                and value.slot == "contact_ref"
            ):
                checked = _input(value.id, action, cert, state, errors)
                if checked is not None:
                    inputs.append(checked)
    if len({value.batch_id for value in inputs}) > 1:
        errors.append("PROV-COHERENCE")
    contact = state.contacts.get(str(args.get("contact_ref", "")))
    if contact is not None:
        choices = [value for value in inputs if value.slot == "contact_ref"]
        if any(value.value != contact.id for value in choices):
            errors.append("PROV-MISMATCH")
        candidates = [
            value
            for value in state.contacts.values()
            if value.owner == action.principal
            and (
                value.name_token == contact.name_token
                or value.phone_token == contact.phone_token
                or bool(set(value.aliases) & set(contact.aliases))
            )
        ]
        if len(candidates) > 1 and not any(value.value == contact.id for value in choices):
            errors.append("PROV-AMBIGUOUS")


def _domain(
    action: BankAction,
    cert: BankCertificate,
    state: BankState,
    amount: Fraction | None,
    errors: list[str],
) -> None:
    args = action.args.model_dump(mode="python")
    source = state.accounts.get(str(args.get("source_ref", args.get("account_ref", ""))))
    if source is not None:
        if source.status != "active":
            errors.append("DOMAIN-STATE")
        if (
            action.kind
            in {
                "transfer",
                "schedule_transfer",
                "lock_funds",
                "unlock_funds",
                "merchant_order",
                "purchase_product",
            }
            and source.kind != "current"
        ):
            errors.append("DOMAIN-STATE")
    if action.kind == "transfer" or (
        action.kind == "schedule_transfer" and args.get("contact_ref") is not None
    ):
        contact = state.contacts.get(str(args.get("contact_ref")))
        if contact is None or contact.verified_at is None or contact.verification_ref is None:
            errors.append("DOMAIN-STATE")
        elif contact.verified_at > state.now:
            errors.append("PROV-STALE")
    if action.kind in {"lock_funds", "unlock_funds"}:
        locked = state.accounts.get(str(args.get("locked_ref")))
        if (
            source is None
            or locked is None
            or locked.kind != "locked"
            or locked.status != "active"
            or locked.parent_ref != source.id
            or locked.owner != action.principal
        ):
            errors.append("DOMAIN-STATE")
    if action.kind == "cancel_subscription":
        subscription = state.subscriptions.get(str(args.get("authorization_ref")))
        if subscription is None or subscription.status != "active":
            errors.append("DOMAIN-STATE")
    if action.kind == "cancel_schedule":
        spa = state.authorizations.get(str(args.get("schedule_ref")))
        if (
            not isinstance(spa, ScheduledPaymentAuthorization)
            or _revoked(state, spa.id, errors)
            or is_cancelled(spa, state)
            or state.now >= spa.end
        ):
            errors.append("DOMAIN-SCHEDULE")
    if action.kind == "merchant_order":
        merchant = state.merchants.get(str(args.get("merchant_ref")))
        if merchant is None:
            errors.append("DOMAIN-STATE")
        else:
            offer = next(
                (offer for offer in merchant.offers if offer.id == args.get("offer_ref")), None
            )
            if offer is None or not offer.available:
                errors.append("DOMAIN-STATE")
    if action.kind == "cancel_order":
        order = state.orders.get(str(args.get("order_ref")))
        if order is None or order.status != "draft":
            errors.extend(["DOMAIN-STATE", "DOMAIN-COMPENSATION"])
        else:
            merchant = state.merchants.get(order.merchant_ref)
            offer = (
                next((offer for offer in merchant.offers if offer.id == order.offer_ref), None)
                if merchant
                else None
            )
            if offer is None or offer.cancel_until < state.now:
                errors.append("DOMAIN-STATE")
    if action.kind == "refund_request":
        receipt = state.receipts.get(str(args.get("receipt_ref")))
        if (
            not isinstance(receipt, BankReceipt)
            or receipt.status != "settled"
            or receipt.kind not in {"transfer", "merchant_order"}
        ):
            errors.append("DOMAIN-COMPENSATION")
        elif refund_requested(receipt.receipt_id, state):
            errors.append("DOMAIN-COMPENSATION")
    if action.kind == "password_change_request" and args.get("principal") != action.principal:
        errors.append("AUTH-PRINCIPAL")
    if amount is not None:
        if amount <= 0 or (amount * 100).denominator != 1:
            errors.append("SCHEMA-UNIT")
        auth = state.authorizations.get(cert.authorization_ref)
        if isinstance(auth, OperationAuthorization):
            used_amount = sum(
                (
                    event.debit.amount
                    for event in _authorization_uses(auth, state)
                    if event.debit is not None
                ),
                Fraction(0),
            )
            if auth.amount_bound is None or used_amount + amount > auth.amount_bound:
                errors.append("AUTH-SCOPE")
        debit_ref = (
            args.get("locked_ref") if action.kind == "unlock_funds" else args.get("source_ref")
        )
        if debit_ref in state.accounts and action.kind != "schedule_transfer":
            if available(state, debit_ref) - amount < state.accounts[debit_ref].floor:
                errors.append("BAL-AVAILABLE")


def _valid_mfa(
    action: BankAction, cert: BankCertificate, state: BankState, facts: Binding, errors: list[str]
) -> bool:
    if not cert.mfa_grant_refs:
        return False
    if len(cert.mfa_grant_refs) != 1:
        errors.append("MFA-INVALID")
        return False
    grant = state.security.mfa_grants.get(cert.mfa_grant_refs[0])
    customer = state.customers.get(action.principal)
    if grant is None or customer is None:
        errors.append("MFA-INVALID")
        return False
    valid = (
        verify(customer.mfa_pubkey, MFA, grant, grant.sig)
        and grant.principal == action.principal
        and grant.device_session_id == action.device_session_id
        and grant.method == "sms_sim"
        and grant.scope_hash == mfa_scope(action, H(facts.card_core))
        and grant.issued_at <= state.now < grant.expiry
        and parse_time(grant.expiry) - parse_time(grant.issued_at)
        <= timedelta(seconds=state.policy.mfa_ttl_seconds)
    )
    if not valid:
        errors.append("MFA-INVALID")
    return valid


def check(
    action: Any,
    cert: Any,
    S: Any,
    *,
    phase: Literal["propose", "dispatch"],
    approved_at: str | None = None,
) -> Accept | Reject | Escalate:
    """Revalidate every input; exceptions never become execution permission."""
    raw_cert: Any = None
    try:
        if phase not in {"propose", "dispatch"}:
            return _reject(["SCHEMA-INVALID"])
        if approved_at is not None:
            parse_time(approved_at)
        raw_cert = _plain(cert)
        parsed_action = BankAction.model_validate(_plain(action))
        parsed_cert = BankCertificate.model_validate(raw_cert)
        state = BankState.model_validate(_plain(S))
        return _check(parsed_action, parsed_cert, state, phase=phase, approved_at=approved_at)
    except (ValidationError, ValueError) as exc:
        return _reject(_schema_rules(exc, raw_cert))
    except (
        TypeError,
        KeyError,
        AttributeError,
        IndexError,
        StopIteration,
        ArithmeticError,
        RecursionError,
    ):
        return _reject(["SCHEMA-INVALID"])


def _check(
    action: BankAction,
    cert: BankCertificate,
    state: BankState,
    *,
    phase: str,
    approved_at: str | None,
) -> Accept | Reject | Escalate:
    errors: list[str] = []
    if approved_at is not None and approved_at > state.now:
        errors.append("SCHEMA-TIME")
    if any(event.ts > state.now for event in state.ledger):
        errors.append("SCHEMA-TIME")
    if cert.action_hash != H(action):
        errors.append("CERT-HASH")
    if action.kind in _BLACK:
        errors.append("TIER-BLACK-KIND")
    if action.kind not in _SUPPORTED or action.kind not in state.policy.tool_whitelist:
        if action.kind not in _BLACK:
            errors.append("TOOL-UNAVAILABLE")
    _authority(action, cert, state, errors)
    _card_origin(action, cert, state, errors)
    authority = state.authorizations.get(cert.authorization_ref)
    if action.kind == "schedule_transfer" and not isinstance(
        authority, ScheduledPaymentAuthorization
    ):
        errors.append("DOMAIN-SPA")
    run = state.schedules.get(action.action_id)
    if (
        run is not None
        and action.kind != "schedule_transfer"
        and (
            not isinstance(authority, ScheduledPaymentAuthorization) or authority.id != run.spa_ref
        )
    ):
        errors.extend(["DOMAIN-SPA", "IDEM-KEY"])
    if action.kind in _SUPPORTED:
        _provenance(action, cert, state, errors)
    try:
        if cert.dependency_hashes != dependency_hashes(action, cert, state):
            errors.append("CERT-HASH")
    except (KeyError, AttributeError, TypeError, ValueError):
        errors.append("CERT-HASH")
    amount: Fraction | None = None
    try:
        amount = resolve_amount(action, state)
    except (KeyError, ValueError, StopIteration):
        errors.append("PROV-MISMATCH")
    if action.kind in _SUPPORTED:
        _domain(action, cert, state, amount, errors)
        allocation_purchase = action.kind == "purchase_product" and bool(
            action.args.model_dump().get("allocation_ref")
        )
        if not allocation_purchase:
            errors.extend(investment_errors(action, cert, state))
        errors.extend(allocation_errors(action, cert, state))
        errors.extend(compensation_errors(action, state, amount))
        errors.extend(card_errors(action, state))
    if action.kind == "aa_request":
        args = action.args.model_dump(mode="python")
        participants = args["participant_refs"]
        if args["source_bill_ref"] != args["total_ref"]:
            errors.append("PROV-COHERENCE")
        if (
            amount is None
            or amount * 100 < len(participants)
            or any(
                not ref.isascii()
                or ref not in state.contacts
                or state.contacts[ref].owner != action.principal
                for ref in participants
            )
        ):
            errors.append("DOMAIN-AA")
    spa = inspect_spa(action, cert, state, amount)
    errors.extend(spa.errors)
    if spa.is_spa and any(
        rule in errors
        for rule in (
            "BAL-AVAILABLE",
            "AUTH-SCOPE",
            "AUTH-SIG",
            "AUTH-PRINCIPAL",
            "PROV-MISMATCH",
            "PROV-STALE",
            "PROV-COHERENCE",
            "DOMAIN-STATE",
        )
    ):
        errors.append("DOMAIN-SPA")
    facts: Binding | None = None
    try:
        facts = binding(action, cert, state)
    except (KeyError, ValueError, StopIteration, AttributeError):
        errors.append("PROV-MISMATCH")
    if facts is not None:
        has_mfa = _valid_mfa(action, cert, state, facts, errors)
        if errors:
            return _reject(errors, facts)
        if risk_upgrade_review(action, state):
            return Escalate(
                rule_ids=["RISK-UPGRADE-REVIEW"],
                reasons=["advisor_review_required_after_refused_purchase"],
                **_details(facts),
            )
        if facts.tier == "red" and not has_mfa and not spa.grant_exempt:
            rule = "DOMAIN-SPA-TIER" if spa.is_spa and not spa.is_creation else "TIER-MFA-REQUIRED"
            return Escalate(
                rule_ids=[rule],
                reasons=["independent_device_verification_required"],
                **_details(facts),
            )
        return Accept(**_details(facts))
    return _reject(errors or ["SCHEMA-INVALID"])
