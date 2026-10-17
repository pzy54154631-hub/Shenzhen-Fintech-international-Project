"""Gateway-owned plan compilation and simulated-clock orchestration.

Every execution below re-enters Gateway.dispatch; this module never calls a bank
executor or synthesizes approval tokens.
"""

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from corridor.crypto.jcs import H
from corridor.kernel.allocation import build_allocation
from corridor.kernel.binding import binding, dependency_hashes, mfa_scope
from corridor.kernel.investment import build_best_interest
from corridor.schemas.bank import (
    BankAction,
    BankCertificate,
    InputTerm,
    OperationAuthorization,
    Plan,
    ReadTerm,
    ReceiptTerm,
    ScheduledPaymentAuthorization,
    SessionAuthorization,
    StateTerm,
    Term,
)
from corridor.schemas.time import parse_time
from corridor.stores.bank import latest_events

if TYPE_CHECKING:
    from corridor.gateway.service import Gateway, GatewayResult


def _node_terms(
    gateway: "Gateway", plan: Plan, node_id: str, *, check_current: bool = True
) -> dict[str, Term]:
    from corridor.gateway.plans import resolve_node_terms

    snapshot = gateway.plan_snapshot(plan.plan_id)
    outputs = {
        key: value["receipt_ref"]
        for key, value in snapshot["nodes"].items()
        if value["status"] == "succeeded" and value.get("receipt_ref")
    }
    return resolve_node_terms(
        plan, node_id, gateway.store.snapshot(), outputs, check_current=check_current
    )


def _arguments(
    gateway: "Gateway",
    plan: Plan,
    terms: dict[str, Term],
    spa: ScheduledPaymentAuthorization | None,
) -> dict[str, Any]:
    state = gateway.store.snapshot()
    args: dict[str, Any] = {}
    for key, term in terms.items():
        field = key.split(".")[0]
        if isinstance(term, StateTerm):
            if term.field == "offers":
                offers = state.merchants[term.object_ref].offers
                target = spa.target.model_dump() if spa else {}
                value = target.get("offer_ref")
                if value is None and len(offers) == 1:
                    value = offers[0].id
                if value is None:
                    raise ValueError("PROV-AMBIGUOUS")
            else:
                value = term.object_ref
        elif isinstance(term, InputTerm):
            item = state.user_inputs[term.input_ref]
            if field in {"allocation_ref", "allocation_item_ref"}:
                if item.slot != "allocation_binding" or not isinstance(item.value, dict):
                    raise ValueError("PROV-FIELD")
                value = item.value[field]
            else:
                value = item.id if field.endswith("_ref") else item.value
        elif isinstance(term, ReceiptTerm):
            value = term.receipt_ref
        elif isinstance(term, ReadTerm):
            value = term.value
        else:
            raise ValueError("PROV-FIELD")
        if "." in key:
            _, index = key.split(".")
            entries = args.setdefault(field, {})
            entries[int(index)] = value
        else:
            args[field] = value
    for key, value in list(args.items()):
        if isinstance(value, dict) and value and all(type(index) is int for index in value):
            if sorted(value) != list(range(len(value))):
                raise ValueError("PROV-FIELD")
            args[key] = [value[index] for index in sorted(value)]
    return args


def compile_node(
    gateway: "Gateway", plan: Plan, node_id: str, *, run_id: str | None = None
) -> tuple[BankAction, BankCertificate]:
    from corridor.gateway.service import _id

    state = gateway.store.snapshot()
    node = next(item for item in plan.nodes if item.node_id == node_id)
    run = state.schedules.get(run_id or "")
    spa = state.authorizations.get(run.spa_ref) if run else None
    if spa is not None and not isinstance(spa, ScheduledPaymentAuthorization):
        raise ValueError("DOMAIN-SPA")
    # Preserve a run's registered scope so the kernel can reject current-state
    # drift and the gateway can record the genuine period as skipped.
    terms = _node_terms(gateway, plan, node_id, check_current=run is None)
    if run is not None:
        terms.pop("schedule_ref", None)
    args = _arguments(gateway, plan, terms, spa)
    kind = spa.target.kind if spa else node.tool
    if spa is not None:
        args.pop("schedule_ref", None)
        if kind == "merchant_order":
            args.pop("amount_ref", None)
            terms.pop("amount_ref", None)
    action = BankAction.model_validate({
        "action_id": run.id if run else _id(plan.plan_id, plan.revision, f"node-{node_id}"),
        "intent_id": spa.id if spa else plan.intent_id,
        "principal": plan.principal,
        "device_session_id": state.security.active_device_sessions.get(
            plan.principal, plan.device_session_id
        )
        if spa
        else plan.device_session_id,
        "plan_id": plan.plan_id,
        "plan_hash": H(plan),
        "node_id": node_id,
        "kind": kind,
        "args": args,
    })
    authority: ScheduledPaymentAuthorization | SessionAuthorization | OperationAuthorization
    if spa is not None:
        authority = spa
    elif kind in {
        "balance_query",
        "transactions_query",
        "bill_analyze",
        "bill_report",
        "anomaly_query",
        "risk_assess",
        "product_compare",
        "allocation_compare",
        "investment_income_query",
        "sandbox_analyze",
    }:
        session_authorities = [
            item
            for item in state.authorizations.values()
            if isinstance(item, SessionAuthorization)
            and item.principal == plan.principal
            and item.device_session_id == plan.device_session_id
            and kind in item.read_kinds
            and item.expires_at > state.now
        ]
        if not session_authorities:
            raise ValueError("AUTH-SCOPE")
        authority = sorted(session_authorities, key=lambda item: item.id)[0]
    else:
        required_inputs = {
            H(state.user_inputs[term.input_ref])
            for term in terms.values()
            if isinstance(term, InputTerm)
        }
        required_objects = {
            term.object_ref for term in terms.values() if isinstance(term, StateTerm)
        }
        operation_authorities = [
            item
            for item in state.authorizations.values()
            if isinstance(item, OperationAuthorization)
            and item.principal == plan.principal
            and item.intent_id == plan.intent_id
            and item.allowed_kind == kind
            and item.expires_at > state.now
            and required_inputs <= set(item.input_hashes)
            and required_objects <= set(item.object_refs)
        ]
        if len(operation_authorities) != 1:
            raise ValueError("AUTH-SCOPE")
        authority = operation_authorities[0]
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=authority.id,
        derivations={f"args.{key}": term for key, term in terms.items()},
        dependency_hashes={},
    )
    if kind == "allocation_compare":
        cert = cert.model_copy(
            update={
                "allocation": build_allocation(
                    action.principal, action.intent_id, str(args["request_ref"]), state
                )
            }
        )
    elif kind == "purchase_product" and args.get("allocation_ref"):
        from corridor.kernel.allocation_execution import inspect_allocation_plan

        execution = inspect_allocation_plan(str(args["allocation_ref"]), state)
        if execution.errors or execution.certificate is None:
            raise ValueError(execution.errors[0] if execution.errors else "PLAN-SCOPE")
        cert = cert.model_copy(update={"allocation": execution.certificate})
    elif kind in {"purchase_product", "product_compare"}:
        cert = cert.model_copy(update={"best_interest": build_best_interest(action, state)})
    cert = cert.model_copy(update={"dependency_hashes": dependency_hashes(action, cert, state)})
    if spa is not None:
        scope = mfa_scope(action, H(binding(action, cert, state).card_core))
        grants = [
            grant.grant_id
            for grant in state.security.mfa_grants.values()
            if grant.principal == plan.principal
            and grant.scope_hash == scope
            and grant.issued_at <= state.now < grant.expiry
            and grant.grant_id not in state.security.consumed_grant_ids
        ]
        if len(grants) == 1:
            cert = cert.model_copy(update={"mfa_grant_refs": grants})
    return action, cert


def advance_plan(gateway: "Gateway", plan_id: str, ownership_epoch: int) -> list["GatewayResult"]:
    from corridor.gateway.plans import node_due_at, topological_order
    from corridor.gateway.service import GatewayResult

    plan = gateway._plans.get(plan_id)
    if plan is None:
        return [GatewayResult("rejected", ["PLAN-SCHEMA"])]
    if plan.ownership_epoch != ownership_epoch or plan_id in gateway._handoff_plans:
        return [GatewayResult("rejected", ["PLAN-OWNER"])]
    if plan_id in gateway._blocked_plans:
        return [GatewayResult("rejected", ["APR-VOID"])]
    results = []
    for node_id in topological_order(plan):
        snapshot = gateway.plan_snapshot(plan_id)
        node = next(item for item in plan.nodes if item.node_id == node_id)
        status = snapshot["nodes"][node_id]["status"]
        due = node_due_at(plan, node_id, gateway.store.snapshot())
        if due is not None and gateway.store.snapshot().now < due:
            continue
        runs = sorted(
            (
                run
                for run in gateway.store.snapshot().schedules.values()
                if run.plan_id == plan_id and run.node_id == node_id
            ),
            key=lambda run: run.run_index,
        )
        for run in runs:
            if (
                run.status in {"pending", "due", "waiting_mfa"}
                and gateway.store.snapshot().now >= run.expires_at
            ):
                gateway._schedule_status(run.id, "expired")
                gateway._audit("schedule_expired", plan.principal, {"run_id": run.id})
        runs = [gateway.store.snapshot().schedules[run.id] for run in runs]
        if any(snapshot["nodes"][ref]["status"] != "succeeded" for ref in node.depends_on):
            continue
        if runs:
            for run in runs:
                state = gateway.store.snapshot()
                if run.status not in {"pending", "due", "waiting_mfa"} or state.now < run.due_at:
                    continue
                try:
                    action, cert = compile_node(gateway, plan, node_id, run_id=run.id)
                    result = gateway.dispatch(action, cert)
                    if result.status == "rejected" and gateway.store.snapshot().schedules[
                        run.id
                    ].status in {"pending", "due", "waiting_mfa"}:
                        gateway._schedule_status(
                            run.id, "expired" if state.now >= run.expires_at else "skipped"
                        )
                    results.append(result)
                except (ValueError, KeyError, TypeError) as exc:
                    gateway._schedule_status(
                        run.id, "expired" if state.now >= run.expires_at else "skipped"
                    )
                    gateway._audit(
                        "schedule_skipped", plan.principal, {"run_id": run.id, "reason": str(exc)}
                    )
                    results.append(GatewayResult("rejected", ["DOMAIN-SPA"]))
            continue
        if status not in {"pending", "ready", "waiting_input", "waiting_approval", "waiting_mfa"}:
            continue
        try:
            action, cert = compile_node(gateway, plan, node_id)
        except (ValueError, KeyError, TypeError):
            gateway._node_status(plan_id, node_id, "waiting_input")
            results.append(GatewayResult("waiting_input", ["AUTH-SCOPE"]))
            continue
        proposal = gateway.propose(action, cert, request_id=H({"action": action, "cert": cert}))
        if proposal.verdict.outcome == "Reject":
            gateway._node_status(plan_id, node_id, "failed")
            details = {}
            if "APR-BUDGET" in proposal.verdict.rule_ids:
                budget = gateway.allocation_approval_budget(
                    str(action.args.model_dump()["allocation_ref"])
                )
                details = {"approval_budget": budget, "message": budget["message"]}
            results.append(
                GatewayResult(
                    "rejected", proposal.verdict.rule_ids, verdict=proposal.verdict, details=details
                )
            )
        elif proposal.verdict.tier == "green":
            results.append(gateway.query(action, cert))
        else:
            status = "waiting_mfa" if proposal.verdict.outcome == "Escalate" else "waiting_approval"
            gateway._node_status(plan_id, node_id, status)
            results.append(
                GatewayResult(
                    status,
                    verdict=proposal.verdict,
                    details={
                        "action": action.model_dump(mode="json"),
                        "cert": cert.model_dump(mode="json"),
                        "card": proposal.card,
                    },
                )
            )
    return results


def compensation_suggestions(
    gateway: "Gateway", plan_id: str, node_id: str | None
) -> list[dict[str, Any]]:
    from corridor.gateway.plans import topological_order

    plan = gateway._plans[plan_id]
    state = gateway.store.snapshot()
    suggestions = []
    for ref in reversed(topological_order(plan)):
        if node_id is not None and ref != node_id:
            continue
        events = [
            event
            for event in latest_events(state).values()
            if event.principal == plan.principal
            and event.event == "settled"
            and isinstance(saved_action := event.object_delta.get("action"), dict)
            and saved_action.get("plan_id") == plan_id
            and saved_action.get("node_id") == ref
        ]
        if not events:
            continue
        event = events[-1]
        original = BankAction.model_validate(event.object_delta["action"])
        args = original.args.model_dump(mode="python")
        suggestion: dict[str, Any] = {"node_id": ref, "receipt_ref": event.bank_receipt_id}
        if event.kind == "lock_funds" and event.debit:
            suggestion.update(
                tool="unlock_funds",
                source_ref=args["source_ref"],
                locked_ref=args["locked_ref"],
                amount=str(event.debit.amount),
                purpose={"original_receipt_ref": event.bank_receipt_id},
            )
        elif event.kind in {"transfer", "merchant_order"}:
            gateway._node_status(plan_id, ref, "non_reversible", event.bank_receipt_id)
            suggestion.update(tool="refund_request")
        elif event.kind == "purchase_product":
            suggestion.update(tool="redeem_product")
        else:
            continue
        suggestions.append(suggestion)
    return suggestions


def birthday_suggestions(gateway: "Gateway", principal: str) -> list[dict[str, str]]:
    state = gateway.store.snapshot()
    if principal not in state.customers:
        raise ValueError("READ-ROLE")
    suggestions = []
    for event in state.calendar.values():
        if event.owner != principal or event.event_type != "birthday":
            continue
        due = (parse_time(event.event_date + "T00:00:00Z") - timedelta(days=2, hours=8)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        if due >= state.now:
            suggestions.append({
                "event_ref": event.id,
                "due_at": due,
                "contact_ref": event.person_contact_ref,
            })
    return sorted(suggestions, key=lambda item: (item["due_at"], item["event_ref"]))
