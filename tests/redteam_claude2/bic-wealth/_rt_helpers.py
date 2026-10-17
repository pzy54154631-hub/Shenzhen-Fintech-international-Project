"""Red-team helpers: build plans/actions under an attacker-chosen intent id.

These reuse the bench BankCase harness (real Gateway, real MockBank, real kernel).
The attacker controls only planner-visible material: plan, action args, cert.
"""

from typing import Any

from corridor.bench.bank_cases import BankCase, PreparedCase
from corridor.crypto.jcs import H
from corridor.kernel.binding import dependency_hashes
from corridor.kernel.investment import evaluate_investment
from corridor.schemas.bank import BankAction, BankCertificate, Plan, PlanNode
from corridor.sim.keys import stable_id


def planner_prepare(
    case: BankCase,
    kind: str,
    args: dict[str, Any],
    terms: dict[str, Any],
    *,
    intent_id: str,
    tag: str,
    goal_input_refs: list[str],
    authorization_ref: str | None = None,
    bic: bool = False,
) -> PreparedCase:
    """A hijacked planner registers its own plan and proposes an action."""
    node = PlanNode.model_validate({
        "node_id": stable_id(case.identity, 0, f"rt-node-{tag}"),
        "tool": kind,
        "args": terms,
    })
    plan = Plan(
        plan_id=stable_id(case.identity, 0, f"rt-plan-{tag}"),
        revision=1,
        principal=case.device.principal,
        device_session_id=case.session,
        intent_id=intent_id,
        goal_input_refs=goal_input_refs,
        nodes=[node],
        ownership_epoch=0,
    )
    registration = case.gateway.submit_plan(plan)
    assert registration.status == "registered", registration.rule_ids
    action = BankAction.model_validate({
        "action_id": stable_id(case.identity, 0, f"rt-action-{tag}"),
        "intent_id": intent_id,
        "principal": case.device.principal,
        "device_session_id": case.session,
        "plan_id": plan.plan_id,
        "plan_hash": H(plan),
        "node_id": node.node_id,
        "kind": kind,
        "args": args,
    })
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=authorization_ref or case.session_authorization.id,
        derivations={f"args.{name}": term for name, term in terms.items()},
        dependency_hashes={},
        best_interest=evaluate_investment(action, case.state).certificate if bic else None,
    )
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(action, cert, case.state)}
    )
    return PreparedCase(action, cert, plan, case.gateway.propose(action, cert))


def current_risk_level(case: BankCase) -> int:
    state = case.state
    customer = state.customers[case.device.principal]
    return state.risk_assessments[customer.risk_profile_ref or ""].level
