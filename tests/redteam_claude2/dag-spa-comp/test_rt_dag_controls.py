"""Red-team: DAG shape limits, Stop/handoff/resume semantics (DESIGN-BANK 7.1-7.3)."""

import pytest
from pydantic import ValidationError

from corridor.bench.bank_cases import BankCase
from corridor.crypto.jcs import H
from corridor.schemas.bank import Plan, PlanNode, StateTerm
from corridor.sim.fixtures import make_state
from corridor.sim.keys import stable_id


def _account():
    return StateTerm(collection="accounts", object_ref="A_CURRENT", field="id", version=1)


def _plan(case, nodes):
    return Plan(
        plan_id=stable_id(case.identity, 0, "plan"),
        revision=1,
        principal=case.device.principal,
        device_session_id=case.session,
        intent_id=case.intent(),
        goal_input_refs=[],
        nodes=nodes,
        ownership_epoch=0,
    )


def _chain(case):
    acct = _account()
    return _plan(
        case,
        [
            PlanNode(node_id="A", tool="balance_query", args={"account_ref": acct}),
            PlanNode(
                node_id="B", tool="balance_query", args={"account_ref": acct}, depends_on=["A"]
            ),
            PlanNode(
                node_id="C", tool="balance_query", args={"account_ref": acct}, depends_on=["B"]
            ),
        ],
    )


def _resume(case, plan_id):
    scope = case.gateway.resume_scope(plan_id)
    confirmation = case.device.confirm_input(
        intent_id=H(scope), slot="plan_resume", value=scope, now=case.state.now
    )
    return case.gateway.resume(plan_id, confirmation)


def test_self_loop_is_a_cycle():
    case = BankCase(make_state(), task_id="RT2-DAG", subcase_id="self-loop")
    plan = _plan(
        case,
        [
            PlanNode(
                node_id="A",
                tool="balance_query",
                args={"account_ref": _account()},
                depends_on=["A"],
            )
        ],
    )
    result = case.gateway.submit_plan(plan)
    assert result.status == "rejected" and "PLAN-CYCLE" in result.rule_ids
    assert case.gateway.bank.execute_count == 0


def test_oversized_plans_rejected_by_schema():
    case = BankCase(make_state(), task_id="RT2-DAG", subcase_id="oversize")
    acct = _account()
    with pytest.raises(ValidationError):
        _plan(
            case,
            [
                PlanNode(node_id=f"N{i}", tool="balance_query", args={"account_ref": acct})
                for i in range(13)
            ],
        )
    # 25 edges among 12 nodes
    nodes = []
    edges = 0
    for i in range(12):
        deps = [f"N{j}" for j in range(i)][: max(0, min(i, 25 - edges))]
        edges += len(deps)
        nodes.append(
            PlanNode(
                node_id=f"N{i}", tool="balance_query", args={"account_ref": acct}, depends_on=deps
            )
        )
    assert edges > 24
    with pytest.raises(ValidationError):
        _plan(case, nodes)


def test_dangling_dependency_rejected():
    case = BankCase(make_state(), task_id="RT2-DAG", subcase_id="dangling")
    plan = _plan(
        case,
        [
            PlanNode(
                node_id="A",
                tool="balance_query",
                args={"account_ref": _account()},
                depends_on=["GHOST"],
            )
        ],
    )
    result = case.gateway.submit_plan(plan)
    assert result.status == "rejected"
    assert case.gateway.bank.execute_count == 0


def test_user_stop_is_terminal_even_after_handoff_and_resume():
    """7.3: Stop cancels every unexecuted node; cancelled is a terminal, append-only state.

    A later handoff + resume (whose confirmation only says "resume plan") must not
    resurrect nodes the user explicitly stopped, nor auto-execute them.
    """
    case = BankCase(make_state(), task_id="RT2-DAG", subcase_id="stop-resume")
    plan = _chain(case)
    assert case.gateway.submit_plan(plan).status == "registered"
    from corridor.gateway.orchestration import compile_node

    assert case.gateway.query(*compile_node(case.gateway, plan, "A")).status == "settled"
    snap = case.gateway.plan_snapshot(plan.plan_id)
    done = {n for n, v in snap["nodes"].items() if v["status"] == "succeeded"}
    executed_before_stop = case.gateway.bank.execute_count
    assert case.gateway.interrupt(plan.plan_id).status == "interrupted"
    stopped = case.gateway.plan_snapshot(plan.plan_id)["nodes"]
    cancelled = {n for n, v in stopped.items() if v["status"] == "cancelled"}
    if not cancelled:
        pytest.skip("whole plan finished before Stop")
    # Agent escalates to a human and the user later resumes the agent.
    assert case.gateway.handoff(plan.plan_id).status == "handoff"
    assert _resume(case, plan.plan_id).status == "resumed"
    epoch = case.gateway.plan_snapshot(plan.plan_id)["ownership_epoch"]
    for _ in range(3):
        case.gateway.advance_plan(plan.plan_id, epoch)
    after = case.gateway.plan_snapshot(plan.plan_id)["nodes"]
    assert done  # sanity
    assert {n for n in cancelled if after[n]["status"] != "cancelled"} == set(), after
    assert case.gateway.bank.execute_count == executed_before_stop
