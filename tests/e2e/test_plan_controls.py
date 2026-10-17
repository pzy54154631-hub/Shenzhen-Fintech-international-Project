"""Real gateway DAG execution respects dependencies, Stop and ownership epochs."""

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.crypto.jcs import H
from corridor.gateway.service import Gateway
from corridor.kernel.binding import dependency_hashes
from corridor.schemas.bank import BankAction, BankCertificate, Plan, PlanNode, StateTerm
from corridor.sim.fixtures import make_state
from corridor.sim.keys import stable_id
from corridor.stores.bank import BankStore, add_seconds


def _plan_case(*, cycle=False):
    case = BankCase(make_state(), task_id="B8-CONTROLS", subcase_id="queries")
    account = StateTerm(collection="accounts", object_ref="A_CURRENT", field="id", version=1)
    plan = Plan(
        plan_id=stable_id(case.identity, 0, "plan"),
        revision=1,
        principal=case.device.principal,
        device_session_id=case.session,
        intent_id=case.intent(),
        goal_input_refs=[],
        nodes=[
            PlanNode(
                node_id="C", tool="balance_query", args={"account_ref": account}, depends_on=["B"]
            ),
            PlanNode(
                node_id="B", tool="balance_query", args={"account_ref": account}, depends_on=["A"]
            ),
            PlanNode(
                node_id="A",
                tool="balance_query",
                args={"account_ref": account},
                depends_on=["C"] if cycle else [],
            ),
        ],
        ownership_epoch=0,
    )
    return case, plan


def _query(case, plan, node_id):
    node = next(item for item in plan.nodes if item.node_id == node_id)
    action = BankAction(
        action_id=stable_id(plan.plan_id, 0, node_id),
        intent_id=plan.intent_id,
        principal=plan.principal,
        device_session_id=plan.device_session_id,
        plan_id=plan.plan_id,
        plan_hash=H(plan),
        node_id=node_id,
        kind=node.tool,
        args={"account_ref": "A_CURRENT"},
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=case.session_authorization.id,
        derivations={f"args.{field}": term for field, term in node.args.items()},
        dependency_hashes={},
    )
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(action, cert, case.state)}
    )
    return action, cert


def _advance_all(gateway, plan_id, epoch):
    results = []
    for _ in range(3):
        results.extend(gateway.advance_plan(plan_id, ownership_epoch=epoch))
    return results


@pytest.mark.rule("PLAN-CYCLE")
def test_cyclic_dag_rejects_without_any_business_execution():
    case, plan = _plan_case(cycle=True)
    result = case.gateway.submit_plan(plan)
    assert result.status == "rejected" and result.rule_ids == ["PLAN-CYCLE"]
    assert case.gateway.bank.execute_count == 0
    assert not case.state.ledger


def test_downstream_is_blocked_until_dependency_and_automatic_queries_execute_once():
    case, plan = _plan_case()
    assert case.gateway.submit_plan(plan).status == "registered"
    action, cert = _query(case, plan, "B")
    assert case.gateway.query(action, cert).rule_ids == ["PLAN-SCOPE"]
    assert case.gateway.bank.execute_count == 0
    _advance_all(case.gateway, plan.plan_id, 0)
    snapshot = case.gateway.plan_snapshot(plan.plan_id)
    assert all(node["status"] == "succeeded" for node in snapshot["nodes"].values())
    assert all(node["receipt_ref"] in case.state.receipts for node in snapshot["nodes"].values())
    assert case.gateway.bank.execute_count == 3
    assert _advance_all(case.gateway, plan.plan_id, 0) == []
    assert case.gateway.bank.execute_count == 3
    assert case.gateway.verify_log()


def test_stop_cancels_every_unexecuted_node_and_blocks_stale_actions():
    case, plan = _plan_case()
    assert case.gateway.submit_plan(plan).status == "registered"
    first = _query(case, plan, "A")
    assert case.gateway.query(*first).status == "settled"
    blocked = _query(case, plan, "B")
    assert case.gateway.interrupt(plan.plan_id).status == "interrupted"
    snapshot = case.gateway.plan_snapshot(plan.plan_id)
    assert snapshot["nodes"]["A"]["status"] == "succeeded"
    assert snapshot["nodes"]["B"]["status"] == "cancelled"
    assert snapshot["nodes"]["C"]["status"] == "cancelled"
    assert case.gateway.query(*blocked).rule_ids == ["APR-VOID"]
    _advance_all(case.gateway, plan.plan_id, snapshot["ownership_epoch"])
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.verify_log()


def test_handoff_old_worker_and_confirmed_resume_preserve_completed_nodes():
    case, plan = _plan_case()
    assert case.gateway.submit_plan(plan).status == "registered"
    assert case.gateway.query(*_query(case, plan, "A")).status == "settled"
    stale = _query(case, plan, "B")
    assert case.gateway.handoff(plan.plan_id).status == "handoff"
    snapshot = case.gateway.plan_snapshot(plan.plan_id)
    assert snapshot["ownership_epoch"] == 1
    assert snapshot["plan"]["revision"] == 2
    assert snapshot["nodes"]["A"]["status"] == "succeeded"
    assert snapshot["audit_checkpoint"]["seq"] > 0
    assert case.gateway.query(*stale).rule_ids == ["PLAN-OWNER"]
    assert case.gateway.advance_plan(plan.plan_id, ownership_epoch=0)[0].rule_ids == ["PLAN-OWNER"]
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.resume(plan.plan_id).status == "rejected"
    scope = case.gateway.resume_scope(plan.plan_id)
    confirmation = case.device.confirm_input(
        intent_id=H(scope), slot="plan_resume", value=scope, now=case.state.now
    )
    assert case.gateway.resume(plan.plan_id, confirmation).status == "resumed"
    snapshot = case.gateway.plan_snapshot(plan.plan_id)
    assert snapshot["ownership_epoch"] == 2 and snapshot["plan"]["revision"] == 3
    assert snapshot["nodes"]["A"]["status"] == "succeeded"
    assert case.gateway.advance_plan(plan.plan_id, ownership_epoch=1)[0].rule_ids == ["PLAN-OWNER"]
    _advance_all(case.gateway, plan.plan_id, 2)
    assert case.gateway.bank.execute_count == 3
    assert all(
        node["status"] == "succeeded"
        for node in case.gateway.plan_snapshot(plan.plan_id)["nodes"].values()
    )
    assert case.gateway.verify_log()


def test_bad_resume_signature_cannot_restart_agent():
    case, plan = _plan_case()
    assert case.gateway.submit_plan(plan).status == "registered"
    assert case.gateway.handoff(plan.plan_id).status == "handoff"
    scope = case.gateway.resume_scope(plan.plan_id)
    confirmation = case.device.confirm_input(
        intent_id=H(scope), slot="plan_resume", value=scope, now=case.state.now
    ).model_copy(update={"sig": "0" * 128})
    assert case.gateway.resume(plan.plan_id, confirmation).status == "rejected"
    assert case.gateway.plan_snapshot(plan.plan_id)["ownership_epoch"] == 1
    _advance_all(case.gateway, plan.plan_id, 1)
    assert case.gateway.bank.execute_count == 0


def test_restart_reprojects_success_and_does_not_repeat_completed_node():
    case, plan = _plan_case()
    assert case.gateway.submit_plan(plan).status == "registered"
    assert case.gateway.query(*_query(case, plan, "A")).status == "settled"
    case.gateway = Gateway(BankStore(case.state), case.gateway.bank, audit=case.gateway.audit)
    assert case.gateway.plan_snapshot(plan.plan_id)["nodes"]["A"]["status"] == "succeeded"
    _advance_all(case.gateway, plan.plan_id, 0)
    assert case.gateway.bank.execute_count == 3
    assert case.gateway.verify_log()


def test_signed_future_due_time_blocks_direct_and_automatic_execution_until_due():
    case, plan = _plan_case()
    due_at = add_seconds(case.state.now, 60)
    due = case.device.confirm_input(
        intent_id=plan.intent_id, slot="due_at", value=due_at, now=case.state.now
    )
    assert case.gateway.submit_input(due).status == "accepted"
    plan = plan.model_copy(
        update={
            "goal_input_refs": [due.id],
            "nodes": [
                node.model_copy(update={"due_at_ref": due.id}) if node.node_id == "A" else node
                for node in plan.nodes
            ],
        }
    )
    assert case.gateway.submit_plan(plan).status == "registered"
    action, cert = _query(case, plan, "A")
    assert case.gateway.query(action, cert).rule_ids == ["PLAN-SCOPE"]
    assert case.gateway.advance_plan(plan.plan_id) == []
    assert case.gateway.bank.execute_count == 0
    assert case.gateway.plan_snapshot(plan.plan_id)["nodes"]["A"]["status"] == "pending"
    case.gateway.advance_clock(due_at)
    _advance_all(case.gateway, plan.plan_id, 0)
    assert case.gateway.bank.execute_count == 3
    assert case.gateway.plan_snapshot(plan.plan_id)["nodes"]["C"]["status"] == "succeeded"


def test_resume_confirmation_cannot_be_replayed_after_second_handoff():
    case, plan = _plan_case()
    assert case.gateway.submit_plan(plan).status == "registered"
    assert case.gateway.handoff(plan.plan_id).status == "handoff"
    scope = case.gateway.resume_scope(plan.plan_id)
    confirmation = case.device.confirm_input(
        intent_id=H(scope), slot="plan_resume", value=scope, now=case.state.now
    )
    assert case.gateway.resume(plan.plan_id, confirmation).status == "resumed"
    assert case.gateway.handoff(plan.plan_id).status == "handoff"
    assert case.gateway.resume(plan.plan_id, confirmation).rule_ids == ["PLAN-OWNER"]
    assert case.gateway.plan_snapshot(plan.plan_id)["ownership_epoch"] == 3
    assert case.gateway.bank.execute_count == 0


@pytest.mark.parametrize("offset", [-1, 300])
def test_resume_confirmation_cannot_be_future_dated_or_expired(offset):
    case, plan = _plan_case()
    assert case.gateway.submit_plan(plan).status == "registered"
    assert case.gateway.handoff(plan.plan_id).status == "handoff"
    scope = case.gateway.resume_scope(plan.plan_id)
    confirmation = case.device.confirm_input(
        intent_id=H(scope), slot="plan_resume", value=scope, now=case.state.now
    )
    case.gateway.store.update(now=add_seconds(case.state.now, offset))
    assert case.gateway.resume(plan.plan_id, confirmation).rule_ids == ["PLAN-OWNER"]
    assert case.gateway.plan_snapshot(plan.plan_id)["ownership_epoch"] == 1
    assert case.gateway.bank.execute_count == 0


def test_handoff_revokes_preapproved_schedule_and_resume_never_reauthorizes_it():
    from corridor.bench.planning_runner import prepare_spa

    case = BankCase(make_state(), task_id="B8-CONTROLS", subcase_id="schedule-handoff")
    prepared, _ = prepare_spa(case)
    assert case.dispatch(prepared).status == "controlled"
    run = next(iter(case.state.schedules.values()))
    assert case.gateway.handoff(prepared.plan.plan_id).status == "handoff"
    assert case.state.schedules[run.id].status == "cancelled"
    scope = case.gateway.resume_scope(prepared.plan.plan_id)
    confirmation = case.device.confirm_input(
        intent_id=H(scope), slot="plan_resume", value=scope, now=case.state.now
    )
    assert case.gateway.resume(prepared.plan.plan_id, confirmation).status == "resumed"
    case.gateway.advance_clock(run.due_at)
    assert case.gateway.tick() == []
    assert case.gateway.bank.execute_count == 0
    assert case.state.schedules[run.id].status == "cancelled"
    action, cert = case.gateway.prepare_scheduled_run(run.id)
    result = case.gateway.dispatch(action, cert)
    assert result.status == "rejected" and "DOMAIN-SCHEDULE" in result.rule_ids
    assert case.gateway.bank.execute_count == 0
