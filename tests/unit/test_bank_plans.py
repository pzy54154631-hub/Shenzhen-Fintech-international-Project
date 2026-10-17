"""DAG structure, typed references and runtime projection fail closed."""

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import SPA, sign
from corridor.gateway.plans import (
    dependency_closure,
    project_runtime,
    ready_nodes,
    resolve_node_terms,
    topological_order,
    validate_plan,
)
from corridor.schemas.bank import (
    Handle,
    InputTerm,
    NodeOutputTerm,
    Plan,
    PlanNode,
    ReceiptTerm,
    StateTerm,
)
from corridor.sim.device import Device
from corridor.sim.keys import signing_key
from tests.bank_cases import query_case, spa_case
from tests.gateway_cases import approve, gateway_case


def _case(edges=None):
    action, cert, state = query_case()
    terms = {key.removeprefix("args."): term for key, term in cert.derivations.items()}
    plan = Plan(
        plan_id=action.plan_id,
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=action.intent_id,
        goal_input_refs=[],
        nodes=[
            PlanNode(node_id=name, tool="balance_query", args=terms, depends_on=dependencies)
            for name, dependencies in (edges or {"C": ["A", "B"], "B": [], "A": []}).items()
        ],
        ownership_epoch=0,
    )
    return plan, state


def _event(plan, node, status, *, receipt_ref=None, epoch=None, plan_hash=None):
    return {
        "event": "plan_node_status",
        "plan_id": plan.plan_id,
        "node_id": node,
        "principal_token": plan.principal,
        "payload": {
            "status": status,
            "receipt_ref": receipt_ref,
            "plan_hash": plan_hash or H(plan),
            "ownership_epoch": plan.ownership_epoch if epoch is None else epoch,
        },
    }


def test_ready_nodes_and_topological_batches_are_deterministic():
    plan, state = _case({"D": ["A"], "C": ["B"], "B": [], "A": []})
    assert validate_plan(plan, state) is None
    assert topological_order(plan) == ["A", "B", "C", "D"]
    assert topological_order(plan.model_copy(update={"nodes": list(reversed(plan.nodes))})) == [
        "A",
        "B",
        "C",
        "D",
    ]
    assert dependency_closure(plan, "C") == {"B"}
    assert ready_nodes(plan, project_runtime(plan, [])) == ["A", "B"]


@pytest.mark.rule("PLAN-CYCLE")
@pytest.mark.parametrize("edges", [{"A": ["A"]}, {"A": ["B"], "B": ["A"]}])
def test_self_and_indirect_cycles_reject(edges):
    plan, state = _case(edges)
    assert validate_plan(plan, state) == "PLAN-CYCLE"
    with pytest.raises(ValueError, match="PLAN-CYCLE"):
        topological_order(plan)


@pytest.mark.parametrize(
    "mutation", ["duplicate_node", "unknown_dependency", "duplicate_edge", "nodes", "edges"]
)
def test_invalid_graph_identity_and_limits_reject(mutation):
    plan, state = _case()
    nodes = list(plan.nodes)
    if mutation == "duplicate_node":
        nodes.append(nodes[0])
    elif mutation == "unknown_dependency":
        nodes[0] = nodes[0].model_copy(update={"depends_on": ["MISSING"]})
    elif mutation == "duplicate_edge":
        nodes[0] = nodes[0].model_copy(update={"depends_on": ["A", "A"]})
    elif mutation == "nodes":
        nodes = [nodes[1].model_copy(update={"node_id": f"N{i}"}) for i in range(13)]
    else:
        nodes = [
            nodes[1].model_copy(
                update={"node_id": f"N{i}", "depends_on": [f"N{j}" for j in range(i)]}
            )
            for i in range(8)
        ]
    assert validate_plan(plan.model_copy(update={"nodes": nodes}), state) in {
        "PLAN-SCHEMA",
        "PLAN-SCOPE",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_arg",
        "extra_arg",
        "wrong_collection",
        "stale",
        "owner",
        "missing_handle",
        "program_handle",
    ],
)
def test_arguments_and_handles_must_resolve_to_current_owned_objects(mutation):
    plan, state = _case({"A": []})
    node = plan.nodes[0]
    args = dict(node.args)
    if mutation == "missing_arg":
        args = {}
    elif mutation == "extra_arg":
        args["amount_ref"] = args["account_ref"]
    elif mutation == "wrong_collection":
        args["account_ref"] = StateTerm(
            collection="contacts", object_ref="CONTACT_CHEN", field="id", version=1
        )
    elif mutation == "stale":
        args["account_ref"] = args["account_ref"].model_copy(update={"version": 999})
    elif mutation == "owner":
        account = state.accounts["A_CURRENT"].model_copy(update={"owner": "OTHER"})
        state = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
    else:
        args["account_ref"] = Handle(
            handle_type="state" if mutation == "missing_handle" else "program", ref="MISSING"
        )
    plan = plan.model_copy(update={"nodes": [node.model_copy(update={"args": args})]})
    assert validate_plan(plan, state) == "PLAN-SCOPE"


def test_owned_state_handle_resolves_to_current_typed_term():
    plan, state = _case({"A": []})
    node = plan.nodes[0].model_copy(
        update={"args": {"account_ref": Handle(handle_type="state", ref="A_CURRENT")}}
    )
    plan = plan.model_copy(update={"nodes": [node]})
    assert validate_plan(plan, state) is None
    assert resolve_node_terms(plan, "A", state, {}) == {
        "account_ref": StateTerm(
            collection="accounts", object_ref="A_CURRENT", field="id", version=1
        )
    }


@pytest.mark.parametrize("source", ["A", "MISSING", "LATER"])
def test_future_self_and_missing_node_outputs_never_become_money_or_account_args(source):
    plan, state = _case({"A": [], "LATER": ["A"]})
    node = plan.nodes[0].model_copy(
        update={"args": {"account_ref": NodeOutputTerm(node_id=source, field="account_ref")}}
    )
    plan = plan.model_copy(update={"nodes": [node, plan.nodes[1]]})
    assert validate_plan(plan, state) == "PLAN-SCOPE"


@pytest.mark.parametrize(
    "status", ["failed", "unknown", "waiting_settlement", "running", "waiting_mfa"]
)
def test_only_completed_dependencies_release_downstream(status):
    plan, _ = _case({"B": ["A"], "A": []})
    runtime = project_runtime(plan, [_event(plan, "A", status, receipt_ref="R")])
    assert "B" not in ready_nodes(plan, runtime)
    assert runtime.receipt_refs == {}


def test_succeeded_requires_receipt_and_stale_epoch_events_do_not_advance():
    plan, _ = _case({"B": ["A"], "A": []})
    with pytest.raises(ValueError, match="PLAN-SCOPE"):
        project_runtime(plan, [_event(plan, "A", "succeeded")])
    runtime = project_runtime(plan, [_event(plan, "A", "succeeded", receipt_ref="R", epoch=1)])
    assert ready_nodes(plan, runtime) == ["A"]
    runtime = project_runtime(plan, [_event(plan, "A", "succeeded", receipt_ref="R")])
    assert ready_nodes(plan, runtime) == ["B"] and runtime.receipt_refs == {"A": "R"}


def test_interrupt_preserves_unknown_and_completed_outputs_and_blocks_every_new_node():
    plan, _ = _case({"C": ["A"], "B": [], "A": []})
    records = [
        _event(plan, "A", "succeeded", receipt_ref="R"),
        _event(plan, "B", "unknown"),
        {
            "event": "plan_interrupted",
            "plan_id": plan.plan_id,
            "principal_token": plan.principal,
            "payload": {},
        },
    ]
    runtime = project_runtime(plan, records)
    assert runtime.statuses == {"C": "cancelled", "B": "unknown", "A": "succeeded"}
    assert runtime.receipt_refs == {"A": "R"} and ready_nodes(plan, runtime) == []


def test_handoff_increments_epoch_and_late_worker_success_is_ignored():
    plan, _ = _case({"B": ["A"], "A": []})
    records = [
        {
            "event": "plan_handoff",
            "plan_id": plan.plan_id,
            "principal_token": plan.principal,
            "payload": {"ownership_epoch": 1},
        },
        _event(plan, "A", "succeeded", receipt_ref="OLD"),
    ]
    runtime = project_runtime(plan, records)
    assert runtime.ownership_epoch == 1 and runtime.blocked
    assert runtime.receipt_refs == {} and ready_nodes(plan, runtime) == []


def test_only_registered_signed_output_of_completed_ancestor_resolves():
    gateway, device, action, cert = gateway_case()
    receipt = gateway.dispatch(action, cert, approve(gateway, device, action, cert)).receipt
    assert receipt is not None
    source = PlanNode(
        node_id=action.node_id,
        tool=action.kind,
        args={field.removeprefix("args."): value for field, value in cert.derivations.items()},
    )
    target = PlanNode(
        node_id="REFUND_NODE",
        tool="refund_request",
        depends_on=[source.node_id],
        args={"receipt_ref": NodeOutputTerm(node_id=source.node_id, field="receipt_id")},
    )
    plan = Plan(
        plan_id=action.plan_id,
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=action.intent_id,
        goal_input_refs=[action.args.amount_ref],
        nodes=[target, source],
        ownership_epoch=0,
    )
    state = gateway.store.snapshot()
    assert validate_plan(plan, state) is None
    with pytest.raises(ValueError, match="PLAN-SCOPE"):
        resolve_node_terms(plan, target.node_id, state, {})
    outputs = {source.node_id: receipt.id}
    assert resolve_node_terms(plan, target.node_id, state, outputs) == {
        "receipt_ref": ReceiptTerm(receipt_ref=receipt.id, field="receipt_id")
    }
    bad = receipt.model_copy(update={"sig": "0" * 128})
    bad_state = state.model_copy(update={"receipts": {bad.id: bad}})
    with pytest.raises(ValueError, match="PLAN-SCOPE"):
        resolve_node_terms(plan, target.node_id, bad_state, outputs)


def test_handoff_and_confirmed_resume_preserve_success_for_unchanged_nodes():
    original, _ = _case({"B": ["A"], "A": []})
    handoff = original.model_copy(update={"revision": 2, "ownership_epoch": 1})
    resumed = original.model_copy(update={"revision": 3, "ownership_epoch": 2})

    def registration(plan):
        return {
            "event": "plan_registered",
            "plan_id": plan.plan_id,
            "principal_token": plan.principal,
            "payload": {"plan": plan.model_dump(mode="json")},
        }

    records = [
        registration(original),
        _event(original, "A", "succeeded", receipt_ref="RECEIPT_A"),
        {
            "event": "plan_handoff",
            "plan_id": original.plan_id,
            "principal_token": original.principal,
            "payload": {"ownership_epoch": 1},
        },
        registration(handoff),
        registration(resumed),
        {
            "event": "plan_resumed",
            "plan_id": original.plan_id,
            "principal_token": original.principal,
            "payload": {"ownership_epoch": 2, "plan_hash": H(resumed)},
        },
        _event(original, "B", "succeeded", receipt_ref="STALE_WORKER"),
    ]
    runtime = project_runtime(resumed, records)
    assert runtime.ownership_epoch == 2 and not runtime.blocked
    assert runtime.receipt_refs == {"A": "RECEIPT_A"}
    assert ready_nodes(resumed, runtime) == ["B"]


def test_repeated_handoff_resume_retains_success_from_each_ownership_epoch():
    original, _ = _case({"C": ["B"], "B": ["A"], "A": []})
    plans = [
        original.model_copy(update={"revision": epoch + 1, "ownership_epoch": epoch})
        for epoch in range(5)
    ]
    records = []
    for epoch, plan in enumerate(plans):
        records.append({
            "event": "plan_registered",
            "plan_id": plan.plan_id,
            "principal_token": plan.principal,
            "payload": {"plan": plan.model_dump(mode="json")},
        })
        if epoch:
            records.append({
                "event": "plan_handoff" if epoch % 2 else "plan_resumed",
                "plan_id": plan.plan_id,
                "principal_token": plan.principal,
                "payload": {"ownership_epoch": epoch, "plan_hash": H(plan)},
            })
        if epoch in {0, 2}:
            node = "A" if epoch == 0 else "B"
            records.append(_event(plan, node, "succeeded", receipt_ref=f"RECEIPT_{node}"))
    runtime = project_runtime(plans[-1], records)
    assert runtime.ownership_epoch == 4 and not runtime.blocked
    assert runtime.receipt_refs == {"A": "RECEIPT_A", "B": "RECEIPT_B"}
    assert ready_nodes(plans[-1], runtime) == ["C"]


@pytest.mark.parametrize("wrong_node", [False, True])
def test_spa_scoped_input_requires_signed_authority_for_exact_plan_node(wrong_node):
    action, cert, state = spa_case()
    plan = Plan(
        plan_id=action.plan_id,
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id="PARENT_GOAL",
        goal_input_refs=[action.args.amount_ref],
        nodes=[
            PlanNode(
                node_id=action.node_id,
                tool=action.kind,
                args={
                    field.removeprefix("args."): value for field, value in cert.derivations.items()
                },
            )
        ],
        ownership_epoch=0,
    )
    if wrong_node:
        spa = state.authorizations[cert.authorization_ref].model_copy(
            update={"node_id": "OTHER_NODE"}
        )
        spa = spa.model_copy(update={"sig": sign(signing_key("device"), SPA, spa)})
        state = state.model_copy(update={"authorizations": {**state.authorizations, spa.id: spa}})
    assert validate_plan(plan, state) == ("PLAN-SCOPE" if wrong_node else None)


def _aa_plan(state, *, receipt_ref=None):
    plan, _ = _case({"AA": []})
    total = Device().confirm_input(
        intent_id=plan.intent_id,
        slot="total",
        value={"amount": "100/1", "ccy": "CNY"},
        now=state.now,
    )
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, total.id: total}})
    args = {
        "source_bill_ref": InputTerm(input_ref=total.id, slot="total"),
        "total_ref": InputTerm(input_ref=total.id, slot="total"),
        "participant_refs": [
            StateTerm(collection="contacts", object_ref="CONTACT_CHEN", field="id", version=1)
        ],
    }
    if receipt_ref is not None:
        args["source_bill_ref"] = ReceiptTerm(receipt_ref=receipt_ref, field="receipt_id")
        args["total_ref"] = ReceiptTerm(receipt_ref=receipt_ref, field="net_spend")
    return plan.model_copy(
        update={
            "goal_input_refs": [total.id],
            "nodes": [PlanNode(node_id="AA", tool="aa_request", args=args)],
            "device_session_id": state.security.active_device_sessions[plan.principal],
        }
    ), state


def test_aa_signed_total_input_and_participant_terms_resolve_without_literals():
    _, state = _case()
    plan, state = _aa_plan(state)
    assert validate_plan(plan, state) is None
    terms = resolve_node_terms(plan, "AA", state, {})
    assert terms["source_bill_ref"] == terms["total_ref"]
    assert terms["participant_refs.0"].object_ref == "CONTACT_CHEN"


@pytest.mark.parametrize(
    "mutation", [None, "wrong_field", "function", "signature", "registry", "owner"]
)
def test_aa_receipt_total_requires_exact_registered_builtin_bill(mutation):
    from tests.e2e.test_billing_gateway import analysis_case

    gateway, _, action, cert = analysis_case()
    receipt = gateway.query(action, cert).analysis_receipt
    assert receipt is not None
    state = gateway.store.snapshot()
    plan, state = _aa_plan(state, receipt_ref=receipt.id)
    if mutation == "wrong_field":
        node = plan.nodes[0]
        plan = plan.model_copy(
            update={
                "nodes": [
                    node.model_copy(
                        update={
                            "args": {
                                **node.args,
                                "total_ref": ReceiptTerm(
                                    receipt_ref=receipt.id, field="gross_spend"
                                ),
                            }
                        }
                    )
                ]
            }
        )
    elif mutation == "registry":
        state = state.model_copy(update={"ledger": []})
    elif mutation is not None:
        changes = {
            "function": {"function_id": "subscriptions_v1"},
            "signature": {"sig": "0" * 128},
            "owner": {"parameters": {**receipt.parameters, "principal": "OTHER"}},
        }[mutation]
        receipt = receipt.model_copy(update=changes)
        state = state.model_copy(update={"receipts": {receipt.id: receipt}})
    assert validate_plan(plan, state) == (None if mutation is None else "PLAN-SCOPE")
