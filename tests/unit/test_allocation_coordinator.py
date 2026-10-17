"""Explicit all-item selection and atomic parent registration contracts."""

from dataclasses import replace

import pytest

from corridor.crypto.jcs import H
from corridor.eval.mockbank.exec import MockBank
from corridor.gateway.allocations import (
    allocation_snapshot,
    draft_allocation,
    register_allocation,
    stop_allocation,
)
from corridor.gateway.audit import AuditLog
from corridor.gateway.service import Gateway
from corridor.kernel.allocation_execution import allocation_plan_hash
from corridor.sim.keys import signing_key
from corridor.sim.wealth_device import WealthDevice
from corridor.stores.bank import BankStore
from tests.wealth_cases import allocation_case


def coordinator_case(tmp_path=None):
    action, _, state = allocation_case()
    gateway = Gateway(
        BankStore(state, path=tmp_path / "state.jsonl" if tmp_path else None),
        MockBank(state, signing_key("bank")),
        audit=AuditLog(tmp_path / "audit.jsonl" if tmp_path else None),
        evidence_dir=tmp_path / "decisions" if tmp_path else None,
    )
    draft = draft_allocation(gateway, action.principal, action.intent_id, action.args.request_ref)
    return gateway, WealthDevice(), draft


def signed_selection(gateway, device, draft):
    return device.sign_allocation(
        draft, [item.item_ref for item in draft.parent.items], now=gateway.store.snapshot().now
    )


def register(gateway, draft, signing):
    return register_allocation(
        gateway,
        draft,
        selection=signing.selection,
        inputs=signing.inputs,
        authorizations=signing.authorizations,
    )


def test_draft_and_partial_selection_create_no_child_authority():
    gateway, device, draft = coordinator_case()
    before = H(gateway.store.snapshot())
    signing = device.sign_allocation(
        draft, [draft.parent.items[0].item_ref], now=gateway.store.snapshot().now
    )
    assert signing.selection is None and signing.inputs == () and signing.authorizations == ()
    assert register(gateway, draft, signing).status == "draft"
    assert H(gateway.store.snapshot()) == before
    assert gateway.bank.execute_count == 0


def test_complete_selection_registers_two_independent_bound_children(tmp_path):
    gateway, device, draft = coordinator_case(tmp_path)
    signing = signed_selection(gateway, device, draft)
    result = register(gateway, draft, signing)
    assert result.status == "ready", result
    state = gateway.store.snapshot()
    assert state.allocation_plans[draft.parent.id] == draft.parent
    assert len(signing.authorizations) == 2
    assert {auth.intent_id for auth in signing.authorizations} == {
        item.child_intent_id for item in draft.parent.items
    }
    assert all(len(auth.input_hashes) == 2 for auth in signing.authorizations)
    assert all(auth.amount_bound == 5000 for auth in signing.authorizations)
    assert allocation_snapshot(gateway, draft.parent.id)["status"] == "ready"
    assert gateway.bank.execute_count == 0
    assert len(list((tmp_path / "allocations").glob("*.json"))) == 1
    assert gateway.verify_log()


def test_tampered_all_selected_signature_has_no_partial_registration():
    gateway, device, draft = coordinator_case()
    signing = signed_selection(gateway, device, draft)
    bad = replace(signing, selection=signing.selection.model_copy(update={"sig": "0" * 128}))
    before = gateway.store.snapshot()
    assert register(gateway, draft, bad).status == "rejected"
    after = gateway.store.snapshot()
    assert after.user_inputs == before.user_inputs
    assert after.authorizations == before.authorizations
    assert after.allocation_plans == {}
    assert gateway.bank.execute_count == 0


def test_parent_stop_survives_journal_restart(tmp_path):
    gateway, device, draft = coordinator_case(tmp_path)
    assert register(gateway, draft, signed_selection(gateway, device, draft)).status == "ready"
    assert stop_allocation(gateway, draft.parent.id).status == "cancelled"
    restarted = Gateway(
        BankStore(gateway.store.snapshot(), path=tmp_path / "state.jsonl"),
        gateway.bank,
        audit=AuditLog(tmp_path / "audit.jsonl"),
    )
    snapshot = allocation_snapshot(restarted, draft.parent.id)
    assert snapshot["status"] == "cancelled"
    assert snapshot["control_status"] == "stopped"
    assert gateway.bank.execute_count == 0


def test_repeat_registration_does_not_restore_stopped_parent():
    gateway, device, draft = coordinator_case()
    signing = signed_selection(gateway, device, draft)
    assert register(gateway, draft, signing).status == "ready"
    stop_allocation(gateway, draft.parent.id)
    assert register(gateway, draft, signing).status == "rejected"
    assert allocation_snapshot(gateway, draft.parent.id)["status"] == "cancelled"


@pytest.mark.parametrize("field", ["child_intent_id", "item_ref", "principal"])
def test_device_rejects_self_rehashed_child_mapping_or_amount_changes(field):
    gateway, device, draft = coordinator_case()
    first = draft.parent.items[0]
    replacement = {
        "child_intent_id": "OTHER_CHILD",
        "item_ref": "OTHER_ITEM",
        "principal": first.principal + 1,
    }[field]
    changed_item = first.model_copy(update={field: replacement})
    children = draft.children
    if field == "child_intent_id":
        child = children[0].model_copy(update={"intent_id": replacement})
        children = (child, *children[1:])
        changed_item = changed_item.model_copy(update={"child_plan_hash": H(child)})
    parent = draft.parent.model_copy(update={"items": [changed_item, *draft.parent.items[1:]]})
    parent = parent.model_copy(update={"plan_hash": allocation_plan_hash(parent)})
    forged = replace(draft, parent=parent, children=children)
    with pytest.raises(ValueError, match="allocation"):
        signed_selection(gateway, device, forged)
