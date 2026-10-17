"""Independent W11 execution/security cases through the real gateway and bank."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import ALLOCATION_POLICY, CATALOG, CONTROL, RECEIPT, RISK, verify
from corridor.gateway.allocations import (
    advance_allocation,
    draft_allocation,
    register_allocation,
    stop_allocation,
)
from corridor.gateway.privacy import PIIVault
from corridor.kernel import check
from corridor.kernel.allocation_execution import inspect_allocation_plan
from corridor.kernel.binding import intent_key
from corridor.schemas.bank import AccountMovement, BusinessEvent, OperationAuthorization
from corridor.schemas.base import loads_exact
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.stores.bank import add_seconds, available, latest_events
from tests.bank_cases import recertify, signed
from tests.e2e.test_gateway_atomicity import add_transfer
from tests.wealth_execution_cases import wealth_execution_case


def _start(case):
    result, signatures = case.start()
    assert result.status in {"registered", "ready"}, result
    assert signatures.selection is not None
    return signatures


def _positions(state):
    result = {}
    for position in state.positions.values():
        result[position.product_ref] = (
            result.get(position.product_ref, Fraction()) + position.principal_amount
        )
    return result


def _settled(case):
    return [
        event
        for event in latest_events(case.state).values()
        if event.kind == "purchase_product" and event.event == "settled"
    ]


def test_w11_default_two_purchases_have_exact_funds_positions_and_distinct_scopes(tmp_path):
    case = wealth_execution_case(path=tmp_path)
    assert case.comparison.analysis_receipt.function_id == "allocation_compare_v1"
    assert case.comparison.analysis_receipt.trust == "builtin"
    assert case.gateway.bank.execute_count == 0
    signatures = _start(case)
    assert len(signatures.authorizations) == 2
    assert len({auth.intent_id for auth in signatures.authorizations}) == 2
    first, approval_a = case.execute_next()
    assert first.status == "settled", first
    assert available(case.state, "A_CURRENT") == 7000
    assert _positions(case.state) == {"P_A": Fraction(5000)}
    second, approval_c = case.execute_next(sequence=1)
    assert second.status == "settled", second
    assert available(case.state, "A_CURRENT") == 2000
    assert _positions(case.state) == {"P_A": Fraction(5000), "P_C": Fraction(5000)}
    assert case.gateway.bank.execute_count == 2
    assert len(_settled(case)) == 2
    assert approval_a.grant.scope_hash != approval_c.grant.scope_hash
    assert approval_a.grant.grant_id != approval_c.grant.grant_id
    assert approval_a.token.nonce != approval_c.token.nonce
    assert case.snapshot()["status"] == "completed"
    assert all(
        verify(case.state.roots.bank_pubkey, RECEIPT, result.receipt, result.receipt.sig)
        for result in (first, second)
    )
    assert case.gateway.verify_log()
    checkpoint = loads_exact((tmp_path / "checkpoint.json").read_bytes())
    assert case.gateway.verify_log(checkpoint)
    records = [loads_exact(path.read_bytes()) for path in (tmp_path / "decisions").glob("*.json")]
    purchases = [record for record in records if record["action"]["kind"] == "purchase_product"]
    assert len(purchases) == 2
    for record in purchases:
        assert record["cert"]["allocation"] is not None
        assert record["action"]["args"]["allocation_ref"] == case.parent_id
        assert record["token_id"] and record["mfa_grant_id"] and record["bank_receipt"]
        PIIVault().ensure_safe(record, rule="PII-OUT")
    manifest = loads_exact((tmp_path / "allocations" / f"{case.parent_id}.json").read_bytes())
    assert manifest["biac_hash"] == H(case.comparison_cert.allocation)
    assert manifest["plan_hash"] == case.draft.parent.plan_hash
    assert {row["decision_key"] for row in manifest["children"]} == {
        first.receipt.intent_key,
        second.receipt.intent_key,
    }
    PIIVault().ensure_safe(manifest, rule="PII-OUT")
    data = (tmp_path / "audit.jsonl").read_bytes()
    assert data.endswith(b"\n")
    assert all(jcs_bytes(loads_exact(line)) == line for line in data.splitlines())


@pytest.mark.parametrize("selected_count", [0, 1])
def test_incomplete_overview_selection_signs_nothing_and_cannot_start(selected_count):
    case = wealth_execution_case()
    selected = [item.item_ref for item in case.draft.parent.items][:selected_count]
    before = H(case.state.authorizations)
    result, signatures = case.start(selected=selected)
    assert signatures.selection is None
    assert signatures.inputs == () and signatures.authorizations == ()
    assert result.status not in {"ready", "registered", "settled"}
    assert H(case.state.authorizations) == before
    assert case.gateway.bank.execute_count == 0
    assert available(case.state, "A_CURRENT") == 12000


def test_no_mfa_cannot_execute_even_with_signed_device_approval():
    case = wealth_execution_case()
    _start(case)
    prepared = case.prepare()
    token = case.device.approve(prepared.action, prepared.cert, prepared.card, now=case.state.now)
    verdict = check(prepared.action, prepared.cert, case.state, phase="dispatch")
    assert verdict.outcome == "Escalate"
    assert "TIER-MFA-REQUIRED" in verdict.rule_ids
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status != "settled"
    assert case.gateway.bank.execute_count == 0
    assert not _positions(case.state)


def test_first_grant_cannot_approve_second_child_and_valid_second_grant_can():
    case = wealth_execution_case()
    _start(case)
    first, approved = case.execute_next()
    assert first.status == "settled"
    prepared = case.prepare()
    wrong = prepared.cert.model_copy(update={"mfa_grant_refs": [approved.grant.grant_id]})
    token = case.device.approve(
        prepared.action, wrong, prepared.card, now=case.state.now, sequence=1
    )
    result = case.gateway.dispatch(prepared.action, wrong, token)
    assert result.status != "settled"
    assert case.gateway.bank.execute_count == 1
    assert available(case.state, "A_CURRENT") == 7000
    final = case.approve(prepared, sequence=2)
    result = case.gateway.dispatch(final.action, final.cert, final.token)
    assert result.status == "settled", result
    assert case.gateway.bank.execute_count == 2


@pytest.mark.parametrize(
    "field,value", [("plan_id", "OTHER_PLAN"), ("node_id", "OTHER_NODE"), ("plan_hash", "9" * 64)]
)
def test_approved_child_cannot_swap_plan_node_or_revision_binding(field, value):
    case = wealth_execution_case()
    _start(case)
    approved = case.approve()
    changed = approved.action.model_copy(update={field: value})
    action, cert, _ = recertify(changed, approved.cert, case.state)
    result = case.gateway.dispatch(action, cert, approved.token)
    assert result.status == "rejected"
    assert case.gateway.bank.execute_count == 0
    assert available(case.state, "A_CURRENT") == 12000


def test_completed_child_and_parent_registration_cannot_be_replayed_after_restart(tmp_path):
    case = wealth_execution_case(path=tmp_path)
    signatures = _start(case)
    first, approved = case.execute_next()
    assert first.status == "settled"
    case.reopen()
    duplicate = case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert duplicate.status == "rejected"
    repeated = register_allocation(
        case.gateway,
        case.draft,
        selection=signatures.selection,
        inputs=signatures.inputs,
        authorizations=signatures.authorizations,
    )
    assert repeated.status != "settled"
    assert case.gateway.bank.execute_count == 1
    assert _positions(case.state) == {"P_A": Fraction(5000)}
    second, _ = case.execute_next(sequence=1)
    assert second.status == "settled", second
    assert case.gateway.bank.execute_count == 2
    assert case.snapshot()["status"] == "completed"


def test_new_authorization_envelope_cannot_rebuy_settled_child():
    case = wealth_execution_case()
    _start(case)
    first, approved = case.execute_next()
    assert first.status == "settled"
    old = case.state.authorizations[approved.cert.authorization_ref]
    assert isinstance(old, OperationAuthorization)
    fresh = signed(old.model_copy(update={"id": "REWRAPPED_AUTH"}), CONTROL)
    assert case.gateway.submit_authorization(fresh).status == "accepted"
    cert = approved.cert.model_copy(update={"authorization_ref": fresh.id})
    action, cert, _ = recertify(approved.action, cert, case.state)
    verdict = check(action, cert, case.state, phase="dispatch")
    assert verdict.outcome == "Reject"
    assert "AUTH-CONSUMED" in verdict.rule_ids
    assert case.gateway.dispatch(action, cert, approved.token).status == "rejected"
    assert case.gateway.bank.execute_count == 1


@pytest.mark.parametrize("handoff", [False, True])
def test_parent_stop_or_handoff_blocks_preapproved_direct_child_and_preserves_first(handoff):
    case = wealth_execution_case()
    _start(case)
    first, _ = case.execute_next()
    assert first.status == "settled"
    approved = case.approve(sequence=1)
    stop_allocation(case.gateway, case.parent_id, handoff=handoff)
    direct = case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert direct.status == "rejected"
    assert case.gateway.bank.execute_count == 1
    assert _positions(case.state) == {"P_A": Fraction(5000)}
    assert available(case.state, "A_CURRENT") == 7000
    assert case.snapshot()["status"] == "partially_executed"
    advance_allocation(case.gateway, case.parent_id)
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.verify_log()


def test_second_purchase_failure_preserves_first_and_reports_partial():
    case = wealth_execution_case()
    _start(case)
    first, _ = case.execute_next()
    assert first.status == "settled"
    approved = case.approve(sequence=1)
    key = intent_key(approved.action, case.state)
    case.gateway.bank.faults[key] = "failed"
    failed = case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert failed.status == "failed"
    assert failed.receipt.exact_effects == []
    assert case.snapshot()["status"] == "partially_executed"
    assert _positions(case.state) == {"P_A": Fraction(5000)}
    assert available(case.state, "A_CURRENT") == 7000
    assert len(_settled(case)) == 1
    assert case.gateway.bank.execute_count == 2
    advance_allocation(case.gateway, case.parent_id)
    assert case.gateway.bank.execute_count == 2


@pytest.mark.parametrize("fault", ["response_loss", "bad_signature"])
def test_unknown_second_purchase_keeps_reservation_and_lookup_never_resends(fault, tmp_path):
    case = wealth_execution_case(path=tmp_path)
    _start(case)
    first, _ = case.execute_next()
    assert first.status == "settled"
    approved = case.approve(sequence=1)
    key = intent_key(approved.action, case.state)
    case.gateway.bank.faults[key] = fault
    unknown = case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert unknown.status == "unknown"
    assert case.snapshot()["status"] == "unknown"
    assert latest_events(case.state)[key].event == "unknown"
    assert available(case.state, "A_CURRENT") == 2000
    assert case.gateway.bank.execute_count == 2
    case.reopen()
    assert key in case.state.security.unknown_intent_ids
    assert (
        case.gateway.dispatch(approved.action, approved.cert, approved.token).status == "rejected"
    )
    resolved = case.gateway.reconcile(key)
    assert resolved.status == "settled"
    assert case.gateway.bank.execute_count == 2
    assert available(case.state, "A_CURRENT") == 2000
    assert _positions(case.state) == {"P_A": Fraction(5000), "P_C": Fraction(5000)}
    assert case.snapshot()["status"] == "completed"
    assert case.gateway.verify_log()


def test_unknown_first_lookup_cannot_restart_remaining_after_lock_clear(
    tmp_path,
):
    case = wealth_execution_case(path=tmp_path)
    _start(case)
    approved = case.approve()
    key = intent_key(approved.action, case.state)
    case.gateway.bank.faults[key] = "response_loss"
    result = case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert result.status == "unknown"
    assert available(case.state, "A_CURRENT") == 7000
    assert case.gateway.bank.execute_count == 1
    case.reopen()
    resolved = case.gateway.reconcile(key)
    assert resolved.status == "settled"
    assert _positions(case.state) == {"P_A": Fraction(5000)}
    assert available(case.state, "A_CURRENT") == 7000
    assert case.gateway.bank.execute_count == 1
    assert case.snapshot()["status"] != "completed"
    assert case.snapshot()["settled_principal"] == "5000/1"
    # Clear only the generic lock in this adversarial state fixture. The durable
    # allocation control must independently prevent an implicit continuation.
    case.gateway.store.update(
        security=case.state.security.model_copy(update={"locked_at": {}, "lock_reason": {}})
    )
    inspection = inspect_allocation_plan(case.parent_id, case.state)
    assert inspection.errors
    assert inspection.control_status in {"unknown", "failed", "stopped"}
    result = advance_allocation(case.gateway, case.parent_id)
    assert result.status not in {"waiting_mfa", "waiting_approval", "settled"}
    assert case.gateway.bank.execute_count == 1
    assert _positions(case.state) == {"P_A": Fraction(5000)}
    assert case.gateway.verify_log()


@pytest.mark.parametrize("control", ["interrupt", "handoff"])
def test_stopping_one_child_routes_to_parent_and_blocks_all_unexecuted_children(control):
    case = wealth_execution_case()
    _start(case)
    approved = case.approve()
    getattr(case.gateway, control)(approved.action.plan_id)
    assert (
        case.gateway.dispatch(approved.action, approved.cert, approved.token).status == "rejected"
    )
    assert inspect_allocation_plan(case.parent_id, case.state).errors
    result = advance_allocation(case.gateway, case.parent_id)
    assert result.status not in {"waiting_mfa", "waiting_approval", "settled"}
    assert case.gateway.bank.execute_count == 0
    assert available(case.state, "A_CURRENT") == 12000


def test_actual_foreign_transfer_is_not_added_back_as_own_allocation_settlement():
    case = wealth_execution_case()
    _start(case)
    first, _ = case.execute_next()
    assert first.status == "settled"
    action, cert = add_transfer(case.gateway, Fraction(200), "WEALTH_EXTERNAL_SPEND")
    proposal = case.gateway.propose(action, cert, request_id="EXTERNAL_TRANSFER_APPROVAL")
    assert proposal.verdict.outcome == "Accept"
    token = case.device.approve(action, cert, proposal.card, now=case.state.now, sequence=3)
    assert case.gateway.dispatch(action, cert, token).status == "settled"
    assert available(case.state, "A_CURRENT") == 6800
    result = advance_allocation(case.gateway, case.parent_id)
    assert result.status not in {"waiting_mfa", "waiting_approval", "settled"}
    assert case.gateway.bank.execute_count == 2
    assert _positions(case.state) == {"P_A": Fraction(5000)}


def test_expired_current_card_and_grant_cannot_execute():
    case = wealth_execution_case()
    _start(case)
    approved = case.approve()
    case.gateway.advance_clock(add_seconds(case.state.now, 300))
    result = case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert result.status == "rejected"
    assert case.gateway.bank.execute_count == 0
    assert available(case.state, "A_CURRENT") == 12000


def _explicit_items(case):
    request = allocation_request(
        selection_mode="explicit_items",
        items=[
            {"product_id": "P_B", "principal": "5000/1"},
            {"product_id": "P_C", "principal": "5000/1"},
        ],
        model_biac_hash=H(case.comparison_cert.allocation),
        reason_code="product_preference",
    )
    case.replace_request(request)
    return request


def test_explicit_item_selection_executes_with_per_card_deviation_and_mfa():
    case = wealth_execution_case()
    _explicit_items(case)
    _start(case)
    first, first_approval = case.execute_next()
    assert first.status == "settled"
    second, second_approval = case.execute_next(sequence=1)
    assert second.status == "settled", second
    assert _positions(case.state) == {"P_B": Fraction(5000), "P_C": Fraction(5000)}
    assert available(case.state, "A_CURRENT") == 2000
    assert case.comparison_cert.allocation.deviations.projected_net_delta == -50
    for approved in (first_approval, second_approval):
        assert approved.card["allocation"]["selection_mode"] == "explicit_items"
        assert approved.card["allocation"]["deviations"]["projected_net_delta"] == "-50/1"
        assert approved.cert.allocation.selection_mode == "explicit_items"
        assert approved.cert.allocation.deviations.projected_net_delta == -50
    assert first_approval.grant.scope_hash != second_approval.grant.scope_hash


def test_superseded_explicit_input_invalidates_preapproved_old_parent_and_cannot_rebuy():
    case = wealth_execution_case()
    request = _explicit_items(case)
    signatures = _start(case)
    first, _ = case.execute_next()
    assert first.status == "settled"
    approved = case.approve(sequence=1)
    old = case.state.user_inputs[case.draft.parent.request_ref]
    replacement = case.device.confirm_input(
        intent_id=old.scope_id,
        slot="allocation",
        value=request.model_dump(mode="json"),
        now=case.state.now,
        step=3,
        supersedes=old.id,
    )
    assert case.gateway.submit_input(replacement).status == "accepted"
    assert (
        case.gateway.dispatch(approved.action, approved.cert, approved.token).status == "rejected"
    )
    with pytest.raises(ValueError, match="AUTH-CONSUMED|PLAN-SCOPE"):
        draft_allocation(case.gateway, old.principal, old.scope_id, replacement.id)
    repeated = register_allocation(
        case.gateway,
        case.draft,
        selection=signatures.selection,
        inputs=signatures.inputs,
        authorizations=signatures.authorizations,
    )
    assert repeated.status not in {"ready", "registered", "settled"}
    assert case.gateway.bank.execute_count == 1
    assert _positions(case.state) == {"P_B": Fraction(5000)}
    assert available(case.state, "A_CURRENT") == 7000


@pytest.mark.parametrize("drift", ["catalog", "policy", "risk", "input", "external_reservation"])
def test_external_context_drift_blocks_second_even_after_first_legitimate_debit(drift):
    case = wealth_execution_case()
    _start(case)
    first, _ = case.execute_next()
    assert first.status == "settled"
    approved = case.approve(sequence=1)
    if drift == "catalog":
        catalog = signed(case.state.catalog.model_copy(update={"version": 2}), CATALOG, "bank")
        case.gateway.store.update(catalog=catalog)
    elif drift == "policy":
        policy = next(iter(case.state.allocation_policies.values()))
        policy = signed(policy.model_copy(update={"version": 2}), ALLOCATION_POLICY, "bank")
        case.gateway.store.update(allocation_policies={policy.id: policy})
    elif drift == "risk":
        risk = case.state.risk_assessments["RISK_DEMO"]
        risk = signed(
            risk.model_copy(
                update={"issued_at": add_seconds(case.state.now, -1), "expires_at": case.state.now}
            ),
            RISK,
            "risk",
        )
        case.gateway.store.update(risk_assessments={risk.id: risk})
    elif drift == "input":
        old = case.state.user_inputs[case.draft.parent.request_ref]
        newer = case.device.confirm_input(
            intent_id=old.scope_id,
            slot="allocation",
            value=old.value,
            now=case.state.now,
            step=10,
            supersedes=old.id,
        )
        assert case.gateway.submit_input(newer).status == "accepted"
    else:
        event = BusinessEvent(
            id="EXTERNAL_RESERVED",
            intent_key=H("external-reservation"),
            event="reserved",
            kind="transfer",
            principal=approved.action.principal,
            debit=AccountMovement(account_ref="A_CURRENT", amount=Fraction(1)),
            ts=case.state.now,
        )
        case.gateway.store.update(ledger=[*case.state.ledger, event])
    result = case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert result.status == "rejected"
    assert case.gateway.bank.execute_count == 1
    assert _positions(case.state) == {"P_A": Fraction(5000)}
    expected_rules = {
        "catalog": {"BIC-CATALOG", "ALLOC-POLICY", "APR-DRIFT"},
        "policy": {"ALLOC-POLICY", "APR-DRIFT"},
        "risk": {"BIC-RISK", "APR-DRIFT"},
        "input": {"BIC-PREFERENCE", "PROV-STALE", "AUTH-SCOPE", "PLAN-SCOPE", "APR-DRIFT"},
        "external_reservation": {"APR-DRIFT"},
    }
    assert set(result.rule_ids) & expected_rules[drift]
    summary = case.snapshot()
    assert summary["status"] == "partially_executed"
    assert summary["settled_principal"] == "5000/1"
    assert summary["items"][0]["status"] == "settled"
    assert summary["items"][0]["receipt_ref"] == first.receipt.id


def test_safety_lock_persistently_voids_parent_even_if_generic_lock_is_cleared():
    case = wealth_execution_case()
    _start(case)
    prepared = case.prepare()
    for index in range(5):
        case.gateway.propose(prepared.action, prepared.cert, request_id=f"LOCK_TRIGGER_{index}")
    assert prepared.action.principal in case.state.security.locked_at
    assert case.gateway.bank.execute_count == 0
    case.gateway.store.update(
        security=case.state.security.model_copy(update={"locked_at": {}, "lock_reason": {}})
    )
    inspection = inspect_allocation_plan(case.parent_id, case.state)
    assert inspection.errors
    assert inspection.control_status in {"failed", "stopped"}
    action, cert, _ = recertify(prepared.action, prepared.cert, case.state)
    verdict = check(action, cert, case.state, phase="dispatch")
    assert verdict.outcome == "Reject"
    assert "APR-VOID" in verdict.rule_ids
    assert not _positions(case.state)


def test_nonzero_purchase_fees_are_charged_once_per_product_and_added_back_exactly():
    state = make_wealth_state()
    products = [
        product.model_copy(update={"purchase_fee_rate": Fraction(1, 3000)})
        for product in state.catalog.products
    ]
    catalog = signed(state.catalog.model_copy(update={"products": products}), CATALOG, "bank")
    case = wealth_execution_case(state=state.model_copy(update={"catalog": catalog}))
    _start(case)
    first, _ = case.execute_next()
    assert first.status == "settled"
    assert available(case.state, "A_CURRENT") == Fraction(699833, 100)
    second, _ = case.execute_next(sequence=1)
    assert second.status == "settled", second
    assert available(case.state, "A_CURRENT") == Fraction(199666, 100)
    assert _positions(case.state) == {"P_A": Fraction(5000), "P_C": Fraction(5000)}
    assert sum((event.debit.amount for event in _settled(case)), Fraction()) == Fraction(
        1000334, 100
    )
    assert case.snapshot()["status"] == "completed"
