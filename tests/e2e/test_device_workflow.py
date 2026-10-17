"""A device gesture signs only facts it retained from canonical gateway previews."""

from fractions import Fraction

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.bench.planning_runner import prepare_transfer
from corridor.bench.transfer_runner import make_conversation
from corridor.crypto.jcs import H
from corridor.sim.device_workflow import DeviceWorkflow
from corridor.sim.fixtures import make_state


def test_yellow_preview_is_unsigned_then_one_gesture_approves_exact_facts_once():
    chat, device = make_conversation(task_id="DEVICE-ONE")
    workflow = DeviceWorkflow(device)
    candidate = chat.receive("给小陈转200元", request_id="input")
    before = H(chat.state)
    display = workflow.show_transfer(chat, candidate)
    assert H(chat.state) == before
    assert not chat.state.user_inputs
    assert display.card["amount"] == "200/1"
    assert display.card["tier"] == "yellow"
    result = workflow.confirm_transfer(chat, display.display_id, request_id="one-click")
    assert result.status == "approved" and result.token is not None
    assert len(chat.state.user_inputs) == 2
    assert chat.gateway.bank.execute_count == 0
    repeated = workflow.confirm_transfer(chat, display.display_id, request_id="one-click")
    assert repeated.token == result.token
    assert len(chat.state.security.approval_requests[device.principal]) == 1
    assert chat.dispatch(result.prepared, result.token).status == "settled"
    assert chat.dispatch(repeated.prepared, repeated.token).status == "rejected"
    assert chat.gateway.bank.execute_count == 1


def test_display_copy_cannot_change_privately_retained_device_facts():
    chat, device = make_conversation(task_id="DEVICE-COPY")
    workflow = DeviceWorkflow(device)
    display = workflow.show_transfer(chat, chat.receive("给小陈转200元", request_id="input"))
    display.card["amount"] = "1/1"
    result = workflow.confirm_transfer(chat, display.display_id, request_id="confirm")
    assert result.status == "approved"
    assert result.prepared.proposal.card["amount"] == "200/1"


@pytest.mark.parametrize("change", ["balance", "contact_version", "destination", "policy"])
def test_preclick_drift_redisplays_without_input_or_approval_signatures(change):
    chat, device = make_conversation(task_id=f"DEVICE-DRIFT-{change}")
    workflow = DeviceWorkflow(device)
    display = workflow.show_transfer(chat, chat.receive("给小陈转200元", request_id="input"))
    state = chat.state
    if change == "balance":
        account = state.accounts["A_CURRENT"].model_copy(update={"opening_balance": Fraction(9000)})
        chat.gateway.store.update(accounts={**state.accounts, account.id: account})
    elif change in {"contact_version", "destination"}:
        values = {"version": 2} if change == "contact_version" else {"destination_ref": "OTHER"}
        contact = state.contacts["CONTACT_CHEN"].model_copy(update=values)
        chat.gateway.store.update(contacts={**state.contacts, contact.id: contact})
    else:
        chat.gateway.store.update(
            policy=state.policy.model_copy(update={"transfer_yellow_limit": Fraction(100)})
        )
    result = workflow.confirm_transfer(chat, display.display_id, request_id="confirm")
    assert result.status == "redisplay" and result.token is None
    assert not chat.state.user_inputs
    assert chat.gateway.bank.execute_count == 0


def test_drift_during_prepare_does_not_receive_an_approval_token(monkeypatch):
    chat, device = make_conversation(task_id="DEVICE-MID-DRIFT")
    workflow = DeviceWorkflow(device)
    display = workflow.show_transfer(chat, chat.receive("给小陈转200元", request_id="input"))
    prepare = chat.prepare

    def changed(*args, **kwargs):
        result = prepare(*args, **kwargs)
        result.proposal.card["available"] = "1/1"
        return result

    monkeypatch.setattr(chat, "prepare", changed)
    result = workflow.confirm_transfer(chat, display.display_id, request_id="confirm")
    assert result.status == "redisplay" and result.token is None
    assert chat.gateway.bank.execute_count == 0


def test_red_transfer_needs_separate_scoped_mfa_before_device_approval():
    chat, device = make_conversation(task_id="DEVICE-RED")
    workflow = DeviceWorkflow(device)
    display = workflow.show_transfer(chat, chat.receive("给小陈转1500元", request_id="input"))
    result = workflow.confirm_transfer(chat, display.display_id, request_id="confirm")
    assert result.status == "waiting_mfa" and result.token is None
    prepared = result.prepared
    red_display = workflow.show_prepared(chat.gateway, prepared)
    missing = workflow.confirm_prepared(chat.gateway, red_display.display_id, request_id="missing")
    assert missing.status == "waiting_mfa" and missing.token is None
    challenge = chat.gateway.request_mfa(prepared.action, prepared.cert)
    grant = device.complete_mfa(chat.gateway.mfa, challenge, now=chat.state.now)
    assert chat.gateway.submit_mfa(grant).status == "accepted"
    prepared.cert = prepared.cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    red_display = workflow.show_prepared(chat.gateway, prepared)
    approved = workflow.confirm_prepared(
        chat.gateway, red_display.display_id, request_id="mfa-confirm"
    )
    assert approved.status == "approved" and approved.token is not None
    assert chat.dispatch(approved.prepared, approved.token).status == "settled"


def test_prepared_plan_selection_does_not_sign_unchecked_nodes():
    case = BankCase(make_state(), task_id="DEVICE-PLAN", subcase_id="selection")
    first = prepare_transfer(case, "100/1", step=0)
    second = prepare_transfer(case, "100/1", step=1)
    workflow = DeviceWorkflow(case.device)
    # The prepared-only API still restricts token signing to explicitly checked nodes.
    displays = {
        item.action.node_id: workflow.show_prepared(case.gateway, item) for item in (first, second)
    }
    result = workflow.confirm_selected(
        case.gateway, displays, [first.action.node_id], request_id="selected"
    )
    assert set(result.tokens) == {first.action.node_id}
    assert second.action.node_id not in result.tokens
    assert case.gateway.bank.execute_count == 0


def test_request_id_cannot_be_reused_for_another_display():
    chat, device = make_conversation(task_id="DEVICE-REQUEST")
    workflow = DeviceWorkflow(device)
    first = workflow.show_transfer(chat, chat.receive("给小陈转200元", request_id="first"))
    workflow.confirm_transfer(chat, first.display_id, request_id="gesture")
    second = workflow.show_transfer(chat, chat.receive("给小陈转300元", request_id="second"))
    with pytest.raises(ValueError, match="request"):
        workflow.confirm_transfer(chat, second.display_id, request_id="gesture")


@pytest.mark.parametrize(
    "field",
    [
        "principal_token",
        "kind",
        "objects",
        "amount",
        "ccy",
        "fees",
        "tier",
        "tier_reasons",
        "total_before",
        "total_after",
        "available",
        "business_date",
        "execution_window",
        "risk",
        "best_interest",
        "irreversible",
        "business_context_hash",
        "action_hash",
        "intent_id",
        "plan_hash",
        "node_id",
        "device_session_id",
        "spa_hash",
        "spa",
    ],
)
def test_each_canonical_fact_drift_during_prepare_prevents_signing(field, monkeypatch):
    chat, device = make_conversation(task_id=f"DEVICE-FIELD-{field}")
    workflow = DeviceWorkflow(device)
    display = workflow.show_transfer(chat, chat.receive("给小陈转200元", request_id="input"))
    prepare = chat.prepare
    signatures = []
    monkeypatch.setattr(device, "approve", lambda *args, **kwargs: signatures.append(args))

    def changed(*args, **kwargs):
        result = prepare(*args, **kwargs)
        result.proposal.card[field] = "corrupted"
        return result

    monkeypatch.setattr(chat, "prepare", changed)
    result = workflow.confirm_transfer(chat, display.display_id, request_id="gesture")
    assert result.status == "redisplay"
    assert result.token is None and signatures == []
    assert result.display.card[field] == display.card[field]


def test_prepared_red_consumed_mfa_is_not_signed_again():
    chat, device = make_conversation(task_id="DEVICE-USED-MFA")
    workflow = DeviceWorkflow(device)
    display = workflow.show_transfer(chat, chat.receive("给小陈转1500元", request_id="input"))
    waiting = workflow.confirm_transfer(chat, display.display_id, request_id="prepare")
    item = waiting.prepared
    challenge = chat.gateway.request_mfa(item.action, item.cert)
    grant = device.complete_mfa(chat.gateway.mfa, challenge, now=chat.state.now)
    assert chat.gateway.submit_mfa(grant).status == "accepted"
    item.cert = item.cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    fresh = workflow.show_prepared(chat.gateway, item)
    security = chat.state.security.model_copy(update={"consumed_grant_ids": [grant.grant_id]})
    chat.gateway.store.update(security=security)
    result = workflow.confirm_prepared(chat.gateway, fresh.display_id, request_id="used")
    assert result.status == "rejected"
    assert result.token is None and "MFA-REUSE" in result.rule_ids


def test_selected_plan_preview_projects_available_and_commitments_without_live_effects():
    from corridor.ui.controller import DemoController

    app = DemoController()
    app.start_session()
    before = H(app.state)
    draft = app.preview_birthday()
    cards = [node["card"] for node in draft["nodes"]]
    assert H(app.state) == before
    assert [card["available"] for card in cards] == ["10000/1", "9000/1", "9000/1", "9000/1"]
    assert [card["total_after"] for card in cards] == ["0/1", "0/1", "300/1", "500/1"]
    assert cards[3]["total_before"] == "300/1"
    for card in cards[1:]:
        spa = card["spa"]
        assert spa["max_runs"] == 1 and spa["schedule"] == {"type": "once"}
        assert spa["creation_tier"] == "yellow"
        assert spa["source_ref"] == "A_CURRENT"
        assert spa["amount"] == card["amount"]
        assert spa["start"] == card["execution_window"]["start"]
        assert spa["expiry"] == card["execution_window"]["end"]
    assert cards[2]["spa"]["target"] == {
        "kind": "merchant_order",
        "merchant_ref": "FLOWERS",
        "offer_ref": "OFFER_FLOWERS",
    }
    assert not app.state.schedules and not app.state.ledger
    result = app.confirm_plan(draft["plan_id"], [node["id"] for node in draft["nodes"]])
    assert result["status"] == "settled"
    assert len(app.state.security.consumed_nonces) == 4
    assert len(app.state.schedules) == 3
