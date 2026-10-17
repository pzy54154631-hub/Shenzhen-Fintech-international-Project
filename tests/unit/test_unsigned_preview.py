"""Unsigned previews reveal only authenticated principal facts and never authorize."""

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.bench.planning_runner import prepare_transfer
from corridor.crypto.jcs import H
from corridor.gateway.preview import PreviewRequest
from corridor.kernel.binding import business_context_hash
from corridor.sim.fixtures import make_state


def prepared():
    case = BankCase(make_state(), task_id="PREVIEW", subcase_id="boundary")
    return case, prepare_transfer(case, "200/1", step=0)


def test_preview_does_not_mutate_live_state_or_count_an_approval_request():
    case, item = prepared()
    before = H(case.state)
    card = case.gateway.preview(item.action, item.cert)
    assert card["amount"] == "200/1"
    assert card["business_context_hash"]
    assert H(case.state) == before
    assert case.gateway.bank.execute_count == 0


@pytest.mark.parametrize("field,value", [("principal", "OTHER"), ("device_session_id", "OTHER")])
def test_preview_rejects_foreign_or_inactive_session(field, value):
    case, item = prepared()
    with pytest.raises(ValueError, match="READ-ROLE"):
        case.gateway.preview(item.action.model_copy(update={field: value}), item.cert)


def test_preview_rejects_foreign_owned_business_object():
    case, item = prepared()
    state = case.state
    contact = state.contacts["CONTACT_CHEN"].model_copy(update={"owner": "OTHER"})
    case.gateway.store.update(contacts={**state.contacts, contact.id: contact})
    with pytest.raises(ValueError, match="READ-ROLE"):
        case.gateway.preview(item.action, item.cert)


def test_preview_cannot_replace_existing_signed_input_semantics():
    case, item = prepared()
    existing = next(iter(case.state.user_inputs.values()))
    changed = existing.model_copy(
        update={"value": {"amount": "1/1", "ccy": "CNY"}, "sig": "0" * 128}
    )
    with pytest.raises(ValueError, match="collision"):
        case.gateway.preview(item.action, item.cert, inputs=[changed])
    assert case.state.user_inputs[existing.id] == existing


def test_preview_refuses_malformed_action_and_duplicate_sequence_node():
    case, item = prepared()
    with pytest.raises(ValueError):
        case.gateway.preview(item.action.model_copy(update={"kind": "invented"}), item.cert)
    request = PreviewRequest(item.action, item.cert)
    with pytest.raises(ValueError, match="node"):
        case.gateway.preview_sequence([request, request])


def test_business_context_ignores_only_signatures_of_identical_input_and_authority():
    case, item = prepared()
    state = case.state
    expected = business_context_hash(item.action, item.cert, state)
    data = state.model_dump(mode="python")
    data["user_inputs"] = {
        key: value.model_copy(update={"sig": "0" * 128}) for key, value in state.user_inputs.items()
    }
    auth = state.authorizations[item.cert.authorization_ref]
    data["authorizations"][auth.id] = auth.model_copy(update={"sig": "0" * 128})
    unsigned = type(state).model_validate(data)
    assert business_context_hash(item.action, item.cert, unsigned) == expected
    amount = next(iter(unsigned.user_inputs.values()))
    data["user_inputs"][amount.id] = amount.model_copy(
        update={"value": {"amount": "1/1", "ccy": "CNY"}}
    )
    changed = type(state).model_validate(data)
    assert business_context_hash(item.action, item.cert, changed) != expected


def test_zero_signature_draft_overlay_never_becomes_live_authority():
    from corridor.bench.transfer_runner import make_conversation
    from corridor.sim.device_workflow import DeviceWorkflow

    chat, device = make_conversation(task_id="PREVIEW-NO-AUTH")
    workflow = DeviceWorkflow(device)
    candidate = chat.receive("给小陈转200元", request_id="candidate")
    display = workflow.show_transfer(chat, candidate)
    request = workflow._displays[display.display_id]["request"]
    assert all(value.sig == "0" * 128 for value in request.inputs)
    assert all(value.sig == "0" * 128 for value in request.authorizations)
    assert chat.gateway.submit_input(request.inputs[0]).status == "rejected"
    assert chat.gateway.submit_authorization(request.authorizations[0]).status == "rejected"
    assert chat.gateway.dispatch(request.action, request.cert).status == "rejected"
    assert not chat.state.user_inputs
    assert chat.gateway.bank.execute_count == 0
