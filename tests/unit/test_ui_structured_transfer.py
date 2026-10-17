"""English device forms reuse exact unsigned previews and gateway approval checks."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.schemas.bank import OperationAuthorization
from corridor.ui.controller import DemoController
from corridor.ui.structured_transfer import preview_structured_transfer


def controller():
    demo = DemoController()
    assert demo.start_session()["status"] == "ready"
    return demo


def preview(demo, amount="200.25", contact="CONTACT_LIN_B", request_id="structured"):
    return preview_structured_transfer(demo, "A_CURRENT", contact, amount, request_id)


def test_structured_preview_is_unsigned_and_exact_device_confirmation_executes_once():
    demo = controller()
    before = H(demo.state)
    pending = preview(demo)
    assert H(demo.state) == before
    assert pending["card"]["amount"] == "801/4"
    assert pending["card"]["objects"]["contact_ref"] == "CONTACT_LIN_B"
    assert pending["card"]["objects"]["source_ref"] == "A_CURRENT"
    assert preview(demo) == pending
    assert H(demo.state) == before
    result = demo.approve_pending(pending["pending_id"])
    assert result["status"] == "settled"
    assert demo.gateway.bank.execute_count == 1
    assert demo.approve_pending(pending["pending_id"]) == result
    assert demo.gateway.bank.execute_count == 1
    assert demo.gateway.bank.final_state()["destinations"] == {"DEST_CONTACT_LIN_B": "801/4"}
    amounts = [value.value for value in demo.state.user_inputs.values() if value.slot == "amount"]
    assert amounts == [{"amount": "801/4", "ccy": "CNY"}]
    contacts = [
        value.value for value in demo.state.user_inputs.values() if value.slot == "contact_ref"
    ]
    assert contacts == ["CONTACT_LIN_B"]
    authorizations = [
        value
        for value in demo.state.authorizations.values()
        if isinstance(value, OperationAuthorization)
    ]
    assert len(authorizations) == 1
    assert authorizations[0].object_refs == ["A_CURRENT", "CONTACT_LIN_B"]
    assert authorizations[0].amount_bound == Fraction(801, 4)
    assert set(authorizations[0].input_hashes) == {
        H(value) for value in demo.state.user_inputs.values()
    }
    assert demo.state.security.consumed_nonces
    assert demo.gateway.verify_log()


@pytest.mark.parametrize("amount", ["0", "-1", "0.001", "1/3", "NaN", "1,000", 2.0])
def test_structured_amount_validation_fails_before_signing(amount):
    demo = controller()
    before = H(demo.state)
    with pytest.raises(ValueError):
        preview(demo, amount=amount)
    assert H(demo.state) == before
    assert not demo.state.user_inputs
    assert demo.gateway.bank.execute_count == 0


@pytest.mark.parametrize("source,contact", [("A_LOCKED", "CONTACT_CHEN"), ("A_CURRENT", None)])
def test_structured_form_requires_an_owned_current_account_and_explicit_contact(source, contact):
    demo = controller()
    before = H(demo.state)
    with pytest.raises(ValueError):
        preview_structured_transfer(demo, source, contact, "200", "invalid-choice")
    assert H(demo.state) == before
    assert not demo.state.user_inputs


def test_structured_request_identity_cannot_change_amount_or_recipient():
    demo = controller()
    preview(demo)
    before = H(demo.state)
    with pytest.raises(ValueError, match="Request ID"):
        preview(demo, amount="201")
    with pytest.raises(ValueError, match="Request ID"):
        preview(demo, contact="CONTACT_CHEN")
    assert H(demo.state) == before
    assert demo.gateway.bank.execute_count == 0


def test_structured_red_transfer_requires_independent_mfa_before_one_dispatch():
    demo = controller()
    pending = preview(demo, amount="1200")
    identifier = pending["pending_id"]
    assert pending["card"]["tier"] == "red"
    assert demo.request_mfa(identifier)["status"] == "intent_confirmation_required"
    assert not demo.state.user_inputs
    assert demo.approve_pending(identifier)["status"] == "waiting_mfa"
    assert demo.approve_pending(identifier)["status"] == "waiting_mfa"
    assert demo.gateway.bank.execute_count == 0
    demo.request_mfa(identifier)
    assert demo.complete_mfa(identifier)["status"] == "mfa_verified"
    result = demo.approve_pending(identifier)
    assert result["status"] == "settled"
    assert demo.approve_pending(identifier) == result
    assert demo.gateway.bank.execute_count == 1
    assert len(demo.state.security.consumed_grant_ids) == 1
    assert len(demo.state.security.consumed_nonces) == 1
    assert demo.gateway.verify_log()


def test_structured_drift_requires_new_card_and_fresh_confirmation():
    demo = controller()
    older = preview(demo, amount="200", request_id="older")
    newer = preview(demo, amount="100", request_id="newer")
    assert demo.approve_pending(newer["pending_id"])["status"] == "settled"
    inputs = H(demo.state.user_inputs)
    result = demo.approve_pending(older["pending_id"])
    assert result["status"] == "redisplay"
    assert H(demo.state.user_inputs) == inputs
    assert demo.gateway.bank.execute_count == 1
    replacement = result["replacement"]
    assert replacement["pending_id"] != older["pending_id"]
    assert replacement["card"]["available"] == "9900/1"
    assert demo.approve_pending(replacement["pending_id"])["status"] == "settled"
    assert Fraction(demo.snapshot()["balances"]["A_CURRENT"]) == 9700
    assert demo.gateway.bank.execute_count == 2
    assert demo.gateway.verify_log()
