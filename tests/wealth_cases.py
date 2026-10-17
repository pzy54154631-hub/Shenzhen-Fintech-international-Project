"""Device-signed allocation comparison triples for the real kernel."""

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL
from corridor.kernel.allocation import build_allocation
from corridor.schemas.bank import BankAction, BankCertificate, InputTerm
from corridor.sim.device import Device
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.stores.bank import add_seconds
from tests.bank_cases import PRINCIPAL, SESSION, recertify, signed


def allocation_case(
    *, request=None, state=None, intent="WEALTH_TEST", build=True, step=1, supersedes=None
):
    state = state or make_wealth_state()
    request = request or allocation_request()
    device = Device()
    value = device.confirm_input(
        intent_id=intent,
        slot="allocation",
        value=request.model_dump(mode="json"),
        now=state.now,
        step=step,
        supersedes=supersedes,
    )
    auth = device.login(session_id=SESSION, expires_at=add_seconds(state.now, 3600))
    auth = signed(auth.model_copy(update={"read_kinds": ["allocation_compare"]}), CONTROL)
    state = state.model_copy(
        update={
            "user_inputs": {**state.user_inputs, value.id: value},
            "authorizations": {**state.authorizations, auth.id: auth},
            "security": state.security.model_copy(
                update={"active_device_sessions": {PRINCIPAL: SESSION}}
            ),
        }
    )
    action = BankAction.model_validate({
        "action_id": "WEALTH_ACTION",
        "intent_id": intent,
        "principal": PRINCIPAL,
        "device_session_id": SESSION,
        "plan_id": "WEALTH_PLAN",
        "plan_hash": H({"plan": "wealth"}),
        "node_id": "WEALTH_COMPARE",
        "kind": "allocation_compare",
        "args": {"request_ref": value.id},
    })
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=auth.id,
        derivations={"args.request_ref": InputTerm(input_ref=value.id, slot="allocation")},
        dependency_hashes={},
        allocation=build_allocation(PRINCIPAL, intent, value.id, state) if build else None,
    )
    return recertify(action, cert, state)
