"""Registered, deterministic plans for gateway integration tests."""

from fractions import Fraction
from pathlib import Path

from corridor.crypto.jcs import H
from corridor.eval.mockbank.exec import MockBank
from corridor.gateway.audit import AuditLog
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.service import Gateway
from corridor.schemas.bank import Plan, PlanNode
from corridor.sim.device import Device
from corridor.sim.keys import signing_key
from corridor.stores.bank import BankStore
from tests.bank_cases import query_case, recertify, transfer_case


def gateway_case(amount=Fraction(200), *, query=False, path: Path | None = None):
    action, cert, state = query_case() if query else transfer_case(amount)
    plan = Plan(
        plan_id=action.plan_id,
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=action.intent_id,
        goal_input_refs=[] if query else [action.args.amount_ref],
        nodes=[
            PlanNode(
                node_id=action.node_id,
                tool=action.kind,
                args={key.removeprefix("args."): term for key, term in cert.derivations.items()},
            )
        ],
        ownership_epoch=0,
    )
    action = action.model_copy(update={"plan_hash": H(plan)})
    action, cert, state = recertify(action, cert, state)
    store = BankStore(state, path=path / "state.jsonl" if path else None)
    bank = MockBank(state, signing_key("bank"))
    gateway = Gateway(
        store,
        bank,
        audit=AuditLog(path / "audit.jsonl" if path else None),
        mfa=MFAVerifier(signing_key("mfa")),
        evidence_dir=path / "decisions" if path else None,
    )
    assert gateway.submit_plan(plan).status == "registered"
    return gateway, Device(), action, cert


def approve(gateway, device, action, cert, *, sequence=0):
    proposal = gateway.propose(action, cert)
    return device.approve(
        action, cert, proposal.card, now=gateway.store.snapshot().now, sequence=sequence
    )


def control_case(kind="password_change_request"):
    from corridor.crypto.sign import CONTROL
    from corridor.schemas.bank import BankAction, InputTerm, StateTerm
    from tests.bank_cases import signed

    action, cert, state = transfer_case()
    device = Device()
    slot = "principal" if kind == "password_change_request" else "draft_handle"
    value = action.principal if slot == "principal" else "DRAFT_TEST"
    item = device.confirm_input(intent_id=action.intent_id, slot=slot, value=value, now=state.now)
    old_auth = state.authorizations[cert.authorization_ref]
    authorization = signed(
        old_auth.model_copy(
            update={
                "allowed_kind": kind,
                "object_refs": [action.principal] if slot == "principal" else [],
                "amount_bound": None,
                "input_hashes": [H(item)],
            }
        ),
        CONTROL,
    )
    state = state.model_copy(
        update={"user_inputs": {item.id: item}, "authorizations": {authorization.id: authorization}}
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": kind,
        "args": {slot: value},
    })
    cert = cert.model_copy(
        update={
            "derivations": {
                f"args.{slot}": StateTerm(
                    collection="customers", object_ref=action.principal, field="id", version=1
                )
                if slot == "principal"
                else InputTerm(input_ref=item.id, slot=slot)
            }
        }
    )
    plan = Plan(
        plan_id=action.plan_id,
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=action.intent_id,
        goal_input_refs=[item.id],
        ownership_epoch=0,
        nodes=[
            PlanNode(
                node_id=action.node_id, tool=kind, args={slot: cert.derivations[f"args.{slot}"]}
            )
        ],
    )
    action = action.model_copy(update={"plan_hash": H(plan)})
    action, cert, state = recertify(action, cert, state)
    gateway = Gateway(
        BankStore(state), MockBank(state, signing_key("bank")), mfa=MFAVerifier(signing_key("mfa"))
    )
    assert gateway.submit_plan(plan).status == "registered"
    return gateway, device, action, cert


def approve_red(gateway, device, action, cert):
    proposal = gateway.propose(action, cert)
    challenge = gateway.request_mfa(action, cert)
    grant = device.complete_mfa(gateway.mfa, challenge, now=gateway.store.snapshot().now)
    assert gateway.submit_mfa(grant).status == "accepted"
    cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    return cert, token
