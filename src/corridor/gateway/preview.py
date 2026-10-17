"""Authenticated, unsigned card projections on disposable validated snapshots.

No snapshot escapes this module. Drafts cannot be submitted or executed here.
Sequence projections cover only the explicitly described lock/SPA effects and
produce neither bank receipts nor any claim that an action is authorized.
"""

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from corridor.crypto.jcs import H
from corridor.gateway.handles import available_handles
from corridor.kernel.binding import binding, intent_key, resolve_amount
from corridor.kernel.spa import due_at
from corridor.schemas.bank import (
    AccountMovement,
    BankAction,
    BankCertificate,
    BusinessEvent,
    InputTerm,
    OperationAuthorization,
    ReadTerm,
    ReceiptTerm,
    ScheduledPaymentAuthorization,
    StateTerm,
    UserInput,
)
from corridor.schemas.domain import ScheduledTask
from corridor.schemas.models import JsonValue
from corridor.schemas.state import BankState
from corridor.stores.bank import add_seconds

DraftAuthority = OperationAuthorization | ScheduledPaymentAuthorization
_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")
_OWNED = (
    "accounts",
    "contacts",
    "transactions",
    "cards",
    "subscriptions",
    "positions",
    "schedules",
    "orders",
    "calendar",
    "user_inputs",
    "authorizations",
    "risk_assessments",
)


@dataclass(frozen=True)
class PreviewRequest:
    action: BankAction
    cert: BankCertificate
    inputs: Sequence[UserInput] = ()
    authorizations: Sequence[DraftAuthority] = ()


def _owner(value: Any, principal: str) -> None:
    owner = getattr(value, "owner", getattr(value, "principal", None))
    if owner is not None and owner != principal:
        raise ValueError("READ-ROLE")


def _references(value: Any, state: BankState, principal: str) -> None:
    """Reject cross-principal references including those inside draft preferences."""
    if isinstance(value, dict):
        for item in value.values():
            _references(item, state, principal)
    elif isinstance(value, (tuple, list)):
        for item in value:
            _references(item, state, principal)
    elif isinstance(value, str):
        for name in _OWNED:
            obj = getattr(state, name).get(value)
            if obj is not None:
                _owner(obj, principal)
        if value in state.customers and value != principal:
            raise ValueError("READ-ROLE")


def _overlay(request: PreviewRequest, state: BankState) -> tuple[PreviewRequest, BankState]:
    action = BankAction.model_validate(request.action.model_dump(mode="python"))
    cert = BankCertificate.model_validate(request.cert.model_dump(mode="python"))
    # Authenticate against live/signed records before any unsigned overlay exists.
    available_handles(state, action.principal, action.device_session_id)
    if cert.action_hash != H(action):
        raise ValueError("Preview action hash mismatch")
    inputs = dict(state.user_inputs)
    authorities = dict(state.authorizations)
    for item in request.inputs:
        item = UserInput.model_validate(item.model_dump(mode="python"))
        _owner(item, action.principal)
        old = inputs.get(item.id)
        if old is not None:
            if H(old) != H(item):
                raise ValueError("Preview input collision")
        elif item.sig != "0" * 128:
            raise ValueError("New preview inputs must be unsigned")
        else:
            inputs[item.id] = item
    for auth in request.authorizations:
        if not isinstance(auth, (OperationAuthorization, ScheduledPaymentAuthorization)):
            raise ValueError("Preview authority must be a narrow unsigned draft")
        auth = type(auth).model_validate(auth.model_dump(mode="python"))
        _owner(auth, action.principal)
        old_auth = authorities.get(auth.id)
        if old_auth is not None:
            if H(old_auth) != H(auth):
                raise ValueError("Preview authority collision")
        elif auth.sig != "0" * 128:
            raise ValueError("New preview authorities must be unsigned")
        else:
            authorities[auth.id] = auth
    payload = state.model_dump(mode="python")
    payload.update(user_inputs=inputs, authorizations=authorities)
    projected = BankState.model_validate(payload)
    selected_authority = projected.authorizations.get(cert.authorization_ref)
    if selected_authority is None:
        raise ValueError("Preview authority is missing")
    _owner(selected_authority, action.principal)
    _references(action.args.model_dump(mode="python"), projected, action.principal)
    for term in cert.derivations.values():
        if isinstance(term, StateTerm):
            if term.collection == "catalog":
                obj = next((p for p in projected.catalog.products if p.id == term.object_ref), None)
            else:
                obj = getattr(projected, term.collection).get(term.object_ref)
            if obj is None:
                raise ValueError("Preview reference is missing")
            _owner(obj, action.principal)
            if term.collection == "customers" and term.object_ref != action.principal:
                raise ValueError("READ-ROLE")
        elif isinstance(term, InputTerm):
            referenced_input = projected.user_inputs.get(term.input_ref)
            if referenced_input is None:
                raise ValueError("Preview input is missing")
            _owner(referenced_input, action.principal)
            _references(referenced_input.value, projected, action.principal)
        elif isinstance(term, ReceiptTerm):
            receipt = projected.receipts.get(term.receipt_ref)
            if receipt is None or getattr(receipt, "trust", None) == "exploratory":
                raise ValueError("Preview requires a trusted financial source")
            owner = getattr(receipt, "principal", None)
            if owner is None:
                owner = getattr(receipt, "parameters", {}).get("principal")
            if owner != action.principal:
                raise ValueError("READ-ROLE")
        elif isinstance(term, ReadTerm):
            _references(term.value, projected, action.principal)
    for item in request.inputs:
        _references(item.value, projected, action.principal)
    for authority in request.authorizations:
        _references(authority.model_dump(mode="python"), projected, action.principal)
    return PreviewRequest(action, cert, request.inputs, request.authorizations), projected


def preview_card(request: PreviewRequest, state: BankState) -> dict[str, JsonValue]:
    request, projected = _overlay(request, state)
    return deepcopy(binding(request.action, request.cert, projected).card_core)


def _project_known_effect(request: PreviewRequest, state: BankState) -> BankState:
    action, cert = request.action, request.cert
    payload = state.model_dump(mode="python")
    args = action.args.model_dump(mode="python")
    if action.kind in {"lock_funds", "unlock_funds"}:
        amount = resolve_amount(action, state)
        if amount is None:
            raise ValueError("Missing projection amount")
        source, locked = args["source_ref"], args["locked_ref"]
        debit, credit = (source, locked) if action.kind == "lock_funds" else (locked, source)
        event = BusinessEvent(
            id=str(uuid5(_NAMESPACE, f"preview:{action.action_id}")),
            intent_key=intent_key(action, state),
            event="settled",
            kind=action.kind,
            principal=action.principal,
            ts=state.now,
            debit=AccountMovement(account_ref=debit, amount=amount),
            credit=AccountMovement(account_ref=credit, amount=amount),
        )
        payload["ledger"] = [*state.ledger, event]
    elif action.kind == "schedule_transfer":
        spa = state.authorizations[cert.authorization_ref]
        if not isinstance(spa, ScheduledPaymentAuthorization):
            raise ValueError("Missing fixed schedule")
        schedules = dict(state.schedules)
        for index in range(spa.max_runs):
            due = due_at(spa, index)
            if due is None:
                break
            run = ScheduledTask(
                id=str(uuid5(_NAMESPACE, f"{spa.id}:{index}:scheduled-run")),
                owner=action.principal,
                plan_id=action.plan_id,
                node_id=action.node_id,
                spa_ref=spa.id,
                run_index=index,
                action_template={"kind": spa.target.kind},
                input_refs=sorted({
                    term.input_ref
                    for term in cert.derivations.values()
                    if isinstance(term, InputTerm)
                }),
                due_at=due,
                expires_at=min(add_seconds(due, 86400), spa.end),
                commitment_id=H({"spa_id": spa.id, "run_index": index}),
                status="pending",
            )
            if run.id in schedules:
                raise ValueError("Schedule projection already exists")
            schedules[run.id] = run
        payload["schedules"] = schedules
    else:
        raise ValueError("Sequential preview requires redisplay after this operation")
    return BankState.model_validate(payload)


def preview_sequence(
    requests: Sequence[PreviewRequest], state: BankState
) -> dict[str, dict[str, JsonValue]]:
    if not requests or len({r.action.node_id for r in requests}) != len(requests):
        raise ValueError("Preview requires distinct selected nodes")
    cards = {}
    for index, request in enumerate(requests):
        request, state = _overlay(request, state)
        cards[request.action.node_id] = deepcopy(
            binding(request.action, request.cert, state).card_core
        )
        if index + 1 < len(requests):
            state = _project_known_effect(request, state)
    return cards
