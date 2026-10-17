"""Append-only public state snapshots and exact event projections.

The gateway owns its transaction lock. No secret values or private keys belong here.
"""

from datetime import timedelta
from fractions import Fraction
from pathlib import Path
from typing import Any

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import CONTROL, INPUT, SPA, verify
from corridor.schemas.bank import (
    Authorization,
    AuthorizationRevocation,
    BusinessEvent,
    ScheduledPaymentAuthorization,
    UserInput,
)
from corridor.schemas.base import loads_exact
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time


def business_date(now: str) -> str:
    return (parse_time(now) + timedelta(hours=8)).date().isoformat()


def add_seconds(now: str, seconds: int) -> str:
    return (parse_time(now) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def latest_events(state: BankState) -> dict[str, BusinessEvent]:
    return {event.intent_key: event for event in state.ledger}


def execution_times(state: BankState) -> dict[str, str]:
    times: dict[str, str] = {}
    previous: dict[str, str] = {}
    for event in state.ledger:
        if event.intent_key not in times or (
            event.event == "reserved" and previous.get(event.intent_key) == "failed"
        ):
            times[event.intent_key] = event.ts
        previous[event.intent_key] = event.event
    return times


def available(state: BankState, account_ref: str) -> Fraction:
    balance = state.accounts[account_ref].opening_balance
    for event in latest_events(state).values():
        if event.event in {"reserved", "settled", "unknown"}:
            if event.debit is not None and event.debit.account_ref == account_ref:
                balance -= event.debit.amount
        if event.event == "settled" and event.credit is not None:
            if event.credit.account_ref == account_ref:
                balance += event.credit.amount
    return balance


def commitments(state: BankState, principal: str, now: str | None = None) -> dict[str, Fraction]:
    day = business_date(now or state.now)
    result: dict[str, Fraction] = {}
    latest = latest_events(state)
    times = execution_times(state)
    executed = {event.commitment_id for event in latest.values() if event.commitment_id}
    for task in state.schedules.values():
        if (
            task.owner == principal
            and task.status in {"pending", "due", "waiting_mfa"}
            and business_date(task.due_at) == day
            and task.commitment_id not in executed
        ):
            spa = state.authorizations.get(task.spa_ref)
            if isinstance(spa, ScheduledPaymentAuthorization) and spa.target.kind in {
                "transfer",
                "merchant_order",
            }:
                result[task.commitment_id] = spa.amount
    for key, event in latest.items():
        if (
            event.principal == principal
            and event.kind in {"transfer", "merchant_order"}
            and event.event in {"reserved", "settled", "unknown"}
            and business_date(times[key]) == day
            and event.debit is not None
        ):
            result[event.commitment_id or key] = event.debit.amount
    return result


def daily_total(state: BankState, principal: str, now: str | None = None) -> Fraction:
    return sum(commitments(state, principal, now).values(), Fraction(0))


def financial_version(state: BankState, principal: str) -> str:
    return H({
        "accounts": {
            key: value for key, value in state.accounts.items() if value.owner == principal
        },
        "ledger": [
            event
            for event in latest_events(state).values()
            if event.principal == principal
            and (
                event.debit is not None
                or event.credit is not None
                or event.kind
                in {"schedule_transfer", "cancel_schedule", "purchase_product", "redeem_product"}
            )
        ],
        "schedules": {
            key: value for key, value in state.schedules.items() if value.owner == principal
        },
        "positions": {
            key: value for key, value in state.positions.items() if value.owner == principal
        },
    })


class BankStore:
    def __init__(self, initial: BankState, *, path: Path | None = None) -> None:
        self.path = path
        self._state = BankState.model_validate(initial.model_dump(mode="python"))
        self._history: list[bytes] = []
        if path is not None and path.exists():
            data = path.read_bytes()
            if data and not data.endswith(b"\n"):
                raise ValueError("Incomplete state journal")
            for line in data.splitlines():
                record = loads_exact(line)
                previous = H(self._history[-1].decode("utf-8")) if self._history else "0" * 64
                if record["prev_hash"] != previous or record["state_hash"] != H(record["state"]):
                    raise ValueError("State journal integrity failure")
                self._state = BankState.model_validate(record["state"])
                self._history.append(line)
        elif path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._commit(self._state)

    def snapshot(self) -> BankState:
        return BankState.model_validate(self._state.model_dump(mode="python"))

    def _commit(self, state: BankState) -> None:
        previous = H(self._history[-1].decode("utf-8")) if self._history else "0" * 64
        line = jcs_bytes({"prev_hash": previous, "state_hash": H(state), "state": state})
        if self.path is not None:
            with self.path.open("ab") as stream:
                data = line + b"\n"
                if stream.write(data) != len(data):
                    raise OSError("AUD-WRITE")
                stream.flush()
        self._history.append(line)
        self._state = state

    def update(self, **changes: Any) -> None:
        value = self._state.model_dump(mode="python")
        value.update(changes)
        new_state = BankState.model_validate(value)
        if new_state.ledger[: len(self._state.ledger)] != self._state.ledger:
            raise ValueError("Append-only ledger cannot be rewritten")
        for name in ("user_inputs", "authorizations", "allocation_plans"):
            before = getattr(self._state, name)
            after = getattr(new_state, name)
            if any(
                key not in after or jcs_bytes(item) != jcs_bytes(after[key])
                for key, item in before.items()
            ):
                raise ValueError(f"Append-only {name} cannot be rewritten")
        self._commit(new_state)

    def append_event(self, event: BusinessEvent) -> None:
        event = BusinessEvent.model_validate(event.model_dump(mode="python"))
        if any(old.id == event.id for old in self._state.ledger):
            raise ValueError("Duplicate business event ID")
        self.update(ledger=[*self._state.ledger, event])

    def append_input(self, value: UserInput) -> None:
        value = UserInput.model_validate(value.model_dump(mode="python"))
        customer = self._state.customers.get(value.principal)
        if customer is None or not verify(customer.device_pubkey, INPUT, value, value.sig):
            raise ValueError("AUTH-SIG")
        if value.id in self._state.user_inputs:
            raise ValueError("Duplicate input ID")
        if value.supersedes is not None:
            previous = self._state.user_inputs.get(value.supersedes)
            if (
                previous is None
                or (previous.principal, previous.scope_id, previous.slot)
                != (value.principal, value.scope_id, value.slot)
                or self.is_superseded(previous.id)
            ):
                raise ValueError("PROV-COHERENCE")
        self.update(user_inputs={**self._state.user_inputs, value.id: value})

    def is_superseded(self, input_id: str) -> bool:
        return any(value.supersedes == input_id for value in self._state.user_inputs.values())

    def append_authorization(self, value: Authorization) -> None:
        customer = self._state.customers.get(value.principal)
        ctx = SPA if isinstance(value, ScheduledPaymentAuthorization) else CONTROL
        if customer is None or not verify(customer.device_pubkey, ctx, value, value.sig):
            raise ValueError("AUTH-SIG")
        if value.id in self._state.authorizations:
            raise ValueError("Duplicate authorization ID")
        if isinstance(value, AuthorizationRevocation):
            original = self._state.authorizations.get(value.authorization_ref)
            if (
                original is None
                or isinstance(original, AuthorizationRevocation)
                or original.principal != value.principal
                or value.revoked_at > self._state.now
            ):
                raise ValueError("AUTH-SCOPE")
        self.update(authorizations={**self._state.authorizations, value.id: value})

    def is_revoked(self, authorization_ref: str) -> bool:
        return any(
            isinstance(value, AuthorizationRevocation)
            and value.authorization_ref == authorization_ref
            and value.revoked_at <= self._state.now
            for value in self._state.authorizations.values()
        )
