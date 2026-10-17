"""Pure validation of signed scheduled-payment scopes and their fixed runs."""

from calendar import monthrange
from dataclasses import dataclass, field
from datetime import timedelta
from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, SPA, verify
from corridor.schemas.bank import (
    AuthorizationRevocation,
    BankAction,
    BankCertificate,
    BusinessEvent,
    FundsArgs,
    MerchantArgs,
    MerchantTarget,
    OnceSchedule,
    ScheduledPaymentAuthorization,
    ScheduleTransferArgs,
    TransferArgs,
    TransferTarget,
)
from corridor.schemas.domain import ScheduledTask
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time


@dataclass
class SpaResult:
    is_spa: bool = False
    is_creation: bool = False
    errors: list[str] = field(default_factory=list)
    creation_tier: str | None = None
    grant_exempt: bool = False
    commitment_id: str | None = None

    def reject(self, *inner: str) -> None:
        for rule in ("DOMAIN-SPA", *inner):
            if rule not in self.errors:
                self.errors.append(rule)


def _is_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _target_valid(spa: ScheduledPaymentAuthorization, state: BankState) -> bool:
    source = state.accounts.get(spa.source_ref)
    if (
        source is None
        or source.owner != spa.principal
        or source.kind != "current"
        or source.status != "active"
    ):
        return False
    target = spa.target
    if isinstance(target, TransferTarget):
        contact = state.contacts.get(target.contact_ref)
        return (
            contact is not None
            and contact.owner == spa.principal
            and contact.destination_version == spa.destination_version
            and contact.verified_at is not None
            and contact.verified_at <= state.now
            and contact.verification_ref is not None
        )
    if isinstance(target, MerchantTarget):
        merchant = state.merchants.get(target.merchant_ref)
        if merchant is None or not merchant.verified or merchant.version != spa.destination_version:
            return False
        offer = next((item for item in merchant.offers if item.id == target.offer_ref), None)
        return (
            offer is not None
            and offer.version == spa.destination_version
            and offer.available
            and offer.amount == spa.amount
        )
    locked = state.accounts.get(target.locked_ref)
    return (
        locked is not None
        and locked.kind == "locked"
        and locked.status == "active"
        and locked.owner == spa.principal
        and locked.parent_ref == spa.source_ref
        and locked.version == spa.destination_version
    )


def _creation_tier(spa: ScheduledPaymentAuthorization, state: BankState) -> str:
    if not isinstance(spa.schedule, OnceSchedule) or spa.amount > 1000:
        return "red"
    if isinstance(spa.target, TransferTarget):
        contact = state.contacts.get(spa.target.contact_ref)
        if contact is None or contact.is_new:
            return "red"
    if isinstance(spa.target, MerchantTarget):
        merchant = state.merchants.get(spa.target.merchant_ref)
        if merchant is None or not merchant.verified or merchant.is_new:
            return "red"
    return "yellow"


def _action_scope(action: BankAction, spa: ScheduledPaymentAuthorization, creation: bool) -> bool:
    if (
        action.principal != spa.principal
        or action.intent_id != spa.id
        or action.plan_id != spa.plan_id
        or action.node_id != spa.node_id
    ):
        return False
    if creation:
        args = action.args
        if (
            not isinstance(args, ScheduleTransferArgs)
            or args.schedule_ref != spa.id
            or args.source_ref != spa.source_ref
        ):
            return False
        if isinstance(spa.target, TransferTarget):
            return args.contact_ref == spa.target.contact_ref
        if isinstance(spa.target, MerchantTarget):
            return (
                args.merchant_ref == spa.target.merchant_ref
                and args.offer_ref == spa.target.offer_ref
            )
        return args.locked_ref == spa.target.locked_ref and args.purpose_ref is not None
    if action.kind != spa.target.kind:
        return False
    if isinstance(spa.target, TransferTarget):
        return (
            isinstance(action.args, TransferArgs)
            and action.args.source_ref == spa.source_ref
            and action.args.contact_ref == spa.target.contact_ref
        )
    if isinstance(spa.target, MerchantTarget):
        return (
            isinstance(action.args, MerchantArgs)
            and action.args.source_ref == spa.source_ref
            and action.args.merchant_ref == spa.target.merchant_ref
            and action.args.offer_ref == spa.target.offer_ref
        )
    return (
        isinstance(action.args, FundsArgs)
        and action.args.source_ref == spa.source_ref
        and action.args.locked_ref == spa.target.locked_ref
    )


def _due_at(spa: ScheduledPaymentAuthorization, run_index: int) -> str | None:
    if run_index < 0 or run_index >= spa.max_runs:
        return None
    if isinstance(spa.schedule, OnceSchedule):
        return spa.start if run_index == 0 else None
    local_start = parse_time(spa.start) + timedelta(hours=8)
    found = 0
    # A permitted 365-day window intersects at most thirteen calendar months.
    for offset in range(14):
        year, month_zero = divmod(local_start.year * 12 + local_start.month - 1 + offset, 12)
        month = month_zero + 1
        if year > 9999:
            return None
        if spa.schedule.day > monthrange(year, month)[1]:
            continue
        local_due = local_start.replace(year=year, month=month, day=spa.schedule.day)
        due = (local_due - timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if due < spa.start:
            continue
        if due >= spa.end:
            return None
        if found == run_index:
            return due
        found += 1
    return None


def due_at(spa: ScheduledPaymentAuthorization, run_index: int) -> str | None:
    """Return the fixed UTC due time; absent calendar days are skipped."""
    return _due_at(spa, run_index)


def _creation_event(spa: ScheduledPaymentAuthorization, state: BankState) -> BusinessEvent | None:
    source = state.accounts.get(spa.source_ref)
    if source is None:
        return None
    key = H({
        "principal": spa.principal,
        "intent_id": spa.id,
        "node_id": spa.node_id,
        "kind": "schedule_transfer",
    })
    candidates = [event for event in state.ledger if event.intent_key == key]
    if not candidates:
        return None
    event = candidates[-1]
    delta = event.object_delta
    if (
        not {
            "spa_hash",
            "creation_tier",
            "approval_verified",
            "approval_hash",
            "mfa_verified",
            "mfa_hash",
            "source_version",
            "destination_version",
        }
        <= delta.keys()
    ):
        return None
    if (
        event.event != "settled"
        or event.kind != "schedule_transfer"
        or event.principal != spa.principal
        or event.ts > spa.start
        or event.ts > state.now
        or delta.get("spa_hash") != H(spa)
        or delta.get("creation_tier") != spa.creation_tier
        or delta.get("approval_verified") is not True
        or not _is_hash(delta.get("approval_hash"))
        or type(delta.get("source_version")) is not int
        or type(delta.get("destination_version")) is not int
        or delta.get("source_version") != source.version
        or delta.get("destination_version") != spa.destination_version
    ):
        return None
    if spa.creation_tier == "red":
        if delta.get("mfa_verified") is not True or not _is_hash(delta.get("mfa_hash")):
            return None
    elif delta.get("mfa_verified") is not False or delta.get("mfa_hash") is not None:
        return None
    return event


def _run_scope(
    task: ScheduledTask,
    action: BankAction,
    spa: ScheduledPaymentAuthorization,
    state: BankState,
    result: SpaResult,
) -> None:
    result.commitment_id = H({"spa_id": spa.id, "run_index": task.run_index})
    if (
        task.owner != spa.principal
        or task.spa_ref != spa.id
        or task.plan_id != spa.plan_id
        or task.node_id != spa.node_id
        or task.id != action.action_id
        or task.commitment_id != result.commitment_id
    ):
        result.reject()
    if task.status not in {"pending", "due", "waiting_mfa"}:
        result.reject("DOMAIN-SCHEDULE")
    matching_runs = [
        entry
        for entry in state.schedules.values()
        if entry.spa_ref == spa.id and entry.run_index == task.run_index
    ]
    if len(matching_runs) != 1:
        result.reject()
    expected_due = _due_at(spa, task.run_index)
    if expected_due is None:
        result.reject("DOMAIN-SCHEDULE")
    else:
        expiry = min(
            (parse_time(expected_due) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"), spa.end
        )
        if (
            task.due_at != expected_due
            or task.expires_at != expiry
            or not expected_due <= state.now < expiry
        ):
            result.reject("DOMAIN-SCHEDULE")
    if any(
        event.intent_key == result.commitment_id or event.commitment_id == result.commitment_id
        for event in state.ledger
    ):
        # Even a failed SPA run cannot silently become a fresh automatic attempt.
        result.reject()


def is_cancelled(spa: ScheduledPaymentAuthorization, state: BankState) -> bool:
    """Read the append-only cancellation evidence shared by creation and runs."""
    return any(
        event.event == "settled"
        and event.kind == "cancel_schedule"
        and event.principal == spa.principal
        and event.object_delta.get("spa_ref") == spa.id
        and event.ts <= state.now
        for event in state.ledger
    )


def inspect_spa(
    action: BankAction, cert: BankCertificate, S: BankState, amount: Fraction | None
) -> SpaResult:
    """Check the persistent SPA scope; the caller handles balance and current MFA.

    Creation needs ordinary device approval and, for red, fresh MFA. Later red
    runs rely on the trusted creation event bound to the complete signed SPA.
    Yellow runs are never MFA-exempt: the caller compares their daily total and
    requests a fresh run-scoped grant when it crosses the threshold.
    """
    spa = S.authorizations.get(cert.authorization_ref)
    if not isinstance(spa, ScheduledPaymentAuthorization):
        return SpaResult()
    result = SpaResult(is_spa=True, is_creation=action.kind == "schedule_transfer")
    if spa.principal in S.security.locked_at:
        result.reject("APR-LOCK")
    customer = S.customers.get(spa.principal)
    if customer is None:
        result.reject("AUTH-PRINCIPAL")
    elif not verify(customer.device_pubkey, SPA, spa, spa.sig):
        result.reject("AUTH-SIG")
    if is_cancelled(spa, S):
        result.reject()
    for record in S.authorizations.values():
        if (
            isinstance(record, AuthorizationRevocation)
            and record.authorization_ref == spa.id
            and record.revoked_at <= S.now
        ):
            result.reject()
            if (
                customer is None
                or record.principal != spa.principal
                or not verify(customer.device_pubkey, CONTROL, record, record.sig)
            ):
                result.reject("AUTH-SIG")
    if not _action_scope(action, spa, result.is_creation):
        result.reject()
    if amount is None or amount != spa.amount:
        result.reject()
    if not _target_valid(spa, S):
        result.reject("DOMAIN-STATE")
    duration = parse_time(spa.end) - parse_time(spa.start)
    if duration <= timedelta(0) or duration > timedelta(days=365):
        result.reject("DOMAIN-SCHEDULE")
    if result.is_creation:
        result.creation_tier = _creation_tier(spa, S)
        if result.creation_tier != spa.creation_tier:
            result.reject()
        if S.now > spa.start or S.now >= spa.end:
            result.reject("DOMAIN-SCHEDULE")
        if _due_at(spa, 0) is None:
            result.reject("DOMAIN-SCHEDULE")
        return result
    result.creation_tier = spa.creation_tier
    if not spa.start <= S.now < spa.end:
        result.reject("DOMAIN-SCHEDULE")
    task = S.schedules.get(action.action_id)
    if task is None:
        result.reject("DOMAIN-SCHEDULE")
    else:
        _run_scope(task, action, spa, S, result)
    if _creation_event(spa, S) is None:
        result.reject()
    result.grant_exempt = (
        not result.errors
        and spa.creation_tier == "red"
        and task is not None
        and task.status != "waiting_mfa"
    )
    return result
