"""Session-authorized reference views, excluding all untrusted transaction text."""

from typing import Literal

from pydantic import Field

from corridor.crypto.sign import CONTROL, verify
from corridor.schemas.bank import AuthorizationRevocation, SessionAuthorization
from corridor.schemas.base import Model
from corridor.schemas.state import BankState


class HandleView(Model):
    kind: Literal["account", "contact"]
    id: str
    version: int
    owner: str
    name_token: str | None = None
    phone_token: str | None = None
    aliases: list[str] = Field(default_factory=list)
    verified: bool = False
    is_new: bool = False
    account_kind: Literal["current", "locked"] | None = None


def available_handles(state: BankState, principal: str, session_id: str) -> list[HandleView]:
    try:
        state = BankState.model_validate(state.model_dump(mode="python"))
        customer = state.customers.get(principal)
        if customer is None or state.security.active_device_sessions.get(principal) != session_id:
            raise ValueError("READ-ROLE")
        revoked = {
            value.authorization_ref
            for value in state.authorizations.values()
            if isinstance(value, AuthorizationRevocation) and value.revoked_at <= state.now
        }
        if not any(
            isinstance(auth, SessionAuthorization)
            and auth.principal == principal
            and auth.device_session_id == session_id
            and auth.expires_at > state.now
            and auth.id not in revoked
            and auth.read_kinds
            and verify(customer.device_pubkey, CONTROL, auth, auth.sig)
            for auth in state.authorizations.values()
        ):
            raise ValueError("READ-ROLE")
        views = [
            HandleView(
                kind="account",
                id=item.id,
                version=item.version,
                owner=principal,
                account_kind=item.kind,
                verified=True,
            )
            for item in state.accounts.values()
            if item.owner == principal and item.status == "active"
        ]
        views.extend(
            HandleView(
                kind="contact",
                id=item.id,
                version=item.version,
                owner=principal,
                name_token=item.name_token,
                phone_token=item.phone_token,
                aliases=list(item.aliases),
                is_new=item.is_new,
                verified=item.verified_at is not None
                and item.verified_at <= state.now
                and item.verification_ref is not None,
            )
            for item in state.contacts.values()
            if item.owner == principal
        )
        return sorted(views, key=lambda item: (item.kind, item.id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("READ-ROLE") from exc


def find_contacts(views: list[HandleView], query: str) -> list[HandleView]:
    query = query.casefold().strip()
    if not query:
        return []
    result = []
    for candidate in views:
        view = HandleView.model_validate(candidate.model_dump(mode="python"))
        labels = [view.id, view.name_token, view.phone_token, *view.aliases]
        if view.kind == "contact" and any(
            label is not None and label.casefold() == query for label in labels
        ):
            result.append(view)
    return sorted(result, key=lambda item: item.id)
