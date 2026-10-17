"""Pure card state checks and canonical projections from trusted bank objects."""

from fractions import Fraction
from typing import cast

from corridor.schemas.bank import BankAction, CardChangeRequest
from corridor.schemas.models import JsonValue
from corridor.schemas.state import BankState
from corridor.stores.bank import latest_events

CARD_KINDS = frozenset({
    "apply_virtual_card",
    "freeze_card",
    "unfreeze_card",
    "report_card_lost",
    "restore_card",
    "lower_card_limit",
    "raise_card_limit",
    "restrict_card",
    "relax_card_restriction",
})
STATE_TRANSITIONS = {
    "freeze_card": ({"active"}, "frozen"),
    "unfreeze_card": ({"frozen"}, "active"),
    "report_card_lost": ({"active", "frozen"}, "lost"),
    "restore_card": ({"lost"}, "frozen"),
}


def card_request(action: BankAction, state: BankState) -> CardChangeRequest | None:
    ref = action.args.model_dump(mode="python").get("change_ref")
    return CardChangeRequest.model_validate(state.user_inputs[ref].value) if ref else None


def card_account_ref(action: BankAction, state: BankState) -> str | None:
    if action.kind not in CARD_KINDS:
        return None
    args = action.args.model_dump(mode="python")
    if action.kind == "apply_virtual_card":
        return cast(str, args["account_ref"])
    card = state.cards.get(str(args.get("card_ref", "")))
    return card.account_ref if card else None


def card_errors(action: BankAction, state: BankState) -> list[str]:
    if action.kind not in CARD_KINDS:
        return []
    errors: list[str] = []
    account_ref = card_account_ref(action, state)
    account = state.accounts.get(account_ref or "")
    if account is None or account.status != "active" or account.kind != "current":
        errors.append("DOMAIN-STATE")
    if account is not None and account.owner != action.principal:
        errors.append("AUTH-PRINCIPAL")
    if action.kind == "apply_virtual_card":
        if state.policy.transfer_yellow_limit <= 0:
            errors.append("SCHEMA-UNIT")
        for event in latest_events(state).values():
            previous = event.object_delta.get("action")
            if (
                event.kind == action.kind
                and event.principal == action.principal
                and event.event in {"reserved", "settled", "unknown"}
                and isinstance(previous, dict)
                and previous.get("intent_id") == action.intent_id
            ):
                errors.append("IDEM-DUP")
        return errors
    card = state.cards.get(str(action.args.model_dump().get("card_ref", "")))
    if card is None:
        return [*errors, "DOMAIN-STATE"]
    if card.owner != action.principal:
        errors.append("AUTH-PRINCIPAL")
    if action.kind in STATE_TRANSITIONS:
        sources, _ = STATE_TRANSITIONS[action.kind]
        if card.status not in sources:
            errors.append("DOMAIN-STATE")
        return errors
    if card.status == "lost":
        errors.append("DOMAIN-STATE")
    try:
        request = card_request(action, state)
    except (KeyError, ValueError):
        return errors
    if request is None:
        return [*errors, "PROV-MISSING"]
    if action.kind in {"lower_card_limit", "raise_card_limit"}:
        valid = request.limit is not None and (
            request.limit < card.limit
            if action.kind == "lower_card_limit"
            else request.limit > card.limit
        )
    else:
        proposed = set(request.restrictions or [])
        current = set(card.restrictions)
        valid = proposed > current if action.kind == "restrict_card" else proposed < current
    if not valid:
        errors.append("DOMAIN-STATE")
    return errors


def _controls(status: str, limit: Fraction, restrictions: list[str]) -> dict[str, JsonValue]:
    return {
        "status": status,
        "limit": f"{limit.numerator}/{limit.denominator}",
        "restrictions": cast(list[JsonValue], sorted(restrictions)),
    }


def card_facts(action: BankAction, state: BankState) -> dict[str, JsonValue]:
    account_ref = card_account_ref(action, state)
    if action.kind == "apply_virtual_card":
        return {
            "card_ref": None,
            "account_ref": account_ref,
            "before": None,
            "after": _controls("active", state.policy.transfer_yellow_limit, []),
        }
    card = state.cards[str(action.args.model_dump()["card_ref"])]
    before = _controls(card.status, card.limit, card.restrictions)
    after = dict(before)
    request = card_request(action, state)
    if action.kind in STATE_TRANSITIONS:
        after["status"] = STATE_TRANSITIONS[action.kind][1]
    elif request is not None and request.limit is not None:
        after["limit"] = f"{request.limit.numerator}/{request.limit.denominator}"
    elif request is not None and request.restrictions is not None:
        after["restrictions"] = cast(list[JsonValue], sorted(request.restrictions))
    return {
        "card_ref": card.id,
        "account_ref": account_ref,
        "before": before,
        "after": after,
    }
