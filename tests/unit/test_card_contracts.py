"""Card requests carry exact user changes and bank orders carry resolved values."""

import pytest
from pydantic import ValidationError

from corridor.schemas.bank import BankOrder, CardChangeRequest


@pytest.mark.parametrize(
    "payload",
    [
        {"card_ref": "CARD_1", "kind": "lower_card_limit", "limit": "500/1"},
        {"card_ref": "CARD_1", "kind": "freeze_card", "status": "frozen"},
        {"card_ref": "CARD_1", "kind": "restrict_card", "restrictions": ["dining"]},
        {"card_ref": "CARD_1", "kind": "relax_card_restriction", "restrictions": []},
    ],
)
def test_exact_card_change_roundtrips(payload):
    request = CardChangeRequest.model_validate(payload)
    assert CardChangeRequest.model_validate_json(request.model_dump_json()) == request


@pytest.mark.parametrize(
    "changes",
    [
        {"limit": "0/1"},
        {"limit": "-1/1"},
        {"limit": "1/1000"},
        {"limit": 500},
        {"limit": "500/1", "status": "active"},
        {"kind": "freeze_card", "status": "active"},
        {"kind": "restrict_card", "restrictions": ["dining", "dining"]},
        {"kind": "restrict_card", "restrictions": ["shopping", "dining"]},
        {"kind": "restrict_card", "restrictions": ["13900001001"]},
        {"kind": "restrict_card", "restrictions": ["arbitrary instructions!"]},
    ],
)
def test_malformed_card_changes_are_rejected(changes):
    payload = {"card_ref": "CARD_1", "kind": "lower_card_limit", **changes}
    with pytest.raises(ValidationError):
        CardChangeRequest.model_validate(payload)


@pytest.mark.parametrize(
    "kind,args",
    [
        ("apply_virtual_card", {"account_ref": "A_1", "limit": "1000/1"}),
        ("freeze_card", {"card_ref": "CARD_1"}),
        ("lower_card_limit", {"card_ref": "CARD_1", "limit": "500/1"}),
        ("restrict_card", {"card_ref": "CARD_1", "restrictions": ["dining"]}),
    ],
)
def test_bank_card_orders_use_resolved_values(kind, args):
    order = BankOrder.model_validate({
        "intent_key": "a" * 64,
        "action_id": "ACTION_1",
        "principal": "C_DEMO",
        "kind": kind,
        "requested_at": "2026-10-16T08:00:00Z",
        "args": args,
    })
    assert order.args.model_dump(mode="json") == args
    with pytest.raises(ValidationError):
        BankOrder.model_validate({
            **order.model_dump(mode="json"),
            "args": {**args, "change_ref": "UNRESOLVED"},
        })
