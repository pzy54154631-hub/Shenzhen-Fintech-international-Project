"""Independent balance examples and immutable snapshot boundaries."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.bank import AccountMovement, BusinessEvent
from corridor.sim.fixtures import make_state
from corridor.stores.bank import BankStore, available, business_date, daily_total


def event(key="one", status="reserved", amount=200, ts="2026-10-16T02:00:00Z"):
    return BusinessEvent(
        id=f"{key}-{status}",
        intent_key=H(key),
        event=status,
        kind="transfer",
        principal="C_DEMO",
        debit=AccountMovement(account_ref="A_CURRENT", amount=Fraction(amount)),
        ts=ts,
    )


def test_snapshot_is_detached_and_rejects_validation_bypass():
    store = BankStore(make_state())
    copy = store.snapshot()
    copy.accounts.clear()
    assert "A_CURRENT" in store.snapshot().accounts
    with pytest.raises(ValueError):
        store.update(now="not-a-time")
    assert store.snapshot().now == "2026-10-16T02:00:00Z"


@pytest.mark.parametrize(
    "status,expected", [("settled", 9800), ("unknown", 9800), ("failed", 10000)]
)
def test_latest_intent_deducts_once_and_failure_releases(status, expected):
    store = BankStore(make_state())
    store.append_event(event())
    assert available(store.snapshot(), "A_CURRENT") == 9800
    store.append_event(event(status=status))
    assert available(store.snapshot(), "A_CURRENT") == expected
    assert daily_total(store.snapshot(), "C_DEMO") == 10000 - expected


def test_journal_roundtrip_and_append_only_signed_inputs(tmp_path):
    from corridor.sim.fixtures import signed_amount

    path = tmp_path / "state.jsonl"
    store = BankStore(make_state(), path=path)
    first = signed_amount("intent", "200/1")
    original = jcs_bytes(first)
    store.append_input(first)
    replacement = signed_amount("intent", "250/1", step=2, supersedes=first.id)
    store.append_input(replacement)
    assert jcs_bytes(store.snapshot().user_inputs[first.id]) == original
    assert len(store.snapshot().user_inputs) == 2
    assert store.is_superseded(first.id)
    assert H(BankStore(make_state(), path=path).snapshot()) == H(store.snapshot())
    assert path.read_bytes().endswith(b"\n")


def test_china_business_date_and_no_refund_netting():
    assert business_date("2026-10-16T15:59:59Z") == "2026-10-16"
    assert business_date("2026-10-16T16:00:00Z") == "2026-10-17"
    store = BankStore(make_state())
    store.append_event(event(status="settled", amount=600))
    store.append_event(
        BusinessEvent(
            id="refund",
            intent_key=H("refund"),
            event="settled",
            kind="refund_request",
            principal="C_DEMO",
            credit=AccountMovement(account_ref="A_CURRENT", amount=Fraction(100)),
            ts=store.snapshot().now,
        )
    )
    assert available(store.snapshot(), "A_CURRENT") == 9500
    assert daily_total(store.snapshot(), "C_DEMO") == 600


def test_duplicate_event_ids_and_unsigned_input_are_rejected():
    from corridor.sim.fixtures import signed_amount

    store = BankStore(make_state())
    store.append_event(event())
    with pytest.raises(ValueError):
        store.append_event(event())
    invalid = signed_amount("intent", "200/1").model_copy(update={"sig": "0" * 128})
    with pytest.raises(ValueError, match="AUTH-SIG"):
        store.append_input(invalid)


def test_general_update_cannot_rewrite_append_only_history():
    from corridor.sim.fixtures import signed_amount

    store = BankStore(make_state())
    store.append_event(event())
    value = signed_amount("intent", "200/1")
    store.append_input(value)
    for changes in (
        {"ledger": []},
        {"user_inputs": {}},
        {"user_inputs": {value.id: value.model_copy(update={"scope_id": "other"})}},
    ):
        with pytest.raises(ValueError, match="Append-only"):
            store.update(**changes)


def test_terminal_event_does_not_move_dispatch_to_the_next_business_day():
    store = BankStore(make_state())
    store.append_event(event(amount=600, ts="2026-10-16T15:59:59Z"))
    store.append_event(event(status="settled", amount=600, ts="2026-10-16T16:00:01Z"))
    assert daily_total(store.snapshot(), "C_DEMO", "2026-10-16T15:59:59Z") == 600
    assert daily_total(store.snapshot(), "C_DEMO", "2026-10-16T16:00:01Z") == 0


def test_revocation_appends_without_changing_original_authorization():
    from corridor.crypto.sign import CONTROL, sign
    from corridor.schemas.bank import AuthorizationRevocation
    from corridor.sim.device import Device
    from corridor.sim.keys import signing_key

    store = BankStore(make_state())
    auth = Device().login(session_id="session", expires_at="2026-10-17T02:00:00Z")
    original = jcs_bytes(auth)
    store.append_authorization(auth)
    revocation = AuthorizationRevocation(
        id="revoke",
        principal="C_DEMO",
        authorization_ref=auth.id,
        revoked_at=store.snapshot().now,
        sig="0" * 128,
    )
    revocation = revocation.model_copy(
        update={"sig": sign(signing_key("device"), CONTROL, revocation)}
    )
    store.append_authorization(revocation)
    assert jcs_bytes(store.snapshot().authorizations[auth.id]) == original
    assert store.is_revoked(auth.id)


def test_short_journal_write_does_not_publish_unpersisted_state(tmp_path, monkeypatch):
    from pathlib import Path

    store = BankStore(make_state(), path=tmp_path / "state.jsonl")
    before = store.snapshot()

    class ShortWriter:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def write(self, data):
            return len(data) - 1

        def flush(self):
            pass

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: ShortWriter())
    with pytest.raises(OSError, match="AUD-WRITE"):
        store.update(now="2026-10-16T02:01:00Z")
    assert store.snapshot() == before
