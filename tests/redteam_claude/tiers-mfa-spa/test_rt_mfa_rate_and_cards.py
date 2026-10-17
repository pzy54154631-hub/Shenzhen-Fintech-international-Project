"""Red-team probes: MFA guessing budget on the unlock path, SPA creation card facts."""

from corridor.crypto.sign import SPA
from corridor.kernel.binding import binding
from corridor.stores.bank import add_seconds
from tests.bank_cases import recertify, signed, spa_case
from tests.gateway_cases import gateway_case


def test_unlock_mfa_reissues_are_bounded_per_window_and_attempts_never_reset():
    """TMS-3's lifetime cap was rejected; verify the actual 120-second scope throttle."""
    gateway, _, action, _ = gateway_case()
    principal = action.principal
    gateway.lock(principal, "test")
    gateway.store.update(now=add_seconds(gateway.store.snapshot().now, 1800))
    issued = {}
    for _ in range(40):
        now = gateway.store.snapshot().now
        challenge = gateway.request_unlock_mfa(principal)
        if challenge is not None and challenge not in issued:
            issued[challenge] = now
            for _ in range(3):
                assert (
                    gateway.mfa.verify(
                        challenge,
                        "000000" if gateway.mfa.test_code(challenge) != "000000" else "111111",
                        now=gateway.store.snapshot().now,
                    )
                    is None
                )
        assert gateway.request_unlock_mfa(principal) == challenge
        assert gateway.mfa.verify(challenge, gateway.mfa.test_code(challenge), now=now) is None
        cutoff = add_seconds(now, -600)
        assert sum(cutoff < created <= now for created in issued.values()) <= 5
        gateway.store.update(now=add_seconds(now, 60))
    assert len(issued) > 6  # A sliding-window rate is not a lifetime challenge cap.


def test_monthly_spa_creation_card_reports_first_due_day_not_start_day():
    """DESIGN-BANK 4.2: future plans account projected cumulative on the China date of due_at."""
    action, cert, state = spa_case()
    spa = state.authorizations["SPA_TEST"]
    # start = 2026-10-17T02:00Z (local Oct 17 10:00); monthly day 5 -> first due local Nov 5.
    spa = signed(
        type(spa).model_validate({
            **spa.model_dump(mode="python"),
            "schedule": {"type": "monthly", "day": 5},
            "max_runs": 3,
            "creation_tier": "red",
        }),
        SPA,
    )
    state = state.model_copy(update={"authorizations": {**state.authorizations, spa.id: spa}})
    action, cert, state = recertify(action, cert, state)
    facts = binding(action, cert, state)
    assert facts.card_core["business_date"] == "2026-11-05", facts.card_core["business_date"]
