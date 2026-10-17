"""Verifier probes for GD-8: properties named by golden tests but never exercised there."""

from corridor.crypto.jcs import H
from corridor.stores.bank import add_seconds
from tests.gateway_cases import gateway_case


def test_relogin_between_kernel_rejections_does_not_reset_streak():
    gateway, device, action, cert = gateway_case()
    bad = cert.model_copy(update={"action_hash": H("wrong")})
    for index in range(2):
        assert gateway.propose(action, bad, request_id=f"BAD_{index}").verdict.outcome == "Reject"
    now = gateway.store.snapshot().now
    login = device.login(session_id="GD8_NEW_SESSION", expires_at=add_seconds(now, 3600))
    assert gateway.login(login).status == "accepted"
    assert gateway.store.snapshot().security.reject_streak[action.principal] == 2
    assert gateway.propose(action, bad, request_id="BAD_2").verdict.outcome == "Reject"
    assert action.principal in gateway.store.snapshot().security.locked_at
