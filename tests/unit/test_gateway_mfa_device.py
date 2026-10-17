"""Explicit device approval and separate deterministic MFA verifier identity."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import APPROVE, MFA, SPA, verify
from corridor.gateway.mfa import MFAVerifier
from corridor.kernel.binding import binding, mfa_scope
from corridor.schemas.time import parse_time
from corridor.sim.device import Device
from corridor.sim.keys import signing_key
from tests.bank_cases import spa_case, transfer_case

NOW = "2026-10-16T02:00:00Z"


def challenge(verifier, **changes):
    args = {
        "principal": "C_DEMO",
        "device_session_id": "SESSION_TEST",
        "scope_hash": H({"scope": 1}),
        "now": NOW,
        **changes,
    }
    return verifier.challenge(**args)


def test_mfa_success_is_signed_by_independent_verifier_and_is_single_use():
    verifier = MFAVerifier(signing_key("mfa"))
    ref = challenge(verifier)
    code = verifier.test_code(ref)
    assert code.isdigit() and len(code) == 6
    grant = verifier.verify(ref, code, now=NOW)
    assert grant is not None and grant.scope_hash == H({"scope": 1})
    assert verify(signing_key("mfa").verify_key, MFA, grant, grant.sig)
    assert not verify(signing_key("device").verify_key, MFA, grant, grant.sig)
    assert not verify(signing_key("gateway").verify_key, MFA, grant, grant.sig)
    assert (parse_time(grant.expiry) - parse_time(grant.issued_at)).total_seconds() == 120
    assert verifier.verify(ref, code, now=NOW) is None


def test_third_wrong_code_permanently_exhausts_challenge():
    verifier = MFAVerifier(signing_key("mfa"))
    ref = challenge(verifier)
    for _ in range(3):
        assert verifier.verify(ref, "wrong", now=NOW) is None
    assert verifier.verify(ref, verifier.test_code(ref), now=NOW) is None
    assert challenge(verifier) == ref  # Re-requesting the same sequence cannot reset attempts.
    assert verifier.verify(ref, verifier.test_code(ref), now=NOW) is None
    fresh = challenge(verifier, sequence=1)
    assert fresh != ref
    assert verifier.verify(fresh, verifier.test_code(fresh), now=NOW) is not None


def test_two_errors_then_correct_code_remains_valid():
    verifier = MFAVerifier(signing_key("mfa"))
    ref = challenge(verifier)
    assert verifier.verify(ref, "wrong", now=NOW) is None
    assert verifier.verify(ref, "wrong", now=NOW) is None
    assert verifier.verify(ref, verifier.test_code(ref), now=NOW) is not None


def test_non_ascii_code_is_a_failed_attempt_and_never_raises():
    verifier = MFAVerifier(signing_key("mfa"))
    ref = challenge(verifier)
    assert verifier.verify(ref, "错误验证码", now=NOW) is None
    assert verifier.verify(ref, verifier.test_code(ref), now=NOW) is not None


def test_duplicate_challenge_request_preserves_original_expiry():
    verifier = MFAVerifier(signing_key("mfa"))
    ref = challenge(verifier)
    assert challenge(verifier, now="2026-10-16T02:01:59Z") == ref
    assert verifier.verify(ref, verifier.test_code(ref), now="2026-10-16T02:02:00Z") is None


@pytest.mark.parametrize("at", ["2026-10-16T01:59:59Z", "2026-10-16T02:02:00Z"])
def test_challenge_half_open_time_window(at):
    verifier = MFAVerifier(signing_key("mfa"))
    ref = challenge(verifier)
    assert verifier.verify(ref, verifier.test_code(ref), now=at) is None


def test_expired_challenge_is_not_revived_by_clock_rewind():
    verifier = MFAVerifier(signing_key("mfa"))
    ref = challenge(verifier)
    assert verifier.verify(ref, verifier.test_code(ref), now="2026-10-16T02:02:00Z") is None
    assert verifier.verify(ref, verifier.test_code(ref), now=NOW) is None


def test_distinct_scopes_sessions_and_principals_get_distinct_challenges():
    verifier = MFAVerifier(signing_key("mfa"))
    refs = [
        challenge(verifier),
        challenge(verifier, principal="OTHER"),
        challenge(verifier, device_session_id="OTHER"),
        challenge(verifier, scope_hash=H({"scope": 2})),
    ]
    assert len(set(refs)) == 4
    assert verifier.verify("missing", "000000", now=NOW) is None
    with pytest.raises(KeyError):
        verifier.test_code("missing")


def test_device_approval_binds_full_card_certificate_action_and_session():
    action, cert, state = transfer_case()
    card = binding(action, cert, state).card_core
    token = Device().approve(action, cert, card, now=state.now)
    assert token.action_hash == H(action) and token.cert_hash == H(cert)
    assert token.card_hash == H(card) and token.device_session_id == action.device_session_id
    assert token.plan_hash == action.plan_hash and token.node_id == action.node_id
    assert token.tier == "yellow" and token.ownership_epoch == 0
    assert verify(state.customers[action.principal].device_pubkey, APPROVE, token, token.sig)
    assert not verify(state.roots.gateway_pubkey, APPROVE, token, token.sig)
    assert (parse_time(token.expiry) - parse_time(token.issued_at)).total_seconds() == 300
    assert Device().approve(action, cert, card, now=state.now) == token
    assert Device().approve(action, cert, card, now=state.now, sequence=1).nonce != token.nonce


def test_device_cannot_sign_for_a_different_customer():
    action, cert, state = transfer_case()
    with pytest.raises(ValueError):
        Device("OTHER").approve(action, cert, binding(action, cert, state).card_core, now=state.now)


@pytest.mark.parametrize("field", ["kind", "plan_hash", "node_id", "device_session_id"])
def test_device_rejects_a_card_for_another_action_context(field):
    action, cert, state = transfer_case()
    card = binding(action, cert, state).card_core
    card[field] = "OTHER"
    with pytest.raises(ValueError):
        Device().approve(action, cert, card, now=state.now)


def test_device_rejects_certificate_for_different_action():
    action, cert, state = transfer_case()
    cert = cert.model_copy(update={"action_hash": H({"wrong": True})})
    with pytest.raises(ValueError):
        Device().approve(action, cert, binding(action, cert, state).card_core, now=state.now)


def test_device_panel_completes_mfa_without_returning_otp_in_grant():
    action, cert, state = transfer_case(Fraction(1200))
    card = binding(action, cert, state).card_core
    verifier = MFAVerifier(signing_key("mfa"))
    ref = verifier.challenge(
        principal=action.principal,
        device_session_id=action.device_session_id,
        scope_hash=mfa_scope(action, H(card)),
        now=state.now,
    )
    grant = Device().complete_mfa(verifier, ref, now=state.now)
    assert grant is not None and grant.scope_hash == mfa_scope(action, H(card))
    assert "otp" not in grant.model_dump() and "code" not in grant.model_dump()
    assert Device().complete_mfa(verifier, ref, now=state.now) is None


def test_device_signs_persistent_spa_in_its_own_domain():
    _, cert, state = spa_case()
    spa = state.authorizations[cert.authorization_ref]
    signed = Device().sign_spa(spa.model_dump(mode="python"))
    assert verify(state.customers["C_DEMO"].device_pubkey, SPA, signed, signed.sig)
    assert not verify(state.roots.gateway_pubkey, SPA, signed, signed.sig)
