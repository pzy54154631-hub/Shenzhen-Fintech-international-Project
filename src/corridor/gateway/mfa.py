"""Independent, local demonstration MFA verifier; no OTP enters public state."""

from dataclasses import dataclass, field
from datetime import timedelta
from hashlib import sha256
from hmac import compare_digest, digest
from threading import RLock
from uuid import NAMESPACE_URL, uuid5

from nacl.signing import SigningKey

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import MFA, sign
from corridor.schemas.bank import MFAGrant
from corridor.schemas.time import parse_time

_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")


@dataclass
class _Challenge:
    principal: str
    device_session_id: str
    scope_hash: str
    issued_at: str
    expiry: str
    code: str = field(repr=False)
    attempts: int = 0
    closed: bool = False


class MFAVerifier:
    """A separate signing identity with 120-second, three-attempt challenges.

    A repeated scope/sequence request returns the same challenge without resetting
    its attempts or expiry. New requests need a new sequence from the gateway.
    ``test_code`` is exclusively a synthetic device-panel testing control.
    """

    def __init__(self, signing_key: SigningKey) -> None:
        self._key = signing_key
        self._challenges: dict[str, _Challenge] = {}
        self._lock = RLock()

    def challenge(
        self,
        *,
        principal: str,
        device_session_id: str,
        scope_hash: str,
        now: str,
        sequence: int = 0,
    ) -> str:
        issued = parse_time(now)
        if (
            not principal
            or not device_session_id
            or type(sequence) is not int
            or sequence < 0
            or len(scope_hash) != 64
            or any(character not in "0123456789abcdef" for character in scope_hash)
        ):
            raise ValueError("Invalid MFA challenge scope")
        scope = {
            "principal": principal,
            "device_session_id": device_session_id,
            "scope_hash": scope_hash,
        }
        challenge_id = str(uuid5(_NAMESPACE, f"{H(scope)}:{sequence}:mfa-challenge"))
        with self._lock:
            if challenge_id not in self._challenges:
                material = digest(
                    self._key.encode(), jcs_bytes({**scope, "sequence": sequence}), sha256
                )
                code = f"{int.from_bytes(material[:8], 'big') % 1000000:06d}"
                self._challenges[challenge_id] = _Challenge(
                    principal,
                    device_session_id,
                    scope_hash,
                    now,
                    (issued + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    code,
                )
            return challenge_id

    def verify(self, challenge_id: str, code: str, *, now: str) -> MFAGrant | None:
        verified_at = parse_time(now)
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None or challenge.closed:
                return None
            if now >= challenge.expiry:
                challenge.closed = True
                return None
            if now < challenge.issued_at:
                return None
            if (
                not isinstance(code, str)
                or not code.isascii()
                or not compare_digest(code, challenge.code)
            ):
                challenge.attempts += 1
                if challenge.attempts >= 3:
                    challenge.closed = True
                return None
            challenge.closed = True
            grant = MFAGrant(
                grant_id=str(uuid5(_NAMESPACE, f"{challenge_id}:0:mfa-grant")),
                principal=challenge.principal,
                device_session_id=challenge.device_session_id,
                scope_hash=challenge.scope_hash,
                method="sms_sim",
                challenge_id=challenge_id,
                issued_at=now,
                expiry=(verified_at + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                sig="0" * 128,
            )
            return grant.model_copy(update={"sig": sign(self._key, MFA, grant)})

    def test_code(self, challenge_id: str) -> str:
        """Expose the simulated SMS solely to the explicit device testing panel."""
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                raise KeyError("Unknown simulated MFA challenge")
            return challenge.code
