"""Ed25519 signatures over a canonical domain-separated object."""

from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from corridor.crypto.jcs import jcs_bytes, json_value

CATALOG = "corridor/bank/catalog/v1"
ALLOCATION_POLICY = "corridor/bank/allocation-policy/v1"
INPUT = "corridor/bank/input/v1"
APPROVE = "corridor/bank/approval/v1"
MFA = "corridor/bank/mfa/v1"
RECEIPT = "corridor/bank/receipt/v1"
RISK = "corridor/bank/risk/v1"
CONTROL = "corridor/bank/control/v1"
SPA = "corridor/bank/spa/v1"
CONTEXTS = frozenset({CATALOG, ALLOCATION_POLICY, INPUT, APPROVE, MFA, RECEIPT, RISK, CONTROL, SPA})


def _payload(ctx: str, body: Any) -> bytes:
    value = json_value(body)
    if ctx not in CONTEXTS or not isinstance(value, dict) or "ctx" in value:
        raise ValueError("Expected a registered context and an object without ctx")
    return jcs_bytes({"ctx": ctx, **{key: item for key, item in value.items() if key != "sig"}})


def sign(key: SigningKey, ctx: str, body: Any) -> str:
    return key.sign(_payload(ctx, body)).signature.hex()


def verify(pub: VerifyKey | bytes | str, ctx: str, body: Any, sig: str) -> bool:
    try:
        key = (
            pub
            if isinstance(pub, VerifyKey)
            else VerifyKey(bytes.fromhex(pub) if isinstance(pub, str) else pub)
        )
        key.verify(_payload(ctx, body), bytes.fromhex(sig))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
