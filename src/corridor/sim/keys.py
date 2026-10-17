"""Deterministic demonstration keys; never production credentials."""

from hashlib import sha256
from uuid import NAMESPACE_URL, uuid5

from nacl.signing import SigningKey

SEED = 20261016
NAMESPACE_CORRIDOR = uuid5(NAMESPACE_URL, "corridor-demo-v0")


def signing_key(label: str, seed: int = SEED) -> SigningKey:
    return SigningKey(sha256(f"corridor-demo-v0|{label}|{seed}".encode()).digest())


def public_key(label: str, seed: int = SEED) -> str:
    return bytes(signing_key(label, seed).verify_key).hex()


def stable_id(task_id: str, step: int, kind: str) -> str:
    return str(uuid5(NAMESPACE_CORRIDOR, f"{task_id}:{step}:{kind}"))
