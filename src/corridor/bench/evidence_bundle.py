"""Exact-byte evidence inventories, separate from the signed gateway audit chain."""

from hashlib import sha256
from pathlib import Path
from typing import Any

from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact

_SEALS = {"bundle.json", "bundle.sha256"}
_SOURCES = {"scripted", "live-recorded", "strict-replay", "not_run"}


def _inventory(root: Path) -> dict[str, str]:
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Evidence symlinks are not supported")
        if path.is_file() and path.relative_to(root).as_posix() not in _SEALS:
            files[path.relative_to(root).as_posix()] = sha256(path.read_bytes()).hexdigest()
    return files


def seal_bundle(root: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    """Seal a completed run; the checksum detects corruption, not malicious re-signing."""
    if metadata.get("source") not in _SOURCES:
        raise ValueError("An explicit evidence source is required")
    root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "evidence-bundle-v1",
        "metadata": metadata,
        "files": _inventory(root),
    }
    raw = jcs_bytes(manifest)
    (root / "bundle.json").write_bytes(raw)
    (root / "bundle.sha256").write_bytes(sha256(raw).hexdigest().encode("ascii") + b"\n")
    return manifest


def verify_bundle(root: Path) -> dict[str, Any]:
    raw = (root / "bundle.json").read_bytes()
    if (root / "bundle.sha256").read_bytes().strip() != sha256(raw).hexdigest().encode("ascii"):
        raise ValueError("Evidence manifest digest mismatch")
    manifest = loads_exact(raw)
    if manifest.get("schema_version") != "evidence-bundle-v1":
        raise ValueError("Unknown evidence manifest")
    actual = _inventory(root)
    if set(actual) != set(manifest["files"]):
        raise ValueError("Evidence inventory mismatch")
    if actual != manifest["files"]:
        raise ValueError("Evidence file digest mismatch")
    return manifest["metadata"]
