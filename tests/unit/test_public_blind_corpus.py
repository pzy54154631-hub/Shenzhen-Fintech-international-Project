"""Public blind inputs preserve the frozen hashes without distributing author logs."""

import shutil
from hashlib import sha256
from pathlib import Path

import pytest

from corridor.bench.blind_nl import load_frozen_cases

CORPUS = Path(__file__).resolve().parents[2] / "data" / "blind"
MANIFEST_HASH = "7aee83c75270c6c96dcde2dfd4be3f6d09fed562a1ca7605e0fcf3dedf28eef7"


def test_distributed_blind_corpus_matches_original_frozen_manifest():
    manifest = CORPUS / "FROZEN-SHA256.txt"
    assert sha256(manifest.read_bytes()).hexdigest() == MANIFEST_HASH
    assert not (CORPUS / "author-session.log").exists()
    for line in manifest.read_text(encoding="utf-8-sig").splitlines():
        digest, name = line.split("  ", 1)
        if name != "author-session.log":
            assert sha256((CORPUS / name.replace("\\", "/")).read_bytes()).hexdigest() == digest
    cases, provenance = load_frozen_cases(CORPUS)
    assert len(cases) == 16
    assert provenance["frozen_manifest_sha256"] == MANIFEST_HASH
    assert provenance["isolated"] is True


@pytest.mark.parametrize(
    "name", ["cases/case-01.json", "materials/world.md", "AUTHOR-TASK.md", "provenance.json"]
)
def test_public_distribution_still_requires_every_evaluation_input(tmp_path, name):
    root = tmp_path / "blind"
    shutil.copytree(CORPUS, root)
    (root / name).unlink()
    with pytest.raises((ValueError, OSError)):
        load_frozen_cases(root)


@pytest.mark.parametrize("name", ["cases/case-01.json", "materials/world.md"])
def test_public_distribution_rejects_changed_input_bytes(tmp_path, name):
    root = tmp_path / "blind"
    shutil.copytree(CORPUS, root)
    path = root / name
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="Frozen hash mismatch"):
        load_frozen_cases(root)


def test_author_log_omission_requires_the_exact_original_manifest(tmp_path):
    root = tmp_path / "blind"
    shutil.copytree(CORPUS, root)
    manifest = root / "FROZEN-SHA256.txt"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    with pytest.raises((ValueError, OSError)):
        load_frozen_cases(root)


def test_present_author_log_is_still_hash_checked(tmp_path):
    root = tmp_path / "blind"
    shutil.copytree(CORPUS, root)
    (root / "author-session.log").write_bytes(b"changed author log")
    with pytest.raises(ValueError, match="Frozen hash mismatch: author-session.log"):
        load_frozen_cases(root)
