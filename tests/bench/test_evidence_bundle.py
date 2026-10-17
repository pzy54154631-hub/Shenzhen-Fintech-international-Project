"""Evidence seals must reject changed files, truncated logs and incomplete bundles."""

import pytest

from corridor.bench.evidence_bundle import seal_bundle, verify_bundle


def test_bundle_detects_file_change_and_truncation(tmp_path):
    (tmp_path / "audit.jsonl").write_bytes(b'{"event":"one"}\n{"event":"two"}\n')
    seal_bundle(tmp_path, {"source": "scripted", "suite": "wealth"})
    assert verify_bundle(tmp_path)["source"] == "scripted"
    (tmp_path / "audit.jsonl").write_bytes(b'{"event":"one"}\n')
    with pytest.raises(ValueError, match="digest"):
        verify_bundle(tmp_path)


def test_bundle_rejects_manifest_tampering_and_extra_files(tmp_path):
    (tmp_path / "result.json").write_bytes(b"{}")
    seal_bundle(tmp_path, {"source": "scripted"})
    original = (tmp_path / "bundle.json").read_bytes()
    (tmp_path / "bundle.json").write_bytes(original.replace(b"scripted", b"recorded"))
    with pytest.raises(ValueError, match="manifest"):
        verify_bundle(tmp_path)
    (tmp_path / "bundle.json").write_bytes(original)
    (tmp_path / "extra.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="inventory"):
        verify_bundle(tmp_path)


def test_seal_requires_explicit_evidence_source(tmp_path):
    with pytest.raises(ValueError, match="source"):
        seal_bundle(tmp_path, {"suite": "wealth"})
