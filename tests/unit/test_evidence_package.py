"""Submission packaging preserves bytes and refuses credentials before publication."""

from hashlib import sha256
from zipfile import ZipFile

import pytest
from typer.testing import CliRunner

from corridor.cli import app
from corridor.schemas.base import loads_exact


def test_evidence_archive_is_reproducible_and_verifies_every_member(tmp_path):
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "result.json").write_bytes(b'{"source":"scripted","passed":true}\n')
    (source / "audit.jsonl").write_bytes(b'{"seq":1}\n')
    target = tmp_path / "deliverable.zip"
    arguments = ["evidence", "--source", str(source), "--output", str(target)]
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.output
    original = target.read_bytes()
    with ZipFile(target) as archive:
        manifest = loads_exact(archive.read("MANIFEST.json"))
        assert manifest["schema_version"] == "corridor-submission-evidence-v1"
        assert manifest["credential_scan"]["findings"] == 0
        assert set(manifest["files"]) == {"evidence/audit.jsonl", "evidence/result.json"}
        for name, entry in manifest["files"].items():
            data = archive.read(name)
            assert sha256(data).hexdigest() == entry["sha256"]
            assert len(data) == entry["bytes"]
            assert data == (source / name.removeprefix("evidence/")).read_bytes()
    assert CliRunner().invoke(app, arguments).exit_code == 0
    assert target.read_bytes() == original


@pytest.mark.parametrize(
    "secret",
    [
        b"sk-test-only-credential-01234567890123456789",
        b'LLM_API_KEY="synthetic-test-value"',
        b'{"Authorization":"Bearer synthetic-token-1234567890"}',
        b"{'authorization': 'Bearer synthetic-token-1234567890'}",
    ],
)
def test_evidence_package_refuses_secret_without_echoing_it(tmp_path, secret):
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "response.txt").write_bytes(secret)
    target = tmp_path / "deliverable.zip"
    result = CliRunner().invoke(app, ["evidence", "--source", str(source), "--output", str(target)])
    assert result.exit_code == 2
    assert "credential" in result.output.lower()
    assert secret.decode("utf-8") not in result.output
    assert not target.exists()


def test_evidence_output_cannot_reenter_source_tree(tmp_path):
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "result.json").write_bytes(b"{}")
    result = CliRunner().invoke(
        app, ["evidence", "--source", str(source), "--output", str(source / "recursive.zip")]
    )
    assert result.exit_code == 2
    assert not (source / "recursive.zip").exists()


def test_evidence_does_not_open_environment_files(tmp_path, monkeypatch):
    source = tmp_path / "evidence"
    source.mkdir()
    secret_file = source / ".env"
    secret_file.write_bytes(b"do not read")
    from pathlib import Path

    read = Path.read_bytes

    def guarded(path):
        assert path != secret_file
        return read(path)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    result = CliRunner().invoke(
        app, ["evidence", "--source", str(source), "--output", str(tmp_path / "bundle.zip")]
    )
    assert result.exit_code == 2
    assert "credential" in result.output.lower()


@pytest.mark.parametrize("link_kind", ["source", "ancestor", "junction"])
def test_evidence_rejects_link_paths_before_resolution_or_reading(tmp_path, monkeypatch, link_kind):
    from pathlib import Path
    from types import SimpleNamespace

    from corridor.cli.evidence import package

    parent = tmp_path / "parent"
    source = parent / "evidence"
    source.mkdir(parents=True)
    protected = source / "result.json"
    protected.write_bytes(b"{}")
    alias = tmp_path / "alias"
    resolve, is_symlink, lstat, read = Path.resolve, Path.is_symlink, Path.lstat, Path.read_bytes

    def resolve_link(path, *args, **kwargs):
        return source if path == alias else resolve(path, *args, **kwargs)

    def link(path):
        return path == (parent if link_kind == "ancestor" else alias) or is_symlink(path)

    def file_info(path, *args, **kwargs):
        if link_kind == "junction" and path == source:
            return SimpleNamespace(st_file_attributes=0x400, st_mode=lstat(path).st_mode)
        return lstat(path, *args, **kwargs)

    def no_evidence_read(path):
        assert path != protected, "Linked evidence was read before rejection"
        return read(path)

    monkeypatch.setattr(Path, "resolve", resolve_link)
    monkeypatch.setattr(Path, "is_symlink", link)
    monkeypatch.setattr(Path, "lstat", file_info)
    monkeypatch.setattr(Path, "read_bytes", no_evidence_read)
    with pytest.raises(ValueError, match="link|reparse"):
        package(alias if link_kind == "source" else source, tmp_path / "bundle.zip")


def test_existing_partial_archive_is_preserved(tmp_path):
    from corridor.cli.evidence import package

    source = tmp_path / "evidence"
    source.mkdir()
    (source / "result.json").write_bytes(b"{}")
    target = tmp_path / "bundle.zip"
    partial = tmp_path / "bundle.zip.partial"
    partial.write_bytes(b"prior interrupted artifact")
    with pytest.raises((FileExistsError, ValueError)):
        package(source, target)
    assert partial.read_bytes() == b"prior interrupted artifact"
    assert not target.exists()
