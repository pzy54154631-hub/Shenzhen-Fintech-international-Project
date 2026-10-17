"""Package exact evidence bytes with a reproducible inventory and credential scan."""

import re
from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import typer

from corridor.crypto.jcs import jcs_bytes

_CREDENTIAL = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    rb"|\bsk-[A-Za-z0-9_-]{16,}\b"
    rb"|\b(?:LLM_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*[\"']?\s*[:=]\s*"
    rb"[\"']?[^\s\"',;{}]{8,}"
    rb"|[\"'](?:api_key|private_key|access_token|refresh_token)[\"']\s*:\s*"
    rb"[\"'][^\"']{16,}[\"']"
    rb"|\bAuthorization[\"']?\s*:\s*[\"']?Bearer\s+[A-Za-z0-9_.-]{16,}",
    re.IGNORECASE,
)


def _reject_links(path: Path) -> None:
    """Check the original path and ancestors before resolve can hide a link."""
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("Evidence paths must not contain symlinks")
        try:
            attributes = getattr(part.lstat(), "st_file_attributes", 0)
        except FileNotFoundError:
            continue
        # Windows directory junctions are reparse points but are not symlinks.
        if attributes & 0x400:
            raise ValueError("Evidence paths must not contain reparse points")


def _files(directory: Path) -> Iterator[Path]:
    for path in sorted(directory.iterdir()):
        _reject_links(path)
        if path.is_dir():
            yield from _files(path)
        elif path.is_file():
            yield path


def inventory(source: Path) -> tuple[dict[str, dict[str, str | int]], list[tuple[str, Path]]]:
    """Reject links/credential files before reading and return exact file digests.

    Pattern scanning does not compare against environment credentials or claim
    detection of arbitrary secret formats. It never prints matched bytes.
    """
    _reject_links(source)
    if not source.is_dir():
        raise ValueError("Evidence source must be a directory without symlinks")
    files, paths = {}, []
    for path in _files(source):
        if path.name.lower() == ".env" or path.suffix.lower() in {".pem", ".key", ".p12"}:
            raise ValueError("Evidence contains a credential file")
        raw = path.read_bytes()
        if _CREDENTIAL.search(raw):
            raise ValueError("Evidence credential pattern detected; package refused")
        name = "evidence/" + path.relative_to(source).as_posix()
        files[name] = {"sha256": sha256(raw).hexdigest(), "bytes": len(raw)}
        paths.append((name, path))
    if not files:
        raise ValueError("Evidence source is empty")
    return files, paths


def package(source: Path, output: Path) -> dict:
    """Create a stable ZIP and verify all bytes before publishing its checksum."""
    _reject_links(source)
    _reject_links(output)
    source, output = source.resolve(), output.resolve()
    if output.is_relative_to(source):
        raise ValueError("Evidence archive must be outside its source tree")
    files, paths = inventory(source)
    manifest = {
        "schema_version": "corridor-submission-evidence-v1",
        "files": files,
        "credential_scan": {
            "files": len(files),
            "findings": 0,
            "method": "credential-patterns-v1; no environment file read",
            "limitation": "Pattern scan is not proof against arbitrary secret encodings",
        },
        "integrity": "SHA-256 inventory; not an externally anchored signature",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".partial")
    checksum = output.with_suffix(output.suffix + ".sha256")
    external_manifest = output.with_suffix(output.suffix + ".manifest.json")
    for target in (temporary, checksum, external_manifest):
        _reject_links(target)
    created = False
    try:
        with ZipFile(temporary, "x", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            created = True
            for name, path in paths:
                _reject_links(path)
                raw = path.read_bytes()
                if sha256(raw).hexdigest() != files[name]["sha256"]:
                    raise ValueError("Evidence changed while packaging")
                info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                archive.writestr(info, raw)
            info = ZipInfo("MANIFEST.json", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, jcs_bytes(manifest))
        with ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise ValueError("Evidence archive CRC failure")
            for name, entry in files.items():
                if sha256(archive.read(name)).hexdigest() != entry["sha256"]:
                    raise ValueError("Evidence archive digest failure")
        temporary.replace(output)
    finally:
        if created:
            temporary.unlink(missing_ok=True)
    checksum.write_text(
        sha256(output.read_bytes()).hexdigest() + "  " + output.name + "\n", encoding="utf-8"
    )
    external_manifest.write_bytes(jcs_bytes(manifest))
    return manifest


def run(
    source: Path = typer.Option(Path("evidence")),
    output: Path = typer.Option(Path("dist/corridor-evidence.zip")),
) -> None:
    try:
        manifest = package(source, output)
    except (ValueError, OSError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else "Evidence filesystem failure"
        typer.echo(message, err=True)
        raise typer.Exit(2) from None
    typer.echo(f"Evidence package: {output}; {len(manifest['files'])} files; credential findings 0")


def register(app: typer.Typer) -> None:
    app.command("evidence")(run)
