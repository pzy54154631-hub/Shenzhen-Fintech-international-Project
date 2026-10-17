"""Generate runtime dependency notices from the active environment's metadata."""

import argparse
import importlib.metadata
import platform
import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def license_label(metadata: importlib.metadata.PackageMetadata) -> str:
    """Prefer declared expressions; never copy long licence text or author details."""
    expression = metadata.get("License-Expression", "").strip()
    if expression:
        return expression
    classifiers = sorted({
        item.rsplit(" :: ", 1)[-1]
        for item in metadata.get_all("Classifier", [])
        if item.startswith("License :: ") and item != "License :: OSI Approved"
    })
    if classifiers:
        return " / ".join(classifiers)
    label = metadata.get("License", "").strip()
    if label and len(label) <= 120 and re.fullmatch(r"[A-Za-z0-9 .()+/_-]+", label):
        if label.lower() not in {"unknown", "other", "see license", "see license.txt"}:
            return label
    return "unknown"


def runtime_distributions(requirements: list[str]) -> list[importlib.metadata.Distribution]:
    """Resolve installed runtime requirements with markers and requested extras."""
    pending = [Requirement(value) for value in requirements]
    selected: dict[str, importlib.metadata.Distribution] = {}
    expanded: dict[str, set[str]] = {}
    while pending:
        requirement = pending.pop()
        if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
            continue
        name = canonicalize_name(requirement.name)
        distribution = importlib.metadata.distribution(name)
        selected[name] = distribution
        contexts = {"", *requirement.extras} - expanded.get(name, set())
        if not contexts:
            continue
        expanded.setdefault(name, set()).update(contexts)
        for value in distribution.requires or []:
            child = Requirement(value)
            if child.marker is None or any(
                child.marker.evaluate({"extra": extra}) for extra in contexts
            ):
                # The parent's extra marker has already been evaluated.
                child.marker = None
                pending.append(child)
    return [selected[name] for name in sorted(selected)]


def render() -> str:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requirements = configuration["project"]["dependencies"]
    direct = {canonicalize_name(Requirement(value).name) for value in requirements}
    distributions = runtime_distributions(requirements)
    lines = [
        "# Third-party notices",
        "",
        "Generated from installed distribution metadata with `importlib.metadata`, starting",
        "from the runtime requirements in `pyproject.toml` and following their transitive",
        "requirements and requested extras. Environment markers use the generation platform;",
        f"this snapshot was generated on {platform.system()} with Python "
        f"{platform.python_version()}.",
        "Development-only and build-only packages are excluded. Other platforms can select",
        "different conditional packages from the same lockfile.",
        "",
        "Licence labels are package metadata declarations: `License-Expression`, then licence",
        "classifiers, then a short `License` value. Unavailable or ambiguous declarations",
        "are marked `unknown`. These labels do not replace the licence and notice files",
        "distributed with each package. Third-party components retain their own terms;",
        "Corridor's evaluation-only licence does not change those terms.",
        "",
        "Regenerate after `uv sync --frozen` with:",
        "",
        "```text",
        "uv run --frozen python scripts/public_notices.py",
        "```",
        "",
        "| Runtime dependency | Installed version | Licence metadata | Requirement |",
        "|---|---|---|---|",
    ]
    for distribution in distributions:
        name = distribution.metadata["Name"]
        relation = "direct" if canonicalize_name(name) in direct else "transitive"
        label = license_label(distribution.metadata).replace("|", "\\|")
        lines.append(f"| {name} | {distribution.version} | {label} | {relation} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "THIRD_PARTY_NOTICES.md")
    arguments = parser.parse_args()
    content = render()
    arguments.output.write_text(content, encoding="utf-8", newline="\n")
    count = sum(line.startswith("| ") for line in content.splitlines()) - 1
    print(f"Generated runtime notices: {count} packages")


if __name__ == "__main__":
    main()
