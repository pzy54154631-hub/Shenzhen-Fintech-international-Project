"""Verify published AgentDojo census rows, summaries, and file hashes offline."""

import hashlib
import json
from pathlib import Path


def verify(root: Path) -> dict[str, int | bool]:
    """Recompute the full pair census and fail on a mismatched published count."""
    summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
    rows = json.loads((root / "rows-census.json").read_text(encoding="utf-8"))
    expected = {(f"user_task_{u}", f"injection_task_{i}") for u in range(16) for i in range(9)}
    if len(rows) != 720 or summary["total_rows"] != len(rows):
        raise ValueError("Incomplete census")
    for group in summary["configs"]:
        selected = [
            row
            for row in rows
            if (row["config"], row["approval_mode"]) == (group["config"], group["approval_mode"])
        ]
        pairs = {(row["user_task"], row["injection_task"]) for row in selected}
        if len(selected) != 144 or pairs != expected or group["attack_n"] != 144:
            raise ValueError("Incomplete or duplicated pair grid")
        for metric in ("security_original", "security_corrected"):
            if group[metric] != sum(row[metric] for row in selected):
                raise ValueError(f"Count mismatch: {metric}")
        if group["attack_utility"] != sum(row["utility"] for row in selected):
            raise ValueError("Utility count mismatch")
        if any(
            row["status"] != "valid_completed"
            or row["model_calls"] != 0
            or row["in_denominator"] is not True
            for row in selected
        ):
            raise ValueError("Invalid census member")
    for freeze in ("freeze1", "freeze7"):
        copied = json.loads((root / f"{freeze}-summary.json").read_text(encoding="utf-8"))
        for cell, group in zip(copied["configs"], summary["configs"], strict=True):
            if any(cell[key] != value for key, value in group.items()):
                raise ValueError("Source-summary projection differs")
            if "intervals" in cell:
                raise ValueError("Census must not carry binomial confidence intervals")
    for entry in json.loads((root / "files.sha256.json").read_text(encoding="utf-8")):
        raw = (root / entry["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError(f"Hash mismatch: {entry['path']}")
    return {"verified": True, "rows": len(rows), "cells": len(summary["configs"])}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent)))
