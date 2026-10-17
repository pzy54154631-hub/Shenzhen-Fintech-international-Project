"""Validate each judge against the frozen, machine-readable expected assertions."""

from pathlib import Path
from typing import Any

from corridor.schemas.base import loads_exact

CATALOG_PATH = Path(__file__).resolve().parents[3] / "data/scenarios/bank_judge.json"


def judge_catalog() -> dict[str, Any]:
    value = loads_exact(CATALOG_PATH.read_bytes())
    if value.get("schema_version") != "bank-judge-v1":
        raise ValueError("Missing judge expected schema")
    tasks = value.get("tasks")
    if not isinstance(tasks, dict) or set(tasks) != {f"J{index:02d}" for index in range(1, 25)}:
        raise ValueError("Missing judge task expectations")
    for task in tasks.values():
        if not task.get("steps") or any(
            set(step) != {"field", "expected"} or not isinstance(step["field"], str)
            for step in task["steps"]
        ):
            raise ValueError("Missing judge step expected value")
    return tasks


def validate_result(task_id: str, result: dict[str, Any]) -> None:
    specification = judge_catalog().get(task_id)
    if (
        specification is None
        or specification["status"] != "implemented"
        or result.get("task_id") != task_id
        or result.get("passed") is not True
    ):
        raise ValueError("Judge task expected complete assertions")
    expected_checks = {
        step["field"].removeprefix("checks.")
        for step in specification["steps"]
        if step["field"].startswith("checks.")
    }
    if expected_checks and set(result.get("checks", {})) != expected_checks:
        raise ValueError("Missing or unknown judge assertion")
    for step in specification["steps"]:
        value: Any = result
        field = step["field"]
        if field.startswith("checks."):
            value = result["checks"][field.removeprefix("checks.")]
        else:
            for key in field.split("."):
                if not isinstance(value, dict) or key not in value:
                    raise ValueError(f"Missing judge expected field: {field}")
                value = value[key]
        if type(value) is not type(step["expected"]) or value != step["expected"]:
            raise ValueError(f"Judge assertion differs from expected: {field}")
