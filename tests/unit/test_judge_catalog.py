"""Frozen judge expectations cannot disappear or silently accept unknown assertions."""

from copy import deepcopy

import pytest

from corridor.bench.judge_catalog import judge_catalog, validate_result


def test_catalog_has_all_24_tasks_with_separate_p1_scope():
    catalog = judge_catalog()
    assert set(catalog) == {f"J{index:02d}" for index in range(1, 25)}
    for task, specification in catalog.items():
        assert specification["status"] == "implemented"
        assert specification["scope"] == ("p0" if task <= "J22" else "p1")
        assert specification["steps"]
        assert all("expected" in step and step["field"] for step in specification["steps"])


def test_missing_extra_false_or_nonboolean_check_fails_closed():
    specification = judge_catalog()["J02"]
    checks = {step["field"].removeprefix("checks."): True for step in specification["steps"]}
    valid = {"task_id": "J02", "passed": True, "checks": checks}
    validate_result("J02", valid)
    for mutation in ("missing", "extra", "false", "integer"):
        result = deepcopy(valid)
        key = next(iter(checks))
        if mutation == "missing":
            del result["checks"][key]
        elif mutation == "extra":
            result["checks"]["unknown"] = True
        else:
            result["checks"][key] = False if mutation == "false" else 1
        with pytest.raises(ValueError, match="expected|assertion"):
            validate_result("J02", result)


def test_empty_expectations_or_wrong_task_never_pass():
    with pytest.raises(ValueError):
        validate_result("J24", {"task_id": "J24", "passed": True})
    with pytest.raises(ValueError):
        validate_result("J02", {"task_id": "J03", "passed": True, "checks": {}})
