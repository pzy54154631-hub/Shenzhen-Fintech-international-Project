"""Episode clocks and deterministic IDs are the only application sources."""

from pathlib import Path

import pytest

from tests._ast_checks import wallclock_violations

SOURCE = Path(__file__).resolve().parents[2] / "src" / "corridor"


def test_no_wallclock_or_random_uuid_in_production() -> None:
    errors = []
    for path in sorted(SOURCE.rglob("*.py")):
        relative = path.relative_to(SOURCE).as_posix()
        errors.extend(wallclock_violations(path.read_text(encoding="utf-8"), relative))
    assert not errors, "\n".join(errors)


@pytest.mark.parametrize(
    "source",
    [
        "from datetime import datetime; datetime.now()",
        "import datetime as dt; dt.datetime.now()",
        "from datetime import datetime as dt; dt.utcnow()",
        "from datetime import date as d; d.today()",
        "from time import time as clock; clock()",
        "import time as t; t.time()",
        "import time; now = time.time; now()",
        "from uuid import uuid4 as new_id; new_id()",
        "import uuid; getattr(uuid, 'uuid4')()",
    ],
)
def test_wallclock_checker_rejects_aliases(source: str) -> None:
    assert wallclock_violations(source, "agent/planner.py")


def test_simulated_clock_and_uuid5_are_allowed() -> None:
    source = "from uuid import uuid5; uuid5(namespace, 'task:0:pay')\nnow = state.now"
    assert not wallclock_violations(source, "agent/planner.py")


def test_log_exception_does_not_exempt_audit_or_random_ids() -> None:
    clock = "import time; time.time()"
    assert not wallclock_violations(clock, "logging.py")
    assert wallclock_violations(clock, "gateway/audit.py")
    assert wallclock_violations("import uuid; uuid.uuid4()", "logging.py")
