"""Validate UTC timestamps and convert payee-local calendar deadlines."""

import re
from datetime import UTC, datetime
from typing import Annotated
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AfterValidator

_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError("Expected YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def validate_time(value: str) -> str:
    parse_time(value)
    return value


Timestamp = Annotated[str, AfterValidator(validate_time)]


def deadline_utc(day: str, zone: str) -> str:
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", day):
        raise ValueError("Expected YYYY-MM-DD")
    try:
        local = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=ZoneInfo(zone))
    except ZoneInfoNotFoundError as exc:
        raise ValueError("Unknown payee timezone") from exc
    return local.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
