"""Bilingual display catalog; canonical facts and identifiers are never translated."""

from pathlib import Path
from typing import Any, cast

from corridor.i18n import tr as core_tr
from corridor.i18n import translated_literal
from corridor.schemas.base import loads_exact

UI_MESSAGES = cast(
    dict[str, dict[str, str]], loads_exact(Path(__file__).with_suffix(".json").read_bytes())
)
for _name in (
    "wealth_messages.json",
    "shell_messages.json",
    "product_messages.json",
    "live_messages.json",
):
    _path = Path(__file__).with_name(_name)
    if _path.is_file():
        UI_MESSAGES.update(cast(dict[str, dict[str, str]], loads_exact(_path.read_bytes())))


def tr(key: str, **values: object) -> str:
    """Render fixed UI copy in the current request's locale."""
    if key in UI_MESSAGES:
        return core_tr(key, catalog=UI_MESSAGES, **values)
    return translated_literal(key)


def prose(value: str) -> str:
    """Localize fixed dialogue clauses; never interpret financial values or model notes."""
    translated = tr(value)
    if translated != value:
        return translated
    for key in sorted(UI_MESSAGES, key=len, reverse=True):
        if len(key) > 15 and value.startswith(key) and len(value) > len(key):
            remainder = value[len(key) :]
            whitespace = remainder[: len(remainder) - len(remainder.lstrip())]
            return tr(key) + whitespace + prose(remainder.lstrip())
    return value


def display_value(value: Any) -> Any:
    """Project display labels without changing the stored facts."""
    if isinstance(value, str):
        return tr(value)
    if isinstance(value, tuple):
        return tuple(display_value(item) for item in value)
    if isinstance(value, list):
        return [display_value(item) for item in value]
    return value
