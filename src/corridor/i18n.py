"""Pure display translation with request-local language selection.

Locales are never inputs to canonical facts, signatures, or authorization checks.
"""

import os
from collections.abc import Mapping
from contextvars import ContextVar, Token

from corridor.messages import MESSAGES

LOCALES = ("en", "zh-CN")
_locale: ContextVar[str | None] = ContextVar("corridor_display_locale", default=None)


def get_locale() -> str:
    """Return a request-local override or the environment's English default."""
    value = _locale.get() or os.environ.get("CORRIDOR_LOCALE", "en")
    return value if value in LOCALES else "en"


def set_locale(locale: str | None) -> Token[str | None]:
    """Select a language for this context without affecting concurrent sessions."""
    if locale is not None and locale not in LOCALES:
        raise ValueError("Unsupported display locale")
    return _locale.set(locale)


def reset_locale(token: Token[str | None]) -> None:
    """Restore the caller's context after a temporary display override."""
    _locale.reset(token)


def tr(
    key: str,
    *,
    locale: str | None = None,
    catalog: Mapping[str, Mapping[str, str]] | None = None,
    **values: object,
) -> str:
    """Format a fixed bilingual template; missing catalog entries fail visibly."""
    language = get_locale() if locale is None else locale
    if language not in LOCALES:
        raise ValueError("Unsupported display locale")
    return (MESSAGES if catalog is None else catalog)[key][language].format(**values)


def translated_literal(value: str) -> str:
    """Translate known canonical display literals without altering their stored value."""
    return tr(value) if value in MESSAGES else value
