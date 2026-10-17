"""Isolated intent candidates; this module has no execution or signing tools."""

import re
from fractions import Fraction
from typing import Literal

from pydantic import Field

from corridor.gateway.privacy import contains_secret
from corridor.schemas.base import Model


class ExtractedIntent(Model):
    kind: Literal["transfer", "balance_query", "clarify", "refuse"]
    contact_refs: list[str] = Field(default_factory=list)
    use_context: bool = False


def amount_candidate(text: str, previous: str | None = None) -> str | None:
    """Parse a displayed candidate; only a subsequent device signature authorizes it."""
    matches = re.findall(r"(?<![A-Za-z0-9_.+,，/\-])([0-9][0-9 .,+/，\-]*)\s*(?:元|块)", text)
    if not matches:
        matches = re.findall(r"(?:转|转账)\s*([0-9][0-9 .,+/，\-]*)(?![A-Za-z0-9_])", text)
    if not matches:
        repeated = re.fullmatch(r"\s*再给[他她]\s*([0-9]+(?:\.[0-9]{1,2})?)\s*", text)
        if repeated is not None:
            matches = [repeated.group(1)]
    if not matches and ("同样金额" in text or "同一金额" in text):
        return previous
    if len(matches) != 1:
        return None
    raw = matches[0].strip()
    if re.fullmatch(r"[0-9]+(?:\.[0-9]{1,2})?", raw) is None:
        return None
    value = Fraction(raw)
    if value <= 0 or (value * 100).denominator != 1:
        return None
    return f"{value.numerator}/{value.denominator}"


def extract_intent(
    text: str, labels: dict[str, list[str]], previous_contact: str | None = None
) -> ExtractedIntent:
    if contains_secret(text):
        return ExtractedIntent(kind="refuse")
    if "余额" in text and "转" not in text:
        return ExtractedIntent(kind="balance_query")
    repeated = re.fullmatch(r"\s*再给[他她]\s*[0-9]+(?:\.[0-9]{1,2})?\s*(?:元|块)?\s*", text)
    if "转" not in text and repeated is None:
        return ExtractedIntent(kind="clarify")
    matched = sorted(
        ref for ref, values in labels.items() if any(value in text for value in values)
    )
    contextual = "他" in text or "她" in text
    if not matched and contextual and previous_contact in labels:
        matched = [previous_contact]
    return ExtractedIntent(kind="transfer", contact_refs=matched, use_context=contextual)


def injection_detected(texts: list[str]) -> bool:
    markers = ("ignore", "system", "忽略", "覆盖", "验证码", "otp", "password", "转账")
    return any(any(marker in text.lower() for marker in markers) for text in texts)
