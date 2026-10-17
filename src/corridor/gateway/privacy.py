"""Private deterministic tokenization and fail-closed boundary scans."""

import re
import unicodedata
from collections.abc import Mapping
from fractions import Fraction
from hashlib import sha256

from pydantic import BaseModel

from corridor.schemas.bank import ApprovalToken

_NUMERIC = re.compile(r"(?<![0-9])[0-9]{11,}[Xx]?(?![0-9])")
_MACHINE_ID = re.compile(
    r"(?<![A-Za-z0-9_])(?:PII_[0-9a-f]{16}|[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}"
    r"|[0-9a-f]{64}|[0-9a-f]{128})(?![A-Za-z0-9_])"
)
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_CODE_WORD = (
    r"(?<![A-Za-z])(?:otp|pin|passcode|one[ -]*time[ -]*(?:code|passcode|password)"
    r"|(?:sms|verification|security)[ -]*code)(?![A-Za-z])"
    r"|验证码|动态码|校验码|短信码|口令|交易码|验证代码"
)
_SECRET_WORD = re.compile(rf"(?:{_CODE_WORD})|password|passwd|密码|关闭mfa", re.IGNORECASE)
_SECRET = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
    r"|\bsk-[A-Za-z0-9_-]{8,}\b"
    r"|(?:password|passwd|api[_ -]?key|private[_ -]?key|密码)"
    r"\s*(?:[:=：]|是|为|\bis\b)\s*[^\s,，;；]+"
    rf"|(?:{_CODE_WORD})\s*[:=：]\s*[^\s,，;；]+"
    rf"|(?:{_CODE_WORD})\s*(?:(?:[:=：]|是|为|\bis\b)\s*)?[0-9]{{4,8}}(?![0-9])",
    re.IGNORECASE,
)
_SENSITIVE_KEYS = frozenset({
    "password",
    "passwd",
    "pwd",
    "otp",
    "otp_code",
    "sms_code",
    "pin",
    "api_key",
    "private_key",
    "raw_phone",
    "phone_number",
    "raw_name",
    "full_name",
    "raw_account",
    "account_number",
})
_EXTRA_DIGITS = {
    char: str(value)
    for glyphs in ("〇一二三四五六七八九", "零壹贰叁肆伍陆柒捌玖")
    for value, char in enumerate(glyphs)
}
# These two enclosed zero glyphs have numeric, but not digit, Unicode values.
_EXTRA_DIGITS.update({"\U0001f10b": "0", "\U0001f10c": "0"})


def _normalize_text(text: str) -> str:
    """Fold Unicode digit values and Chinese digit glyphs before privacy matching."""
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(
        str(digit)
        if (digit := unicodedata.digit(char, None)) is not None
        else _EXTRA_DIGITS.get(char, char)
        for char in normalized
    )


def _scan_text(text: str) -> str:
    normalized = _normalize_text(text)
    return _MACHINE_ID.sub(lambda match: "A" * len(match.group()), normalized)


def _alphanumeric_projection(text: str) -> tuple[str, list[int]]:
    """Discard every non-alphanumeric separator and retain original offsets."""
    positions = [index for index, char in enumerate(text) if char.isalnum()]
    return "".join(text[index] for index in positions), positions


def _projected_spans(pattern: re.Pattern[str], text: str) -> list[tuple[int, int]]:
    projection, positions = _alphanumeric_projection(_scan_text(text))
    return [
        (positions[match.start()], positions[match.end() - 1] + 1)
        for match in pattern.finditer(projection)
    ]


def contains_secret(text: str) -> bool:
    """Refuse labeled credentials before tokenization could hide their labels."""
    normalized = _normalize_text(text)
    normalized = "".join(char for char in normalized if unicodedata.category(char) != "Cf")
    return _SECRET_WORD.search(normalized) is not None or _SECRET.search(normalized) is not None


class PIIVault:
    """Raw mappings remain private; state, prompts, and audit contain only tokens."""

    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self._values = dict(mapping or {})
        if any(not token or not raw or token == raw for token, raw in self._values.items()):
            raise ValueError("Invalid private token mapping")

    def register(self, value: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("Invalid private value")
        for token, raw in self._values.items():
            if raw == value:
                return token
        token = "PII_" + sha256(value.encode("utf-8")).hexdigest()[:16]
        self._values[token] = value
        return token

    def tokenize(self, text: str) -> str:
        text = _normalize_text(text)
        for token, raw in sorted(self._values.items(), key=lambda item: (-len(item[1]), item[0])):
            normalized = _normalize_text(raw)
            text = text.replace(normalized, token)
            private, _ = _alphanumeric_projection(normalized)
            if private and any(char.isdecimal() for char in private):
                for start, end in reversed(_projected_spans(re.compile(re.escape(private)), text)):
                    text = text[:start] + token + text[end:]
        for pattern in (_SECRET, _EMAIL):
            text = pattern.sub(lambda match: self.register(match.group()), text)
        for start, end in reversed(_projected_spans(_NUMERIC, text)):
            text = text[:start] + self.register(text[start:end]) + text[end:]
        return text

    def contains_private(self, text: str) -> bool:
        normalized = _normalize_text(text)
        return (
            any(
                _normalize_text(raw) in normalized
                or (
                    any(char.isdecimal() for char in private)
                    and bool(_projected_spans(re.compile(re.escape(private)), normalized))
                )
                for raw in self._values.values()
                for private, _ in [_alphanumeric_projection(_normalize_text(raw))]
            )
            or bool(_projected_spans(_NUMERIC, normalized))
            or _EMAIL.search(normalized) is not None
            or _SECRET.search(normalized) is not None
        )

    def ensure_safe(self, value: object, rule: str = "PII-CTX") -> None:
        if isinstance(value, ApprovalToken):
            raw = value.model_dump(mode="json", warnings=False)
            try:
                token = ApprovalToken.model_validate(raw)
            except ValueError as exc:
                raise ValueError(rule) from exc
            # This is a typed cryptographic nonce, not arbitrary model text.
            if any(private in token.nonce for private in self._values.values()):
                raise ValueError(rule)
            self.ensure_safe({key: item for key, item in raw.items() if key != "nonce"}, rule)
        elif isinstance(value, BaseModel):
            self.ensure_safe(value.model_dump(mode="json", warnings=False), rule)
        elif isinstance(value, str):
            if self.contains_private(value):
                raise ValueError(rule)
        elif isinstance(value, bytes):
            try:
                self.ensure_safe(value.decode("utf-8"), rule)
            except UnicodeDecodeError as exc:
                raise ValueError(rule) from exc
        elif isinstance(value, Mapping):
            for key, child in value.items():
                if (
                    isinstance(key, str)
                    and key.casefold().replace("-", "_").replace(" ", "_") in _SENSITIVE_KEYS
                ):
                    raise ValueError(rule)
                self.ensure_safe(key, rule)
                self.ensure_safe(child, rule)
        elif isinstance(value, (list, tuple)):
            for child in value:
                self.ensure_safe(child, rule)
        elif isinstance(value, int) and not isinstance(value, bool):
            self.ensure_safe(str(value), rule)
        elif value is not None and not isinstance(value, (bool, Fraction)):
            raise ValueError(rule)

    def __repr__(self) -> str:
        return "PIIVault(<redacted>)"
