"""Private, in-memory synthetic PII mapping, excluded from public bank snapshots."""

from hashlib import sha256


class PIIVault:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values = dict(values or {})

    def register(self, value: str) -> str:
        token = "PII_" + sha256(value.encode("utf-8")).hexdigest()[:16]
        self._values[token] = value
        return token

    def tokenize(self, text: str) -> str:
        for token, value in sorted(self._values.items(), key=lambda item: -len(item[1])):
            text = text.replace(value, token)
        return text

    def contains_private(self, text: str) -> bool:
        return any(value in text for value in self._values.values())

    def __repr__(self) -> str:
        return "PIIVault(<redacted>)"
