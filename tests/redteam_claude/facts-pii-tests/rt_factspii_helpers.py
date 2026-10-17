"""Shared helpers: capture every prompt/tool_state that reaches the single LLM entry point."""

import re
from typing import Any

from corridor.crypto.jcs import jcs_bytes


def capture_llm(chat) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    original = chat.client.complete

    def spy(**kwargs):
        seen.append({"prompt": kwargs["prompt"], "tool_state": kwargs["tool_state"]})
        return original(**kwargs)

    chat.client.complete = spy
    return seen


def digits_in(payload: object) -> str:
    """All decimal digits that reached the model, in order, with separators removed."""
    return re.sub(r"[^0-9]", "", jcs_bytes(payload).decode("utf-8"))
