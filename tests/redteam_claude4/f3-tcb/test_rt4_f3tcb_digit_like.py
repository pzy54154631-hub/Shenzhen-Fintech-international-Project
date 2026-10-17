"""RT4-F3TCB: digit-like characters outside Unicode category Nd bypass F3 privacy normalisation.

Spec: DESIGN-BANK PII-CTX (raw protected values never enter prompts); F3 RT3-LLMDLG-02
claims every Unicode decimal spelling is folded before known-value / numeric scans.
F3 folds only NFKC + category Nd. Characters that every reader (and every LLM) reads as
digits but which are category No/Lo with no NFKC decomposition survive untouched:
  * dingbat negative circled digits  U+2776..U+277E (and U+24FF for zero)
  * dingbat circled sans-serif digits U+2780..U+2788 (zero U+1F10B)
  * double circled digits U+24F5..U+24FD (zero U+24EA, which NFKC does fold)
  * CJK numerals 〇/零 一 二 ... 九 (how Chinese users commonly dictate phone numbers)
"""

import unicodedata
from copy import deepcopy

import pytest

from corridor.agent.llm import LLMClient, default_context_guard
from corridor.agent.wealth_dialogue import WealthDialogue
from corridor.bench.wealth_smoke import make_wealth_conversation
from corridor.gateway.privacy import PIIVault, contains_secret

KNOWN_PHONE = "13900001001"  # registered in the wealth smoke vault
CARD = "6222021234567890"


def _spell(number: str, zero: str, one_to_nine_start: int | None, cjk: str | None = None) -> str:
    if cjk is not None:
        return "".join(cjk[int(c)] for c in number)
    assert one_to_nine_start is not None
    return "".join(zero if c == "0" else chr(one_to_nine_start + int(c) - 1) for c in number)


SPELLINGS = {
    "dingbat-negative-circled": lambda n: _spell(n, "⓿", 0x2776),
    "dingbat-sans-circled": lambda n: _spell(n, "\U0001f10b", 0x2780),
    "dingbat-negative-sans-zero": lambda n: _spell(n, "\U0001f10c", 0x2776),
    "double-circled": lambda n: _spell(n, "⓪", 0x24F5),
    "cjk-numerals": lambda n: _spell(n, "", None, cjk="零一二三四五六七八九"),
    "cjk-ling-circle": lambda n: _spell(n, "", None, cjk="〇一二三四五六七八九"),
    "cjk-financial": lambda n: _spell(n, "", None, cjk="零壹贰叁肆伍陆柒捌玖"),
}


def _reading(text: str) -> str:
    """How a human or model reads the text: every digit-like glyph as its value."""
    out = []
    for ch in text:
        if ch in "零〇":
            out.append("0")
        elif ch in "一二三四五六七八九":
            out.append(str("一二三四五六七八九".index(ch) + 1))
        elif ch in "壹贰叁肆伍陆柒捌玖":
            out.append(str("壹贰叁肆伍陆柒捌玖".index(ch) + 1))
        else:
            value = unicodedata.digit(ch, None)
            if value is None:
                value = unicodedata.numeric(ch, None)
            if value is not None and float(value).is_integer() and 0 <= value <= 9:
                out.append(str(int(value)))
    return "".join(out)


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
def test_vault_recognises_registered_phone_in_digit_like_spelling(spelling):
    spelled = SPELLINGS[spelling](KNOWN_PHONE)
    assert _reading(spelled) == KNOWN_PHONE  # sanity: humans/models read the same number
    # Control: the fixed F3 path catches the Nd/ASCII form.
    assert PIIVault({"PII_aaaaaaaaaaaaaaaa": KNOWN_PHONE}).contains_private(f"call {KNOWN_PHONE}")
    vault = PIIVault({"PII_aaaaaaaaaaaaaaaa": KNOWN_PHONE})
    assert vault.contains_private(f"call me on {spelled}"), (
        f"registered phone spelled with {spelling} is not recognised as private"
    )


def _chat():
    legacy, _ = make_wealth_conversation(client=LLMClient(mode="scripted", api="responses"))
    return WealthDialogue(
        legacy.gateway,
        legacy.client,
        principal=legacy.principal,
        session_id=legacy.session_id,
        source_account_ref="A_CURRENT",
        allowed_types=["wealth"],
    )


@pytest.mark.parametrize("number", [KNOWN_PHONE, CARD])
def test_control_ascii_number_is_tokenized_before_model(number):
    chat = _chat()
    seen: list[dict] = []
    original = chat.client.complete

    def spy(**kwargs):
        seen.append(deepcopy(kwargs["tool_state"]))
        return original(**kwargs)

    chat.client.complete = spy  # type: ignore[method-assign]
    chat.turn(f"I want something safe, reach me at {number}.", request_id="rt4-ascii")
    texts = [str(state.get("user_text", "")) for state in seen]
    assert texts and all(number not in _reading(text) for text in texts)


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
@pytest.mark.parametrize("number", [KNOWN_PHONE, CARD])
def test_wealth_dialogue_turn_does_not_send_digit_like_number_to_model(spelling, number):
    chat = _chat()
    seen: list[dict] = []
    accepted: list[object] = []
    original = chat.client.complete

    def spy(**kwargs):
        seen.append(deepcopy({"prompt": kwargs["prompt"], "tool_state": kwargs["tool_state"]}))
        return original(**kwargs)

    chat.client.complete = spy  # type: ignore[method-assign]
    chat.client.observers.append(
        lambda stage, value: accepted.append(value) if stage == "request" else None
    )
    utterance = f"I want something safe, reach me at {SPELLINGS[spelling](number)}."
    try:
        chat.turn(utterance, request_id="rt4-digit-like")
    except ValueError:
        pass  # a refusal is acceptable
    texts = [str(call["tool_state"].get("user_text", "")) for call in seen]
    assert texts, "the turn must reach the model so the boundary is exercised"
    assert all(number not in _reading(text) for text in texts), (
        f"{spelling} spelling carried a protected number into the model request"
    )
    assert accepted, "the sanitized request must also pass the actual context guard"
    assert all(number not in _reading(str(request)) for request in accepted)


@pytest.mark.rule("PII-CTX")
@pytest.mark.rule("PII-OUT")
@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
@pytest.mark.parametrize("separator", ["", ".", "\u200b"])
def test_digit_like_phone_rejected_and_tokenized_twin_is_safe(spelling, separator):
    spelled = separator.join(SPELLINGS[spelling](KNOWN_PHONE))
    vault = PIIVault({"PII_aaaaaaaaaaaaaaaa": KNOWN_PHONE})
    raw = f"Contact {spelled} for the appointment."
    with pytest.raises(ValueError, match="^PII-CTX$") as context_error:
        vault.ensure_safe({"text": raw})
    assert str(context_error.value) == "PII-CTX"
    with pytest.raises(ValueError, match="^PII-OUT$") as output_error:
        default_context_guard({"text": raw})
    assert str(output_error.value) == "PII-OUT"
    safe = vault.tokenize(raw)
    assert safe == "Contact PII_aaaaaaaaaaaaaaaa for the appointment."
    assert vault.tokenize(safe) == safe
    vault.ensure_safe({"text": safe})
    default_context_guard({"text": safe})


@pytest.mark.rule("PII-OUT")
@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
def test_secret_and_default_context_guards_share_digit_projection(spelling):
    raw = f"verification code is {SPELLINGS[spelling]('123456')}"
    assert contains_secret(raw)
    with pytest.raises(ValueError, match="^PII-OUT$") as error:
        default_context_guard({"text": raw})
    assert str(error.value) == "PII-OUT"
    safe = PIIVault().tokenize(raw)
    assert safe.startswith("PII_")
    assert not contains_secret(safe)
    default_context_guard({"text": safe})


def test_every_unicode_digit_value_is_folded_before_numeric_scan():
    vault = PIIVault()
    for codepoint in range(0x110000):
        char = chr(codepoint)
        if unicodedata.digit(char, None) is not None:
            raw = char * 11
            assert vault.contains_private(raw), f"Missed digit U+{codepoint:04X}"
            safe = vault.tokenize(raw)
            assert "PII_" in safe and raw not in safe, f"Missed tokenization U+{codepoint:04X}"
            default_context_guard(safe)


@pytest.mark.parametrize(
    "text", ["Review product R2 for 200 CNY.", "PII_1234567890123456", "2026-10-16T08:00:00Z"]
)
def test_benign_text_and_machine_identifiers_stay_safe(text):
    vault = PIIVault()
    assert vault.tokenize(text) == text
    assert not contains_secret(text)
    vault.ensure_safe(text)
    default_context_guard(text)
