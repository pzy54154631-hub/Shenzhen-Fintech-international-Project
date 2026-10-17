"""PII-CTX: a protected number written in non-ASCII decimal digits must not reach the model.

Spec: DESIGN-BANK 5.3 / 10.2 PII-CTX (raw protected values never enter prompts), AGENTS
rule 6 (no PII plaintext), W6 dialogue reuses the same gateway vault. NFKC folds
full-width digits but NOT Arabic-Indic / Devanagari digits, which every model reads as
the same number.
"""

import unicodedata
from copy import deepcopy

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.wealth_smoke import make_wealth_conversation
from corridor.crypto.jcs import jcs_bytes
from corridor.gateway.privacy import PIIVault

KNOWN_PHONE = "13900001001"
CARD = "6222021234567890"  # 16-digit synthetic card/account-like number


def _script(number: str, zero: int) -> str:
    return "".join(chr(zero + int(ch)) for ch in number)


def _ascii_digits(text: str) -> str:
    return "".join(str(unicodedata.decimal(ch)) if ch.isdecimal() else "" for ch in text)


SCRIPTS = {"arabic-indic": 0x0660, "devanagari": 0x0966}


def _capture(client: LLMClient) -> list[dict]:
    seen: list[dict] = []
    original = client.complete

    def spy(**kwargs):
        seen.append(deepcopy({"prompt": kwargs["prompt"], "tool_state": kwargs["tool_state"]}))
        return original(**kwargs)

    client.complete = spy  # type: ignore[method-assign]
    return seen


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_vault_flags_unregistered_long_number_in_other_decimal_scripts(script):
    text = f"my card number is {_script(CARD, SCRIPTS[script])}"
    # Control: the ASCII form is recognised as private.
    assert PIIVault().contains_private(f"my card number is {CARD}")
    assert PIIVault().contains_private(text), "16-digit number in another script not detected"


@pytest.mark.parametrize("script", sorted(SCRIPTS))
@pytest.mark.parametrize("number", [KNOWN_PHONE, CARD])
def test_wealth_receive_does_not_forward_number_in_other_decimal_script(script, number):
    client = LLMClient(mode="scripted")
    chat, _ = make_wealth_conversation(client=client)
    seen = _capture(client)
    utterance = f"I want something safe; reach me at {_script(number, SCRIPTS[script])}."
    try:
        chat.receive(utterance, request_id="rt3-digits")
    except ValueError:
        pass  # refusal is acceptable
    wire = jcs_bytes(seen).decode("utf-8")
    assert number not in _ascii_digits(wire), (
        f"{script} digits carried a protected number into the model request"
    )


@pytest.mark.parametrize("number", [KNOWN_PHONE, CARD])
def test_control_ascii_number_is_tokenized_before_model(number):
    client = LLMClient(mode="scripted")
    chat, _ = make_wealth_conversation(client=client)
    seen = _capture(client)
    chat.receive(f"I want something safe; reach me at {number}.", request_id="rt3-ascii")
    assert seen and number not in _ascii_digits(jcs_bytes(seen).decode("utf-8"))


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_record_default_guard_rejects_number_in_other_decimal_script(tmp_path, script):
    """`corridor record --requests` relies on default_context_guard alone."""
    client = LLMClient(
        mode="record",
        replay_dir=tmp_path,
        model="openai/gpt-6.1-sol",
        api="responses",
        api_key="rt3-placeholder-credential",
        max_calls=1,
        max_usd="1",
        env_file=None,
    )
    sent = []

    def fake_live(prompt, state, trace):
        sent.append(prompt)
        trace["cost_usd"] = "0/1"
        return {"status": "clarify"}

    client._live = fake_live  # type: ignore[method-assign]
    with pytest.raises(ValueError):
        client.complete(
            task_id="W04",
            step="wealth-clarify:0",
            prompt={"instruction": "x"},
            tool_state={"user_text": f"card {_script(CARD, SCRIPTS[script])}"},
            scripted=lambda: {"status": "clarify"},
        )
    assert sent == []
