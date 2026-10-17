"""W6 wealth dialogue: secret-bearing chat must be refused before any model request.

Spec: PROP-013 / ADR-009 (refuse secret-bearing chat before any LLM call), DESIGN-BANK
PII-CTX, ADR-012 key/secret discipline. The bank Conversation enforces this via
``extract_intent -> contains_secret``; the W6 WealthConversation must not be weaker.
"""

import re
from copy import deepcopy

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.wealth_smoke import make_wealth_conversation
from corridor.crypto.jcs import jcs_bytes
from corridor.gateway.privacy import contains_secret

SECRET_UTTERANCES = [
    # Labelled one-time code, label separated from digits by a few words.
    ("I want something safe. The SMS code the bank just texted me is 654321.", "654321"),
    (
        "My one-time passcode, which you asked for earlier, is 654321. Something safe please.",
        "654321",
    ),
    # Labelled password whose label is not immediately followed by ':' / 'is'.
    ("Something safe. My password for online banking: hunter2-synthetic", "hunter2-synthetic"),
    ("Use my PIN, it's 4821, and invest safely.", "4821"),
]


def _capture(client: LLMClient) -> list[dict]:
    seen: list[dict] = []
    original = client.complete

    def spy(**kwargs):
        seen.append(deepcopy({"prompt": kwargs["prompt"], "tool_state": kwargs["tool_state"]}))
        return original(**kwargs)

    client.complete = spy  # type: ignore[method-assign]
    return seen


@pytest.mark.parametrize(("utterance", "secret"), SECRET_UTTERANCES)
def test_bank_layer_classifies_these_as_secret_bearing(utterance, secret):
    # Control: the shared privacy helper (used by the bank dialogue) flags each one.
    assert contains_secret(utterance)


@pytest.mark.parametrize(("utterance", "secret"), SECRET_UTTERANCES)
def test_wealth_receive_never_sends_secret_to_model(utterance, secret):
    client = LLMClient(mode="scripted")
    chat, _ = make_wealth_conversation(client=client)
    seen = _capture(client)
    try:
        chat.receive(utterance, request_id="rt3-secret")
    except ValueError:
        pass  # A refusal is an acceptable secure outcome.
    wire = jcs_bytes(seen).decode("utf-8")
    assert secret not in wire, f"raw secret reached the model request: {wire[:400]}"
    # Secure behaviour mirrors the bank dialogue: refuse before any model call.
    assert seen == [], "secret-bearing wealth utterance still produced a model request"
    assert client.calls == []
    assert not re.search(re.escape(secret), str(chat.gateway.audit.records()))


@pytest.mark.parametrize(("utterance", "secret"), SECRET_UTTERANCES)
def test_control_bank_dialogue_refuses_same_utterance_without_model_call(utterance, secret):
    from corridor.bench.transfer_runner import make_conversation

    chat, _ = make_conversation(task_id="RT3_SECRET_CTRL")
    seen = _capture(chat.client)
    result = chat.receive(utterance, request_id="r1")
    assert result.status == "refused" and seen == []
