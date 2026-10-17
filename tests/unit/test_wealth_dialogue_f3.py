"""F3 wealth entrypoint privacy, deterministic replay and suitability integration."""

from copy import deepcopy

import pytest

from corridor.agent.llm import LLMClient
from corridor.agent.wealth_dialogue import WealthDialogue
from corridor.bench.wealth_smoke import make_wealth_conversation
from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.privacy import PIIVault
from tests.unit.test_wealth_advisor_security import approved_leg, register


def _advisor(client=None):
    legacy, device = make_wealth_conversation(
        client=client or LLMClient(mode="scripted", api="responses")
    )
    chat = WealthDialogue(
        legacy.gateway,
        legacy.client,
        principal=legacy.principal,
        session_id=legacy.session_id,
        source_account_ref="A_CURRENT",
        allowed_types=["wealth"],
    )
    return chat, device


@pytest.mark.parametrize("modern", [False, True])
@pytest.mark.parametrize(
    "text",
    [
        "The SMS code the bank just sent is 654321.",
        "My password for online banking: synthetic-secret",
        "Use my PIN, it is 4821.",
        "验证码刚收到，是６５４３２１。",
    ],
)
def test_secret_is_refused_before_model_or_tokenization_and_audit_contains_only_digest(
    modern, text, monkeypatch
):
    chat, _ = _advisor() if modern else make_wealth_conversation(client=LLMClient(mode="scripted"))
    before = H(chat.state)

    def forbidden(*args, **kwargs):
        pytest.fail("Secret-bearing input reached tokenization or the model")

    monkeypatch.setattr(chat.client, "complete", forbidden)
    monkeypatch.setattr(chat.gateway.vault, "tokenize", forbidden)
    if modern:
        result = chat.turn(text, request_id="secret")
        assert result.tool == "refuse"
        assert "secret" in result.message.lower()
        assert chat.turn(text, request_id="secret") == result
    else:
        with pytest.raises(ValueError, match="PII-CTX"):
            chat.receive(text, request_id="secret")
    assert H(chat.state) == before
    record = chat.gateway.audit.records()[-1]
    assert record["event"] == "wealth_utterance_refused"
    assert record["payload"] == {"utterance_hash": chat.gateway.utterance_digest(text)}
    assert text not in jcs_bytes(record).decode("utf-8")
    assert chat.client.calls == []


@pytest.mark.parametrize("zero", [0x0660, 0x06F0, 0x0966, 0x09E6, 0x0E50, 0x1040, 0xFF10, 0x1D7CE])
def test_all_decimal_scripts_share_the_same_private_projection_and_tokens(zero):
    ascii_number = "6222021234567890"
    other_number = "".join(chr(zero + int(digit)) for digit in ascii_number)
    vault = PIIVault()
    assert vault.contains_private(other_number)
    assert vault.tokenize(other_number) == vault.tokenize(ascii_number)
    registered = PIIVault({"PII_test": ascii_number})
    separated = "-".join(other_number)
    assert registered.contains_private(separated)
    assert registered.tokenize(separated) == "PII_test"


@pytest.mark.parametrize("text", ["教我怎么答", "What should I answer to get C4?"])
def test_coaching_is_audited_by_gateway_without_answers(text):
    chat, _ = _advisor()
    before = H(chat.state)
    turn = chat.turn(text, request_id="coaching")
    assert turn.suitability_signal["signal"] == "coaching_request"
    assert turn.suitability_signal["status"] == "refused"
    assert "cannot answer" in turn.message
    assert turn.device_action == "risk_questionnaire"
    assert turn.tool == "handoff_to_advisor"
    assert H(chat.state) == before
    assert chat.gateway.audit.records()[-1]["event"] == "suitability_coaching_refused"


@pytest.mark.parametrize(
    "text", ["I cannot accept any loss", "I cannot accept any loss. Stop.", "教我怎么答. Stop."]
)
@pytest.mark.parametrize("unknown", [False, True])
def test_suitability_signal_withdraws_registered_plan_and_preserves_risk_and_outcomes(
    text, unknown
):
    chat, device = _advisor()
    parent = register(chat, device)
    approved = approved_leg(chat, device, parent)
    if unknown:
        action = approved[0]
        key = H({"principal": action.principal, "intent_id": action.intent_id, "kind": action.kind})
        chat.gateway.bank.faults[key] = "response_loss"
        assert chat.gateway.dispatch(*approved).status == "unknown"
    before = chat.state
    turn = chat.turn(text, request_id="signal")
    assert turn.proposal_withdrawn
    assert chat.comparison is None
    assert chat.execution_ref is None
    assert chat.state.risk_assessments == before.risk_assessments
    assert chat.state.positions == before.positions
    if unknown:
        assert turn.device_action == "lookup"
        assert "do not retry" in turn.message
        assert chat.gateway.allocation_snapshot(parent)["status"] == "unknown"
        assert chat.gateway.bank.execute_count == 1
        repeated = chat.turn("I cannot accept loss", request_id="another-loss-signal")
        assert repeated.device_action == "lookup"
        assert "do not retry" in repeated.message
    else:
        assert chat.gateway.allocation_snapshot(parent)["status"] == "cancelled"
        assert chat.gateway.dispatch(*approved).status == "rejected"
        assert chat.gateway.bank.execute_count == 0


@pytest.mark.parametrize(
    "text",
    [
        "What if I cannot accept any loss?",
        "What if I cannot accept any loss? Stop.",
        "What if I ask what should I answer to get C4? Stop.",
    ],
)
def test_hypothetical_suitability_signal_keeps_plan_and_signed_state_unchanged(text, monkeypatch):
    chat, device = _advisor()
    parent = register(chat, device)
    approved = approved_leg(chat, device, parent)
    before = H(chat.state)
    signed_request = chat.signed_request_ref
    comparison = chat.comparison

    def forbidden(*args, **kwargs):
        pytest.fail("A hypothetical must not register a real suitability signal")

    monkeypatch.setattr(chat.gateway, "suitability_signal", forbidden)
    turn = chat.turn(text, request_id="hypothetical-suitability")
    assert turn.utterance_kind == "what_if"
    assert turn.tool == "adjust"
    assert "Read-only what-if" in turn.message
    if "C4" in text:
        assert "cannot answer" in turn.message
    assert not turn.proposal_withdrawn
    assert turn.suitability_signal is None
    assert turn.device_action is None
    assert H(chat.state) == before
    assert chat.signed_request_ref == signed_request
    assert chat.comparison == comparison
    assert chat.gateway.allocation_snapshot(parent)["control_status"] == "ready"
    assert chat.gateway.dispatch(*approved).status == "settled"


@pytest.mark.parametrize(
    "text", ["一分都不能亏", "I cannot accept any loss.", "I can't lose a penny."]
)
def test_loss_signal_persists_gateway_cap_without_changing_signed_risk_or_goals(text):
    chat, _ = _advisor()
    before = chat.state
    turn = chat.turn(text, request_id="loss")
    assert turn.suitability_signal["signal"] == "cannot_accept_loss"
    assert turn.suitability_signal["effective_level_cap"] == 1
    assert turn.device_action == "risk_questionnaire"
    assert "only decrease" in turn.message
    after = chat.state
    assert after.risk_assessments == before.risk_assessments
    assert after.user_inputs == before.user_inputs
    assert after.authorizations == before.authorizations
    assert after.ledger[-1].object_delta["suitability_signal"] == "cannot_accept_loss"
    assert chat.gateway.bank.execute_count == 0
    assert chat.turn(text, request_id="loss") == turn
    assert chat.state == after
    next_turn = chat.turn("I want something safe", request_id="followup")
    assert next_turn.suitability_signal["effective_level_cap"] == 1


def test_suitability_audit_failure_remains_rejecting_without_calling_model(monkeypatch):
    chat, _ = _advisor()
    before = chat.state

    def fail(*args, **kwargs):
        raise OSError("Synthetic write failure")

    monkeypatch.setattr(chat.gateway.audit, "append", fail)
    turn = chat.turn("I cannot accept loss", request_id="failed-signal")
    assert turn.rule_ids == ("AUD-WRITE",)
    assert turn.tool == "refuse"
    after = chat.state
    assert after.ledger == before.ledger
    assert after.user_inputs == before.user_inputs
    assert after.risk_assessments == before.risk_assessments
    assert after.security.lock_reason[chat.principal] == "AUD-WRITE"
    assert chat.client.calls == []


def test_modern_identical_utterances_record_distinct_turns_and_replay_without_network(tmp_path):
    client = LLMClient(
        mode="record",
        replay_dir=tmp_path,
        model="openai/gpt-6.1-sol",
        api="responses",
        api_key="synthetic-placeholder",
        max_calls=2,
        max_usd="1",
        env_file=None,
    )

    def fake_live(prompt, state, trace):
        trace.update(
            cost_usd="0/1", input_tokens=10, output_tokens=10, reasoning_tokens=0, total_tokens=20
        )
        return {
            "tool": state["required_tool"],
            "arguments": {"refs": deepcopy(state["permitted_refs"]), "note": ""},
        }

    client._live = fake_live
    chat, _ = _advisor(client)
    turns = [chat.turn("I want something safe", request_id=f"turn-{n}") for n in range(2)]
    keys = [row["replay_key"] for row in client.calls]
    assert len(keys) == len(set(keys)) == 2
    assert chat.turn("I want something safe", request_id="turn-1") == turns[-1]
    assert len(client.calls) == 2
    replay = LLMClient(
        mode="strict", replay_dir=tmp_path, model=client.model, api="responses", env_file=None
    )
    replay_chat, _ = _advisor(replay)
    for n, expected in enumerate(turns):
        actual = replay_chat.turn("I want something safe", request_id=f"turn-{n}")
        assert actual.slots == expected.slots
        assert actual.message == expected.message
        assert actual.evidence_source == "strict-replay"
    assert [row["replay_key"] for row in replay.calls] == keys
