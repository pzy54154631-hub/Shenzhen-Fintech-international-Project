"""Replay identity of W6 wealth dialogue turns.

Spec: AGENTS rule 9/10 (deterministic per-step identity; record never replaces a replay),
PROP-025 (replay identity covers the request profile), DESIGN-BANK replay contract.
Two distinct clarification turns (different request_id, different intent_id) are
different model requests and must have distinct replay identities; otherwise record
mode refuses the second turn and strict replay cannot represent it.
"""

from corridor.agent.llm import LLMClient
from corridor.bench.wealth_smoke import make_wealth_conversation


def _record_client(tmp_path) -> tuple[LLMClient, list]:
    client = LLMClient(
        mode="record",
        replay_dir=tmp_path,
        model="openai/gpt-6.1-sol",
        api="responses",
        reasoning_effort="low",
        api_key="rt3-placeholder-credential",
        max_calls=10,
        max_usd="1",
        max_output_tokens=2048,
        env_file=None,
    )
    sent: list = []

    def fake_live(prompt, state, trace):
        # Offline stand-in for one paid Responses call (no network, no SDK).
        sent.append(state)
        trace["cost_usd"] = "1/1000"
        trace.update(input_tokens=10, output_tokens=10, reasoning_tokens=0, total_tokens=20)
        return {
            "status": "clarify",
            "missing_fields": [
                "source_account_ref",
                "amount",
                "horizon_days",
                "liquidity_days",
                "liquidity_amount",
                "allowed_types",
                "objective",
            ],
        }

    client._live = fake_live  # type: ignore[method-assign]
    return client, sent


def test_two_distinct_turns_with_same_text_get_distinct_replay_identity(tmp_path):
    client, sent = _record_client(tmp_path)
    chat, _ = make_wealth_conversation(client=client)
    first = chat.receive("I want something safe.", request_id="turn-1")
    second = chat.receive("I want something safe.", request_id="turn-2")
    assert first.intent_id != second.intent_id
    keys = [row["replay_key"] for row in client.calls]
    assert len(keys) == 2 and keys[0] != keys[1], keys
    assert len(sent) == 2

    replay = LLMClient(
        mode="strict",
        replay_dir=tmp_path,
        model=client.model,
        api="responses",
        reasoning_effort="low",
        max_output_tokens=2048,
        env_file=None,
    )
    replay_chat, _ = make_wealth_conversation(client=replay)
    assert replay_chat.receive("I want something safe.", request_id="turn-1") == first
    assert replay_chat.receive("I want something safe.", request_id="turn-2") == second
    assert [row["replay_key"] for row in replay.calls] == keys
    assert all(row["source"] == "replay" for row in replay.calls)
