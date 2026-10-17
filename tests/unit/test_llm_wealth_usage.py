"""Persist exact provider usage without counting replay as new inference."""

import os

import httpx
import pytest

from corridor.agent.llm import LLMClient, ReplayCorrupt, _hash
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact

_USAGE = {"input_tokens": 30, "output_tokens": 8, "reasoning_tokens": 2, "total_tokens": 38}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("LLM_"):
            monkeypatch.delenv(name)


def _client(tmp_path, mode):
    return LLMClient(
        mode=mode,
        replay_dir=tmp_path,
        model="gpt-6.1-sol",
        api="responses",
        api_key="synthetic-usage-credential",
        max_calls=1,
        max_usd="1",
        env_file=None,
    )


def _complete(client):
    return client.complete(
        task_id="W04",
        step="usage",
        prompt={"instruction": "Choose a supplied handle."},
        tool_state={"handles": ["FACT_A"]},
        scripted=lambda: {"fact_ref": "FACT_A"},
    )


def _record(tmp_path, monkeypatch):
    def send(self, request):
        return httpx.Response(
            200,
            json={
                "id": "resp_synthetic",
                "object": "response",
                "status": "completed",
                "model": "gpt-6.1-sol",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": '{"fact_ref":"FACT_A"}',
                            }
                        ],
                    }
                ],
                "usage": {
                    "input_tokens": 30,
                    "output_tokens": 8,
                    "total_tokens": 38,
                    "output_tokens_details": {"reasoning_tokens": 2},
                },
            },
        )

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", send)
    _complete(_client(tmp_path, "record"))
    path = next(tmp_path.rglob("*.json"))
    return path, loads_exact(path.read_bytes())


def test_replay_persists_usage_separately_from_current_inference(tmp_path, monkeypatch):
    _, record = _record(tmp_path, monkeypatch)
    assert record["usage"] == _USAGE
    assert record["usage_hash"] == _hash(_USAGE)
    replay = _client(tmp_path, "strict")
    assert _complete(replay).source == "replay"
    assert replay.calls[-1]["recorded_usage"] == _USAGE
    assert replay.api_calls == replay.spent_usd == 0
    assert not any(field in replay.calls[-1] for field in _USAGE)


def test_legacy_replay_has_no_invented_usage(tmp_path, monkeypatch):
    path, record = _record(tmp_path, monkeypatch)
    record.pop("usage")
    record.pop("usage_hash")
    path.write_bytes(jcs_bytes(record))
    client = _client(tmp_path, "strict")
    assert _complete(client).source == "replay"
    assert "recorded_usage" not in client.calls[-1]


@pytest.mark.parametrize(
    "mutation",
    [
        "hash",
        "bool",
        "string",
        "negative",
        "total",
        "reasoning",
        "extra",
        "missing-usage",
        "missing-hash",
    ],
)
def test_corrupt_usage_metadata_is_rejected_even_with_rehashed_invalid_types(
    tmp_path, monkeypatch, mutation
):
    path, record = _record(tmp_path, monkeypatch)
    if mutation == "missing-usage":
        record.pop("usage")
    elif mutation == "missing-hash":
        record.pop("usage_hash")
    elif mutation == "hash":
        record["usage_hash"] = "0" * 64
    else:
        field, value = {
            "bool": ("input_tokens", True),
            "string": ("input_tokens", "30"),
            "negative": ("output_tokens", -8),
            "total": ("total_tokens", 39),
            "reasoning": ("reasoning_tokens", 9),
            "extra": ("cached_tokens", 0),
        }[mutation]
        record["usage"][field] = value
        record["usage_hash"] = _hash(record["usage"])
    path.write_bytes(jcs_bytes(record))
    with pytest.raises(ReplayCorrupt):
        _complete(_client(tmp_path, "strict"))
