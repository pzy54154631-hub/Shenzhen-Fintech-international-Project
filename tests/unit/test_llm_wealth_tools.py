"""Named wealth tool calls keep the offline, exact-output and budget boundaries."""

import builtins
import os
from copy import deepcopy
from fractions import Fraction

import httpx
import pytest

from corridor.agent.llm import (
    BudgetExceeded,
    LLMClient,
    LLMConfigurationError,
    LLMOutputError,
    ReplayCorrupt,
    ReplayMiss,
)
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact

_NAMES = (
    "capture_goal",
    "start_risk_profile",
    "compare_products",
    "explain_fact",
    "why_not",
    "propose_allocation",
    "adjust",
    "execute_plan",
    "handoff_to_advisor",
)
_ARGUMENTS = {"fact_ref": "FACT_SYNTHETIC"}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("LLM_"):
            monkeypatch.delenv(name)


def _prompt():
    return {
        "instruction": "Choose one tool using the supplied fact handles.",
        "tools": [
            {
                "type": "function",
                "name": name,
                "description": f"Use {name} with supplied fact handles.",
                "parameters": {
                    "type": "object",
                    "properties": {"fact_ref": {"type": "string"}},
                    "required": ["fact_ref"],
                    "additionalProperties": False,
                },
                "strict": True,
            }
            for name in _NAMES
        ],
    }


def _client(tmp_path, **changes):
    options = {
        "mode": "record",
        "replay_dir": tmp_path,
        "model": "gpt-6.1-sol",
        "api": "responses",
        "api_key": "synthetic-named-tools-credential",
        "max_calls": 3,
        "max_usd": "1",
        "env_file": None,
    }
    options.update(changes)
    return LLMClient(**options)


def _complete(client, **changes):
    options = {
        "task_id": "W04",
        "step": "wealth-dialogue",
        "prompt": _prompt(),
        "tool_state": {"fact_refs": ["FACT_SYNTHETIC"]},
        "scripted": lambda: {"tool": "capture_goal", "arguments": deepcopy(_ARGUMENTS)},
    }
    options.update(changes)
    return client.complete(**options)


def _transport(monkeypatch, *, name="capture_goal", mutate=None):
    sends = []

    def send(self, request):
        body = loads_exact(request.content)
        sends.append(body)
        response = {
            "id": "resp_synthetic",
            "object": "response",
            "created_at": 1,
            "model": body["model"],
            "status": "completed",
            "output": [
                {"id": "rs_synthetic", "type": "reasoning", "summary": []},
                {
                    "id": "fc_synthetic",
                    "type": "function_call",
                    "call_id": "call_synthetic",
                    "name": name,
                    "arguments": jcs_bytes(_ARGUMENTS).decode("utf-8"),
                    "status": "completed",
                },
            ],
            "usage": {
                "input_tokens": 30,
                "output_tokens": 8,
                "total_tokens": 38,
                "output_tokens_details": {"reasoning_tokens": 2},
            },
        }
        if mutate:
            mutate(response)
        return httpx.Response(200, json=response)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", send)
    return sends


@pytest.mark.parametrize("name", _NAMES)
def test_model_selects_one_of_nine_actual_strict_tools(tmp_path, monkeypatch, name):
    sends = _transport(monkeypatch, name=name)
    client = _client(tmp_path)
    result = _complete(client)
    assert result.output == {"tool": name, "arguments": _ARGUMENTS}
    assert result.source == "live-recorded"
    assert len(sends) == 1
    body = sends[0]
    assert body["tools"] == _prompt()["tools"]
    assert body["tool_choice"] == "required"
    assert body["parallel_tool_calls"] is False
    assert body["reasoning"] == {"effort": "low"}
    assert "text" not in body
    assert client.api_calls == 1
    assert client.spent_usd == Fraction(30 * 10 + 8 * 40, 1_000_000)


def test_named_schema_is_closed_without_mutating_the_callers_prompt(tmp_path, monkeypatch):
    sends = _transport(monkeypatch)
    prompt = _prompt()
    prompt["tools"][0]["parameters"] = {
        "type": "object",
        "properties": {
            "fact_ref": {"type": "string", "default": "FACT_SYNTHETIC"},
            "nested": {"type": "object", "properties": {"note": {"type": "string"}}},
        },
    }
    original = deepcopy(prompt)
    _complete(_client(tmp_path), prompt=prompt)
    schema = sends[0]["tools"][0]["parameters"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"fact_ref", "nested"}
    assert schema["properties"]["nested"]["additionalProperties"] is False
    assert schema["properties"]["nested"]["required"] == ["note"]
    assert "default" not in schema["properties"]["fact_ref"]
    assert prompt == original


@pytest.mark.parametrize(
    "change",
    ["empty", "null", "not-list", "name", "duplicate", "type", "strict", "schema", "extra", "both"],
)
def test_invalid_tool_configuration_rejects_before_a_request(tmp_path, monkeypatch, change):
    sends = _transport(monkeypatch)
    prompt = _prompt()
    if change == "empty":
        prompt["tools"] = []
    elif change == "null":
        prompt["tools"] = None
    elif change == "not-list":
        prompt["tools"] = "capture_goal"
    elif change == "duplicate":
        prompt["tools"][1] = deepcopy(prompt["tools"][0])
    elif change == "both":
        prompt["response_schema"] = {"type": "object", "properties": {}}
    else:
        field, value = {
            "name": ("name", "transfer_funds"),
            "type": ("type", "web_search"),
            "strict": ("strict", False),
            "schema": ("parameters", {"type": "array"}),
            "extra": ("defer_loading", True),
        }[change]
        prompt["tools"][0][field] = value
    client = _client(tmp_path)
    with pytest.raises(LLMConfigurationError):
        _complete(client, prompt=prompt)
    assert sends == []
    assert client.api_calls == 0 and client.spent_usd == 0


def test_named_tools_cannot_silently_use_chat_completions(tmp_path, monkeypatch):
    sends = _transport(monkeypatch)
    client = _client(tmp_path, model="gpt-5.4-mini", api="chat")
    with pytest.raises(LLMConfigurationError):
        _complete(client)
    assert sends == [] and client.api_calls == 0


@pytest.mark.parametrize(
    "change",
    ["unknown", "not-offered", "multiple", "text", "text-and-tool", "incomplete", "missing"],
)
def test_unsafe_tool_envelopes_never_record(tmp_path, monkeypatch, change):
    def mutate(response):
        call = response["output"][1]
        if change in {"unknown", "not-offered"}:
            call["name"] = "transfer_funds" if change == "unknown" else "adjust"
        elif change == "multiple":
            response["output"].append(deepcopy(call))
        elif change in {"text", "text-and-tool"}:
            message = {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": '{"tool":"execute_plan"}'}],
            }
            if change == "text":
                response["output"] = [message]
            else:
                response["output"].append(message)
        elif change == "incomplete":
            call["status"] = "incomplete"
        else:
            response["output"] = []

    _transport(monkeypatch, mutate=mutate)
    prompt = _prompt()
    if change == "not-offered":
        prompt["tools"] = prompt["tools"][:1]
    client = _client(tmp_path)
    with pytest.raises(LLMOutputError):
        _complete(client, prompt=prompt)
    assert not list(tmp_path.rglob("*.json"))
    assert client.calls[-1]["source"] == "output-rejected"
    assert client.spent_usd > Fraction(30 * 10 + 8 * 40, 1_000_000)


@pytest.mark.parametrize(
    "arguments",
    ['{"amount":1.5}', '{"x":1,"x":2}', "[]", "null", "true", '"fact"', "broken", {}],
)
def test_arguments_use_exact_object_decoding(tmp_path, monkeypatch, arguments):
    _transport(
        monkeypatch,
        mutate=lambda response: response["output"][1].update(arguments=arguments),
    )
    with pytest.raises(LLMOutputError):
        _complete(_client(tmp_path))
    assert not list(tmp_path.rglob("*.json"))


def test_empty_arguments_are_valid_for_a_no_argument_tool(tmp_path, monkeypatch):
    _transport(monkeypatch, mutate=lambda response: response["output"][1].update(arguments="{}"))
    prompt = _prompt()
    prompt["tools"][0]["parameters"] = {"type": "object", "properties": {}}
    result = _complete(_client(tmp_path), prompt=prompt)
    assert result.output == {"tool": "capture_goal", "arguments": {}}


def test_replay_is_offline_and_binds_every_tool_schema(tmp_path, monkeypatch):
    _transport(monkeypatch, name="why_not")
    recorded = _complete(_client(tmp_path))
    original_import = builtins.__import__

    def offline(name, *args, **kwargs):
        if name.split(".")[0] in {"openai", "httpx", "litellm"}:
            raise AssertionError("Strict replay imported a provider SDK")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", offline)
    replay = _complete(_client(tmp_path, mode="strict"))
    assert replay.output == recorded.output and replay.source == "replay"
    prompt = _prompt()
    prompt["tools"][-1]["parameters"]["properties"]["fact_ref"]["enum"] = ["FACT_SYNTHETIC"]
    with pytest.raises(ReplayMiss):
        _complete(_client(tmp_path, mode="strict"), prompt=prompt)


@pytest.mark.parametrize("mode", ["scripted", "fallback"])
@pytest.mark.parametrize(
    "output",
    [
        {"tool": "transfer_funds", "arguments": {}},
        {"tool": "capture_goal", "arguments": []},
        {"tool": "capture_goal", "arguments": {}, "extra": "execute_plan"},
    ],
)
def test_offline_modes_preserve_the_named_result_boundary(tmp_path, mode, output):
    with pytest.raises(LLMOutputError):
        _complete(_client(tmp_path, mode=mode), scripted=lambda: output)


def test_replay_revalidates_tool_selection(tmp_path, monkeypatch):
    from corridor.agent.llm import _hash

    _transport(monkeypatch)
    _complete(_client(tmp_path))
    path = next(tmp_path.rglob("*.json"))
    record = loads_exact(path.read_bytes())
    record["output"]["tool"] = "transfer_funds"
    record["output_hash"] = _hash(record["output"])
    path.write_bytes(jcs_bytes(record))
    with pytest.raises(ReplayCorrupt):
        _complete(_client(tmp_path, mode="strict"))


def test_full_named_tool_request_is_reserved_and_call_budget_is_enforced(tmp_path, monkeypatch):
    sends = _transport(monkeypatch, mutate=lambda response: response.update(usage=None))
    client = _client(tmp_path, max_calls=1)
    with pytest.raises(LLMOutputError):
        _complete(client)
    reserve = Fraction((len(jcs_bytes(sends[0])) + 1024) * 10 + 512 * 40, 1_000_000)
    assert client.spent_usd == reserve
    assert Fraction(client.calls[-1]["cost_usd"]) == reserve
    with pytest.raises(BudgetExceeded):
        _complete(client, step="next")
    assert len(sends) == 1
    capped = _client(tmp_path, max_usd=reserve - Fraction(1, 1_000_000))
    with pytest.raises(BudgetExceeded):
        _complete(capped)
    assert capped.api_calls == 0 and len(sends) == 1
