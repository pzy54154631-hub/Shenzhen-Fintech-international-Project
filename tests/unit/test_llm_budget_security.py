"""Independent offline attacks on the Responses budget and privacy boundary."""

import builtins
import traceback
from copy import deepcopy
from fractions import Fraction
from types import SimpleNamespace

import httpx
import pytest

from corridor.agent.llm import (
    BudgetExceeded,
    LLMClient,
    LLMOutputError,
    ReplayMiss,
)
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact

_CREDENTIAL = "synthetic-budget-test-credential-never-persist"
_OUTPUT = {"contact_ref": "CONTACT_SYNTHETIC"}
_USAGE = {
    "input_tokens": 100,
    "output_tokens": 20,
    "total_tokens": 120,
    "input_tokens_details": {"cached_tokens": 99},
    "output_tokens_details": {"reasoning_tokens": 15},
}
_ACTUAL_COST = Fraction(100 * 10 + 20 * 40, 1_000_000)


@pytest.fixture(autouse=True)
def isolated_llm_environment(monkeypatch):
    """Tests never consult repository credentials or caller configuration."""
    for name in (
        "LLM_API_KEY",
        "LLM_API",
        "LLM_MODEL",
        "LLM_MODEL_CHEAP",
        "LLM_MODEL_WEAK",
        "LLM_REASONING_EFFORT",
        "LLM_MAX_CALLS",
        "LLM_MAX_USD",
        "LLM_ASSUMED_PRICE_IN",
        "LLM_ASSUMED_PRICE_OUT",
    ):
        monkeypatch.delenv(name, raising=False)


def _client(tmp_path, **changes):
    options = {
        "mode": "record",
        "replay_dir": tmp_path,
        "model": "openai/gpt-6.1-sol",
        "api": "responses",
        "reasoning_effort": "low",
        "api_key": _CREDENTIAL,
        "max_calls": 10,
        "max_usd": "1",
        "assumed_price_in": "10",
        "assumed_price_out": "40",
        "env_file": None,
    }
    options.update(changes)
    return LLMClient(**options)


def _complete(client, **changes):
    request = {
        "task_id": "J01",
        "step": "planner",
        "prompt": {
            "instruction": "Return a supplied contact handle.",
            "response_schema": {
                "type": "object",
                "properties": {"contact_ref": {"type": "string"}},
                "required": ["contact_ref"],
                "additionalProperties": False,
            },
        },
        "tool_state": {"handles": ["CONTACT_SYNTHETIC"]},
        "scripted": lambda: deepcopy(_OUTPUT),
    }
    request.update(changes)
    return client.complete(**request)


def _transport(monkeypatch, *, usage=None, output=None, failure=None):
    """Exercise the real SDK serializer against a completely local transport."""
    sends = []

    def send(self, request):
        body = loads_exact(request.content)
        sends.append(body)
        if failure is not None:
            raise failure
        tool = body["tools"][0]
        response = {
            "id": "resp_synthetic",
            "object": "response",
            "created_at": 1,
            "status": "completed",
            "model": body["model"],
            "output": [
                {
                    "id": "fc_synthetic",
                    "type": "function_call",
                    "call_id": "call_synthetic",
                    "name": tool["name"],
                    "arguments": jcs_bytes(_OUTPUT if output is None else output).decode("utf-8"),
                    "status": "completed",
                }
            ],
            "usage": deepcopy(_USAGE if usage is None else usage),
        }
        return httpx.Response(200, json=response)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", send)
    return sends


def _failed_reservation(tmp_path, monkeypatch):
    sends = _transport(monkeypatch, failure=RuntimeError("synthetic transport failure"))
    client = _client(tmp_path)
    with pytest.raises(LLMOutputError):
        _complete(client)
    assert len(sends) == client.api_calls == 1
    assert client.spent_usd > 0
    assert not list(tmp_path.rglob("*.json"))
    return client.spent_usd


def test_exact_reservation_boundary_is_checked_before_transport(tmp_path, monkeypatch):
    reserve = _failed_reservation(tmp_path / "probe", monkeypatch)
    sends = _transport(monkeypatch)
    short = _client(tmp_path / "short", max_usd=reserve - Fraction(1, 10**9))
    with pytest.raises(BudgetExceeded):
        _complete(short)
    assert sends == []
    assert short.api_calls == 0 and short.spent_usd == 0
    exact = _client(tmp_path / "exact", max_usd=reserve)
    assert _complete(exact).source == "live-recorded"
    assert len(sends) == 1 and exact.spent_usd == _ACTUAL_COST


def test_successful_tasks_share_one_cumulative_usd_budget(tmp_path, monkeypatch):
    reserve = _failed_reservation(tmp_path / "probe", monkeypatch)
    sends = _transport(monkeypatch)
    client = _client(tmp_path / "records", max_usd=reserve + _ACTUAL_COST)
    assert _complete(client, task_id="J01").source == "live-recorded"
    assert _complete(client, task_id="W04").source == "live-recorded"
    with pytest.raises(BudgetExceeded):
        _complete(client, task_id="W04", step="repair")
    assert len(sends) == client.api_calls == 2
    assert client.spent_usd == 2 * _ACTUAL_COST


def test_failed_attempt_consumes_call_limit_across_task_ids(tmp_path, monkeypatch):
    sends = _transport(monkeypatch, failure=RuntimeError("synthetic transport failure"))
    client = _client(tmp_path, max_calls=1)
    with pytest.raises(LLMOutputError):
        _complete(client, task_id="J01")
    reserve = client.spent_usd
    with pytest.raises(BudgetExceeded):
        _complete(client, task_id="W04")
    assert len(sends) == client.api_calls == 1
    assert client.spent_usd == reserve > 0
    assert not list(tmp_path.rglob("*.json"))


def test_failed_attempt_keeps_usd_reservation_before_next_task(tmp_path, monkeypatch):
    reserve = _failed_reservation(tmp_path / "probe", monkeypatch)
    sends = _transport(monkeypatch, failure=RuntimeError("synthetic transport failure"))
    client = _client(tmp_path / "records", max_usd=2 * reserve - Fraction(1, 10**9))
    with pytest.raises(LLMOutputError):
        _complete(client, task_id="J01")
    with pytest.raises(BudgetExceeded):
        _complete(client, task_id="W04")
    assert len(sends) == client.api_calls == 1
    assert client.spent_usd == reserve


def test_cached_input_and_reasoning_tokens_do_not_discount_assumed_price(tmp_path, monkeypatch):
    _transport(monkeypatch)
    client = _client(tmp_path)
    _complete(client)
    assert client.spent_usd == _ACTUAL_COST
    trace = client.calls[-1]
    assert trace["input_tokens"] == 100
    assert trace["output_tokens"] == 20
    assert trace["reasoning_tokens"] == 15
    assert Fraction(trace["cost_usd"]) == _ACTUAL_COST


@pytest.mark.parametrize(
    "field,value",
    [
        ("input_tokens", True),
        ("input_tokens", -1),
        ("input_tokens", "100"),
        ("output_tokens", True),
        ("output_tokens", -1),
        ("output_tokens", "20"),
    ],
)
def test_malformed_usage_cannot_refund_reservation(tmp_path, monkeypatch, field, value):
    reserve = _failed_reservation(tmp_path / "probe", monkeypatch)
    usage = {**_USAGE, field: value}
    sends = _transport(monkeypatch, usage=usage)
    client = _client(tmp_path / "records")
    with pytest.raises(LLMOutputError):
        _complete(client)
    assert len(sends) == 1
    assert client.api_calls == 1 and client.spent_usd >= reserve
    assert not list((tmp_path / "records").rglob("*.json"))


@pytest.mark.parametrize("missing", ["input_tokens", "output_tokens"])
def test_missing_usage_keeps_reservation_and_cannot_record(tmp_path, monkeypatch, missing):
    reserve = _failed_reservation(tmp_path / "probe", monkeypatch)
    usage = deepcopy(_USAGE)
    del usage[missing]
    sends = _transport(monkeypatch, usage=usage)
    client = _client(tmp_path / "records")
    with pytest.raises(LLMOutputError):
        _complete(client)
    assert len(sends) == 1
    assert client.api_calls == 1 and client.spent_usd >= reserve
    assert not list((tmp_path / "records").rglob("*.json"))


def test_provider_usage_above_budget_stops_and_cannot_reset_on_next_task(tmp_path, monkeypatch):
    sends = _transport(
        monkeypatch,
        usage={**_USAGE, "input_tokens": 1_000_000, "total_tokens": 1_000_020},
    )
    client = _client(tmp_path)
    with pytest.raises(BudgetExceeded):
        _complete(client, task_id="J01")
    with pytest.raises(BudgetExceeded):
        _complete(client, task_id="W04")
    assert len(sends) == client.api_calls == 1
    assert not list(tmp_path.rglob("*.json"))


def test_transport_error_cannot_persist_or_chain_credential(tmp_path, monkeypatch, capsys):
    _transport(monkeypatch, failure=RuntimeError(f"Authorization: Bearer {_CREDENTIAL}"))
    client = _client(tmp_path)
    with pytest.raises(LLMOutputError) as error:
        _complete(client)
    visible = "".join(traceback.format_exception(error.value))
    captured = capsys.readouterr()
    visible += str(client.calls) + captured.out + captured.err
    assert _CREDENTIAL not in visible
    assert not list(tmp_path.rglob("*.json"))
    assert client.api_calls == 1 and client.spent_usd > 0


@pytest.mark.parametrize("output", [{"api_key": _CREDENTIAL}, {"contact_ref": _CREDENTIAL}])
def test_unsafe_output_keeps_reservation_and_never_records(tmp_path, monkeypatch, output):
    reserve = _failed_reservation(tmp_path / "probe", monkeypatch)
    _transport(monkeypatch, output=output)
    client = _client(tmp_path / "records")
    with pytest.raises(LLMOutputError) as error:
        _complete(client)
    assert _CREDENTIAL not in "".join(traceback.format_exception(error.value))
    assert _CREDENTIAL not in str(client.calls)
    assert client.api_calls == 1 and client.spent_usd >= reserve
    assert not list((tmp_path / "records").rglob("*.json"))


@pytest.mark.parametrize(
    "changed",
    [
        {"api": "chat"},
        {"reasoning_effort": "medium"},
        {"model": "openai/gpt-6-luna"},
    ],
)
def test_responses_replay_profile_change_misses_without_sdk(tmp_path, monkeypatch, changed):
    _transport(monkeypatch)
    _complete(_client(tmp_path))
    original = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.split(".")[0] in {"litellm", "httpx", "openai", "requests", "anthropic"}:
            raise AssertionError("Replay imported a network SDK")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    strict = _client(tmp_path, mode="strict")
    assert _complete(strict).source == "replay"
    with pytest.raises(ReplayMiss):
        _complete(_client(tmp_path, mode="strict", **changed))
    assert strict.api_calls == 0 and strict.spent_usd == 0


def test_constructor_cannot_raise_environment_budget_caps(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_MAX_CALLS", "1")
    monkeypatch.setenv("LLM_MAX_USD", "1/10")
    sends = _transport(monkeypatch)
    client = _client(tmp_path, max_calls=30, max_usd="100")
    assert client.max_calls == 1
    assert client.max_usd == Fraction(1, 10)
    _complete(client, task_id="J01")
    with pytest.raises(BudgetExceeded):
        _complete(client, task_id="W04")
    assert len(sends) == 1


@pytest.mark.parametrize("configure", ["arguments", "environment"])
def test_chat_cannot_ignore_configured_assumed_prices(tmp_path, monkeypatch, configure):
    from tests.unit.test_llm import _request, _sdk

    _, sends = _sdk(monkeypatch)
    options = {}
    if configure == "arguments":
        options.update(assumed_price_in="100000", assumed_price_out="100000")
    else:
        monkeypatch.setenv("LLM_ASSUMED_PRICE_IN", "100000")
        monkeypatch.setenv("LLM_ASSUMED_PRICE_OUT", "100000")
    client = LLMClient(
        mode="record",
        replay_dir=tmp_path,
        model="openai/fixed-model-v1",
        api="chat",
        api_key=_CREDENTIAL,
        max_calls=2,
        max_usd="1",
        env_file=None,
        **options,
    )
    with pytest.raises(BudgetExceeded):
        _request(client)
    assert not sends
    assert client.api_calls == 0 and client.spent_usd == 0


def test_chat_configured_prices_and_usage_are_in_trace(tmp_path, monkeypatch):
    from tests.unit.test_llm import _request, _sdk

    _sdk(monkeypatch)
    client = LLMClient(
        mode="record",
        replay_dir=tmp_path,
        model="openai/fixed-model-v1",
        api="chat",
        api_key=_CREDENTIAL,
        max_calls=2,
        max_usd="1",
        assumed_price_in="10",
        assumed_price_out="40",
        env_file=None,
    )
    _request(client)
    assert client.spent_usd == Fraction(30 * 10 + 8 * 40, 1_000_000)
    assert client.calls[-1]["input_tokens"] == 30
    assert client.calls[-1]["output_tokens"] == 8
    assert client.calls[-1]["pricing_source"] == "assumed_or_local_max"


@pytest.mark.parametrize("attack", ["nested_tool", "output_cap", "retry", "cached"])
def test_responses_transport_rejects_sdk_scope_changes_and_hidden_calls(
    tmp_path, monkeypatch, attack
):
    import openai

    sends = _transport(monkeypatch)

    class AlteringSDK:
        def __init__(self, **settings):
            self.http = settings["http_client"]
            self.responses = SimpleNamespace(create=self.create)

        def create(self, **body):
            if attack == "cached":
                return {"output": _OUTPUT}
            if attack == "nested_tool":
                body["tools"][0]["strict"] = False
            if attack == "output_cap":
                body["max_output_tokens"] = 8192
            self.http.post("https://api.openai.com/v1/responses", json=body)
            if attack == "retry":
                self.http.post("https://api.openai.com/v1/responses", json=body)

    monkeypatch.setattr(openai, "OpenAI", AlteringSDK)
    client = _client(tmp_path)
    with pytest.raises(LLMOutputError):
        _complete(client)
    assert len(sends) == (1 if attack == "retry" else 0)
    assert client.api_calls == 1 and client.spent_usd > 0
    assert not list(tmp_path.rglob("*.json"))
