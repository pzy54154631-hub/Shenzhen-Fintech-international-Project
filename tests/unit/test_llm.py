"""Offline replay isolation, exact identity, and explicit live budget boundaries."""

import builtins
import os
import subprocess
import sys
from fractions import Fraction
from hashlib import sha256
from types import SimpleNamespace

import pytest

from corridor.agent.llm import (
    BudgetExceeded,
    LLMClient,
    LLMConfigurationError,
    LLMOutputError,
    ReplayCorrupt,
    ReplayMiss,
)
from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.base import loads_exact


def _request(client, **changes):
    fields = {
        "task_id": "J01",
        "step": "planner",
        "prompt": {"instruction": "Choose a typed contact handle."},
        "tool_state": {"handles": ["CONTACT_CHEN"]},
        "sample_idx": 0,
        "scripted": lambda: {"contact_ref": "CONTACT_CHEN"},
    }
    fields.update(changes)
    return client.complete(**fields)


def _sdk(monkeypatch, *, response=None, failure=None, prices=True):
    import httpx

    payload = response or {
        "choices": [{"message": {"content": '{"contact_ref":"CONTACT_CHEN"}'}}],
        "usage": {"prompt_tokens": 30, "completion_tokens": 8},
    }
    monkeypatch.setattr(
        httpx.HTTPTransport,
        "handle_request",
        lambda self, request: httpx.Response(200, json=payload),
    )
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        if failure is not None:
            raise failure
        kwargs["client"]._client.post(
            "https://api.openai.com/v1/chat/completions",
            json={
                "model": kwargs["model"].split("/", 1)[1],
                "messages": kwargs["messages"],
                "max_completion_tokens": kwargs["max_completion_tokens"],
                "n": 1,
                "stream": False,
                "response_format": {"type": "json_object"},
            },
        )
        return payload

    module = SimpleNamespace(
        completion=completion,
        token_counter=lambda **kwargs: 30,
        get_model_info=lambda model: (
            {"input_cost_per_token": "0.000001", "output_cost_per_token": "0.000002"}
            if prices
            else {}
        ),
        model_cost={
            "openai/fixed-model-v1": {
                "mode": "chat",
                "max_input_tokens": 1024,
                "max_output_tokens": 512,
                "input_cost_per_token": "0.000001",
                "output_cost_per_token": "0.000002",
            }
        }
        if prices
        else {},
        num_retries=3,
        model_fallbacks=["unexpected-model"],
        Timeout=TimeoutError,
    )
    monkeypatch.setitem(sys.modules, "litellm", module)
    return module, calls


def _live(tmp_path, mode="record", **kwargs):
    return LLMClient(
        mode=mode,
        replay_dir=tmp_path,
        model="openai/fixed-model-v1",
        api_key="unit-test-credential",
        max_calls=kwargs.pop("max_calls", 3),
        max_usd=kwargs.pop("max_usd", "1"),
        env_file=None,
        **kwargs,
    )


def test_scripted_is_never_saved_as_a_live_record(tmp_path, monkeypatch):
    original = builtins.__import__

    def blocked(name, *args, **kwargs):
        assert not name.startswith("litellm")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    client = LLMClient(mode="scripted", replay_dir=tmp_path)
    result = _request(client)
    assert result.source == "scripted"
    assert result.output == {"contact_ref": "CONTACT_CHEN"}
    assert list(tmp_path.rglob("*.json")) == []
    assert client.calls[0]["source"] == "scripted"
    assert client.calls[0]["schema_version"] == "bank-llm-v1"
    assert (
        client.calls[0]["tool_state_hash"]
        == sha256(jcs_bytes({"handles": ["CONTACT_CHEN"]})).hexdigest()
    )


def test_record_then_strict_replay_has_complete_exact_key(tmp_path, monkeypatch):
    _, api_calls = _sdk(monkeypatch)
    recorder = _live(tmp_path)
    result = _request(recorder)
    assert result.source == "live-recorded"
    identity = {
        "schema_version": "bank-llm-v1",
        "model": "openai/fixed-model-v1",
        "api": "chat",
        "reasoning_effort": None,
        "max_output_tokens": 512,
        "prompt_hash": sha256(
            jcs_bytes({"instruction": "Choose a typed contact handle."})
        ).hexdigest(),
        "tool_state_hash": sha256(jcs_bytes({"handles": ["CONTACT_CHEN"]})).hexdigest(),
        "task_id": "J01",
        "step": "planner",
        "sample_idx": 0,
        "config": "cca",
        "user_policy": "careful",
    }
    assert result.replay_key == H(identity)
    paths = list(tmp_path.rglob("*.json"))
    assert len(paths) == 1
    assert paths[0].stem == identity["prompt_hash"][:16]
    assert len(paths[0].relative_to(tmp_path).parts) <= 2
    cached = loads_exact(paths[0].read_bytes())
    assert cached["source"] == "live-recorded"
    assert cached["request"] == identity
    replay = LLMClient(mode="strict", replay_dir=tmp_path, model=identity["model"])
    assert _request(replay).output == result.output
    assert _request(replay).source == "replay"
    assert len(api_calls) == 1
    assert api_calls[0]["timeout"] == 20
    assert api_calls[0]["num_retries"] == api_calls[0]["max_retries"] == 0


@pytest.mark.parametrize(
    "field",
    ["model", "config", "user_policy", "task_id", "step", "sample_idx", "prompt", "tool_state"],
)
def test_any_replay_identity_input_change_misses(tmp_path, monkeypatch, field):
    _sdk(monkeypatch)
    _request(_live(tmp_path))
    settings = {"model": "openai/fixed-model-v1", "config": "cca", "user_policy": "careful"}
    changed = {}
    if field in settings:
        settings[field] = "different"
    else:
        changed[field] = {
            "task_id": "J02",
            "step": "repair",
            "sample_idx": 1,
            "prompt": {"instruction": "Choose another typed handle."},
            "tool_state": {"handles": ["CONTACT_OTHER"]},
        }[field]
    client = LLMClient(mode="strict", replay_dir=tmp_path, **settings)
    with pytest.raises(ReplayMiss, match="prompt diff"):
        _request(client, **changed)


def test_prompt_signature_field_also_participates_in_cache_hash(tmp_path):
    client = LLMClient(replay_dir=tmp_path)
    first = _request(client, prompt={"sig": "first"})
    second = _request(client, prompt={"sig": "second"})
    assert first.replay_key != second.replay_key


def test_miss_diff_only_contains_paths_and_hashes(tmp_path, monkeypatch):
    _sdk(monkeypatch)
    _request(_live(tmp_path), prompt={"instruction": "PRIVATE_FREE_MARKER_ONE"})
    client = LLMClient(mode="strict", replay_dir=tmp_path, model="openai/fixed-model-v1")
    with pytest.raises(ReplayMiss) as error:
        _request(client, prompt={"instruction": "PRIVATE_FREE_MARKER_TWO"})
    message = str(error.value)
    assert "J01" in message and "planner" in message and "prompt diff" in message
    assert "instruction" in message
    assert "PRIVATE_FREE_MARKER" not in message
    assert client.calls[-1]["source"] == "replay-miss"


@pytest.mark.parametrize("mutation", ["source", "output", "request"])
def test_tampered_or_scripted_cache_is_not_a_real_replay(tmp_path, monkeypatch, mutation):
    _sdk(monkeypatch)
    _request(_live(tmp_path))
    path = next(tmp_path.rglob("*.json"))
    record = loads_exact(path.read_bytes())
    if mutation == "source":
        record["source"] = "scripted"
    elif mutation == "output":
        record["output"] = {"contact_ref": "CONTACT_OTHER"}
    else:
        record["request"]["config"] = "d0"
    path.write_bytes(jcs_bytes(record))
    with pytest.raises(ReplayCorrupt):
        _request(LLMClient(mode="strict", replay_dir=tmp_path, model="openai/fixed-model-v1"))


def test_default_context_guard_blocks_raw_sensitive_input_before_sdk(tmp_path, monkeypatch):
    _, calls = _sdk(monkeypatch)
    client = _live(tmp_path)
    for prompt in (
        {"phone": "13800138000"},
        {"text": "Contact 13800138000"},
        {"password": "hidden"},
    ):
        with pytest.raises(ValueError, match="PII-CTX"):
            _request(client, prompt=prompt)
    assert calls == []
    assert not list(tmp_path.rglob("*.json"))


def test_guard_failure_does_not_copy_private_identity_into_call_trace(tmp_path):
    client = LLMClient(replay_dir=tmp_path)
    with pytest.raises(ValueError, match="PII-CTX"):
        _request(client, task_id="13800138000")
    assert "13800138000" not in str(client.calls)


def test_record_existing_key_refuses_before_new_api_charge(tmp_path, monkeypatch):
    _, calls = _sdk(monkeypatch)
    client = _live(tmp_path)
    _request(client)
    with pytest.raises(ReplayCorrupt):
        _request(client)
    assert len(calls) == 1


def test_live_transport_blocks_hidden_second_sdk_send(tmp_path, monkeypatch):
    import httpx

    module, _ = _sdk(monkeypatch)
    sends = []

    def network_stub(self, request):
        sends.append(request.url)
        return httpx.Response(200, json={"stub": True})

    def hidden_retry(**kwargs):
        client = kwargs["client"]._client
        body = {
            "model": "fixed-model-v1",
            "messages": kwargs["messages"],
            "max_completion_tokens": 512,
            "n": 1,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        client.post("https://api.openai.com/v1/chat/completions", json=body)
        client.post("https://api.openai.com/v1/chat/completions", json=body)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", network_stub)
    module.completion = hidden_retry
    with pytest.raises(LLMOutputError):
        _request(_live(tmp_path))
    assert len(sends) == 1
    assert not list(tmp_path.rglob("*.json"))


def test_cached_sdk_response_cannot_masquerade_as_actual_record(tmp_path, monkeypatch):
    module, _ = _sdk(monkeypatch)
    module.completion = lambda **kwargs: {
        "choices": [{"message": {"content": "{}"}}],
        "usage": {"prompt_tokens": 30, "completion_tokens": 1},
    }
    with pytest.raises(LLMOutputError):
        _request(_live(tmp_path))
    assert not list(tmp_path.rglob("*.json"))


def test_corrupt_diff_metadata_never_discloses_raw_cache_text(tmp_path, monkeypatch):
    _sdk(monkeypatch)
    _request(_live(tmp_path))
    path = next(tmp_path.rglob("*.json"))
    cached = loads_exact(path.read_bytes())
    cached["prompt_fingerprints"] = {"13800138000": "RAW_SECRET"}
    path.write_bytes(jcs_bytes(cached))
    client = LLMClient(mode="strict", replay_dir=tmp_path, model="openai/fixed-model-v1")
    with pytest.raises(ReplayMiss) as error:
        _request(client, prompt={"instruction": "changed"})
    assert "13800138000" not in str(error.value)
    assert "RAW_SECRET" not in str(error.value)


def test_invalid_json_response_traceback_does_not_disclose_its_keys(tmp_path, monkeypatch):
    import traceback

    _sdk(
        monkeypatch,
        response={"choices": [{"message": {"content": '{"13800138000":1,"13800138000":2}'}}]},
    )
    with pytest.raises(LLMOutputError) as error:
        _request(_live(tmp_path))
    assert "13800138000" not in "".join(traceback.format_exception(error.value))


def test_sensitive_model_output_has_outbound_rule_and_is_not_recorded(tmp_path, monkeypatch):
    _sdk(
        monkeypatch,
        response={
            "choices": [{"message": {"content": '{"phone":"13800138000"}'}}],
            "usage": {"prompt_tokens": 30, "completion_tokens": 8},
        },
    )
    with pytest.raises(LLMOutputError, match="PII-OUT"):
        _request(_live(tmp_path))
    assert not list(tmp_path.rglob("*.json"))


def test_context_guard_is_called_for_request_state_and_output(tmp_path):
    seen = []
    client = LLMClient(replay_dir=tmp_path, context_guard=lambda value: seen.append(value))
    _request(client)
    assert any(value == {"handles": ["CONTACT_CHEN"]} for value in seen)
    assert any(value == {"contact_ref": "CONTACT_CHEN"} for value in seen)


def test_observers_see_actual_request_and_guard_rejected_output_without_persistence(tmp_path):
    client = LLMClient(replay_dir=tmp_path)
    seen = []
    client.observers.append(lambda stage, value: seen.append((stage, value)))
    with pytest.raises(LLMOutputError, match="PII-OUT"):
        _request(client, scripted=lambda: {"text": "给13900001001转200元"})
    assert seen == [
        (
            "request",
            {
                "prompt": {"instruction": "Choose a typed contact handle."},
                "tool_state": {"handles": ["CONTACT_CHEN"]},
            },
        ),
        ("output", {"text": "给13900001001转200元"}),
    ]
    assert "13900001001" not in str(client.calls)
    assert list(tmp_path.rglob("*.json")) == []


def test_observers_cannot_change_request_or_output(tmp_path):
    client = LLMClient(replay_dir=tmp_path)

    def corrupt(stage, value):
        value.clear()

    client.observers.append(corrupt)
    result = _request(client)
    assert result.output == {"contact_ref": "CONTACT_CHEN"}
    assert (
        client.calls[0]["prompt_hash"]
        == sha256(jcs_bytes({"instruction": "Choose a typed contact handle."})).hexdigest()
    )


@pytest.mark.parametrize(
    "option,value",
    [("api_key", ""), ("max_calls", 0), ("max_usd", "0"), ("model", "scripted-bank-v1")],
)
def test_live_refuses_missing_credentials_or_budget(tmp_path, monkeypatch, option, value):
    kwargs = {
        "mode": "live",
        "replay_dir": tmp_path,
        "model": "openai/fixed-model-v1",
        "api_key": "test-credential",
        "max_calls": 1,
        "max_usd": "1",
        "env_file": None,
    }
    kwargs[option] = value
    for key in ("LLM_API_KEY", "LLM_MODEL", "LLM_MAX_USD", "LLM_MAX_CALLS"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(LLMConfigurationError):
        LLMClient(**kwargs)


def test_budget_reservation_blocks_call_before_network(tmp_path, monkeypatch):
    _, calls = _sdk(monkeypatch)
    client = _live(tmp_path, max_usd="0.000001")
    with pytest.raises(BudgetExceeded):
        _request(client)
    assert calls == []


def test_call_limit_counts_each_actual_attempt(tmp_path, monkeypatch):
    _, calls = _sdk(monkeypatch)
    client = _live(tmp_path, max_calls=1)
    _request(client)
    with pytest.raises(BudgetExceeded):
        _request(client, step="repair")
    assert len(calls) == 1
    assert client.spent_usd == Fraction(46, 1000000)
    assert client.calls[0]["input_tokens"] == 30
    assert client.calls[0]["output_tokens"] == 8
    assert client.calls[0]["reasoning_tokens"] == 0
    assert client.calls[0]["total_tokens"] == 38


def test_configured_chat_assumptions_cannot_use_cheaper_local_prices(tmp_path, monkeypatch):
    _, calls = _sdk(monkeypatch)
    client = _live(tmp_path, assumed_price_in="1000000", assumed_price_out="1000000")
    with pytest.raises(BudgetExceeded):
        _request(client)
    assert calls == [] and client.api_calls == 0


def test_chat_usage_above_reservation_latches_shared_budget(tmp_path, monkeypatch):
    _sdk(
        monkeypatch,
        response={
            "choices": [{"message": {"content": '{"contact_ref":"CONTACT_CHEN"}'}}],
            "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 8},
        },
    )
    client = _live(tmp_path)
    with pytest.raises(BudgetExceeded):
        _request(client)
    with pytest.raises(BudgetExceeded):
        _request(client, task_id="W04")
    assert client.api_calls == 1 and client.spent_usd > client.max_usd


def test_chat_unsafe_output_cannot_hide_reported_overspend(tmp_path, monkeypatch):
    _sdk(
        monkeypatch,
        response={
            "choices": [{"message": {"content": '{"api_key":"synthetic-secret"}'}}],
            "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 8},
        },
    )
    client = _live(tmp_path)
    with pytest.raises(BudgetExceeded):
        _request(client)
    with pytest.raises(BudgetExceeded):
        _request(client, task_id="W04")
    assert client.api_calls == 1 and client.spent_usd > client.max_usd
    assert not list(tmp_path.rglob("*.json"))


def test_missing_price_refuses_network(tmp_path, monkeypatch):
    _, calls = _sdk(monkeypatch, prices=False)
    with pytest.raises(LLMConfigurationError, match="pricing"):
        _request(_live(tmp_path))
    assert calls == []


def test_timeout_is_labelled_scripted_and_never_recorded(tmp_path, monkeypatch):
    _, calls = _sdk(monkeypatch, failure=TimeoutError())
    client = _live(tmp_path)
    result = _request(client)
    assert result.source == "scripted-timeout"
    assert len(calls) == 1
    assert not list(tmp_path.rglob("*.json"))
    assert client.spent_usd > 0


@pytest.mark.parametrize("content", ['{"amount":1.2}', '["not-an-object"]', "not-json"])
def test_invalid_model_output_is_never_recorded(tmp_path, monkeypatch, content):
    _sdk(
        monkeypatch,
        response={
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 30, "completion_tokens": 8},
        },
    )
    with pytest.raises(LLMOutputError):
        _request(_live(tmp_path))
    assert not list(tmp_path.rglob("*.json"))


def test_strict_and_fallback_in_process_with_network_and_sdk_import_forbidden(
    tmp_path, monkeypatch
):
    _sdk(monkeypatch)
    _request(_live(tmp_path))
    script = r"""
import builtins, socket, sys
original = builtins.__import__
def blocked_import(name, *args, **kwargs):
    if name.split('.')[0] in {'litellm', 'httpx', 'requests', 'openai', 'anthropic'}:
        raise AssertionError('network SDK imported')
    return original(name, *args, **kwargs)
builtins.__import__ = blocked_import
def blocked(*args, **kwargs):
    raise AssertionError('network attempted')
socket.socket = blocked
socket.create_connection = blocked
from pathlib import Path
from corridor.agent.llm import LLMClient, ReplayMiss
kwargs = dict(
    task_id='J01', step='planner',
    prompt={'instruction':'Choose a typed contact handle.'},
    tool_state={'handles':['CONTACT_CHEN']},
    scripted=lambda:{'contact_ref':'CONTACT_CHEN'},
)
strict = LLMClient(mode='strict', replay_dir=Path(sys.argv[1]), model='openai/fixed-model-v1')
assert strict.complete(**kwargs).source == 'replay'
try:
    strict.complete(**{**kwargs, 'step':'missing'})
except ReplayMiss as error:
    assert 'J01' in str(error) and 'missing' in str(error) and 'prompt diff' in str(error)
else:
    raise AssertionError('strict silently fell back')
fallback = LLMClient(mode='fallback', replay_dir=Path(sys.argv[1]), model='openai/fixed-model-v1')
assert fallback.complete(**{**kwargs, 'step':'missing'}).source == 'scripted-fallback'
assert 'litellm' not in sys.modules
"""
    env = {**os.environ, "LLM_API_KEY": "present-but-offline"}
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    missed = subprocess.run(
        [
            sys.executable,
            "-c",
            script + "\nstrict.complete(**{**kwargs, 'step':'fatal-miss'})",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=20,
    )
    assert missed.returncode != 0
    assert "J01" in missed.stderr and "fatal-miss" in missed.stderr
    assert "prompt diff" in missed.stderr
