"""Responses strict tools, profile identity, and nullable default compatibility."""

import builtins
import traceback
from copy import deepcopy
from fractions import Fraction

import httpx
import pytest

from corridor.agent.llm import LLMClient, LLMConfigurationError, LLMOutputError, ReplayMiss
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact
from corridor.schemas.narrative import Narrative

_SCHEMA = {
    "type": "object",
    "properties": {"contact_ref": {"type": "string", "default": "CONTACT_A"}},
}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in tuple(__import__("os").environ):
        if name.startswith("LLM_"):
            monkeypatch.delenv(name)


def _client(tmp_path, **changes):
    options = {
        "mode": "record",
        "replay_dir": tmp_path,
        "model": "openai/gpt-6.1-sol",
        "api": "responses",
        "reasoning_effort": "low",
        "api_key": "synthetic-responses-credential",
        "max_calls": 3,
        "max_usd": "1",
        "max_output_tokens": 2048,
        "env_file": None,
    }
    options.update(changes)
    return LLMClient(**options)


def _complete(client, schema=None, **changes):
    options = {
        "task_id": "J01",
        "step": "planner",
        "prompt": {"instruction": "Use a supplied handle.", "response_schema": schema or _SCHEMA},
        "tool_state": {"handles": ["CONTACT_A"]},
        "scripted": lambda: {"contact_ref": "CONTACT_A"},
    }
    options.update(changes)
    return client.complete(**options)


def _transport(monkeypatch, *, output=None, mutate=None):
    sends = []

    def send(self, request):
        body = loads_exact(request.content)
        sends.append((str(request.url), body))
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
                    "name": "emit_result",
                    "arguments": jcs_bytes(output or {"contact_ref": "CONTACT_A"}).decode("utf-8"),
                    "status": "completed",
                },
            ],
            "usage": {
                "input_tokens": 30,
                "output_tokens": 8,
                "total_tokens": 38,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 2},
            },
        }
        if mutate:
            mutate(response)
        return httpx.Response(200, json=response)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", send)
    return sends


def test_responses_uses_flat_strict_function_and_actual_usage(tmp_path, monkeypatch):
    sends = _transport(monkeypatch)
    original = builtins.__import__

    def no_litellm(name, *args, **kwargs):
        assert name.split(".")[0] != "litellm"
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_litellm)
    schema = deepcopy(_SCHEMA)
    client = _client(tmp_path)
    result = _complete(client, schema)
    assert result.source == "live-recorded"
    assert result.output == {"contact_ref": "CONTACT_A"}
    assert schema == _SCHEMA
    endpoint, body = sends[0]
    assert endpoint == "https://api.openai.com/v1/responses"
    assert body["model"] == "gpt-6.1-sol"
    assert body["reasoning"] == {"effort": "low"}
    assert body["max_output_tokens"] == 2048
    assert body["parallel_tool_calls"] is False and body["store"] is False
    assert body["tool_choice"] == {"type": "function", "name": "emit_result"}
    assert body["tools"][0] == {
        "type": "function",
        "name": "emit_result",
        "description": "Return the requested typed result using only supplied handles.",
        "parameters": {
            "type": "object",
            "properties": {"contact_ref": {"type": "string"}},
            "required": ["contact_ref"],
            "additionalProperties": False,
        },
        "strict": True,
    }
    assert client.spent_usd == Fraction(30 * 10 + 8 * 40, 1_000_000)
    assert client.calls[-1]["reasoning_tokens"] == 2
    assert client.calls[-1]["total_tokens"] == 38
    assert client.calls[-1]["pricing_source"] == "assumed"


def test_nullable_default_is_omitted_so_fact_ref_does_not_assert_null(tmp_path, monkeypatch):
    _transport(
        monkeypatch,
        output={
            "fact_refs": [{"receipt_ref": "R_SYNTHETIC", "field": "amount", "expected": None}],
            "note": "",
        },
    )
    result = _complete(_client(tmp_path), Narrative.model_json_schema())
    parsed = Narrative.model_validate(result.output)
    assert "expected" not in parsed.fact_refs[0].model_fields_set
    assert parsed.fact_refs[0].expected is None


def test_nonnull_expected_fact_is_preserved_and_freeform_maps_closed(tmp_path, monkeypatch):
    sends = _transport(
        monkeypatch,
        output={
            "fact_refs": [{"receipt_ref": "R_SYNTHETIC", "field": "amount", "expected": "10/1"}],
            "note": "",
        },
    )
    result = _complete(_client(tmp_path), Narrative.model_json_schema())
    assert result.output["fact_refs"][0]["expected"] == "10/1"

    def closed(node):
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            for child in node.values():
                closed(child)
        elif isinstance(node, list):
            for child in node:
                closed(child)

    closed(sends[0][1]["tools"][0]["parameters"])


def test_strict_normalization_preserves_properties_named_like_schema_keywords():
    from corridor.agent.llm import _strict_schema

    schema = {
        "type": "object",
        "properties": {"default": {"type": "string", "default": "x"}},
    }
    assert _strict_schema(schema)["properties"] == {"default": {"type": "string"}}


@pytest.mark.parametrize("change", ["name", "multiple", "text", "incomplete", "float", "missing"])
def test_noncanonical_tool_responses_are_not_recorded(tmp_path, monkeypatch, change):
    def mutate(response):
        if change == "name":
            response["output"][1]["name"] = "unexpected_tool"
        elif change == "multiple":
            response["output"].append(deepcopy(response["output"][1]))
        elif change == "text":
            response["output"] = [{"type": "message", "content": [{"type": "refusal"}]}]
        elif change == "incomplete":
            response["status"] = "incomplete"
        elif change == "float":
            response["output"][1]["arguments"] = '{"amount":1.5}'
        else:
            response["usage"] = None

    _transport(monkeypatch, mutate=mutate)
    with pytest.raises(LLMOutputError):
        _complete(_client(tmp_path))
    assert not list(tmp_path.rglob("*.json"))


@pytest.mark.parametrize(
    "change", [{"max_output_tokens": 1024}, {"api": "chat"}, {"reasoning_effort": "medium"}]
)
def test_profile_changes_miss_offline_replay(tmp_path, monkeypatch, change):
    _transport(monkeypatch)
    _complete(_client(tmp_path))
    assert _complete(_client(tmp_path, mode="strict")).source == "replay"
    if change.get("api") == "chat":
        change["max_output_tokens"] = 512
    with pytest.raises(ReplayMiss):
        _complete(_client(tmp_path, mode="strict", **change))


@pytest.mark.parametrize("model", ["gpt-6.1-sol", "openai/gpt-6.1-sol"])
def test_bare_and_openai_model_names_use_responses(tmp_path, monkeypatch, model):
    sends = _transport(monkeypatch)
    client = _client(tmp_path, model=model, api=None, reasoning_effort=None)
    _complete(client)
    assert sends[0][1]["model"] == "gpt-6.1-sol"
    assert client.api == "responses" and client.reasoning_effort == "low"


def test_env_profiles_and_model_tiers_use_only_fake_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "synthetic-tier-credential")
    monkeypatch.setenv("LLM_API", "responses")
    monkeypatch.setenv("LLM_MODEL", "gpt-6.1-sol")
    monkeypatch.setenv("LLM_MODEL_CHEAP", "gpt-6-luna")
    monkeypatch.setenv("LLM_MODEL_WEAK", "gpt-6-sol")
    monkeypatch.setenv("LLM_MAX_CALLS", "30")
    monkeypatch.setenv("LLM_MAX_USD", "1")
    for tier, model in (("main", "gpt-6.1-sol"), ("cheap", "gpt-6-luna"), ("weak", "gpt-6-sol")):
        client = LLMClient(mode="live", model_tier=tier, env_file=None)
        assert client.model == model and client.api == "responses"
        assert client.reasoning_effort == "low"


@pytest.mark.parametrize("limit", [127, 8193, True])
def test_responses_generation_limit_is_bounded(tmp_path, limit):
    with pytest.raises(LLMConfigurationError):
        _client(tmp_path, max_output_tokens=limit)


def test_strict_mode_never_reads_environment_file(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline mode read an environment file")

    monkeypatch.setattr(type(tmp_path), "read_text", forbidden)
    client = LLMClient(mode="strict", model="gpt-6.1-sol", env_file=tmp_path / "unused.env")
    with pytest.raises(ReplayMiss):
        _complete(client)


def test_real_envelope_sampling_metadata_is_discarded_without_decoding_floats(
    tmp_path, monkeypatch
):
    from corridor.agent.llm import _response_envelope

    raw = (
        b'{"temperature":1.0,"top_p":1e0,"usage":{"input_tokens":30},'
        b'"output":[{"arguments":"{\\"note\\":\\"escaped } \\\\\\" {\\"}"}]}'
    )
    parsed = _response_envelope(raw)
    assert parsed["temperature"] is None and parsed["top_p"] is None
    assert parsed["usage"]["input_tokens"] == 30
    assert "escaped }" in parsed["output"][0]["arguments"]
    _transport(
        monkeypatch,
        mutate=lambda response: response.update(
            temperature=1.0,
            top_p=1.0,
            created_at=1.0,
            completed_at=2.0,
            frequency_penalty=0.0,
            presence_penalty=0.0,
        ),
    )
    assert _complete(_client(tmp_path)).source == "live-recorded"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"usage":{"temperature":1.0}}',
        b'{"usage":{"input_tokens":30.0}}',
        b'{"temperature":1.0,"temperature":1.0}',
        b'{"temperature":01.0}',
        b'{"temperature":1.}',
        b'{"temperature":NaN}',
        b'{"temperature":Infinity}',
        b'{"temperature":1.0e}',
        b'{"nested":[{"top_p":1.0}]}',
        b'{"nested":{"created_at":1.0}}',
        b'{"completed_at":1.0,"completed_at":2.0}',
        b'{"usage":{"frequency_penalty":0.0}}',
        b'{"output":[{"presence_penalty":0.0}]}',
    ],
)
def test_transport_mask_never_relaxes_other_json_numbers(raw):
    from corridor.agent.llm import _response_envelope

    with pytest.raises(ValueError):
        _response_envelope(raw)


def test_transport_mask_leaves_generated_argument_strings_exact():
    from corridor.agent.llm import _response_envelope

    raw = b'{"temperature":1.0,"output":[{"arguments":"{\\"temperature\\":1.5}"}]}'
    arguments = _response_envelope(raw)["output"][0]["arguments"]
    assert arguments == '{"temperature":1.5}'
    with pytest.raises(ValueError):
        loads_exact(arguments)


def test_transport_mask_preserves_penalty_names_inside_generated_arguments():
    from corridor.agent.llm import _response_envelope

    raw = (
        b'{"frequency_penalty":0.0,"presence_penalty":0.0,'
        b'"output":[{"arguments":"{\\"frequency_penalty\\":0.5,\\"presence_penalty\\":0.5}"}]}'
    )
    arguments = _response_envelope(raw)["output"][0]["arguments"]
    assert arguments == '{"frequency_penalty":0.5,"presence_penalty":0.5}'
    with pytest.raises(ValueError):
        loads_exact(arguments)


@pytest.mark.parametrize("known_fields", [True, False])
def test_http_error_diagnostics_only_expose_allowlisted_fields(tmp_path, monkeypatch, known_fields):
    secret = "synthetic-responses-credential"
    failure = {
        "error": {
            "message": f"Authorization: Bearer {secret}",
            "type": "invalid_request_error" if known_fields else secret,
            "code": "invalid_json_schema" if known_fields else secret,
            "param": "tools[0].parameters" if known_fields else secret,
        }
    }
    monkeypatch.setattr(
        httpx.HTTPTransport,
        "handle_request",
        lambda self, request: httpx.Response(400, json=failure),
    )
    client = _client(tmp_path)
    with pytest.raises(LLMOutputError) as caught:
        _complete(client)
    trace = client.calls[-1]
    assert trace["http_status"] == 400
    assert trace["error_type"] == "BadRequestError"
    if known_fields:
        assert trace["provider_error_type"] == "invalid_request_error"
        assert trace["provider_error_code"] == "invalid_json_schema"
        assert trace["provider_error_param"] == "tools[0].parameters"
    else:
        assert not any(name.startswith("provider_error_") for name in trace)
    assert secret not in str(client.calls)
    assert secret not in "".join(traceback.format_exception(caught.value))
    assert not list(tmp_path.rglob("*.json"))
    assert client.api_calls == 1 and client.spent_usd > 0


def test_transport_exception_diagnostics_only_report_known_classes(tmp_path, monkeypatch):
    secret = "synthetic-responses-credential"

    def fail(self, request):
        raise httpx.ConnectError(f"Authorization: Bearer {secret}")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fail)
    client = _client(tmp_path)
    with pytest.raises(LLMOutputError) as caught:
        _complete(client)
    trace = client.calls[-1]
    assert trace["error_type"] == "APIConnectionError"
    assert "ConnectError" in trace["error_cause_types"]
    assert secret not in str(client.calls)
    assert secret not in "".join(traceback.format_exception(caught.value))
    assert "http_status" not in trace


def test_exact_envelope_decoder_failure_has_safe_stage_and_status(tmp_path, monkeypatch):
    _transport(monkeypatch, mutate=lambda response: response.update(extra_number=1.25))
    client = _client(tmp_path)
    with pytest.raises(LLMOutputError):
        _complete(client)
    trace = client.calls[-1]
    assert trace["http_status"] == 200
    assert trace["error_stage"] == "response-envelope"
    assert "ValueError" in trace["error_cause_types"] or trace["error_type"] == "ValueError"
    assert trace["envelope_error_reason"] == "float"
    assert len(trace["envelope_float_paths"]) == 1
    assert trace["envelope_float_paths"][0].startswith("$.field_")
    assert "extra_number" not in str(trace)


def test_envelope_field_paths_do_not_expose_unknown_keys_or_string_values():
    from corridor.agent.llm import _envelope_diagnostics

    raw = (
        b'{"moderation":{"category_scores":{"synthetic-private-key":0.125}},'
        b'"output":[{"content":[{"score":0.75,"text":"secret 1.25"}]}]}'
    )
    diagnostics = _envelope_diagnostics(
        raw, ValueError("JSON floating-point numbers are forbidden: 0.125")
    )
    assert diagnostics["envelope_error_reason"] == "float"
    paths = diagnostics["envelope_float_paths"]
    assert len(paths) == 2
    assert paths[0].startswith("$.moderation.category_scores.field_")
    assert paths[1] == "$.output[*].content[*].score"
    assert all(
        value not in str(diagnostics)
        for value in ("synthetic-private-key", "0.125", "0.75", "secret")
    )


@pytest.mark.parametrize(
    "raw,error,reason",
    [
        (
            b'{"x":1,"x":2}',
            ValueError("Duplicate JSON property: synthetic-secret"),
            "duplicate-key",
        ),
        (b'{"x":1.}', ValueError("Malformed provider JSON envelope"), "json-syntax"),
        (b"", ValueError("Provider response exceeds the transport bound"), "response-too-large"),
    ],
)
def test_envelope_reason_does_not_include_error_message(raw, error, reason):
    from corridor.agent.llm import _envelope_diagnostics

    diagnostics = _envelope_diagnostics(raw, error)
    assert diagnostics["envelope_error_reason"] == reason
    assert "synthetic-secret" not in str(diagnostics)
