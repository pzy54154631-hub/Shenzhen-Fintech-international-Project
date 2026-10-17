"""M4 validation remains bounded, provenance-honest and offline in strict mode."""

import builtins
import os

import httpx
import pytest

from corridor.agent import wealth_guard_validation
from corridor.agent.llm import LLMResult, ReplayMiss
from corridor.agent.wealth_guard_validation import GUARANTEE_PROMPTS, run_guarantee_checks
from corridor.crypto.jcs import jcs_bytes
from corridor.gateway.output_guard import _APPROVED_PROSE, GuardedProse, guard_prose
from corridor.schemas.base import loads_exact
from tests.unit.test_wealth_validation import _client


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("LLM_"):
            monkeypatch.delenv(name)


@pytest.mark.parametrize("locale", ["en", "zh-CN"])
def test_ten_bilingual_scripted_checks_use_guard_and_share_the_client(
    tmp_path, monkeypatch, locale
):
    monkeypatch.setenv("CORRIDOR_LOCALE", locale)
    client = _client(tmp_path)
    rows = run_guarantee_checks(client)
    assert len(rows) == len(GUARANTEE_PROMPTS) == len(client.calls) == 10
    assert all(row["passed"] and row["sources"] == ["scripted"] for row in rows)
    assert all(row["guard_status"] == "rewritten" for row in rows)
    assert client.api_calls == 0
    assert {row["language"] for row in rows} == {"en", "zh"}
    assert all(row["rendered_note"].isascii() for row in rows)


@pytest.mark.parametrize("locale", ["en", "zh-CN"])
def test_guarantee_check_rejects_accepted_object_with_unapproved_prose(
    tmp_path, monkeypatch, locale
):
    monkeypatch.setenv("CORRIDOR_LOCALE", locale)
    unapproved = "This product is the perfect choice for everyone."
    assert unapproved not in _APPROVED_PROSE
    seen_locales = []

    def forged_accepted(note, *args, **kwargs):
        if note in {case.scripted_note for case in GUARANTEE_PROMPTS}:
            seen_locales.append(kwargs.get("locale"))
            return GuardedProse(unapproved, "accepted")
        return guard_prose(note, *args, **kwargs)

    monkeypatch.setattr(wealth_guard_validation, "guard_prose", forged_accepted)
    rows = run_guarantee_checks(_client(tmp_path))
    assert len(rows) == 10
    assert all(row["status"] == "failed" and not row["passed"] for row in rows)
    assert all(row["guard_status"] == "accepted" for row in rows)
    assert seen_locales == ["en"] * 10


def test_mock_record_and_strict_replay_are_ten_requests_not_live_evidence(tmp_path, monkeypatch):
    sends = []

    def send(self, request):
        body = loads_exact(request.content)
        sends.append(body)
        return httpx.Response(
            200,
            json={
                "status": "completed",
                "output": [
                    {
                        "type": "function_call",
                        "name": "emit_result",
                        "arguments": jcs_bytes({"note": "CNY 9,999 is guaranteed."}).decode(
                            "utf-8"
                        ),
                        "call_id": "synthetic_guard",
                    }
                ],
                "usage": {"input_tokens": 10, "output_tokens": 8, "total_tokens": 18},
            },
        )

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", send)
    client = _client(tmp_path, "record")
    rows = run_guarantee_checks(client)
    assert len(sends) == client.api_calls == 10
    assert all(row["passed"] and row["sources"] == ["live-recorded"] for row in rows)
    assert all("unsupported_promise" in row["guard_reasons"] for row in rows)
    assert all("unverified_number" in row["guard_reasons"] for row in rows)
    assert all("9,999" not in row["rendered_note"] for row in rows)
    original = builtins.__import__

    def offline(name, *args, **kwargs):
        if name.split(".")[0] in {"openai", "httpx", "litellm"}:
            pytest.fail("Strict guard validation imported a provider")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", offline)
    replayed = run_guarantee_checks(_client(tmp_path, "strict"))
    assert len(sends) == 10
    assert all(row["passed"] and row["sources"] == ["strict-replay"] for row in replayed)
    assert [row["replay_key"] for row in rows] == [row["replay_key"] for row in replayed]


def test_strict_miss_is_fatal_with_no_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", lambda *_: pytest.fail("network"))
    with pytest.raises(ReplayMiss):
        run_guarantee_checks(_client(tmp_path, "strict"))


def test_record_mode_never_accepts_a_scripted_result_as_live(tmp_path):
    client = _client(tmp_path, "record")
    client.complete = lambda **_: LLMResult({"note": ""}, "scripted", "synthetic")
    rows = run_guarantee_checks(client)
    assert len(rows) == 10 and all(not row["passed"] for row in rows)
    assert all(row["sources"] == ["not_run"] for row in rows)


def test_errors_are_sanitized_and_budget_stops_remaining_calls(tmp_path, monkeypatch):
    attempts = []

    def failure(self, request):
        attempts.append(request)
        raise httpx.ConnectError("private-output-guard-sentinel")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", failure)
    rows = run_guarantee_checks(_client(tmp_path, "record", max_calls=1))
    assert len(attempts) == 1 and len(rows) == 10
    assert all(not row["passed"] for row in rows)
    assert "private-output-guard-sentinel" not in str(rows)
    assert sum(row["status"] == "not_run_budget" for row in rows) == 9
