"""Hosted live credentials stay private and spending is bounded across sessions."""

import logging
import os
import traceback
from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction

import httpx
import pytest

from corridor.agent.llm import BudgetExceeded, LLMOutputError
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact
from corridor.ui.live_runtime import DailyBudget, LiveConfig, LiveRateLimited, LiveSession


def _config(**changes):
    return LiveConfig.from_sources(
        {
            "LLM_API_KEY": "synthetic-server-credential",
            "LIVE_ACCESS_CODE": "synthetic-code",
            **changes,
        },
        environ={},
    )


def _session(tmp_path, **changes):
    session = LiveSession(_config(**changes), journal_dir=tmp_path, monotonic=lambda: 100)
    assert session.authorize("synthetic-code") == "accepted"
    return session


def _request(client):
    return client.complete(
        task_id="LIVE-TEST",
        step="planner",
        prompt={"instruction": "Choose a supplied handle."},
        tool_state={"handles": ["CONTACT_A"]},
        scripted=lambda: {"contact_ref": "CONTACT_A"},
    )


def _transport(monkeypatch, *, secret=None, fail=False):
    sends = []

    def send(self, request):
        sends.append(str(request.url))
        if secret:
            logging.getLogger("openai").error("Provider echoed %s", secret)
        if fail:
            raise RuntimeError(f"Provider failure {secret}")
        body = loads_exact(request.content)
        return httpx.Response(
            200,
            json={
                "id": "resp_synthetic",
                "model": body["model"],
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": '{"contact_ref":"CONTACT_A"}'}],
                    }
                ],
                "usage": {"input_tokens": 20, "output_tokens": 5, "total_tokens": 25},
            },
        )

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", send)
    return sends


def test_no_credentials_and_wrong_access_are_disabled(tmp_path):
    empty = LiveSession(LiveConfig.from_sources({}, environ={}), journal_dir=tmp_path)
    assert not empty.available
    assert empty.snapshot()["reason"] == "missing_credentials"
    session = LiveSession(_config(), journal_dir=tmp_path, monotonic=lambda: 100)
    assert not session.available
    assert session.authorize("wrong") == "invalid"
    assert session.authorize("synthetic-code") == "throttled"
    assert not session.available


def test_access_rotation_revokes_existing_authorization(tmp_path):
    session = _session(tmp_path)
    assert session.available
    session.refresh_config(_config(LIVE_ACCESS_CODE="new-code"))
    assert not session.available
    session.refresh_config(_config(LLM_API_KEY=""))
    assert not session.available


def test_session_call_cap_and_rate_limit_are_checked_before_transport(tmp_path, monkeypatch):
    sends = _transport(monkeypatch)
    tick = [100]
    session = LiveSession(
        _config(LIVE_SESSION_CALLS="2"), journal_dir=tmp_path, monotonic=lambda: tick[0]
    )
    session.authorize("synthetic-code")
    client = session.client()
    assert _request(client).source == "live"
    with pytest.raises(LiveRateLimited):
        _request(client)
    assert len(sends) == 1
    tick[0] += 2
    _request(client)
    assert session.snapshot()["calls_remaining"] == 0
    assert session.snapshot()["exhausted"]
    with pytest.raises(BudgetExceeded):
        _request(client)
    assert len(sends) == 2


def test_daily_journal_reserves_atomically_and_keeps_unknown_cost(tmp_path):
    budgets = [DailyBudget(tmp_path, Fraction(1), day=lambda: "2026-10-17") for _ in range(8)]

    def reserve(budget):
        try:
            return budget.reserve(Fraction(1, 2))
        except BudgetExceeded:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        tickets = list(pool.map(reserve, budgets))
    assert len([ticket for ticket in tickets if ticket is not None]) == 2
    assert budgets[0].remaining() == 0
    ticket = next(ticket for ticket in tickets if ticket is not None)
    ticket(Fraction(1, 4))
    assert budgets[1].remaining() == Fraction(1, 4)
    ticket(Fraction(0))
    assert budgets[1].remaining() == Fraction(1, 4)


def test_byok_never_inherits_server_endpoint_or_persists_credentials(tmp_path, monkeypatch, caplog):
    secret = "synthetic-byok-credential-not-for-persistence"
    before = dict(os.environ)
    sends = _transport(monkeypatch, secret=secret)
    session = LiveSession(
        _config(LLM_API_BASE="http://127.0.0.1:11434/v1", LIVE_DAILY_USD="0"), journal_dir=tmp_path
    )
    session.set_byok(secret)
    assert session.available
    assert _request(session.client()).source == "live"
    assert sends == ["https://api.openai.com/v1/responses"]
    assert session.snapshot()["source"] == "byok"
    assert session.snapshot()["calls_remaining"] is None
    assert dict(os.environ) == before
    assert secret not in caplog.text
    assert secret not in jcs_bytes(session.client().calls).decode("utf-8")
    assert secret not in repr(session.config)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes()
    assert not list(tmp_path.rglob("*.json"))
    session.set_byok("")
    assert not session.available


def test_live_failure_is_sanitized_without_scripted_fallback(tmp_path, monkeypatch, caplog):
    secret = "synthetic-private-failure-credential"
    _transport(monkeypatch, secret=secret, fail=True)
    session = LiveSession(LiveConfig.from_sources({}, environ={}), journal_dir=tmp_path)
    session.set_byok(secret)
    with pytest.raises(LLMOutputError) as error:
        _request(session.client())
    assert secret not in "".join(traceback.format_exception(error.value))
    assert secret not in caplog.text
    assert session.client().calls[-1]["source"] == "live-error"


def test_shared_daily_exhaustion_disables_new_server_session(tmp_path, monkeypatch):
    _transport(monkeypatch, fail=True)
    session = _session(tmp_path, LIVE_DAILY_USD="1/1000")
    with pytest.raises(BudgetExceeded):
        _request(session.client())
    assert session.snapshot()["exhausted"]
    assert session.snapshot()["calls_used"] == 0


def test_only_server_client_uses_explicit_loopback_base(tmp_path, monkeypatch):
    sends = _transport(monkeypatch)
    session = _session(tmp_path, LLM_API_BASE="http://127.0.0.1:11434/v1")
    _request(session.client())
    assert sends == ["http://127.0.0.1:11434/v1/responses"]


def test_daily_rollover_retains_previous_day_reservations(tmp_path):
    day = ["2026-10-17"]
    budget = DailyBudget(tmp_path, Fraction(1), day=lambda: day[0])
    settle = budget.reserve(Fraction(1))
    assert budget.remaining() == 0
    day[0] = "2026-10-18"
    assert budget.remaining() == 1
    settle(Fraction(1, 4))
    assert budget.remaining() == 1
    day[0] = "2026-10-17"
    assert budget.remaining() == Fraction(3, 4)


def test_revoked_clients_cannot_spend_after_credential_removal(tmp_path, monkeypatch):
    sends = _transport(monkeypatch)
    session = _session(tmp_path)
    server = session.client()
    session.refresh_config(_config(LLM_API_KEY=""))
    session.set_byok("synthetic-owned-key")
    with pytest.raises(BudgetExceeded):
        _request(server)
    byok = session.client()
    session.set_byok("")
    with pytest.raises(BudgetExceeded):
        _request(byok)
    assert sends == []


def test_server_failure_retains_reservation_for_other_sessions(tmp_path, monkeypatch):
    _transport(monkeypatch, fail=True)
    first = _session(tmp_path)
    with pytest.raises(LLMOutputError):
        _request(first.client())
    spent = first.client().spent_usd
    assert spent > 0
    second = _session(tmp_path)
    assert Fraction(second.snapshot()["daily_remaining_usd"]) == 5 - spent
    assert first.snapshot()["calls_used"] == 1


def test_budget_journal_failure_closes_server_access_but_not_byok(tmp_path):
    tmp_path.joinpath("live-budget.sqlite3").write_bytes(b"corrupted journal")
    session = _session(tmp_path)
    assert not session.available
    session.set_byok("synthetic-owned-key")
    assert session.available


def test_operational_controls_do_not_read_dotenv_or_global_llm_limits(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text("LLM_API_KEY=private-dotenv-secret\n", encoding="utf-8")
    monkeypatch.setenv("LLM_MAX_CALLS", "0")
    monkeypatch.setenv("LLM_MAX_USD", "0")
    session = LiveSession(LiveConfig.from_sources({}, environ={}), journal_dir=tmp_path / "budget")
    assert not session.available
    session.set_byok("synthetic-owned-key")
    assert session.client().max_calls > 40


def test_exact_key_in_prompt_rejected_before_observers_or_transport(tmp_path, monkeypatch):
    sends = _transport(monkeypatch)
    session = _session(tmp_path)
    client = session.client()
    observed = []
    client.observers.append(lambda stage, value: observed.append(value))
    with pytest.raises(ValueError, match="PII-CTX"):
        client.complete(
            task_id="UI",
            step="planner",
            prompt={"note": session.config.api_key},
            tool_state={},
            scripted=lambda: {},
        )
    assert not observed and not sends


def test_access_verification_uses_constant_time_comparison(tmp_path, monkeypatch):
    import hmac

    compare = hmac.compare_digest
    comparisons = []

    def observe(left, right):
        comparisons.append((type(left), type(right)))
        return compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", observe)
    session = _session(tmp_path)
    assert session.available and comparisons == [(bytes, bytes)]
