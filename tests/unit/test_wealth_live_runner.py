"""The two live smoke tasks share one hard budget and retain honest outcomes."""

from fractions import Fraction
from types import SimpleNamespace

import pytest

from corridor.agent.llm import BudgetExceeded
from scripts import wealth_live_smoke as runner


def _client():
    return SimpleNamespace(
        api_calls=0,
        spent_usd=Fraction(0),
        calls=[],
        model="gpt-6.1-sol",
        api="responses",
        reasoning_effort="low",
        max_calls=30,
        max_usd=Fraction(15),
    )


def test_smokes_share_client_and_refuse_existing_evidence(monkeypatch, tmp_path):
    client = _client()
    seen = []

    def smoke(actual, evidence_dir):
        assert actual is client
        seen.append(actual.api_calls)
        actual.api_calls += 1
        actual.spent_usd += Fraction(1, 100)
        actual.calls.append({"source": "live", "input_tokens": 10, "output_tokens": 2})
        return {"passed": True}

    monkeypatch.setattr(runner, "run_j01", smoke)
    monkeypatch.setattr(runner, "run_w04", smoke)
    result = runner.run_smokes(client, tmp_path / "live")
    assert result["passed"]
    assert result["api_calls"] == 2
    assert result["input_tokens"] == 20
    assert seen == [0, 1]
    with pytest.raises(FileExistsError):
        runner.run_smokes(client, tmp_path / "live")
    assert client.api_calls == 2


def test_budget_failure_stops_and_never_records_exception_text(monkeypatch, tmp_path):
    client = _client()

    def exhausted(actual, evidence_dir):
        raise BudgetExceeded("synthetic-sensitive-sentinel")

    monkeypatch.setattr(runner, "run_j01", exhausted)
    monkeypatch.setattr(runner, "run_w04", lambda *_args, **_kwargs: pytest.fail("second task ran"))
    result = runner.run_smokes(client, tmp_path / "live")
    assert not result["passed"]
    assert result["runs"]["W04"]["status"] == "not_run_budget"
    assert "synthetic-sensitive-sentinel" not in repr(result)
    assert "synthetic-sensitive-sentinel" not in (tmp_path / "live/summary.json").read_text(
        encoding="utf-8"
    )


def test_scripted_timeout_cannot_be_reported_as_live_success(monkeypatch, tmp_path):
    client = _client()

    def fallback(actual, evidence_dir):
        actual.calls.append({"source": "scripted-timeout"})
        actual.api_calls += 1
        return {"passed": True}

    monkeypatch.setattr(runner, "run_j01", fallback)
    monkeypatch.setattr(runner, "run_w04", fallback)
    result = runner.run_smokes(client, tmp_path / "live")
    assert not result["passed"]
    assert all(not row["passed"] for row in result["runs"].values())
