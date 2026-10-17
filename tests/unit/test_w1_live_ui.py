"""Live UI keeps planner provenance and never substitutes a scripted turn."""

import httpx
import pytest

from corridor.agent.llm import LLMClient, LLMOutputError
from corridor.crypto.jcs import jcs_bytes
from corridor.schemas.base import loads_exact
from corridor.ui.live_runtime import LiveConfig, LiveSession
from corridor.ui.wealth_controller import WealthController
from tests.e2e.test_demo_ui import app


def test_unconfigured_live_is_disabled_and_demo_is_default(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LIVE_ACCESS_CODE", raising=False)
    page = app()
    assert not page.exception
    assert page.toggle(key="live_mode").disabled
    assert not page.toggle(key="live_mode").value
    assert page.session_state["wealth_controller"].client.mode == "scripted"


def test_live_error_does_not_create_a_scripted_response(monkeypatch):
    controller = WealthController()
    client = LLMClient(mode="scripted", env_file=None)
    client.mode = "live"
    client.model = "test-model"
    controller.set_client(client)
    controller.start_session()

    def fail(**kwargs):
        raise RuntimeError("synthetic provider failure")

    monkeypatch.setattr(client, "complete", fail)
    with pytest.raises(LLMOutputError, match="Live"):
        controller.receive_goal("I want something safe", request_id="live-failure")
    assert controller.client.mode == "live"
    assert controller.wealth_chat.mode == "assistant"
    assert controller.dialogue_result is None
    assert controller.gateway.bank.execute_count == 0


def test_mode_cannot_change_after_signed_comparison():
    from tests.e2e.test_wealth_ui import prepare_wealth

    page = app()
    controller = prepare_wealth(page)
    assert not controller.at_transaction_boundary()
    assert page.toggle(key="live_mode").disabled
    with pytest.raises(ValueError, match="transaction"):
        controller.set_client(LLMClient(mode="scripted", env_file=None))


def test_reset_replaces_financial_state_but_keeps_abuse_counters():
    page = app()
    original = page.session_state["wealth_controller"]
    live = page.session_state["live_session"]
    page.button(key="enter").click().run()
    from corridor.stores.bank import add_seconds

    original.advance_clock(add_seconds(original.state.now, 60))
    page.button(key="reset_demo").click().run()
    assert not page.exception
    assert page.session_state["wealth_controller"] is not original
    assert page.session_state["live_session"] is live
    assert page.session_state["wealth_controller"].state.now != original.state.now
    assert page.button(key="enter")


def test_complete_byok_flow_never_records_fake_key(tmp_path, monkeypatch, caplog, capsys):
    from tests.unit.test_w1_session_isolation import GOALS

    fake_key = "synthetic-byok-full-workflow-private-credential"
    requests = []

    def send(self, request):
        body = loads_exact(request.content)
        state = loads_exact(body["input"][1]["content"])["tool_state"]
        requests.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "id": "resp_synthetic",
                "model": body["model"],
                "status": "completed",
                "output": [
                    {
                        "type": "function_call",
                        "name": state["required_tool"],
                        "call_id": "call_synthetic",
                        "arguments": jcs_bytes({
                            "refs": state["permitted_refs"],
                            "note": "",
                        }).decode(),
                    }
                ],
                "usage": {"input_tokens": 20, "output_tokens": 5, "total_tokens": 25},
            },
        )

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", send)
    live = LiveSession(LiveConfig.from_sources({}, environ={}), journal_dir=tmp_path / "budget")
    live.set_byok(fake_key)
    controller = WealthController(evidence_dir=tmp_path / "evidence")
    controller.set_client(live.make_client(context_guard=controller.gateway.vault.ensure_safe))
    controller.start_session()
    controller.submit_risk_answers([1] * 5)
    controller.receive_goal("I want something safe", request_id="byok-full")
    assert controller.confirm_goals(GOALS)["status"] == "comparison_only"
    overview = controller.prepare_allocation()
    controller.start_allocation([item["item_ref"] for item in overview["items"]])
    for _ in range(2):
        action_id = controller.leg["action"].action_id
        assert controller.verify_leg(action_id)["status"] == "mfa_verified"
        assert controller.approve_leg(action_id)["status"] == "settled"
    assert controller.execution_snapshot()["status"] == "completed"
    assert controller.gateway.verify_log()
    assert len(requests) == 2
    assert all(url == "https://api.openai.com/v1/responses" for url in requests)
    assert controller.proposal_source == "live: gpt-6.1-sol"
    captured = capsys.readouterr()
    (tmp_path / "captured.log").write_text(
        caplog.text + captured.out + captured.err, encoding="utf-8"
    )
    (tmp_path / "audit.jsonl").write_bytes(
        b"".join(jcs_bytes(row) + b"\n" for row in controller.gateway.audit.records())
    )
    (tmp_path / "calls.json").write_bytes(jcs_bytes(controller.client.calls))
    assert list((tmp_path / "evidence").glob("*.json"))
    assert not (tmp_path / "budget").exists()
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert fake_key.encode() not in path.read_bytes(), path.name


def test_chat_retry_after_live_proposal_failure_preserves_live_card_provenance(monkeypatch):
    from corridor.agent.llm import LLMResult
    from tests.unit.test_w1_session_isolation import GOALS

    controller = WealthController()
    client = LLMClient(mode="scripted", env_file=None)
    client.mode, client.model = "live", "test-model"
    controller.set_client(client)
    controller.start_session()
    controller.submit_risk_answers([1] * 5)
    attempts = []

    def complete(**kwargs):
        attempts.append(kwargs)
        if len(attempts) == 2:
            raise RuntimeError("Synthetic transient failure")
        state = kwargs["tool_state"]
        return LLMResult(
            {
                "tool": state["required_tool"],
                "arguments": {"refs": state["permitted_refs"], "note": ""},
            },
            "live",
            "synthetic-key",
        )

    monkeypatch.setattr(client, "complete", complete)
    controller.receive_goal("I want something safe", request_id="first")
    assert controller.confirm_goals(GOALS)["status"] == "rejected"
    assert not controller.at_transaction_boundary()
    with pytest.raises(ValueError, match="transaction"):
        controller.set_client(LLMClient(mode="scripted", env_file=None))
    controller.receive_goal("Propose allocation", request_id="retry")
    assert controller.comparison is not None
    assert controller.proposal_source == "live: test-model"


def test_live_client_setup_failure_blocks_the_page_without_scripted_work(monkeypatch, tmp_path):
    from corridor.agent.llm import BudgetExceeded

    monkeypatch.setenv("LLM_API_KEY", "synthetic-server-credential")
    monkeypatch.setenv("LIVE_ACCESS_CODE", "synthetic-code")
    monkeypatch.setenv("LIVE_JOURNAL_DIR", str(tmp_path))

    def unavailable(*args, **kwargs):
        raise BudgetExceeded("Another session consumed the remaining budget")

    monkeypatch.setattr(LiveSession, "make_client", unavailable)
    page = app()
    page.text_input(key="live_access_code").set_value("synthetic-code")
    page.button(key="live_unlock").click().run()
    page.toggle(key="live_mode").set_value(True).run()
    assert not page.exception
    assert page.error
    assert not page.chat_message
    assert page.session_state["wealth_controller"].gateway.bank.execute_count == 0
