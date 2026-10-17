"""Judge outcomes depend on authenticated values, never presentation language."""

from dataclasses import replace

import pytest

from corridor.agent.llm import LLMClient
from corridor.agent.wealth_dialogue import WealthDialogue
from corridor.bench.transfer_runner import run_j01
from corridor.bench.wealth_dialogue_eval import run_dialogue_task
from corridor.gateway.service import Gateway


@pytest.mark.parametrize("locale", ["zh-CN", "en"])
def test_transfer_judge_uses_receipt_fields_with_arbitrary_display(monkeypatch, locale):
    monkeypatch.setenv("CORRIDOR_LOCALE", locale)
    render = Gateway.render_narrative

    def translated(self, *args, **kwargs):
        result = render(self, *args, **kwargs)
        return result.model_copy(update={"text": "展示 / presentation"})

    monkeypatch.setattr(Gateway, "render_narrative", translated)
    result = run_j01(LLMClient(mode="scripted"))
    assert result["passed"], result
    assert result["transfer_dispatches"] == 1
    assert result["balance"] == "9800/1"


@pytest.mark.parametrize("task", ["W04", "W11"])
def test_wealth_workflow_uses_failure_and_terminal_state_not_messages(monkeypatch, task):
    turn = WealthDialogue.turn

    def translated(self, *args, **kwargs):
        return replace(turn(self, *args, **kwargs), message="展示 / presentation")

    monkeypatch.setattr(WealthDialogue, "turn", translated)
    result = run_dialogue_task(task, LLMClient(mode="scripted"))
    assert result["passed"], result


def test_transfer_judge_rejects_missing_settlement_fact_despite_success_prose(monkeypatch):
    render = Gateway.render_narrative

    def missing_status(self, *args, **kwargs):
        result = render(self, *args, **kwargs)
        return result.model_copy(
            update={
                "text": "Transfer settled",
                "facts": [fact for fact in result.facts if fact.field != "status"],
            }
        )

    monkeypatch.setattr(Gateway, "render_narrative", missing_status)
    result = run_j01(LLMClient(mode="scripted"))
    assert result["passed"] is False
    assert result["transfer_dispatches"] == 1
