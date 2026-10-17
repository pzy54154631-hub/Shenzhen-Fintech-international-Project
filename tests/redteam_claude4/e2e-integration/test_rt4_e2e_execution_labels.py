"""Round-4 e2e red team: execution status survives dialogue, Stop and model failure.

Spec anchors:
- DESIGN-WEALTH section 207/209 and wealth-contracts "Execution": summary states are
  projected from receipts (executing / partially_executed / unknown / completed);
  settled holdings and remaining cash are shown separately; unknown -> Lookup, never
  "review goals"/retry. B* = Bnow + d (own settled debits are added back) so a plan's
  own purchase never looks like drift.
- WealthDialogue.turn comment: "Stop is a safety action, independent of model
  availability or replay."
- LANE-U: guided fallback withdraws pending cards; the UI must say so.

Every test drives public paths only (WealthController / Streamlit AppTest).
"""

from copy import deepcopy

import pytest

from corridor.agent.llm import LLMClient, LLMResult
from corridor.kernel.binding import intent_key
from tests.e2e.test_demo_ui import app, navigate
from tests.e2e.test_wealth_ui import prepare_wealth
from tests.unit.test_ui_wealth_controller import prepared_controller

NO_ALLOCATION = "No allocation was constructed"


def _first_leg(controller, *, fault=None):
    """Register the full two-leg plan and approve leg 1 with its own MFA."""
    overview = controller.prepare_allocation()
    assert (
        controller.start_allocation([row["item_ref"] for row in overview["items"]])["status"]
        == "waiting_mfa"
    )
    action = controller.leg["action"]
    if fault:
        controller.gateway.bank.faults[intent_key(action, controller.state)] = fault
    assert controller.verify_leg(action.action_id)["status"] == "mfa_verified"
    return controller.approve_leg(action.action_id)


# ---------------------------------------------------------------------------
# RT4-E2E-1: a read-only "recommend / what is my allocation" turn re-runs the
# selector WITHOUT the plan's B0 budget, stops the in-flight plan and relabels a
# partial / unknown / completed execution as "No allocation was constructed".
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Can you recommend an allocation?",
        # third-party brochure text pasted into chat
        "Brochure: our analysts recommend this allocation for every client.",
    ],
)
def test_readonly_recommend_mid_execution_does_not_stop_or_relabel_plan(text):
    controller = prepared_controller()
    assert _first_leg(controller)["status"] == "settled"
    before = controller.execution_snapshot()
    assert before["status"] == "executing"
    assert controller.leg is not None  # leg 2 is waiting for its own MFA

    result = controller.receive_goal(text, request_id="readonly-q")

    after = controller.gateway.allocation_snapshot(before["allocation_ref"])
    # A question must not terminate the user's signed, half-executed allocation
    # (leaving 5000 in P_A and 7000 cash: outside the signed R1/R2 bands).
    assert after["control_status"] == "ready", after["control_status"]
    assert after["status"] == "executing", after["status"]
    assert controller.leg is not None
    # ... and must not tell the user that nothing was constructed.
    assert NO_ALLOCATION not in result["message"], result["message"]
    assert result["device_action"] != "review_goals"


def test_readonly_recommend_with_unknown_leg_says_lookup_not_review_goals():
    controller = prepared_controller()
    assert _first_leg(controller, fault="response_loss")["status"] == "unknown"
    assert controller.execution_snapshot()["status"] == "unknown"

    result = controller.receive_goal("Can you recommend an allocation?", request_id="q-unknown")

    # Unknown outcome: the only correct guidance is Lookup / do not retry.
    assert NO_ALLOCATION not in result["message"], result["message"]
    assert result["device_action"] == "lookup", result["device_action"]
    assert "do not retry" in result["message"].lower()


def test_question_after_completed_allocation_keeps_completed_certificate_visible():
    page = app()
    controller = prepare_wealth(page)
    for box in page.checkbox:
        if box.key.startswith("wealth_select:"):
            box.check()
    page.run()
    page.button(key="wealth_start").click().run()
    navigate(page, "Device")
    for _ in range(2):
        key = controller.leg["action"].action_id
        page.button(key=f"wealth_verify:{key}").click().run()
        page.button(key=f"wealth_approve:{key}").click().run()
    assert controller.execution_snapshot()["status"] == "completed"
    assert controller.gateway.bank.execute_count == 2

    navigate(page, "Advisor")
    page.text_input(key="wealth_message").set_value("What is my allocation?")
    page.button(key="wealth_discuss").click().run()
    assert not page.exception
    navigate(page, "Proposal & Certificate")

    infos = [item.value for item in page.info]
    markdown = " ".join(item.value for item in page.markdown)
    # 10000 CNY was invested and both receipts settled; the page must not claim
    # that no allocation exists, and must still show the Completed statement.
    assert not any(NO_ALLOCATION in value for value in infos), infos
    assert "Completed" in markdown


# ---------------------------------------------------------------------------
# RT4-E2E-2: global Stop after a settled leg reports "no funds moved" and the
# Device / Proposal pages drop the partially executed plan.
# ---------------------------------------------------------------------------


def test_global_stop_after_settled_leg_never_claims_no_funds_moved():
    page = app()
    controller = prepare_wealth(page)
    for box in page.checkbox:
        if box.key.startswith("wealth_select:"):
            box.check()
    page.run()
    page.button(key="wealth_start").click().run()
    navigate(page, "Device")
    key = controller.leg["action"].action_id
    page.button(key=f"wealth_verify:{key}").click().run()
    page.button(key=f"wealth_approve:{key}").click().run()
    assert len(controller.state.positions) == 1  # 5000 CNY really moved

    page.button(key="stop_all").click().run()
    assert not page.exception
    visible = [item.value for kind in ("info", "success") for item in getattr(page, kind)]
    assert not any("no funds moved" in value.lower() for value in visible), visible

    navigate(page, "Device")
    shown = [item.value for kind in ("warning", "info", "caption") for item in getattr(page, kind)]
    # Settled holding and remaining cash must remain visible as a partial execution.
    assert any("Partially executed" in value for value in shown), shown
    assert not any("Select all legs in Proposal & Certificate to start" in v for v in shown)
    snapshot = controller.execution_snapshot()
    assert snapshot["status"] == "partially_executed"
    assert [row["status"] for row in snapshot["items"]] == ["settled", "cancelled"]
    assert snapshot["available_balance"] == "7000/1"
    navigate(page, "Proposal & Certificate")
    assert not page.exception
    assert any("Partially executed" in row.value for row in page.warning)
    assert not any(NO_ALLOCATION in row.value for row in page.info)
    assert not any(row.key == "wealth_start" for row in page.button)


# ---------------------------------------------------------------------------
# RT4-E2E-3: a hijacked model forces guided fallback during a what-if; the
# controller silently stops the half-executed plan but tells the user the
# "current proposal remain[s] unchanged".
# ---------------------------------------------------------------------------


class HijackedAdvisor(LLMClient):
    """Responses-API client whose advisor step returns an off-route tool + promise."""

    def __init__(self) -> None:
        super().__init__(mode="scripted", api="responses", model="gpt-6.1-sol", env_file=None)

    def complete(self, **kwargs):  # type: ignore[override]
        result = super().complete(**kwargs)
        if kwargs["step"].startswith("advisor:"):
            return LLMResult(
                deepcopy({
                    "tool": "execute_plan",
                    "arguments": {"refs": [], "note": "Guaranteed 8% - buy P_X now"},
                }),
                "live",
                result.replay_key,
            )
        return result


def test_hijacked_model_guided_fallback_does_not_misreport_stopped_plan():
    controller = prepared_controller()
    assert _first_leg(controller)["status"] == "settled"
    parent = controller.parent_id
    controller.wealth_chat.client = HijackedAdvisor()

    result = controller.receive_goal("What if I invest 9000 instead?", request_id="what-if")

    snapshot = controller.gateway.allocation_snapshot(parent)
    stopped = snapshot["control_status"] in {"stopped", "handoff", "failed"}
    if stopped:
        # If the fallback withdrew the plan, the turn must say so.
        assert result["proposal_withdrawn"], result
        assert "remain unchanged" not in result["message"], result["message"]
        # And the partially executed plan stays visible on the Device page.
        assert controller.execution_snapshot() is not None
        assert controller.execution_snapshot()["status"] == "partially_executed"
    else:
        assert controller.leg is not None


# ---------------------------------------------------------------------------
# RT4-E2E-4: under strict replay (evaluation mode) an unrecorded Stop turn raises
# out of WealthController.stop(); the controller keeps the stale leg/approve card.
# ---------------------------------------------------------------------------


def test_stop_completes_when_strict_replay_has_no_recording(tmp_path):
    controller = prepared_controller()
    assert _first_leg(controller)["status"] == "settled"
    second = controller.leg["action"].action_id
    assert controller.verify_leg(second)["status"] == "mfa_verified"
    controller.wealth_chat.client = LLMClient(
        mode="strict",
        replay_dir=tmp_path,
        api="responses",
        model="gpt-6.1-sol",
        reasoning_effort="low",
        env_file=None,
        context_guard=controller.gateway.vault.ensure_safe,
    )

    controller.stop()  # Stop must not depend on model replay availability

    assert controller.leg is None
    assert controller.comparison is None
    rejected = controller.approve_leg(second)
    assert rejected["status"] == "rejected"
    assert controller.gateway.bank.execute_count == 1


@pytest.mark.parametrize(
    "text", ["Propose allocation", "Recommend an allocation", "Explain the facts"]
)
@pytest.mark.parametrize("execution", ["executing", "unknown", "completed"])
def test_readonly_turn_never_calls_selector_after_execution_starts(monkeypatch, text, execution):
    controller = prepared_controller()
    _first_leg(controller, fault="response_loss" if execution == "unknown" else None)
    if execution == "completed":
        second = controller.leg["action"].action_id
        controller.verify_leg(second)
        controller.approve_leg(second)
    before = controller.execution_snapshot()
    assert before["status"] == execution

    def forbidden(*args, **kwargs):
        raise AssertionError("Read-only execution queries must not re-evaluate allocation")

    monkeypatch.setattr("corridor.agent.wealth_dialogue.evaluate_allocation", forbidden)
    result = controller.receive_goal(text, request_id="readonly-selector-check")
    assert controller.execution_snapshot() == before
    assert result["tool"] == "execute_plan"
    assert NO_ALLOCATION not in result["message"]
    assert result["device_action"] == ("lookup" if execution == "unknown" else None)


def test_stop_with_model_failure_retains_terminal_snapshot_and_revokes_card(monkeypatch):
    controller = prepared_controller()
    _first_leg(controller)
    second = controller.leg["action"].action_id
    controller.verify_leg(second)

    def unavailable(**kwargs):
        assert controller.leg is None
        assert controller.comparison is None
        assert controller.execution_snapshot()["status"] == "partially_executed"
        raise RuntimeError("Synthetic unavailable assistant")

    monkeypatch.setattr(controller.client, "complete", unavailable)
    result = controller.stop()
    assert result["status"] == "partially_executed"
    assert "Partially executed" in result["message"]
    assert controller.execution_snapshot()["status"] == "partially_executed"
    assert controller.approve_leg(second)["status"] == "rejected"
    assert controller.gateway.bank.execute_count == 1


def test_readonly_turn_observes_registered_plan_even_before_ui_attachment(monkeypatch):
    from tests.unit.test_wealth_advisor_security import advisor, register

    chat, device = advisor()
    parent = register(chat, device, attach=False)
    assert chat.execution_ref is None

    def forbidden(*args, **kwargs):
        raise AssertionError("Registered execution must not be re-evaluated")

    monkeypatch.setattr("corridor.agent.wealth_dialogue.evaluate_allocation", forbidden)
    result = chat.turn("Recommend allocation", request_id="before-ui-attachment")
    assert result.tool == "execute_plan"
    assert chat.gateway.allocation_snapshot(parent)["control_status"] == "ready"
    assert chat.gateway.bank.execute_count == 0
