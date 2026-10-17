"""Card UI gestures preserve unsigned previews, state controls and independent MFA."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.ui.controller import DemoController
from tests.e2e.test_demo_ui import app as make_ui
from tests.e2e.test_demo_ui import navigate


def demo_with_card():
    demo = DemoController()
    demo.start_session()
    draft = demo.preview_card_operation("apply_virtual_card", request_id="apply")
    assert demo.approve_pending(draft["pending_id"])["status"] == "settled"
    return demo, next(iter(demo.state.cards))


def finish(demo, draft):
    pending = draft["pending_id"]
    result = demo.approve_pending(pending)
    if result["status"] == "waiting_mfa":
        demo.request_mfa(pending)
        assert demo.complete_mfa(pending)["status"] == "mfa_verified"
        result = demo.approve_pending(pending)
    assert result["status"] == "settled"
    return result


def test_apply_card_preview_unsigned_and_one_confirm_creates_one_synthetic_card():
    demo = DemoController()
    demo.start_session()
    before = H(demo.state)
    draft = demo.preview_card_operation("apply_virtual_card", request_id="apply")
    assert draft["card"]["tier"] == "yellow"
    assert draft["card"]["card_change"]["after"] == {
        "status": "active",
        "limit": "1000/1",
        "restrictions": [],
    }
    assert H(demo.state) == before
    result = finish(demo, draft)
    assert len(demo.state.cards) == 1
    assert demo.approve_pending(draft["pending_id"]) == result
    assert demo.gateway.bank.execute_count == 1
    card = next(iter(demo.state.cards.values()))
    assert card.status == "active"
    assert card.card_token and not card.card_token.isdigit()
    assert demo.snapshot()["cards"][0]["id"] == card.id
    assert demo.gateway.verify_log()


@pytest.mark.parametrize(
    ("kind", "change", "field", "expected"),
    [
        ("freeze_card", None, "status", "frozen"),
        ("lower_card_limit", {"limit": "500.25"}, "limit", Fraction(2001, 4)),
        ("restrict_card", {"restrictions": ["online"]}, "restrictions", ["online"]),
    ],
)
def test_yellow_card_controls_need_one_device_confirmation(kind, change, field, expected):
    demo, ref = demo_with_card()
    before = H(demo.state)
    draft = demo.preview_card_operation(kind, card_ref=ref, change=change, request_id=kind)
    assert draft["card"]["tier"] == "yellow"
    assert H(demo.state) == before
    result = demo.approve_pending(draft["pending_id"])
    assert result["status"] == "settled"
    assert getattr(demo.state.cards[ref], field) == expected
    assert demo.gateway.bank.execute_count == 2
    assert not demo.state.security.mfa_grants


@pytest.mark.parametrize(
    ("kind", "setup", "change", "field", "expected"),
    [
        ("report_card_lost", None, None, "status", "lost"),
        ("restore_card", "report_card_lost", None, "status", "frozen"),
        ("raise_card_limit", None, {"limit": "1500"}, "limit", Fraction(1500)),
        ("unfreeze_card", "freeze_card", None, "status", "active"),
        (
            "relax_card_restriction",
            "restrict_card",
            {"restrictions": []},
            "restrictions",
            [],
        ),
    ],
)
def test_red_card_controls_need_intent_then_independent_mfa(kind, setup, change, field, expected):
    demo, ref = demo_with_card()
    if setup:
        finish(
            demo,
            demo.preview_card_operation(
                setup,
                card_ref=ref,
                change={"restrictions": ["online"]} if setup == "restrict_card" else None,
                request_id="setup",
            ),
        )
    before = H(demo.state.cards)
    inputs = H(demo.state.user_inputs)
    calls = demo.gateway.bank.execute_count
    draft = demo.preview_card_operation(kind, card_ref=ref, change=change, request_id=kind)
    assert draft["card"]["tier"] == "red"
    assert H(demo.state.user_inputs) == inputs
    pending = draft["pending_id"]
    assert demo.request_mfa(pending)["status"] == "intent_confirmation_required"
    assert H(demo.state.user_inputs) == inputs
    assert demo.approve_pending(pending)["status"] == "waiting_mfa"
    assert demo.approve_pending(pending)["status"] == "waiting_mfa"
    assert H(demo.state.cards) == before
    assert demo.gateway.bank.execute_count == calls
    demo.request_mfa(pending)
    assert demo.complete_mfa(pending)["status"] == "mfa_verified"
    assert demo.approve_pending(pending)["status"] == "settled"
    assert getattr(demo.state.cards[ref], field) == expected
    assert demo.gateway.bank.execute_count == calls + 1


def test_card_request_identity_cannot_replace_limit_and_lost_cannot_directly_activate():
    demo, ref = demo_with_card()
    demo.preview_card_operation(
        "lower_card_limit", card_ref=ref, change={"limit": "500"}, request_id="limit"
    )
    with pytest.raises(ValueError, match="Request ID"):
        demo.preview_card_operation(
            "lower_card_limit", card_ref=ref, change={"limit": "600"}, request_id="limit"
        )
    finish(demo, demo.preview_card_operation("report_card_lost", card_ref=ref, request_id="lost"))
    before = H(demo.state.cards)
    draft = demo.preview_card_operation("unfreeze_card", card_ref=ref, request_id="invalid")
    result = demo.approve_pending(draft["pending_id"])
    assert result["status"] == "rejected"
    assert "DOMAIN-STATE" in result["rule_ids"]
    assert H(demo.state.cards) == before


def test_card_page_is_visible_and_apply_freeze_use_real_confirmation():
    page = make_ui()
    page.button(key="enter").click().run()
    navigate(page, "Cards")
    assert not page.exception
    demo = page.session_state["controller"]
    assert not demo.state.cards
    assert not demo.state.user_inputs
    page.button(key="preview_apply_card").click().run()
    assert not page.exception
    assert not demo.state.cards
    page.button(key="approve_card").click().run()
    assert not page.exception
    assert len(demo.state.cards) == 1
    page.run()
    assert demo.gateway.bank.execute_count == 1
    page.selectbox(key="card_operation").select("freeze_card").run()
    page.button(key="preview_card_control").click().run()
    assert next(iter(demo.state.cards.values())).status == "active"
    page.button(key="approve_card").click().run()
    assert not page.exception
    assert next(iter(demo.state.cards.values())).status == "frozen"


def test_red_card_page_enters_device_mfa_and_keeps_card_frozen_until_confirmed():
    page = make_ui()
    page.button(key="enter").click().run()
    demo = page.session_state["controller"]
    finish(demo, demo.preview_card_operation("apply_virtual_card", request_id="apply"))
    ref = next(iter(demo.state.cards))
    finish(demo, demo.preview_card_operation("freeze_card", card_ref=ref, request_id="freeze"))
    navigate(page, "Cards")
    page.selectbox(key="card_operation").select("unfreeze_card").run()
    page.button(key="preview_card_control").click().run()
    pending = page.session_state["card_pending"]["pending_id"]
    navigate(page, "Device")
    assert not any(button.key == f"mfa_request:{pending}" for button in page.button)
    page.button(key=f"approve:{pending}").click().run()
    assert demo.state.cards[ref].status == "frozen"
    page.button(key=f"mfa_request:{pending}").click().run()
    page.button(key=f"mfa_complete:{pending}").click().run()
    page.button(key=f"approve:{pending}").click().run()
    assert not page.exception
    assert demo.state.cards[ref].status == "active"
    assert demo.gateway.verify_log()
    navigate(page, "Cards")
    assert any("Executed" in item.value for item in page.success)
    assert not any("Awaiting MFA" in item.value for item in page.warning)
