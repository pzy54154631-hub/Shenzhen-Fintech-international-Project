"""Switching display language preserves the signed international wealth session."""

from corridor.crypto.jcs import H
from tests.e2e.test_demo_ui import app, navigate
from tests.e2e.test_wealth_ui import prepare_wealth


def test_locale_switch_preserves_signed_goals_and_certificate(monkeypatch):
    monkeypatch.setenv("CORRIDOR_LOCALE", "en")
    page = app()
    controller = prepare_wealth(page)
    goals_hash = H(controller.signed_goals)
    certificate_hash = H(controller.comparison.cert)
    page.selectbox(key="locale").select("zh-CN").run()
    assert not page.exception
    assert page.session_state["page"] == "Proposal & Certificate"
    assert H(controller.signed_goals) == goals_hash
    assert H(controller.comparison.cert) == certificate_hash
    assert controller.gateway.bank.execute_count == 0
    page.selectbox(key="locale").select("en").run()
    assert not page.exception
    assert page.session_state["page"] == "Proposal & Certificate"
    page.button(key="wealth_audit").click().run()
    assert not page.exception
    assert page.session_state["page"] == "Evidence & Audit"
    navigate(page, "Advisor")
    assert H(controller.signed_goals) == goals_hash
