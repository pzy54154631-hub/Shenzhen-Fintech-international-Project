"""Session-local planner controls for the hosted Streamlit application."""

from fractions import Fraction

import streamlit as st

from corridor.agent.llm import BudgetExceeded, LLMClient, LLMConfigurationError
from corridor.schemas.money import display_amount
from corridor.ui.live_runtime import LiveConfig, LiveSession
from corridor.ui.messages import tr


def reset_demo():
    """Discard synthetic state while retaining access and request counters."""
    retained = {
        name: st.session_state[name]
        for name in ("locale", "live_session")
        if name in st.session_state
    }
    for name in list(st.session_state):
        del st.session_state[name]
    st.session_state.update(retained)


def render_live_controls(controller):
    try:
        secrets = st.secrets.to_dict()
    except (FileNotFoundError, RuntimeError):
        secrets = {}
    try:
        config = LiveConfig.from_sources(secrets=secrets)
    except LLMConfigurationError:
        st.error(tr("Live AI configuration is unavailable. Demo mode remains available."))
        config = LiveConfig.from_sources({}, environ={})
    if "live_session" not in st.session_state:
        st.session_state["live_session"] = LiveSession(config)
    live = st.session_state["live_session"]
    live.update_config(config)
    boundary = controller.at_transaction_boundary()
    with st.expander(tr("Live AI access"), expanded=False):
        st.caption(tr("Use the judges' access code or your own OpenAI API key."))
        with st.form("live_access", clear_on_submit=True):
            code = st.text_input(
                tr("Access code"), type="password", key="live_access_code", max_chars=256
            )
            if st.form_submit_button(
                tr("Unlock server AI"), key="live_unlock", disabled=not boundary
            ):
                status = live.authorize(code)
                if status == "accepted":
                    st.success(tr("Live access unlocked for this session."))
                else:
                    st.warning(tr("Access denied or temporarily rate limited. Try again later."))
        with st.form("live_byok", clear_on_submit=True):
            key = st.text_input(
                tr("Your OpenAI API key"), type="password", key="live_byok_key", max_chars=1024
            )
            if st.form_submit_button(tr("Use my key"), key="live_use_key", disabled=not boundary):
                live.set_byok(key)
        st.caption(tr("Your key stays in this session's memory and is never recorded."))
        if st.button(tr("Forget my key"), key="live_forget_key", disabled=not boundary):
            live.set_byok("")
    info = live.snapshot()
    if boundary and st.session_state.get("live_mode") and not info["available"]:
        st.session_state["live_mode"] = False
        st.session_state["live_boundary_notice"] = True
    left, right = st.columns([5, 1])
    with left:
        enabled = st.toggle(
            tr("Real AI"), key="live_mode", disabled=not info["available"] or not boundary
        )
    with right:
        st.button(tr("Reset demo"), key="reset_demo", on_click=reset_demo)
    if enabled and info["available"] and boundary:
        try:
            client = live.make_client(context_guard=controller.gateway.vault.ensure_safe)
        except (BudgetExceeded, LLMConfigurationError):
            st.error(
                tr("Live AI failed. No scripted fallback ran. Check access, budget and retry.")
            )
            st.stop()
        if client is not controller.client:
            controller.set_client(client)
    elif not enabled and controller.client.mode == "live" and boundary:
        controller.set_client(
            LLMClient(
                mode="scripted",
                env_file=None,
                environment={},
                context_guard=controller.gateway.vault.ensure_safe,
            )
        )
    status = [tr("Planner source") + ": " + controller.planner_source]
    if not enabled:
        status = [tr("Demo mode · scripted · no API calls")]
    if info["reason"] == "budget_exhausted":
        status.append(tr("The server live budget is exhausted for this session or UTC day."))
    elif not info["available"]:
        status.append(
            tr("Live AI requires a configured server key and valid access code, or your key.")
        )
    if not boundary:
        status.append(tr("Planner mode is locked until this transaction completes or is stopped."))
    if st.session_state.pop("live_boundary_notice", False):
        st.warning(
            tr("Live access or budget ended. Demo mode resumed at the transaction boundary.")
        )
    if info.get("source") == "byok":
        status.append(tr("BYOK · charged to your OpenAI account; server budget is not used."))
    elif info.get("source") == "server" and config.api_key:
        status.append(
            tr(
                "Server budget remaining: {usd} USD · session calls remaining: {calls}",
                usd=display_amount(Fraction(info["daily_remaining_usd"])),
                calls=info["calls_remaining"],
            )
        )
    st.caption(" · ".join(status))
    return live
