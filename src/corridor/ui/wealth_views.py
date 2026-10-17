"""English wealth pages backed by signed goals and gateway results."""

from fractions import Fraction

import streamlit as st

from corridor.agent.llm import ReplayCorrupt, ReplayMiss
from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.money import display_amount
from corridor.ui.components import open_audit, render_result
from corridor.ui.evaluation import ATTACK_CLASSES, run_attack_class
from corridor.ui.wealth_statement import render_biac

PROFILE_NAMES = {1: "Conservative", 2: "Cautious", 3: "Balanced", 4: "Growth", 5: "Aggressive"}
ANSWER_OPTIONS = {
    "Investment experience": (
        "None",
        "Savings only",
        "Simple funds",
        "Several product types",
        "Complex products",
    ),
    "Loss tolerance": (
        "None",
        "A small loss",
        "A moderate loss",
        "A substantial loss",
        "A large loss",
    ),
    "Income stability": ("No stable income", "Variable", "Mostly stable", "Stable", "Very stable"),
    "Liquidity needs": (
        "Immediate access",
        "Frequent access",
        "Occasional access",
        "Rare access",
        "No near-term need",
    ),
    "Investment horizon": ("Immediate", "Short term", "Medium term", "Long term", "Very long term"),
}


def device_action(controller, method, arguments, result_key):
    try:
        st.session_state[result_key] = getattr(controller, method)(*arguments)
    except (ValueError, RuntimeError, KeyError, OSError):
        st.session_state[result_key] = {
            "status": "rejected",
            "message": "The operation was not completed. Review current facts.",
        }


def risk_questionnaire(controller):
    st.subheader("Device risk questionnaire")
    st.caption("Your answers stay on the simulated device and are never sent to the assistant.")
    profile = controller.risk_profile()
    if profile:
        level = profile["level"]
        st.info(
            f"Signed profile: C{level} · {PROFILE_NAMES[level]} · "
            f"valid until {profile['expires_at']}"
        )
        suitability_status(controller)
        if profile["expires_at"] <= controller.state.now:
            st.warning(f"Your profile expired on {profile['expires_at']}; please retake. BIC-RISK")
    else:
        st.info("Complete the questionnaire before a suitability comparison can be constructed.")
    st.caption("A synthetic questionnaire, not a professional suitability assessment.")
    st.caption("Only device-signed questionnaire answers set your level; chat cannot raise it.")
    questions = controller.state.policy.risk_questions
    if any(question not in ANSWER_OPTIONS for question in questions):
        st.error("The current questionnaire needs an approved device presentation.")
        return
    with st.form("wealth_risk_form"):
        answers = [
            st.selectbox(
                question,
                [None, *range(5)],
                format_func=lambda value, options=options: (
                    "Choose an answer" if value is None else options[value]
                ),
                key=f"wealth_risk_{index}",
            )
            for index, question in enumerate(questions)
            for options in [ANSWER_OPTIONS[question]]
        ]
        submitted = st.form_submit_button("Sign answers on device", key="wealth_sign_risk")
    if submitted:
        if None in answers:
            st.warning("Answer all five questions yourself before signing.")
        else:
            result = controller.submit_risk_answers(answers)
            st.session_state["wealth_risk_result"] = result
            if result["status"] == "settled":
                st.rerun()
    render_result(st.session_state.get("wealth_risk_result"))


def suitability_status(controller):
    facts = controller.suitability_details
    if not facts or facts.get("effective_level") is None:
        return
    level = facts["effective_level"]
    message = f"Effective risk level: C{level} · {PROFILE_NAMES[level]}"
    (st.warning if facts.get("clarification") else st.info)(message)
    if facts.get("clarification"):
        st.caption(facts["clarification"])
    st.caption("Allowed product levels: " + ", ".join(f"R{n}" for n in range(1, level + 1)))


def dialogue_response(response):
    if not response:
        return
    if response.get("guided"):
        st.warning("Guided mode (assistant unavailable). Signed goals are retained for review.")
    st.info(response["message"])
    for name, slot in response.get("slots", {}).items():
        st.caption(f"{name.replace('_', ' ').capitalize()}: {slot['value']} · {slot['source']}")
    for fact in response.get("facts", []):
        st.write(fact["text"])
        st.caption(f"Verified source: {fact['receipt_ref']} · {fact['field']}")
    for fact in response.get("projected_facts", []):
        st.write(fact["text"])
        st.caption(f"Verified projection: {fact['source_ref'].receipt_ref} · {fact['path']}")
    if response.get("assistant_note"):
        st.caption("Assistant · unverified")
        st.text(response["assistant_note"])
    action = response.get("device_action")
    routes = {
        "confirm_goals": "Open Device to review and sign your goals.",
        "risk_questionnaire": "Open Device to complete or clarify your own risk questionnaire.",
        "select_allocation_items": "Open Proposal & Certificate to select the allocation legs.",
        "lookup": "Open Device and use Lookup. Do not repeat the purchase.",
        "review_goals": "Open Device to review your goals before signing a correction.",
        "edit_allocation": (
            "Review the certificate and ask an advisor about a new signed adjustment."
        ),
        "advisor": "Advisor review requested. Remaining work is stopped.",
    }
    if action in routes:
        st.caption(routes[action])


def advisor(controller):
    st.header("Wealth Advisor")
    st.write("Compare the declared catalogue against your signed goals and risk profile.")
    st.caption("Evidence mode: scripted · live-recorded: not_run · strict-replay: not_run")
    with st.form("wealth_advisor"):
        text = st.text_input(
            "What would you like to achieve?",
            placeholder="I want something safe",
            key="wealth_message",
        )
        submitted = st.form_submit_button("Discuss my goals", key="wealth_discuss")
    if submitted and text.strip():
        try:
            st.session_state["wealth_dialogue"] = controller.receive_goal(
                text, request_id=controller._id("wealth-message")
            )
        except (ReplayMiss, ReplayCorrupt):
            st.error(
                "Strict replay failed. The recording is missing or invalid; no model fallback ran."
            )
        except (ValueError, RuntimeError):
            st.error("The discussion could not be completed. Review your goals on Device.")
    response = controller.dialogue_result
    dialogue_response(response)
    suitability_status(controller)
    if controller.comparison is not None:
        st.success("Goals signed on device. Your current comparison is ready for review.")
        st.info(
            "Open Proposal & Certificate to review your allocation and its status. "
            "Open Device for any remaining approvals."
        )
    else:
        if response:
            st.caption("Pending signed goals: " + ", ".join(response["pending_slots"]))
        st.info("Open Device to complete your questionnaire and confirm goals.")
    st.subheader("Try to break it")
    st.caption(
        "Scripted security demonstrations on isolated synthetic accounts. Live attacks: not_run."
    )
    columns = st.columns(2)
    for index, (kind, spec) in enumerate(ATTACK_CLASSES.items()):
        if columns[index % 2].button(
            spec["label"], key=f"wealth_attack:{kind}", use_container_width=True
        ):
            with st.spinner("Running the actual attack and benign twin..."):
                st.session_state["wealth_attack_result"] = run_attack_class(kind)
    result = st.session_state.get("wealth_attack_result")
    if result:
        (st.success if result["passed"] else st.error)(
            "Blocked · " + result["violation_summary"]
            if result["passed"]
            else "Security check failed"
        )
        st.write("Attempt: " + result["attempt"])
        st.write(result["reason"])
        st.caption("Observed rules: " + " · ".join(result["rule_ids"]))
        st.write(f"Funds moved: CNY {display_amount(Fraction(result['funds_moved_cny']))}")
        st.caption(
            f"Benign twin completed: {result['benign_completed']} · "
            f"evidence: {result['evidence_mode']}"
        )
        with st.expander("Attack audit records"):
            st.json(result["audit_entries"])
            st.json(result["audit_checkpoint"])
        st.download_button(
            "Download attack audit",
            data=result["audit_jsonl"],
            file_name=f"{result['kind']}-audit.jsonl",
            mime="application/x-ndjson",
            key="wealth_attack_audit",
        )


def goal_sheet(controller):
    st.subheader("Confirm goals on device")
    if controller.candidate is None:
        st.caption("Start a goal discussion in Advisor. No amount or risk level is inferred.")
        return
    st.caption("Draft · not signed. Principal and purchase fees are separate.")
    slots = {name: slot.value for name, slot in controller.wealth_chat.slots.items()}
    defaults = {
        "wealth_source": slots.get("source_account_ref", "A_CURRENT"),
        "wealth_amount": display_amount(Fraction(slots["amount"])) if "amount" in slots else "",
        "wealth_horizon": slots.get("horizon_days", 365),
        "wealth_days": slots.get("liquidity_days", 3),
        "wealth_liquid": display_amount(Fraction(slots["liquidity_amount"]))
        if "liquidity_amount" in slots
        else "",
        "wealth_types": slots.get("allowed_types", ["wealth"]),
        "wealth_objective": slots.get("objective", "net_return"),
    }
    fingerprint = H({"intent": controller.wealth_chat.intent_id, "slots": slots})
    changed = st.session_state.get("wealth_goal_defaults") != fingerprint
    for key, value in defaults.items():
        if changed or key not in st.session_state:
            st.session_state[key] = value
    st.session_state["wealth_goal_defaults"] = fingerprint
    with st.form("wealth_goals"):
        source = st.selectbox("Source account", ["A_CURRENT"], key="wealth_source")
        amount = st.text_input("New principal (CNY)", key="wealth_amount")
        horizon = st.number_input("Investment horizon (days)", 1, 365, key="wealth_horizon")
        days = st.number_input("Access needed within (days)", 0, 365, key="wealth_days")
        liquid = st.text_input("Minimum accessible net principal (CNY)", key="wealth_liquid")
        types = st.multiselect("Allowed product types", ["wealth", "deposit"], key="wealth_types")
        objective = st.selectbox(
            "Ranking objective",
            ["net_return", "total_fee", "liquidity"],
            format_func=lambda value: {
                "net_return": "Performance benchmark (not guaranteed)",
                "total_fee": "Lowest total fees",
                "liquidity": "Earliest access",
            }[value],
            key="wealth_objective",
        )
        confirmed = st.form_submit_button("Confirm goals", key="wealth_confirm_goals")
    if confirmed:
        try:
            result = controller.confirm_goals({
                "source_account_ref": source,
                "amount": amount,
                "horizon_days": horizon,
                "liquidity_days": days,
                "liquidity_amount": liquid,
                "allowed_types": types,
                "objective": objective,
            })
            st.session_state["wealth_comparison"] = result
        except (ValueError, RuntimeError):
            st.session_state["wealth_comparison"] = {
                "status": "rejected",
                "message": "No allocation was constructed. Review your goals, profile and policy.",
            }
        render_result(st.session_state["wealth_comparison"])
    if controller.signed_goals:
        st.success("Goals signed on device. Comparison does not authorize a purchase.")


def execution_summary(execution):
    if execution["status"] == "unknown":
        st.warning("Outcome pending reconciliation - do not retry. Use Lookup on Device.")
    elif execution["status"] == "partially_executed":
        st.warning("Partially executed. Settled holdings remain; remaining work is stopped.")
    elif execution["status"] == "completed":
        st.success("Completed. Every purchase has a verified bank receipt.")
    elif execution["status"] in {"cancelled", "failed"}:
        st.info("Remaining execution stopped. Review the leg status and receipts below.")
    st.caption("Settled holdings and remaining legs · gateway execution facts")
    st.dataframe(
        [
            {
                "Product": item["product_ref"],
                "Principal (CNY)": display_amount(Fraction(item["principal"])),
                "Purchase fee (CNY)": display_amount(Fraction(item["fee_buy"])),
                "Status": item["status"],
                "Receipt": item["receipt_ref"] or "No settlement receipt",
            }
            for item in execution["items"]
        ],
        hide_index=True,
    )
    st.write("Available cash (CNY): " + display_amount(Fraction(execution["available_balance"])))


def proposal(controller):
    st.header("Proposal & Certificate")
    suitability_status(controller)
    if (
        controller.parent_id is None
        and controller.comparison is not None
        and not controller.comparison_is_current()
    ):
        controller.withdraw_proposal()
    execution = controller.execution_snapshot()
    if controller.comparison is None and execution is not None:
        execution_summary(execution)
        st.caption("This retained execution record cannot authorize another purchase.")
        return
    if controller.comparison is None:
        st.info(
            "No allocation was constructed. Confirm complete goals and a valid profile on Device."
        )
        return
    if execution is None:
        st.success("Comparison complete – no purchase executed")
    request = controller.signed_goals.value
    render_biac(
        controller.comparison.cert.allocation,
        request,
        controller.state.allocation_policies[request["allocation_policy_ref"]],
        controller.risk_profile(),
        execution=execution,
        audit_href="#wealth-audit",
        audit_jsonl=b"".join(jcs_bytes(row) + b"\n" for row in controller.gateway.audit.records()),
        suitability=controller.comparison.result.analysis_receipt.parameters.get("suitability"),
    )
    st.markdown('<div id="wealth-audit"></div>', unsafe_allow_html=True)
    st.button("View wealth audit", key="wealth_audit", on_click=open_audit)
    if execution is None:
        overview = controller.prepare_allocation()
        st.subheader("Choose every leg before starting")
        st.caption(overview["notice"])
        selected = []
        for row in overview["items"]:
            label = (
                f"{row['product_ref']} · CNY {display_amount(Fraction(row['principal']))} "
                f"+ fee {display_amount(Fraction(row['fee_buy']))}"
            )
            if st.checkbox(label, key=f"wealth_select:{row['item_ref']}", value=False):
                selected.append(row["item_ref"])
        st.button(
            "Start selected allocation",
            key="wealth_start",
            disabled=len(selected) != len(overview["items"]),
            on_click=device_action,
            args=(controller, "start_allocation", (selected,), "wealth_start_result"),
        )
        result = st.session_state.get("wealth_start_result")
        if result and result.get("status") == "approval_budget":
            st.warning(
                f"Needs {result['needed']} approvals; {result['remaining']} remain. "
                f"Window clears at {result['window_clears_at']}. No purchases submitted."
            )
        elif result:
            render_result(result)
    else:
        st.info("Open Device to review each leg, verify MFA, and approve.")


def allocation_device(controller):
    window = controller.approval_window()
    st.subheader("Allocation approvals")
    percent = min(100, window["used"] * 100 // window["limit"])
    st.progress(
        percent,
        text=f"Approval window: {window['used']} / {window['limit']} requests · "
        f"{window['remaining']} further requests before lock",
    )
    if window["next_release_at"]:
        st.caption(
            f"Next approval released at {window['next_release_at']}; "
            f"window clears at {window['window_clears_at']}."
        )
    else:
        st.caption("No earlier approvals are expiring in the current window.")
    st.caption("The threshold request triggers the safety lock.")
    if window["locked"]:
        st.warning("Safety lock active. New approvals are unavailable.")
    execution = controller.execution_snapshot()
    if execution is None:
        st.caption("Select all legs in Proposal & Certificate to start.")
        return
    execution_summary(execution)
    st.caption(execution["approval_budget"]["message"])
    if execution["status"] == "unknown":
        st.warning("Outcome pending reconciliation – do not retry")
        st.button(
            "Lookup pending outcome",
            key="wealth_lookup",
            on_click=device_action,
            args=(controller, "lookup_pending", (), "wealth_lookup_result"),
        )
    elif execution["status"] == "partially_executed":
        st.warning(
            "Partially executed. Settled purchases are retained; nothing reversed automatically."
        )
    elif execution["status"] == "completed":
        st.success("Allocation completed. Every purchase has a verified bank receipt.")
    leg = controller.leg
    if leg:
        action = leg["action"]
        item = execution["next_leg"]
        st.markdown(f"### Leg {item['leg_index']} of {item['leg_count']} · {item['product_ref']}")
        st.write(
            f"CNY {display_amount(Fraction(item['principal']))} + fee "
            f"{display_amount(Fraction(item['fee_buy']))}"
        )
        st.caption("Verify MFA → Approve · separate device grant for this leg")
        from corridor.ui.components import render_card

        with st.expander("Canonical approval facts", expanded=False):
            render_card(leg["card"])
        identifier = action.action_id
        st.button(
            "Verify MFA",
            key=f"wealth_verify:{identifier}",
            disabled=leg["verified"],
            on_click=device_action,
            args=(controller, "verify_leg", (identifier,), "wealth_leg_result"),
        )
        st.button(
            "Approve",
            key=f"wealth_approve:{identifier}",
            disabled=not leg["verified"],
            type="primary",
            on_click=device_action,
            args=(controller, "approve_leg", (identifier,), "wealth_leg_result"),
        )
    if st.session_state.get("wealth_leg_result"):
        st.caption("Latest device action result · the receipt identifies the approved leg")
        render_result(st.session_state["wealth_leg_result"])
    if controller.parent_id and execution["status"] not in {"completed", "unknown"}:
        left, right = st.columns(2)
        if left.button("Keep settled purchases and stop", key="wealth_keep"):
            controller.keep_or_handoff()
            st.rerun()
        if right.button("Ask an advisor", key="wealth_handoff"):
            controller.keep_or_handoff(handoff=True)
            st.rerun()
    st.caption(
        "Stopped or failed plans cannot resume automatically. New work needs newly signed goals."
    )
    with st.expander("Leg receipts and audit checkpoint"):
        st.json(execution)


def evidence(controller):
    st.markdown('<div id="wealth-audit"></div>', unsafe_allow_html=True)
    st.subheader("Wealth evidence & audit")
    snapshot = controller.snapshot()
    st.caption("scripted · live-recorded: not_run · strict-replay: not_run")
    (st.success if snapshot["audit_valid"] else st.error)(
        "Wealth audit chain verified"
        if snapshot["audit_valid"]
        else "Wealth audit verification failed"
    )
    st.write(f"Simulated bank dispatches: {snapshot['dispatch_count']}")
    for parent in [*controller.history, *([controller.parent_id] if controller.parent_id else [])]:
        st.json(controller.execution_snapshot(parent))
    st.json({key: snapshot[key] for key in ("audit", "receipts")})
    st.caption(
        "W suite: not_run in this UI session. J results below are separate supporting-bank tests."
    )
