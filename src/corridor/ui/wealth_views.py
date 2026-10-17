"""Bilingual wealth pages backed by signed goals and gateway results."""

from fractions import Fraction
from html import escape

import streamlit as st

from corridor.agent.llm import LLMOutputError, ReplayCorrupt, ReplayMiss
from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.output_guard import project_allocation_fact
from corridor.schemas.money import display_amount
from corridor.ui.components import STATUSES, localized_facts, open_audit, render_result
from corridor.ui.evaluation import ATTACK_CLASSES, run_attack_class
from corridor.ui.messages import display_value, prose, tr
from corridor.ui.product_style import badge, currency, product_label
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

MONEY_FACTS = {
    "total_principal": "Principal",
    "principal": "Principal",
    "total_buy_fees": "Purchase fee",
    "fee_buy": "Purchase fee",
    "fee_hold": "Holding fee",
    "fee_sell": "Redemption fee",
    "total_debit": "Total debit",
    "projected_net": "Net performance benchmark (not guaranteed)",
    "expected_net": "Net performance benchmark (not guaranteed)",
    "liquid_principal": "Net accessible principal",
    "liquid_net_principal": "Net accessible principal",
    "amount": "Amount",
    "balance_after": "Available cash",
    "available_balance": "Available cash",
}


def device_action(controller, method, arguments, result_key):
    try:
        st.session_state[result_key] = getattr(controller, method)(*arguments)
    except (ValueError, RuntimeError, KeyError, OSError):
        st.session_state[result_key] = {
            "status": "rejected",
            "message": tr("The operation was not completed. Review current facts."),
        }


def risk_questionnaire(controller):
    st.subheader(tr("Device risk questionnaire"))
    st.caption(tr("A synthetic questionnaire, not a professional suitability assessment."))
    profile = controller.risk_profile()
    if profile:
        level = profile["level"]
        st.info(
            f"{tr('Signed profile: C')}"
            f"{level}"
            " · "
            f"{display_value(PROFILE_NAMES[level])}"
            f"{tr(' · valid until ')}"
            f"{profile['expires_at']}"
        )
        suitability_status(controller)
        if profile["expires_at"] <= controller.state.now:
            st.warning(
                f"{tr('Your profile expired on ')}"
                f"{profile['expires_at']}"
                f"{tr('; please retake. BIC-RISK')}"
            )
    questions = controller.state.policy.risk_questions
    if any(question not in ANSWER_OPTIONS for question in questions):
        st.error(tr("The current questionnaire needs an approved device presentation."))
        return
    with st.form("wealth_risk_form"):
        answers = []
        columns = st.columns(2)
        for index, question in enumerate(questions):
            options = display_value(ANSWER_OPTIONS[question])
            labels = {None: tr("Choose an answer"), **dict(enumerate(options))}
            answers.append(
                columns[index % 2].selectbox(
                    tr(question),
                    [None, *range(5)],
                    format_func=labels.__getitem__,
                    key=f"wealth_risk_{index}",
                )
            )
        submitted = st.form_submit_button(
            tr("Sign answers on device"), key="wealth_sign_risk", type="primary"
        )
    if submitted:
        if None in answers:
            st.warning(tr("Answer all five questions yourself before signing."))
        else:
            result = controller.submit_risk_answers(answers)
            st.session_state["wealth_risk_result"] = result
            if result["status"] == "settled":
                st.rerun()
    render_result(st.session_state.get("wealth_risk_result"))
    with st.expander(tr("Technical evidence")):
        st.caption(
            tr("Your answers stay on the simulated device and are never sent to the assistant.")
        )
        st.caption(
            tr("Only device-signed questionnaire answers set your level; chat cannot raise it.")
        )


def suitability_status(controller):
    facts = controller.suitability_details
    if not facts or facts.get("effective_level") is None:
        return
    level = facts["effective_level"]
    message = f"{tr('Effective risk level: C')}{level} · {display_value(PROFILE_NAMES[level])}"
    (st.warning if facts.get("clarification") else st.info)(message)
    if facts.get("clarification"):
        st.caption(tr(facts["clarification"]))
    st.caption(tr("Allowed product levels: ") + ", ".join(f"R{n}" for n in range(1, level + 1)))


def dialogue_response(response, controller):
    if not response:
        st.write(tr("Tell me your goals. You will review and sign every financial detail."))
        return
    st.caption(tr("Planner source") + ": " + response.get("planner_source", "scripted"))
    if response.get("guided"):
        st.warning(tr("Guided mode (assistant unavailable). Signed goals are retained for review."))
    st.write(prose(response["message"]))
    facts = localized_facts(response.get("facts", []), controller)
    for fact in facts:
        field = fact["field"]
        if field in MONEY_FACTS:
            st.write(tr(MONEY_FACTS[field]) + ": " + currency(fact["exact_value"]))
        elif field in {"status", "projection_notice", "suitability_clarification"}:
            st.write(fact["text"])
    for fact in response.get("projected_facts", []):
        current = project_allocation_fact(
            fact["source_ref"],
            fact["path"],
            controller.state,
            controller.device.principal,
            controller.gateway.vault,
        )
        field = next((part for part in reversed(current.path) if isinstance(part, str)), "")
        if field in MONEY_FACTS:
            st.write(tr(MONEY_FACTS[field]) + ": " + currency(current.exact_value))
        elif field in {"weight", "risk_level", "access_days", "rank", "sleeve"}:
            st.write(current.text)
        elif field == "product_id":
            st.write(product_label(str(current.exact_value)))
    if response.get("assistant_note"):
        with st.expander(tr("Assistant note (unverified)")):
            st.text(response["assistant_note"])
    if facts or response.get("projected_facts") or response.get("slots"):
        with st.expander(tr("Technical evidence")):
            st.json({"slots": response.get("slots", {}), "facts": facts})
            for fact in response.get("projected_facts", []):
                st.caption(f"{fact['source_ref'].receipt_ref} · {fact['path']}")


def go_to(page):
    st.session_state["page"] = page
    st.session_state["active_page"] = page
    st.session_state["supporting_page"] = "None"


def set_goal_example(text):
    st.session_state["wealth_message"] = text


def context_panel(controller):
    with st.container(border=True):
        context_content(controller)


def context_content(controller):
    st.subheader(tr("Your current context"))
    profile = controller.risk_profile()
    if profile:
        level = (
            controller.suitability_details.get("effective_level")
            if controller.suitability_details
            else profile["level"]
        )
        level = level or profile["level"]
        st.markdown(
            badge(f"C{level} · {tr(PROFILE_NAMES[level])}", "green"), unsafe_allow_html=True
        )
    else:
        st.markdown(badge(tr("Risk profile needed"), "yellow"), unsafe_allow_html=True)
    if controller.signed_goals:
        request = controller.signed_goals.value
        st.caption(tr("Signed goals"))
        st.metric(tr("New principal"), currency(request["amount"]))
        st.write(f"{tr('Investment horizon')}: {request['horizon_days']} {tr('days')}")
        st.write(f"{tr('Accessible principal')}: {currency(request['liquidity_amount'])}")
        st.caption(tr("Goals signed on device. Comparison does not authorize a purchase."))
        with st.expander(tr("Technical evidence")):
            st.json(request)
    else:
        st.info(tr("Your goals are a draft until you confirm them on the device."))
    execution = controller.execution_snapshot()
    if execution and execution["status"] == "completed":
        next_step = tr("Your purchases are complete. Review the verified receipts.")
        destination = "Evidence & Audit"
    elif controller.parent_id:
        next_step = tr("Review each purchase, verify MFA, then approve.")
        destination = "Device"
    elif controller.comparison is not None:
        next_step = tr("Review your proposal and certificate, then select every purchase.")
        destination = "Proposal & Certificate"
    else:
        next_step = tr("Complete your risk profile and confirm your goals on the device.")
        destination = "Device"
    st.caption(tr("Next step"))
    st.write(next_step)
    st.button(
        tr("Continue") + " →",
        key="wealth_continue",
        on_click=go_to,
        args=(destination,),
        use_container_width=True,
    )


def advisor(controller):
    st.header(tr("Wealth Advisor"))
    st.caption(tr("A clear plan, grounded in your goals."))
    left, right = st.columns([3, 2], gap="large")
    with left:
        if st.session_state.get("wealth_last_message"):
            with st.chat_message("user"):
                st.write(st.session_state["wealth_last_message"])
        with st.chat_message("assistant"):
            dialogue_response(controller.dialogue_result, controller)
        st.caption(tr("Try a starting point"))
        examples = st.columns(2)
        for column, key, text in (
            (examples[0], "one_year", "I have 10,000 CNY for one year"),
            (examples[1], "safe", "I want something safe"),
        ):
            column.button(
                tr(text),
                key=f"wealth_example:{key}",
                on_click=set_goal_example,
                args=(text,),
                use_container_width=True,
            )
        with st.form("wealth_advisor"):
            text = st.text_input(
                tr("What would you like to achieve?"),
                placeholder=tr("I want something safe"),
                key="wealth_message",
            )
            submitted = st.form_submit_button(
                tr("Discuss my goals"),
                key="wealth_discuss",
                type="primary",
                use_container_width=True,
            )
        if submitted and text.strip():
            try:
                st.session_state["wealth_dialogue"] = controller.receive_goal(
                    text, request_id=controller._id("wealth-message")
                )
                st.session_state["wealth_last_message"] = text
                st.rerun()
            except (ReplayMiss, ReplayCorrupt):
                st.error(
                    tr(
                        "Strict replay failed. The recording is missing or invalid; "
                        "no model fallback ran."
                    )
                )
            except LLMOutputError:
                st.error(
                    tr("Live AI failed. No scripted fallback ran. Check access, budget and retry.")
                )
            except (ValueError, RuntimeError):
                st.error(tr("The discussion could not be completed. Review your goals on Device."))
        if controller.comparison is not None:
            st.success(tr("Goals signed on device. Your current comparison is ready for review."))
        elif controller.dialogue_result:
            st.caption(
                tr("Pending signed goals: ")
                + ", ".join(
                    tr("slot." + name) for name in controller.dialogue_result["pending_slots"]
                )
            )
    with right:
        context_panel(controller)
    st.divider()
    attack_gallery()


def attack_gallery():
    st.subheader(tr("Try to break it"))
    st.caption(tr("Four isolated security checks. Your account stays untouched."))
    for offset in (0, 2):
        columns = st.columns(2)
        for column, (kind, spec) in zip(
            columns, list(ATTACK_CLASSES.items())[offset : offset + 2], strict=True
        ):
            with column:
                with st.container(border=True):
                    st.markdown("**" + tr(spec["label"]) + "**")
                    short_attempts = {
                        "induced_transfer": "Change the signed recipient",
                        "data_extraction": "Read a file outside the sandbox",
                        "privilege_escalation": "Skip independent MFA",
                        "prompt_injection": "Insert instructions in product text",
                    }
                    st.caption(tr(short_attempts[kind]))
                    if st.button(
                        tr("Run check"), key=f"wealth_attack:{kind}", use_container_width=True
                    ):
                        with st.spinner(tr("Running the actual attack and benign twin...")):
                            st.session_state["wealth_attack_result"] = run_attack_class(kind)
    result = st.session_state.get("wealth_attack_result")
    if not result:
        st.caption(tr("Choose a check to compare a blocked attack with its authorized control."))
        return
    st.markdown("#### " + tr(ATTACK_CLASSES[result["kind"]]["label"]))
    attack, control = st.columns(2)
    with attack:
        with st.container(border=True):
            (st.error if result["passed"] else st.warning)(
                tr("Attack blocked") if result["passed"] else tr("Security check failed")
            )
            st.write(tr(result["reason"]))
            st.caption(tr("Observed rules: ") + " · ".join(result["rule_ids"]))
            movements, funds = st.columns(2)
            movements.metric(tr("Bank movements"), result["bank_dispatches"])
            funds.metric(tr("Funds moved"), currency(result["funds_moved_cny"]))
            st.caption(
                tr("No funds moved")
                if Fraction(result["funds_moved_cny"]) == 0
                else tr("Review the observed effects")
            )
    with control:
        with st.container(border=True):
            (st.success if result["benign_completed"] else st.error)(
                tr("Authorized control completed")
                if result["benign_completed"]
                else tr("Authorized control incomplete")
            )
            st.write(tr("The same legitimate task completes with the required approval."))
            st.metric(tr("Bank movements"), result["benign"]["bank_dispatches"])
            st.caption(
                tr("Evidence mode: scripted · live-recorded: not_run · strict-replay: not_run")
            )
    with st.expander(tr("Technical evidence")):
        st.json({key: value for key, value in result.items() if key != "audit_jsonl"})
        st.download_button(
            tr("Download attack audit"),
            data=result["audit_jsonl"],
            file_name=f"{result['kind']}-audit.jsonl",
            mime="application/x-ndjson",
            key="wealth_attack_audit",
        )


def goal_sheet(controller):
    st.subheader(tr("Confirm goals on device"))
    if controller.candidate is None:
        st.caption(tr("Start a goal discussion in Advisor. No amount or risk level is inferred."))
        return
    st.caption(
        tr(
            "Draft · not signed. Principal and purchase fees are separate. "
            "Synthetic data · simulated device."
        )
    )
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
        left, right = st.columns(2)
        source = left.selectbox(
            tr("Source account"),
            ["A_CURRENT"],
            format_func={"A_CURRENT": tr("Synthetic cash account")}.__getitem__,
            key="wealth_source",
        )
        amount = right.text_input(tr("New principal (CNY)"), key="wealth_amount")
        horizon = left.number_input(tr("Investment horizon (days)"), 1, 365, key="wealth_horizon")
        days = right.number_input(tr("Access needed within (days)"), 0, 365, key="wealth_days")
        liquid = left.text_input(tr("Minimum accessible net principal (CNY)"), key="wealth_liquid")
        types = right.multiselect(
            tr("Allowed product types"),
            ["wealth", "deposit"],
            format_func={value: tr(value) for value in ("wealth", "deposit")}.__getitem__,
            key="wealth_types",
        )
        objective = st.selectbox(
            tr("Ranking objective"),
            ["net_return", "total_fee", "liquidity"],
            format_func={
                "net_return": tr("Performance benchmark (not guaranteed)"),
                "total_fee": tr("Lowest total fees"),
                "liquidity": tr("Earliest access"),
            }.__getitem__,
            key="wealth_objective",
        )
        confirmed = st.form_submit_button(
            tr("Confirm goals"), key="wealth_confirm_goals", type="primary"
        )
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
                "message": tr(
                    "No allocation was constructed. Review your goals, profile and policy."
                ),
            }
        render_result(st.session_state["wealth_comparison"])
    if controller.signed_goals:
        st.success(tr("Goals signed on device. Comparison does not authorize a purchase."))


def execution_summary(execution):
    if execution["status"] == "unknown":
        st.warning(tr("Outcome pending reconciliation - do not retry. Use Lookup on Device."))
    elif execution["status"] == "partially_executed":
        st.warning(tr("Partially executed. Settled holdings remain; remaining work is stopped."))
    elif execution["status"] == "completed":
        st.success(tr("Completed. Every purchase has a verified bank receipt."))
    elif execution["status"] in {"cancelled", "failed"}:
        st.info(tr("Remaining execution stopped. Review the leg status and receipts below."))
    settled = sum(item["status"] == "settled" for item in execution["items"])
    st.caption(f"{tr('Verified purchases')}: {settled} / {len(execution['items'])}")
    rows = []
    for item in execution["items"]:
        status = tr(STATUSES.get(item["status"], item["status"]))
        tone = "green" if item["status"] == "settled" else "yellow"
        rows.append(
            '<div class="cw-timeline-item"><div><strong>'
            + escape(product_label(item["product_ref"]))
            + "</strong><br><small>"
            + escape(tr("Purchase fee") + ": " + currency(item["fee_buy"]))
            + "</small></div><div><strong>"
            + escape(currency(item["principal"]))
            + "</strong><br>"
            + badge(status, tone)
            + "</div></div>"
        )
    st.markdown('<div class="cw-timeline">' + "".join(rows) + "</div>", unsafe_allow_html=True)
    st.metric(tr("Available cash"), currency(execution["available_balance"]))
    with st.expander(tr("Technical evidence")):
        st.json(execution)


def correction_summary(controller):
    """Display only differences authenticated by the existing receipt fact gate."""
    if not controller.wealth_chat or controller.wealth_chat.previous_comparison is None:
        return
    try:
        changes = controller.wealth_chat.change_explanation()
    except ValueError:
        st.warning(tr("The previous comparison could not be verified for a change summary."))
        return
    changed = [fact for fact in changes if Fraction(fact.exact_value)]
    if not changed:
        return
    st.subheader(tr("What changed after your signed correction"))
    st.caption(
        tr(
            "Verified comparison receipts · synthetic data · simulated device signatures. "
            "The earlier proposal and approvals are withdrawn; a new purchase needs fresh approval."
        )
    )
    st.dataframe(
        [
            {
                tr("Product"): product_label(fact.product_id)
                if fact.product_id
                else tr("Allocation total"),
                tr("Fact"): tr(fact.label),
                tr("Before (CNY)"): currency(fact.before),
                tr("After (CNY)"): currency(fact.after),
                tr("Change (CNY)"): currency(fact.exact_value),
            }
            for fact in changed
        ],
        hide_index=True,
        use_container_width=True,
    )
    with st.expander(tr("Sources for the signed correction")):
        for reference in changes[0].source_refs:
            st.caption(f"Verified source: {reference.receipt_ref} · {reference.field}")
        st.caption(tr("Performance benchmark (not guaranteed). Not investment advice."))


def proposal(controller):
    st.header(tr("Proposal & Certificate"))
    if controller.suitability_details and controller.suitability_details.get("clarification"):
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
        st.caption(tr("This retained execution record cannot authorize another purchase."))
        return
    if controller.comparison is None:
        st.info(
            tr(
                "No allocation was constructed. Confirm complete goals and a valid"
                " profile on Device."
            )
        )
        return
    correction_summary(controller)
    request = controller.signed_goals.value
    st.caption(tr("Planner source") + ": " + controller.proposal_source)
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
    st.button(tr("View wealth audit"), key="wealth_audit", on_click=open_audit)
    if execution is None:
        overview = controller.prepare_allocation()
        st.subheader(tr("Choose every leg before starting"))
        st.caption(tr(overview["notice"]))
        selected = []
        for row in overview["items"]:
            label = (
                f"{product_label(row['product_ref'])} · {currency(row['principal'])}"
                f"{tr(' + fee ')}"
                f"{currency(row['fee_buy'])}"
            )
            if st.checkbox(label, key=f"wealth_select:{row['item_ref']}", value=False):
                selected.append(row["item_ref"])
        st.button(
            tr("Start selected allocation"),
            key="wealth_start",
            disabled=len(selected) != len(overview["items"]),
            on_click=device_action,
            args=(controller, "start_allocation", (selected,), "wealth_start_result"),
        )
        result = st.session_state.get("wealth_start_result")
        if result and result.get("status") == "approval_budget":
            st.warning(
                f"{tr('Needs ')}"
                f"{result['needed']}"
                f"{tr(' approvals; ')}"
                f"{result['remaining']}"
                f"{tr(' remain. Window clears at ')}"
                f"{result['window_clears_at']}"
                f"{tr('. No purchases submitted.')}"
            )
        elif result:
            render_result(result)
    else:
        st.info(tr("Open Device to review each leg, verify MFA, and approve."))


def verify_visible_mfa(controller, identifier):
    code = st.session_state.get(f"wealth_mfa_code:{identifier}", "")
    device_action(controller, "verify_leg", (identifier, code), "wealth_leg_result")
    if controller.leg and controller.leg.get("verified"):
        st.session_state.pop(f"wealth_mfa_code:{identifier}", None)


def reject_purchase(controller):
    st.session_state["wealth_leg_result"] = controller.keep_or_handoff()
    for key in list(st.session_state):
        if key.startswith("wealth_mfa_code:"):
            del st.session_state[key]


def allocation_device(controller):
    st.subheader(tr("Allocation approvals"))
    window = controller.approval_window()
    execution = controller.execution_snapshot()
    if window["locked"]:
        st.warning(tr("Safety lock active. New approvals are unavailable."))
    if execution is None:
        st.info(tr("Select all legs in Proposal & Certificate to start."))
        return
    if execution["status"] == "unknown":
        st.warning(tr("Outcome pending reconciliation – do not retry"))
        st.button(
            tr("Lookup pending outcome"),
            key="wealth_lookup",
            on_click=device_action,
            args=(controller, "lookup_pending", (), "wealth_lookup_result"),
        )
    elif execution["status"] == "partially_executed":
        st.warning(
            tr(
                "Partially executed. Settled purchases are retained; "
                "nothing reversed automatically."
            )
        )
    leg = controller.leg
    if leg:
        identifier = leg["action"].action_id
        factor = controller.prepare_leg_mfa(identifier) if not leg["verified"] else None
        with st.container(border=True):
            from corridor.ui.components import render_card

            render_card(leg["card"], planner_source=controller.proposal_source)
            st.caption(tr("Review this purchase. MFA and approval apply only to this purchase."))
            field_key = f"wealth_mfa_code:{identifier}"
            if field_key not in st.session_state:
                st.session_state[field_key] = factor or ""
            st.text_input(
                tr("Independent device MFA"),
                key=field_key,
                type="password",
                disabled=leg["verified"],
                help=tr(
                    "A synthetic device factor is prefilled for this demonstration. "
                    "No code is sent to the assistant."
                ),
            )
            st.button(
                tr("Verify MFA"),
                key=f"wealth_verify:{identifier}",
                disabled=leg["verified"] or factor is None,
                on_click=verify_visible_mfa,
                args=(controller, identifier),
            )
            if leg["verified"]:
                st.success(tr("MFA verified for this purchase"))
            approve, reject = st.columns(2)
            approve.button(
                tr("Approve"),
                key=f"wealth_approve:{identifier}",
                disabled=not leg["verified"],
                type="primary",
                use_container_width=True,
                on_click=device_action,
                args=(controller, "approve_leg", (identifier,), "wealth_leg_result"),
            )
            reject.button(
                tr("Reject"),
                key=f"wealth_reject:{identifier}",
                use_container_width=True,
                on_click=reject_purchase,
                args=(controller,),
            )
    result = st.session_state.get("wealth_leg_result")
    if result and result.get("status") == "rejected":
        st.error(tr("Verification unsuccessful. Review the device factor and current facts."))
    st.subheader(tr("Purchase activity"))
    execution_summary(execution)
    if controller.parent_id and execution["status"] not in {"completed", "unknown"}:
        left, right = st.columns(2)
        if left.button(tr("Keep settled purchases and stop"), key="wealth_keep"):
            reject_purchase(controller)
            st.rerun()
        if right.button(tr("Ask an advisor"), key="wealth_handoff"):
            controller.keep_or_handoff(handoff=True)
            st.rerun()
    with st.expander(tr("Technical evidence")):
        if result:
            render_result(result)
        st.caption("APR-BUDGET preflight · " + tr(execution["approval_budget"]["message"]))
        st.json(window)
        st.caption(
            tr(
                "Stopped or failed plans cannot resume automatically. "
                "New work needs newly signed goals."
            )
        )


def evidence(controller):
    st.markdown('<div id="wealth-audit"></div>', unsafe_allow_html=True)
    st.subheader(tr("Receipts & audit"))
    snapshot = controller.snapshot()
    (st.success if snapshot["audit_valid"] else st.error)(
        tr("✓ chain verified")
        if snapshot["audit_valid"]
        else tr("Wealth audit verification failed")
    )
    parents = [*controller.history, *([controller.parent_id] if controller.parent_id else [])]
    if not parents:
        st.info(tr("Your verified purchase receipts will appear here after approval."))
    for parent in parents:
        execution = controller.execution_snapshot(parent)
        if execution:
            execution_summary(execution)
    with st.expander(tr("Technical evidence")):
        st.caption(tr("Planner source") + ": " + controller.proposal_source)
        st.json({key: snapshot[key] for key in ("audit", "receipts", "dispatch_count")})
