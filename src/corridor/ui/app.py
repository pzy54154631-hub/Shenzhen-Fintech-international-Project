"""Topic B entry point with bilingual display and explicit device gestures."""

import os
from collections.abc import Callable
from html import escape
from typing import Any

import streamlit as st

from corridor.bench.adversary import development_cases
from corridor.crypto.jcs import H
from corridor.i18n import get_locale, set_locale
from corridor.sim.keys import stable_id
from corridor.ui import wealth_views
from corridor.ui.components import (
    KINDS,
    STYLES,
    fact_rows,
    render_bic,
    render_card,
    render_fact_projection,
    render_plans,
    render_result,
)
from corridor.ui.controller import DemoController
from corridor.ui.evaluation import run_hijacked_case, run_judge_task
from corridor.ui.live_controls import render_live_controls
from corridor.ui.messages import tr
from corridor.ui.structured_transfer import render_structured_transfer
from corridor.ui.wealth_controller import WealthController
from corridor.ui.wealth_statement import EXCLUSIONS

PAGES = (
    "Advisor",
    "Proposal & Certificate",
    "Device",
    "Evidence & Audit",
)
SUPPORTING_PAGES = (
    "None",
    "Transfers",
    "Bills & Balance",
    "Subscriptions",
    "Cards",
    "Product comparison",
    "Task Plans",
    "Human Handoff",
)


def request_id(kind: str, payload: Any = None) -> str:
    """A rerun reuses a request; an explicit new draft advances its sequence."""
    key = f"request:{kind}:{H(payload)}"
    if key not in st.session_state:
        sequence = st.session_state.get("request_sequence", 0)
        st.session_state[key] = stable_id("UI-DEMO", sequence, kind)
        st.session_state["request_sequence"] = sequence + 1
    return st.session_state[key]


def perform(call: Callable[[], dict[str, Any]], key: str = "last_result") -> dict[str, Any] | None:
    try:
        result = call()
    except (ValueError, RuntimeError, KeyError):
        st.error(
            tr("The operation could not complete. Review the current facts and inputs, then retry.")
        )
        return None
    st.session_state[key] = result
    return result


def pending_rows(controller: DemoController) -> list[dict[str, Any]]:
    snapshot = controller.snapshot()
    rows = snapshot.get("pending", snapshot.get("pending_actions", []))
    rows = list(rows.values()) if isinstance(rows, dict) else rows
    return [row for row in rows if not row.get("completed")]


def approve_saved(controller: DemoController, pending_key: str, result_key: str) -> None:
    pending = st.session_state[pending_key]
    result = perform(lambda: controller.approve_pending(pending["pending_id"]), result_key)
    if result and result.get("replacement"):
        st.session_state[pending_key] = result["replacement"]


def approve_device(controller: DemoController, identifier: str) -> None:
    result = perform(lambda: controller.approve_pending(identifier), f"approved:{identifier}")
    st.session_state["device_redisplay"] = bool(result and result.get("status") == "redisplay")


def stop_all(controller: DemoController) -> None:
    bank_result = perform(controller.stop, "stop_result")
    wealth = st.session_state.get("wealth_controller")
    if wealth is not None:
        wealth_result = perform(wealth.stop, "wealth_stop_result")
        if wealth_result and wealth_result.get("execution"):
            st.session_state["stop_result"] = {
                "status": "interrupted",
                "message": wealth_result["message"],
                "bank_result": bank_result,
                "wealth_result": wealth_result,
            }
    retired = {
        "transfer_draft",
        "subscription_pending",
        "subscription_cancel",
        "investment_pending",
        "redemption_pending",
        "birthday_draft",
        "compensation_pending",
        "transfer_changed",
        "card_pending",
        "card_result",
        "structured_transfer_pending",
        "structured_transfer_result",
        "structured_transfer_request",
        "wealth_start_result",
        "wealth_leg_result",
        "wealth_comparison",
    }
    for key in list(st.session_state):
        if key in retired or key.startswith(("request:", "mfa:", "mfa_result:")):
            del st.session_state[key]


def conversation(controller: DemoController) -> None:
    st.markdown(tr("## Describe a transfer, then confirm it on your device"))
    st.caption(
        tr("For example: transfer CNY 200 to Chen. Review the facts before authorizing payment.")
    )
    with st.form("transfer_form"):
        text = st.text_input(
            tr("What would you like to do?"),
            placeholder=tr("Transfer CNY 200 to Chen"),
            key="transfer_text",
        )
        submitted = st.form_submit_button(
            tr("Prepare transfer draft"), key="preview_transfer", type="primary"
        )
    if submitted and text.strip():
        perform(
            lambda: controller.preview_transfer(text, request_id=request_id("transfer", text)),
            "transfer_draft",
        )
        st.session_state.pop("transfer_result", None)
        st.session_state.pop("displayed_contact", None)
    draft = st.session_state.get("transfer_draft")
    if draft:
        contacts = draft.get("contacts", [])
        selection = None
        if draft.get("status") == "clarify" and not contacts:
            st.warning(tr("transfer_no_match"))
        elif draft.get("status") == "clarify" or len(contacts) > 1:
            st.warning(
                tr(
                    "More than one contact matches. Select the recipient on your devic"
                    "e before authorization."
                )
            )
            options = {
                str(item.get("id", item.get("contact_ref"))): str(item.get("label", item.get("id")))
                for item in contacts
                if isinstance(item, dict)
            }
            if not options:
                options = {str(item): str(item) for item in contacts}
            selection = st.selectbox(
                tr("Select the recipient"),
                [None, *options],
                format_func=lambda value: (
                    tr("Choose a contact") if value is None else options[value]
                ),
                key="contact_selection",
            )
            if st.button(
                tr("Show the selected recipient's canonical card"),
                key="show_selected_contact",
                disabled=selection is None,
            ):
                refreshed = perform(
                    lambda: controller.select_contact(draft["draft_id"], selection),
                    "transfer_draft",
                )
                if refreshed and refreshed.get("card"):
                    st.session_state["displayed_contact"] = selection
                    st.rerun()
        card = draft.get("card", {})
        if card:
            render_card(card, canonical=bool(draft.get("canonical", False)))
        elif draft.get("message"):
            st.info(draft["message"])
        confirmed = st.session_state.get("transfer_result")
        if not confirmed and draft.get("draft_id"):
            can_confirm = bool(card) and (
                len(contacts) <= 1 or selection == st.session_state.get("displayed_contact")
            )
            if st.button(
                tr("Confirm on device and execute"),
                key="confirm_transfer",
                type="primary",
                disabled=not can_confirm,
            ):
                result = perform(
                    lambda: controller.confirm_transfer(
                        draft["draft_id"],
                        request_id=request_id("confirm-transfer", draft["draft_id"]),
                    ),
                    "transfer_result",
                )
                if result and result.get("status") == "redisplay" and result.get("card"):
                    st.session_state["transfer_draft"] = {**draft, **result}
                    st.session_state.pop("transfer_result", None)
                    st.session_state["transfer_changed"] = True
                    st.rerun()
                if result and result.get("status") != "redisplay":
                    st.session_state.pop("transfer_changed", None)
        if st.session_state.get("transfer_changed"):
            st.warning(
                tr("The canonical facts changed. Review the new card before confirming again.")
            )
        render_result(st.session_state.get("transfer_result"))
        if st.session_state.get("transfer_result") and st.button(
            tr("Start another transfer"), key="new_transfer"
        ):
            for key in list(st.session_state):
                if key.startswith("request:transfer:") or key in {
                    "transfer_draft",
                    "transfer_result",
                }:
                    del st.session_state[key]
            st.rerun()
    with st.expander(tr("Assistant note (unverified)"), expanded=False):
        st.write(
            tr(
                "The assistant helps prepare your request. Recipient, amount, appr"
                "oval tier and outcome come from canonical device facts and verifi"
                "ed bank receipts."
            )
        )


def billing(controller: DemoController) -> None:
    st.markdown(tr("## Bills and verifiable balances"))
    st.caption(
        tr(
            "Balances, categories, totals and alerts come from trusted records"
            ". Green-tier queries need no payment approval."
        )
    )
    left, right = st.columns(2)
    with left:
        if st.button(tr("Check balance"), key="query_balance", use_container_width=True):
            perform(controller.query_balance, "balance_result")
    with right:
        if st.button(
            tr("Create sample September bill"), key="bill_report", use_container_width=True
        ):
            perform(controller.bill_report, "bill_result")
    for key in ("balance_result", "bill_result"):
        result = st.session_state.get(key)
        if result:
            render_result(result)
            if result.get("facts"):
                render_fact_projection(result["facts"], controller)


def subscriptions(controller: DemoController) -> None:
    st.markdown(tr("## Subscriptions"))
    st.info(
        tr(
            "Subscription queries and renewal reminders require yellow-tier ap"
            "proval. Confirm before viewing subscriptions. Cancellation does n"
            "ot refund settled charges."
        )
    )
    if st.button(
        tr("Prepare subscription query approval"), key="preview_subscriptions", type="primary"
    ):
        perform(
            lambda: controller.preview_subscriptions(request_id=request_id("subscriptions")),
            "subscription_pending",
        )
    pending = st.session_state.get("subscription_pending")
    if pending and pending.get("card"):
        render_card(pending["card"])
        st.button(
            tr("Confirm subscription query on device"),
            key="approve_subscriptions",
            on_click=approve_saved,
            args=(controller, "subscription_pending", "subscription_result"),
        )
    result = st.session_state.get("subscription_result")
    render_result(result)
    if result and result.get("status") in {"settled", "complete"}:
        rows = result.get("subscriptions", result.get("items", []))
        if rows:
            st.dataframe(rows, use_container_width=True, hide_index=True)
        refs = result.get("cancellable", [])
        if refs:
            chosen = st.selectbox(
                tr("Choose an authorized subscription"), refs, key="subscription_ref"
            )
            if st.button(tr("Prepare cancellation approval"), key="cancel_subscription"):
                perform(
                    lambda: controller.cancel_subscription(
                        chosen, request_id=request_id("cancel-subscription", chosen)
                    ),
                    "subscription_cancel",
                )
    cancel = st.session_state.get("subscription_cancel")
    if cancel and cancel.get("card"):
        render_card(cancel["card"])
        st.button(
            tr("Confirm cancellation on device"),
            key="approve_cancel_subscription",
            on_click=approve_saved,
            args=(controller, "subscription_cancel", "subscription_cancel_result"),
        )
    render_result(st.session_state.get("subscription_cancel_result"))


def investments(controller: DemoController) -> None:
    st.markdown(tr("## Product comparison and best-interest certificate"))
    st.caption(
        tr(
            "Synthetic product catalogue · performance benchmark (not guarante"
            "ed), for comparison only; not realized income."
        )
    )
    objective = st.selectbox(
        tr("Choose your comparison objective"),
        ["net_return", "total_fee", "liquidity"],
        format_func=lambda item: {
            "net_return": tr("Net performance benchmark (not guaranteed)"),
            "total_fee": tr("Total fees"),
            "liquidity": tr("Liquidity"),
        }[item],
        key="investment_objective",
    )
    if st.button(
        tr("Confirm objective and compare the full catalogue"),
        key="compare_investments",
        type="primary",
    ):
        perform(lambda: controller.compare_investments(objective), "comparison")
    comparison = st.session_state.get("comparison")
    if comparison:
        render_result(comparison)
        bic = comparison.get("bic") or {}
        if bic:
            render_bic(bic)
        excluded = comparison.get("excluded", comparison.get("exclusions"))
        if excluded:
            st.write(tr("Excluded products and reasons"))
            for item in excluded:
                if isinstance(item, dict):
                    reasons = item.get("reason_codes", item.get("reasons", []))
                    st.write(
                        str(item.get("product_id", ""))
                        + " · "
                        + " · ".join(tr(EXCLUSIONS.get(reason, reason)) for reason in reasons)
                    )
                elif isinstance(excluded, dict):
                    reasons = excluded[item]
                    reasons = reasons if isinstance(reasons, list) else [reasons]
                    st.write(
                        str(item)
                        + " · "
                        + " · ".join(tr(EXCLUSIONS.get(reason, reason)) for reason in reasons)
                    )
            with st.expander(tr("Binding identifiers and complete canonical JSON")):
                st.json(excluded)
        products = comparison.get("candidate_ids", bic.get("candidate_ids", []))
        selection = st.selectbox(
            tr("Choose another product explicitly (optional)"),
            [None, *products],
            format_func=lambda item: (
                tr("Use the highest-ranked eligible product") if item is None else str(item)
            ),
            key="explicit_product",
        )
        if st.button(tr("Confirm preference and prepare purchase card"), key="preview_investment"):
            perform(
                lambda: controller.preview_investment(
                    selection, request_id=request_id("investment", [objective, selection])
                ),
                "investment_pending",
            )
        with st.expander(tr("Marketing metadata twin (isolated)")):
            st.caption(
                tr(
                    "Change a sponsor flag and check that the complete catalogue and r"
                    "ecommendation remain sponsor-independent within the declared cata"
                    "logue and policy. This test uses an isolated account."
                )
            )
            sponsored = st.toggle(
                tr("Toggle synthetic sponsor flag"), key="sponsored_twin", value=False
            )
            if st.button(tr("Verify unchanged recommendation"), key="run_marketing_twin"):
                perform(lambda: controller.marketing_twin(sponsored), "marketing_twin")
            twin = st.session_state.get("marketing_twin")
            if twin:
                (st.success if twin.get("unchanged") else st.error)(
                    tr("Marketing twin: recommendation and complete catalogue are unchanged")
                    if twin.get("unchanged")
                    else tr("Marketing twin verification failed")
                )
                render_bic(twin.get("bic", {}))
    pending = st.session_state.get("investment_pending")
    if pending and pending.get("card"):
        render_card(pending["card"])
        st.info(
            tr(
                "The purchase has not executed. Open Device to complete simulated "
                "MFA and final approval."
            )
        )
    positions = [item["id"] for item in controller.snapshot().get("positions", [])]
    if positions:
        position = st.selectbox(
            tr("Choose one of your synthetic positions"), positions, key="redemption_position"
        )
        if st.button(
            tr("Prepare redemption of an existing synthetic position"), key="preview_redemption"
        ):
            perform(
                lambda: controller.redeem(position, request_id=request_id("redemption", position)),
                "redemption_pending",
            )
    redemption = st.session_state.get("redemption_pending")
    if redemption and redemption.get("card"):
        render_card(redemption["card"])
        st.button(
            tr("Confirm redemption on device"),
            key="approve_redemption",
            on_click=approve_saved,
            args=(controller, "redemption_pending", "redemption_result"),
        )
    render_result(st.session_state.get("redemption_result"))


def cards(controller: DemoController) -> None:
    st.markdown(tr("## Cards"))
    st.caption(
        tr(
            "Synthetic virtual cards display demo tokens. Card operations use "
            "no real card numbers or payment services."
        )
    )
    rows = controller.snapshot().get("cards", [])
    if st.button(
        tr("Apply for a simulated virtual card · show yellow-tier approval"),
        key="preview_apply_card",
    ):
        perform(
            lambda: controller.preview_card_operation(
                "apply_virtual_card",
                request_id=request_id("apply-card", sorted(row["id"] for row in rows)),
            ),
            "card_pending",
        )
        st.session_state.pop("card_result", None)
    if rows:
        by_ref = {row["id"]: row for row in rows}
        ref = st.selectbox(
            tr("Choose one of your simulated cards"),
            list(by_ref),
            format_func=lambda value: by_ref[value]["card_token"],
            key="card_ref",
        )
        card = by_ref[ref]
        fact_rows({
            key: card[key]
            for key in ("card_token", "account_ref", "status", "limit", "restrictions")
        })
        state_kinds = {
            "active": ["freeze_card", "report_card_lost"],
            "frozen": ["unfreeze_card", "report_card_lost"],
            "lost": ["restore_card"],
        }
        kinds = state_kinds[card["status"]]
        if card["status"] != "lost":
            kinds += [
                "lower_card_limit",
                "raise_card_limit",
                "restrict_card",
                "relax_card_restriction",
            ]
        else:
            st.info(
                tr(
                    "A lost card must first be restored to frozen status, then separat"
                    "ely verified to unfreeze. Existing limits and restrictions remain"
                    " in force."
                )
            )
        kind = st.selectbox(
            tr("Choose a card operation"), kinds, format_func=KINDS.get, key="card_operation"
        )
        change = None
        if kind in {"lower_card_limit", "raise_card_limit"}:
            limit = st.text_input(tr("New limit (CNY, to the nearest cent)"), key="card_limit")
            change = {"limit": limit}
        elif kind in {"restrict_card", "relax_card_restriction"}:
            categories = {
                "online": tr("Online transactions"),
                "overseas": tr("Overseas transactions"),
                "cash": tr("Cash transactions"),
                "entertainment": tr("Entertainment spending"),
            }
            options = sorted(set(categories) | set(card["restrictions"]))
            restricted = st.multiselect(
                tr("All transaction categories to restrict after this change"),
                options,
                default=card["restrictions"],
                format_func=lambda value: categories.get(value, value),
                key=f"card_restrictions:{ref}:{kind}:{card['version']}",
            )
            change = {"restrictions": sorted(restricted)}
            st.caption(
                tr(
                    "Restricting adds categories; relaxing removes categories and requ"
                    "ires independent MFA."
                )
            )
        if st.button(
            tr("Show card operation approval"), key="preview_card_control", type="primary"
        ):
            perform(
                lambda: controller.preview_card_operation(
                    kind,
                    card_ref=ref,
                    change=change,
                    request_id=request_id(
                        "card-control",
                        {
                            "kind": kind,
                            "card_ref": ref,
                            "change": change,
                            "version": card["version"],
                        },
                    ),
                ),
                "card_pending",
            )
            st.session_state.pop("card_result", None)
    else:
        st.info(
            tr(
                "No simulated virtual cards yet. Check the default limit and trans"
                "action restrictions before applying."
            )
        )
    pending = st.session_state.get("card_pending")
    result = st.session_state.get("card_result")
    if pending and pending.get("card"):
        render_card(pending["card"])
        live = next(
            (
                row
                for row in controller.snapshot()["pending"]
                if row["pending_id"] == pending["pending_id"]
            ),
            None,
        )
        if live and live["completed"]:
            result = live["result"]
        if live and not live["completed"]:
            red = pending["card"].get("tier") == "red"
            if red and live["mode"] == "prepared":
                st.info(
                    tr(
                        "Your device confirmed the intent; the operation has not executed."
                        " Open Device for MFA and final approval."
                    )
                )
            else:
                st.button(
                    tr("Confirm intent on device, then verify MFA")
                    if red
                    else tr("Confirm on device and execute card operation"),
                    key="approve_card",
                    type="primary",
                    on_click=approve_saved,
                    args=(controller, "card_pending", "card_result"),
                )
    render_result(result)


def device(controller: DemoController) -> None:
    st.markdown(tr("## Device approvals"))
    st.info(
        tr(
            "Simulated independent device. Complete MFA here; verification cod"
            "es stay out of chat, logs and model input."
        )
    )
    if st.session_state.get("device_redisplay"):
        st.warning(
            tr("The facts changed. Review the current canonical card before confirming again.")
        )
    rows = pending_rows(controller)
    if not rows:
        st.caption(
            tr("No operations awaiting approval. Prepare a task to see its canonical card here.")
        )
    for index, pending in enumerate(rows):
        identifier = pending.get("pending_id", pending.get("id"))
        if identifier is None:
            continue
        st.markdown(f"{tr('### Pending operation ')}{index + 1}")
        render_card(pending.get("card", {}))
        red = pending.get("needs_mfa") or pending.get("card", {}).get("tier") == "red"
        if red and pending.get("mode") == "draft":
            st.info(
                tr(
                    "Review and confirm the intent below, then request independent sim"
                    "ulated MFA. It is not yet signed or executed."
                )
            )
        if red and pending.get("mode") != "draft":
            if st.button(tr("Request independent simulated MFA"), key=f"mfa_request:{identifier}"):
                perform(
                    lambda identifier=identifier: controller.request_mfa(identifier),
                    f"mfa:{identifier}",
                )
            challenge = st.session_state.get(f"mfa:{identifier}")
            if challenge:
                st.caption(
                    tr(
                        "A simulated challenge was sent to the independent device channel."
                        " Verification keeps codes out of chat."
                    )
                )
                if st.button(tr("Verify on simulated device"), key=f"mfa_complete:{identifier}"):
                    perform(
                        lambda identifier=identifier: controller.complete_mfa(identifier),
                        f"mfa_result:{identifier}",
                    )
                verified = st.session_state.get(f"mfa_result:{identifier}")
                if verified:
                    st.write(
                        tr("Simulated verification status:"), verified.get("status", "waiting")
                    )
        st.button(
            tr("Review the facts above and approve"),
            key=f"approve:{identifier}",
            type="primary",
            on_click=approve_device,
            args=(controller, identifier),
        )
        render_result(st.session_state.get(f"approved:{identifier}"))
    for completed in controller.snapshot().get("pending", []):
        if completed.get("completed"):
            render_result(st.session_state.get(f"approved:{completed['pending_id']}"))


def plans(controller: DemoController) -> None:
    st.markdown(tr("## Task plans"))
    st.caption(
        tr(
            "Authorize each item separately. Unselected items have no executio"
            "n permission; scheduled tasks are checked again when due."
        )
    )
    if st.button(tr("Prepare birthday task plan"), key="preview_birthday", type="primary"):
        perform(
            lambda: controller.preview_birthday(request_id=request_id("birthday")),
            "birthday_draft",
        )
        st.session_state.pop("plan_result", None)
    draft = st.session_state.get("birthday_draft")
    if draft:
        st.info(
            tr(
                "The draft plan is not authorized. Check each amount, date, recipi"
                "ent and irreversible effect."
            )
        )
        selected = []
        for index, node in enumerate(draft.get("nodes", [])):
            identifier = str(node.get("node_id", node.get("id", index)))
            label = tr(str(node.get("label", node.get("kind", "Plan item"))))
            st.markdown(f"### {index + 1}. {label}")
            if node.get("card"):
                render_card(
                    node["card"],
                    canonical=bool(node.get("canonical", draft.get("canonical", False))),
                )
            else:
                fact_rows(node)
            if st.checkbox(
                tr("I have reviewed and authorize this item"),
                key=f"plan_select:{draft['plan_id']}:{identifier}",
                value=False,
            ):
                selected.append(identifier)
        st.button(
            tr("Confirm all selected items"),
            key="confirm_plan",
            type="primary",
            disabled=not selected,
            on_click=confirm_birthday,
            args=(controller,),
        )
    render_result(st.session_state.get("plan_result"))
    snapshot = controller.snapshot()
    running = snapshot.get("plans", [])
    if running:
        st.write(tr("Current item status and dependencies"))
        render_plans(running)
    schedules = snapshot.get("schedules", [])
    if schedules:
        st.write(tr("Scheduled task status by occurrence"))
        for schedule in schedules:
            fact_rows({
                key: value
                for key, value in schedule.items()
                if key
                in {
                    "id",
                    "status",
                    "due_at",
                    "expires_at",
                    "run_index",
                    "amount",
                    "receipt_ref",
                    "waiting_mfa_at",
                    "mfa_deadline",
                }
            })
    st.warning(
        tr(
            "If daily cumulative spending raises a yellow-tier scheduled task "
            "to red, it waits for MFA for that occurrence. It expires after 24"
            " hours without verification; amounts are not changed to retry."
        )
    )
    render_result(st.session_state.get("clock_result"))


def confirm_birthday(controller: DemoController) -> None:
    draft = st.session_state["birthday_draft"]
    plan_id = draft["plan_id"]
    selected = [
        node["id"]
        for node in draft["nodes"]
        if st.session_state.get(f"plan_select:{plan_id}:{node['id']}", False)
    ]
    result = perform(lambda: controller.confirm_plan(plan_id, selected), "plan_result")
    if result and result.get("replacement"):
        st.session_state["birthday_draft"] = result["replacement"]
    elif result and result.get("status") == "settled":
        st.session_state.pop("birthday_draft", None)


def handoff(controller: DemoController) -> None:
    st.markdown(tr("## Human advisor handoff"))
    st.caption(
        tr(
            "Handoff pauses automatic execution. The advisor sees redacted evi"
            "dence; later financial actions still require authorization and ga"
            "teway checks."
        )
    )
    if st.button(tr("Hand off to a simulated advisor"), key="handoff", type="primary"):
        perform(controller.handoff, "handoff_result")
    result = st.session_state.get("handoff_result")
    if result:
        render_result(result)
    snapshot = controller.snapshot()
    st.write(tr("Session and plan status"))
    render_plans(snapshot.get("plans", []))
    plan_ids = [item["plan"]["plan_id"] for item in snapshot.get("plans", [])]
    if plan_ids:
        selected = st.selectbox(tr("Choose a plan for follow-up"), plan_ids, key="recovery_plan")
        if st.button(
            tr("Prepare reversible compensation and a new approval card"),
            key="preview_compensation",
        ):
            perform(lambda: controller.compensate(selected), "compensation_pending")
        pending = st.session_state.get("compensation_pending")
        if pending:
            if pending.get("card"):
                render_card(pending["card"])
                st.button(
                    tr("Confirm the new compensation action on device"),
                    key="approve_compensation",
                    on_click=approve_saved,
                    args=(controller, "compensation_pending", "compensation_result"),
                )
            else:
                render_result(pending)
        render_result(st.session_state.get("compensation_result"))
        with st.expander(tr("Reconfirm automatic execution scope")):
            scope = controller.resume_scope(selected)
            fact_rows(scope)
            if st.button(tr("Confirm this scope on device and resume"), key="resume_plan"):
                perform(lambda: controller.resume(selected), "resume_result")
            render_result(st.session_state.get("resume_result"))
    st.info(
        tr(
            "Settled transfers cannot be directly reversed. Reversible compens"
            "ation needs a new approval; a refund request is not a received re"
            "fund."
        )
    )


def audit_judge(controller: DemoController) -> None:
    st.markdown('<div id="audit-entry"></div>', unsafe_allow_html=True)
    st.markdown(tr("## Evidence & Audit"))
    snapshot = controller.snapshot()
    st.write(tr("Current session audit and receipts"))
    (st.success if snapshot.get("audit_valid") else st.error)(
        tr("Audit hash chain verified")
        if snapshot.get("audit_valid")
        else tr("Audit hash chain verification failed")
    )
    st.json({key: snapshot.get(key) for key in ("audit", "receipts", "dispatch_count")})
    st.divider()
    st.info(
        tr(
            "These evaluations use isolated synthetic state. Evidence mode: sc"
            "ripted. Scripted results demonstrate system mechanisms. Live-reco"
            "rded results: not_run."
        )
    )
    hijacked = st.toggle(tr("Hijacked AI mode"), key="hijacked", value=False)
    if hijacked:
        specs = development_cases()
        labels = {item.case_id: f"{item.case_id} · {item.family} · {item.attack}" for item in specs}
        selected = st.selectbox(
            tr("Choose an isolated adversarial case"),
            list(labels),
            format_func=labels.get,
            key="attack_case",
        )
        if st.button(
            tr("Run attack and benign twin in isolation"), key="run_attack", type="primary"
        ):
            with st.spinner(tr("Checking gateway rejection and benign completion…")):
                perform(lambda: run_hijacked_case(selected), "evaluation_result")
    else:
        selected = st.selectbox(
            tr("Choose a banking judge task (P0 + P1)"),
            [f"J{number:02d}" for number in range(1, 25)],
            key="judge_task",
        )
        if st.button(tr("Run selected judge task"), key="run_judge", type="primary"):
            with st.spinner(tr("Running all assertions in an isolated synthetic session…")):
                perform(lambda: run_judge_task(selected), "evaluation_result")
    result = st.session_state.get("evaluation_result")
    if result:
        passed = result.get("passed", result.get("attack", {}).get("passed", False))
        (st.success if passed else st.error)(
            tr("Evaluation PASS") if passed else tr("Evaluation FAIL / incomplete")
        )
        st.json(result)
    st.caption(
        tr(
            "J01–J22: P0 banking tasks. J23–J24: P1 card operations. External "
            "blind tests: not_run (16 planned)."
        )
    )


def operator_panel(controller: DemoController) -> None:
    """Show simulation controls only when an operator explicitly enables them."""
    if os.environ.get("CORRIDOR_OPERATOR_MODE") != "1":
        return
    with st.sidebar.expander(tr("Operator panel"), expanded=False):
        st.caption(tr("Supporting-bank clock · separate from the wealth simulation"))
        if st.button(tr("Advance simulated clock by 10 minutes 1 second"), key="advance_window"):
            perform(lambda: controller.advance_clock(601), "global_clock_result")
            st.rerun()
        if st.button(tr("Advance simulated clock to October 18"), key="advance_clock"):
            perform(lambda: controller.advance_clock("2026-10-18T02:00:00Z"), "clock_result")
            st.rerun()


def select_primary_page() -> None:
    """Return from a supporting workflow when the primary navigation changes."""
    st.session_state["supporting_page"] = "None"


def remember_page() -> None:
    """Retain route selection independently of translated widget identities."""
    st.session_state["active_page"] = st.session_state["page"]
    select_primary_page()


def wealth_progress(controller: WealthController) -> int:
    """Point to the next customer action using the current gateway-backed state."""
    execution = controller.execution_snapshot()
    if execution is not None:
        return 4 if execution["status"] == "completed" else 3
    if controller.comparison is not None:
        return 2
    if controller.candidate is not None and controller.risk_profile() is None:
        return 1
    return 0


def render_progress(controller: WealthController) -> None:
    current = wealth_progress(controller)
    execution = controller.execution_snapshot()
    settled = execution is not None and execution["status"] == "completed"
    complete = (
        controller.signed_goals is not None,
        controller.risk_profile() is not None,
        execution is not None,
        settled,
        settled,
    )
    steps = (
        ("goals", "Goals"),
        ("risk", "Risk profile"),
        ("proposal", "Proposal & certificate"),
        ("approvals", "Approvals"),
        ("receipts", "Receipts"),
    )
    items = []
    for index, (identifier, label) in enumerate(steps):
        state = "current" if index == current else "complete" if complete[index] else "pending"
        mark = "&#10003;" if complete[index] else str(index + 1)
        items.append(
            f'<li data-step="{identifier}" data-state="{state}"'
            + (' aria-current="step"' if index == current else "")
            + f'><span class="cw-step-number">{mark}</span>'
            + f"<span>{escape(tr(label))}</span></li>"
        )
    st.markdown('<ol class="cw-progress">' + "".join(items) + "</ol>", unsafe_allow_html=True)


SHELL_STYLES = """<style>
[data-testid="stAppDeployButton"], .stDeployButton, #MainMenu {display:none !important}
header[data-testid="stHeader"] {height:2.25rem!important;min-height:0!important;
background:transparent!important}
.cw-progress {list-style:none;display:flex;gap:8px;margin:4px 0 12px;padding:0}
.cw-progress li {flex:1;display:flex;align-items:center;gap:9px;padding:12px 10px;
border-bottom:3px solid #dfe6e8;color:#68777e;font-size:14px;font-weight:600;min-width:0}
.cw-progress li[data-state="current"] {color:#126c60;border-color:#168570;background:#edf7f3;
border-radius:9px 9px 0 0}
.cw-progress li[data-state="complete"] {color:#126c60;border-color:#8cc2ad}
.cw-step-number {display:inline-flex;align-items:center;justify-content:center;
width:25px;height:25px;flex:none;border:1px solid currentColor;border-radius:50%;font-size:12px}
.cw-brand {font-size:27px;font-weight:750;letter-spacing:-.8px;line-height:1.25;color:#163d3b}
.cw-brand span {color:#b48d52;font-size:24px;padding-right:10px}
.cw-disclosure {font-size:13px;color:#667674;margin-top:5px}
.cw-home {padding:42px;border-radius:20px;background:#173f3c;color:white;margin:16px 0}
.cw-home h2 {color:white!important;font-size:34px!important;max-width:700px;margin-bottom:14px}
.cw-home p {font-size:18px;color:#d8ebe5;max-width:740px}
@media(max-width:700px){.cw-progress{gap:3px}.cw-progress li{font-size:11px;padding:8px 3px;
flex-direction:column;text-align:center}.cw-brand{font-size:23px}.cw-disclosure{font-size:11px}}
</style>"""


def main() -> None:
    if "locale" not in st.session_state:
        st.session_state["locale"] = get_locale()
    set_locale(st.session_state["locale"])
    st.set_page_config(
        page_title="Corridor Wealth",
        page_icon="▧",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.markdown(STYLES + SHELL_STYLES, unsafe_allow_html=True)
    brand, language = st.columns([5, 1])
    with brand:
        st.markdown(
            '<div class="cw-brand"><span>⇄</span>Corridor Wealth</div>'
            f'<div class="cw-disclosure">{tr("Product disclosure")}</div>',
            unsafe_allow_html=True,
        )
    with language:
        language_labels = {"en": "English", "zh-CN": tr("language_zh")}
        st.selectbox(
            tr("language_label"),
            ("en", "zh-CN"),
            format_func=language_labels.__getitem__,
            key="locale",
            label_visibility="collapsed",
            on_change=lambda: set_locale(st.session_state["locale"]),
        )
    if "controller" not in st.session_state:
        st.session_state["controller"] = DemoController()
    if "wealth_controller" not in st.session_state:
        st.session_state["wealth_controller"] = WealthController()
    controller = st.session_state["controller"]
    wealth = st.session_state["wealth_controller"]
    render_live_controls(wealth)
    render_progress(wealth)
    if "active_page" not in st.session_state:
        st.session_state["active_page"] = st.session_state.get("page", PAGES[0])
    page_labels = {page: tr(page) for page in PAGES}
    left, right = st.columns([6, 1])
    with left:
        st.selectbox(
            tr("Primary navigation"),
            PAGES,
            format_func=page_labels.__getitem__,
            index=PAGES.index(st.session_state["active_page"]),
            key="page",
            label_visibility="collapsed",
            on_change=remember_page,
        )
    with right:
        st.button(
            tr("Stop"),
            key="stop_all",
            use_container_width=True,
            on_click=stop_all,
            args=(controller,),
        )
    if st.session_state.get("stop_result"):
        render_result(st.session_state["stop_result"])
    snapshot = controller.snapshot()
    logged_in = bool(snapshot.get("logged_in", getattr(controller, "logged_in", False)))
    if not logged_in:
        st.markdown(
            '<div class="cw-home"><div class="eyebrow">CORRIDOR WEALTH</div>'
            f"<h2>{tr('A clear plan. Every decision yours.')}</h2>"
            f"<p>{tr('Product welcome')}</p></div>",
            unsafe_allow_html=True,
        )
        if st.button(tr("Enter synthetic demo"), key="enter", type="primary"):
            result = perform(controller.start_session)
            if result and result.get("status") in {"accepted", "logged_in", "complete", "ready"}:
                perform(wealth.start_session, "wealth_login")
                st.rerun()
        st.caption(
            tr(
                "Fictional customers, institutions and products. "
                "Starting does not authorize payment."
            )
        )
        return
    operator_panel(controller)
    render_result(st.session_state.get("global_clock_result"))
    if snapshot.get("status") in {"handoff", "handed_off", "paused"}:
        st.warning(tr("Automatic execution is paused"))
    with st.sidebar.expander(tr("More · supporting capabilities"), expanded=False):
        supporting_labels = {page: tr(page) for page in SUPPORTING_PAGES}
        supporting_page = st.selectbox(
            tr("Supporting capability"),
            SUPPORTING_PAGES,
            format_func=supporting_labels.__getitem__,
            key="supporting_page",
        )
    handlers = {
        "Advisor": conversation,
        "Proposal & Certificate": investments,
        "Device": device,
        "Evidence & Audit": audit_judge,
        "Transfers": conversation,
        "Bills & Balance": billing,
        "Subscriptions": subscriptions,
        "Cards": cards,
        "Product comparison": investments,
        "Task Plans": plans,
        "Human Handoff": handoff,
    }
    selected_page = st.session_state["page"] if supporting_page == "None" else supporting_page
    try:
        if selected_page == "Advisor":
            wealth_views.advisor(wealth)
        elif selected_page == "Proposal & Certificate":
            wealth_views.proposal(wealth)
        elif selected_page == "Device":
            if wealth.parent_id is None and wealth.execution_snapshot() is None:
                profile, goals = st.columns([1, 1], gap="large")
                with profile:
                    wealth_views.risk_questionnaire(wealth)
                with goals:
                    wealth_views.goal_sheet(wealth)
            else:
                wealth_views.allocation_device(wealth)
                with st.expander(tr("Risk questionnaire and signed goals"), expanded=False):
                    wealth_views.risk_questionnaire(wealth)
                    wealth_views.goal_sheet(wealth)
            with st.expander(
                tr("Supporting-bank device approvals"), expanded=bool(pending_rows(controller))
            ):
                device(controller)
        elif selected_page == "Evidence & Audit":
            wealth_views.evidence(wealth)
            with st.expander(tr("Supporting-bank evidence and evaluation"), expanded=False):
                audit_judge(controller)
        elif selected_page == "Transfers":
            st.caption(tr("Separate synthetic supporting-bank account"))
            render_structured_transfer(controller)
            with st.expander(tr("Legacy conversation demonstration")):
                conversation(controller)
        else:
            st.caption(tr("Separate synthetic supporting-bank account"))
            handlers[selected_page](controller)
    except (ValueError, RuntimeError, TimeoutError, KeyError, OSError):
        st.error(
            tr(
                "The operation was not completed. "
                "Review current facts and retry from a fresh proposal."
            )
        )
    st.divider()
    st.caption(
        tr("Scripted demo · verified receipts · no real money")
        if wealth.client.mode == "scripted"
        else tr("Planner source") + ": " + wealth.planner_source + " · " + tr("Product disclosure")
    )
    with st.expander(tr("Technical evidence"), expanded=False):
        st.caption(
            f"{tr('Wealth simulated clock: ')}{wealth.state.now}"
            f"{tr(' · Wealth bank dispatches: ')}{wealth.snapshot()['dispatch_count']}"
        )
        st.caption(tr("Planner source") + ": " + wealth.planner_source)


if __name__ == "__main__":
    main()
