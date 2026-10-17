"""Topic B entry point with auxiliary banking workflows and explicit device gestures."""

import os
from collections.abc import Callable
from typing import Any

import streamlit as st

from corridor.bench.adversary import development_cases
from corridor.crypto.jcs import H
from corridor.sim.keys import stable_id
from corridor.ui import wealth_views
from corridor.ui.components import (
    KINDS,
    STYLES,
    fact_rows,
    render_bic,
    render_card,
    render_plans,
    render_result,
)
from corridor.ui.controller import DemoController
from corridor.ui.evaluation import run_hijacked_case, run_judge_task
from corridor.ui.structured_transfer import render_structured_transfer
from corridor.ui.wealth_controller import WealthController

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
            "The operation could not complete. Review the current facts and inputs, then retry."
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
    st.markdown("## Describe a transfer, then confirm it on your device")
    st.caption(
        "For example: transfer CNY 200 to Chen. Review the facts before authorizing payment."
    )
    with st.form("transfer_form"):
        text = st.text_input(
            "What would you like to do?",
            placeholder="Transfer CNY 200 to Chen",
            key="transfer_text",
        )
        submitted = st.form_submit_button(
            "Prepare transfer draft", key="preview_transfer", type="primary"
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
        if draft.get("status") == "clarify" or len(contacts) > 1:
            st.warning(
                "More than one contact matches. "
                "Select the recipient on your device before authorization."
            )
            options = {
                str(item.get("id", item.get("contact_ref"))): str(item.get("label", item.get("id")))
                for item in contacts
                if isinstance(item, dict)
            }
            if not options:
                options = {str(item): str(item) for item in contacts}
            selection = st.selectbox(
                "Select the recipient",
                [None, *options],
                format_func=lambda value: "Choose a contact" if value is None else options[value],
                key="contact_selection",
            )
            if st.button(
                "Show the selected recipient's canonical card",
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
                "Confirm on device and execute",
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
            st.warning("The canonical facts changed. Review the new card before confirming again.")
        render_result(st.session_state.get("transfer_result"))
        if st.session_state.get("transfer_result") and st.button(
            "Start another transfer", key="new_transfer"
        ):
            for key in list(st.session_state):
                if key.startswith("request:transfer:") or key in {
                    "transfer_draft",
                    "transfer_result",
                }:
                    del st.session_state[key]
            st.rerun()
    with st.expander("Assistant note (unverified)", expanded=False):
        st.write(
            "The assistant helps prepare your request. "
            "Recipient, amount, approval tier and outcome "
            "come from canonical device facts and verified bank receipts."
        )


def billing(controller: DemoController) -> None:
    st.markdown("## Bills and verifiable balances")
    st.caption(
        "Balances, categories, totals and alerts come from trusted records. "
        "Green-tier queries need no payment approval."
    )
    left, right = st.columns(2)
    with left:
        if st.button("Check balance", key="query_balance", use_container_width=True):
            perform(controller.query_balance, "balance_result")
    with right:
        if st.button("Create sample September bill", key="bill_report", use_container_width=True):
            perform(controller.bill_report, "bill_result")
    for key in ("balance_result", "bill_result"):
        result = st.session_state.get(key)
        if result:
            render_result(result)
            if result.get("facts"):
                fact_rows(result["facts"])


def subscriptions(controller: DemoController) -> None:
    st.markdown("## Subscriptions")
    st.info(
        "Subscription queries and renewal reminders require yellow-tier approval. "
        "Confirm before viewing subscriptions. Cancellation does not refund settled charges."
    )
    if st.button(
        "Prepare subscription query approval", key="preview_subscriptions", type="primary"
    ):
        perform(
            lambda: controller.preview_subscriptions(request_id=request_id("subscriptions")),
            "subscription_pending",
        )
    pending = st.session_state.get("subscription_pending")
    if pending and pending.get("card"):
        render_card(pending["card"])
        st.button(
            "Confirm subscription query on device",
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
            chosen = st.selectbox("Choose an authorized subscription", refs, key="subscription_ref")
            if st.button("Prepare cancellation approval", key="cancel_subscription"):
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
            "Confirm cancellation on device",
            key="approve_cancel_subscription",
            on_click=approve_saved,
            args=(controller, "subscription_cancel", "subscription_cancel_result"),
        )
    render_result(st.session_state.get("subscription_cancel_result"))


def investments(controller: DemoController) -> None:
    st.markdown("## Product comparison and best-interest certificate")
    st.caption(
        "Synthetic product catalogue · performance benchmark (not guaranteed), "
        "for comparison only; not realized income."
    )
    objective = st.selectbox(
        "Choose your comparison objective",
        ["net_return", "total_fee", "liquidity"],
        format_func=lambda item: {
            "net_return": "Net performance benchmark (not guaranteed)",
            "total_fee": "Total fees",
            "liquidity": "Liquidity",
        }[item],
        key="investment_objective",
    )
    if st.button(
        "Confirm objective and compare the full catalogue",
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
            st.write("Excluded products and reasons")
            st.json(excluded)
        products = comparison.get("candidate_ids", bic.get("candidate_ids", []))
        selection = st.selectbox(
            "Choose another product explicitly (optional)",
            [None, *products],
            format_func=lambda item: (
                "Use the highest-ranked eligible product" if item is None else str(item)
            ),
            key="explicit_product",
        )
        if st.button("Confirm preference and prepare purchase card", key="preview_investment"):
            perform(
                lambda: controller.preview_investment(
                    selection, request_id=request_id("investment", [objective, selection])
                ),
                "investment_pending",
            )
        with st.expander("Marketing metadata twin (isolated)"):
            st.caption(
                "Change a sponsor flag and check that the complete catalogue and recommendation "
                "remain sponsor-independent within the declared catalogue and policy. "
                "This test uses an isolated account."
            )
            sponsored = st.toggle(
                "Toggle synthetic sponsor flag", key="sponsored_twin", value=False
            )
            if st.button("Verify unchanged recommendation", key="run_marketing_twin"):
                perform(lambda: controller.marketing_twin(sponsored), "marketing_twin")
            twin = st.session_state.get("marketing_twin")
            if twin:
                (st.success if twin.get("unchanged") else st.error)(
                    "Marketing twin: recommendation and complete catalogue are unchanged"
                    if twin.get("unchanged")
                    else "Marketing twin verification failed"
                )
                render_bic(twin.get("bic", {}))
    pending = st.session_state.get("investment_pending")
    if pending and pending.get("card"):
        render_card(pending["card"])
        st.info(
            "The purchase has not executed. "
            "Open Device to complete simulated MFA and final approval."
        )
    positions = [item["id"] for item in controller.snapshot().get("positions", [])]
    if positions:
        position = st.selectbox(
            "Choose one of your synthetic positions", positions, key="redemption_position"
        )
        if st.button(
            "Prepare redemption of an existing synthetic position", key="preview_redemption"
        ):
            perform(
                lambda: controller.redeem(position, request_id=request_id("redemption", position)),
                "redemption_pending",
            )
    redemption = st.session_state.get("redemption_pending")
    if redemption and redemption.get("card"):
        render_card(redemption["card"])
        st.button(
            "Confirm redemption on device",
            key="approve_redemption",
            on_click=approve_saved,
            args=(controller, "redemption_pending", "redemption_result"),
        )
    render_result(st.session_state.get("redemption_result"))


def cards(controller: DemoController) -> None:
    st.markdown("## Cards")
    st.caption(
        "Synthetic virtual cards display demo tokens. "
        "Card operations use no real card numbers or payment services."
    )
    rows = controller.snapshot().get("cards", [])
    if st.button(
        "Apply for a simulated virtual card · show yellow-tier approval", key="preview_apply_card"
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
            "Choose one of your simulated cards",
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
                "A lost card must first be restored to frozen status, "
                "then separately verified to unfreeze. "
                "Existing limits and restrictions remain in force."
            )
        kind = st.selectbox(
            "Choose a card operation", kinds, format_func=KINDS.get, key="card_operation"
        )
        change = None
        if kind in {"lower_card_limit", "raise_card_limit"}:
            limit = st.text_input("New limit (CNY, to the nearest cent)", key="card_limit")
            change = {"limit": limit}
        elif kind in {"restrict_card", "relax_card_restriction"}:
            categories = {
                "online": "Online transactions",
                "overseas": "Overseas transactions",
                "cash": "Cash transactions",
                "entertainment": "Entertainment spending",
            }
            options = sorted(set(categories) | set(card["restrictions"]))
            restricted = st.multiselect(
                "All transaction categories to restrict after this change",
                options,
                default=card["restrictions"],
                format_func=lambda value: categories.get(value, value),
                key=f"card_restrictions:{ref}:{kind}:{card['version']}",
            )
            change = {"restrictions": sorted(restricted)}
            st.caption(
                "Restricting adds categories; "
                "relaxing removes categories and requires independent MFA."
            )
        if st.button("Show card operation approval", key="preview_card_control", type="primary"):
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
            "No simulated virtual cards yet. "
            "Check the default limit and transaction restrictions before applying."
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
                    "Your device confirmed the intent; the operation has not executed. "
                    "Open Device for MFA and final approval."
                )
            else:
                st.button(
                    "Confirm intent on device, then verify MFA"
                    if red
                    else "Confirm on device and execute card operation",
                    key="approve_card",
                    type="primary",
                    on_click=approve_saved,
                    args=(controller, "card_pending", "card_result"),
                )
    render_result(result)


def device(controller: DemoController) -> None:
    st.markdown("## Device approvals")
    st.info(
        "Simulated independent device. Complete MFA here; "
        "verification codes stay out of chat, logs and model input."
    )
    if st.session_state.get("device_redisplay"):
        st.warning("The facts changed. Review the current canonical card before confirming again.")
    rows = pending_rows(controller)
    if not rows:
        st.caption(
            "No operations awaiting approval. Prepare a task to see its canonical card here."
        )
    for index, pending in enumerate(rows):
        identifier = pending.get("pending_id", pending.get("id"))
        if identifier is None:
            continue
        st.markdown(f"### Pending operation {index + 1}")
        render_card(pending.get("card", {}))
        red = pending.get("needs_mfa") or pending.get("card", {}).get("tier") == "red"
        if red and pending.get("mode") == "draft":
            st.info(
                "Review and confirm the intent below, then request independent simulated MFA. "
                "It is not yet signed or executed."
            )
        if red and pending.get("mode") != "draft":
            if st.button("Request independent simulated MFA", key=f"mfa_request:{identifier}"):
                perform(
                    lambda identifier=identifier: controller.request_mfa(identifier),
                    f"mfa:{identifier}",
                )
            challenge = st.session_state.get(f"mfa:{identifier}")
            if challenge:
                st.caption(
                    "A simulated challenge was sent to the independent device channel. "
                    "Verification keeps codes out of chat."
                )
                if st.button("Verify on simulated device", key=f"mfa_complete:{identifier}"):
                    perform(
                        lambda identifier=identifier: controller.complete_mfa(identifier),
                        f"mfa_result:{identifier}",
                    )
                verified = st.session_state.get(f"mfa_result:{identifier}")
                if verified:
                    st.write("Simulated verification status:", verified.get("status", "waiting"))
        st.button(
            "Review the facts above and approve",
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
    st.markdown("## Task plans")
    st.caption(
        "Authorize each item separately. Unselected items have no execution permission; "
        "scheduled tasks are checked again when due."
    )
    if st.button("Prepare birthday task plan", key="preview_birthday", type="primary"):
        perform(
            lambda: controller.preview_birthday(request_id=request_id("birthday")),
            "birthday_draft",
        )
        st.session_state.pop("plan_result", None)
    draft = st.session_state.get("birthday_draft")
    if draft:
        st.info(
            "The draft plan is not authorized. "
            "Check each amount, date, recipient and irreversible effect."
        )
        selected = []
        for index, node in enumerate(draft.get("nodes", [])):
            identifier = str(node.get("node_id", node.get("id", index)))
            st.markdown(f"### {index + 1}. {node.get('label', node.get('kind', 'Plan item'))}")
            if node.get("card"):
                render_card(
                    node["card"],
                    canonical=bool(node.get("canonical", draft.get("canonical", False))),
                )
            else:
                fact_rows(node)
            if st.checkbox(
                "I have reviewed and authorize this item",
                key=f"plan_select:{draft['plan_id']}:{identifier}",
                value=False,
            ):
                selected.append(identifier)
        st.button(
            "Confirm all selected items",
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
        st.write("Current item status and dependencies")
        render_plans(running)
    schedules = snapshot.get("schedules", [])
    if schedules:
        st.write("Scheduled task status by occurrence")
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
        "If daily cumulative spending raises a yellow-tier scheduled task to red, it waits for MFA "
        "for that occurrence. It expires after 24 hours without verification; "
        "amounts are not changed to retry."
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


def handoff(controller: DemoController) -> None:
    st.markdown("## Human advisor handoff")
    st.caption(
        "Handoff pauses automatic execution. The advisor sees redacted evidence; "
        "later financial actions still require authorization and gateway checks."
    )
    if st.button("Hand off to a simulated advisor", key="handoff", type="primary"):
        perform(controller.handoff, "handoff_result")
    result = st.session_state.get("handoff_result")
    if result:
        render_result(result)
    snapshot = controller.snapshot()
    st.write("Session and plan status")
    render_plans(snapshot.get("plans", []))
    plan_ids = [item["plan"]["plan_id"] for item in snapshot.get("plans", [])]
    if plan_ids:
        selected = st.selectbox("Choose a plan for follow-up", plan_ids, key="recovery_plan")
        if st.button(
            "Prepare reversible compensation and a new approval card", key="preview_compensation"
        ):
            perform(lambda: controller.compensate(selected), "compensation_pending")
        pending = st.session_state.get("compensation_pending")
        if pending:
            if pending.get("card"):
                render_card(pending["card"])
                st.button(
                    "Confirm the new compensation action on device",
                    key="approve_compensation",
                    on_click=approve_saved,
                    args=(controller, "compensation_pending", "compensation_result"),
                )
            else:
                render_result(pending)
        render_result(st.session_state.get("compensation_result"))
        with st.expander("Reconfirm automatic execution scope"):
            scope = controller.resume_scope(selected)
            fact_rows(scope)
            if st.button("Confirm this scope on device and resume", key="resume_plan"):
                perform(lambda: controller.resume(selected), "resume_result")
            render_result(st.session_state.get("resume_result"))
    st.info(
        "Settled transfers cannot be directly reversed. "
        "Reversible compensation needs a new approval; a refund request is not a received refund."
    )


def audit_judge(controller: DemoController) -> None:
    st.markdown('<div id="audit-entry"></div>', unsafe_allow_html=True)
    st.markdown("## Evidence & Audit")
    snapshot = controller.snapshot()
    st.write("Current session audit and receipts")
    (st.success if snapshot.get("audit_valid") else st.error)(
        "Audit hash chain verified"
        if snapshot.get("audit_valid")
        else "Audit hash chain verification failed"
    )
    st.json({key: snapshot.get(key) for key in ("audit", "receipts", "dispatch_count")})
    st.divider()
    st.info(
        "These evaluations use isolated synthetic state. Evidence mode: scripted. "
        "Scripted results demonstrate system mechanisms. Live-recorded results: not_run."
    )
    hijacked = st.toggle("Hijacked AI mode", key="hijacked", value=False)
    if hijacked:
        specs = development_cases()
        labels = {item.case_id: f"{item.case_id} · {item.family} · {item.attack}" for item in specs}
        selected = st.selectbox(
            "Choose an isolated adversarial case",
            list(labels),
            format_func=labels.get,
            key="attack_case",
        )
        if st.button("Run attack and benign twin in isolation", key="run_attack", type="primary"):
            with st.spinner("Checking gateway rejection and benign completion…"):
                perform(lambda: run_hijacked_case(selected), "evaluation_result")
    else:
        selected = st.selectbox(
            "Choose a banking judge task (P0 + P1)",
            [f"J{number:02d}" for number in range(1, 25)],
            key="judge_task",
        )
        if st.button("Run selected judge task", key="run_judge", type="primary"):
            with st.spinner("Running all assertions in an isolated synthetic session…"):
                perform(lambda: run_judge_task(selected), "evaluation_result")
    result = st.session_state.get("evaluation_result")
    if result:
        passed = result.get("passed", result.get("attack", {}).get("passed", False))
        (st.success if passed else st.error)(
            "Evaluation PASS" if passed else "Evaluation FAIL / incomplete"
        )
        st.json(result)
    st.caption(
        "J01–J22: P0 banking tasks. J23–J24: P1 card operations. "
        "External blind tests: not_run (16 planned)."
    )


def select_primary_page() -> None:
    """Return from a supporting workflow when the primary navigation changes."""
    st.session_state["supporting_page"] = "None"


def operator_panel(controller: DemoController) -> None:
    """Show simulation controls only when an operator explicitly enables them."""
    if os.environ.get("CORRIDOR_OPERATOR_MODE") != "1":
        return
    with st.sidebar.expander("Operator panel", expanded=False):
        st.caption("Supporting-bank clock · separate from the wealth simulation")
        if st.button("Advance simulated clock by 10 minutes 1 second", key="advance_window"):
            perform(lambda: controller.advance_clock(601), "global_clock_result")
            st.rerun()
        if st.button("Advance simulated clock to October 18", key="advance_clock"):
            perform(lambda: controller.advance_clock("2026-10-18T02:00:00Z"), "clock_result")
            st.rerun()


def main() -> None:
    st.set_page_config(
        page_title="Corridor Wealth Advisory / Topic B",
        page_icon="▧",
        layout="centered",
        initial_sidebar_state="collapsed",
    )
    st.markdown(STYLES, unsafe_allow_html=True)
    st.markdown(
        '<div class="bank-header"><div class="bank-mark">⇄</div><div>'
        '<div class="bank-brand">CORRIDOR / CERTIFIED ACTIONS</div>'
        '<div class="bank-name">Demo Bank (simulated environment)</div></div></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="notice">synthetic data · simulated authentication · no real money<br>'
        "Evidence mode: scripted · Live-recorded: not_run · Strict-replay: not_run</div>",
        unsafe_allow_html=True,
    )
    if "controller" not in st.session_state:
        st.session_state["controller"] = DemoController()
    if "wealth_controller" not in st.session_state:
        st.session_state["wealth_controller"] = WealthController()
    controller = st.session_state["controller"]
    wealth = st.session_state["wealth_controller"]
    left, right = st.columns([3, 1])
    with left:
        st.selectbox(
            "Primary navigation",
            PAGES,
            key="page",
            label_visibility="collapsed",
            on_change=select_primary_page,
        )
    with right:
        st.button(
            "Stop",
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
            '<div class="hero"><div class="eyebrow">Signed goals · Auditable actions</div>'
            "<h2>Wealth advice with verifiable evidence.</h2>"
            "<p>Compare synthetic products, confirm facts on an independent device, "
            "and inspect the kernel decision and simulated bank receipts. "
            "Explore wealth advice first, with supporting banking capabilities in More."
            "</p></div>",
            unsafe_allow_html=True,
        )
        if st.button("Enter synthetic demo", key="enter", type="primary"):
            result = perform(controller.start_session)
            if result and result.get("status") in {"accepted", "logged_in", "complete", "ready"}:
                perform(wealth.start_session, "wealth_login")
                st.rerun()
        st.caption(
            "Fictional customers, institutions and products. Starting does not authorize payment."
        )
        return
    st.caption(
        f"Wealth simulated clock: {wealth.state.now} · "
        f"Wealth bank dispatches: {wealth.snapshot()['dispatch_count']}"
    )
    operator_panel(controller)
    render_result(st.session_state.get("global_clock_result"))
    if snapshot.get("status") in {"handoff", "handed_off", "paused"}:
        st.warning("Automatic execution is paused")
    with st.sidebar.expander("More · supporting capabilities", expanded=False):
        supporting_page = st.selectbox(
            "Supporting capability", SUPPORTING_PAGES, key="supporting_page"
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
            wealth_views.allocation_device(wealth)
            with st.expander(
                "Risk questionnaire and signed goals", expanded=wealth.parent_id is None
            ):
                wealth_views.risk_questionnaire(wealth)
                wealth_views.goal_sheet(wealth)
            with st.expander(
                "Supporting-bank device approvals", expanded=bool(pending_rows(controller))
            ):
                device(controller)
        elif selected_page == "Evidence & Audit":
            wealth_views.evidence(wealth)
            audit_judge(controller)
        elif selected_page == "Transfers":
            st.caption("Separate synthetic supporting-bank account")
            render_structured_transfer(controller)
            with st.expander("Legacy conversation demonstration"):
                conversation(controller)
        else:
            st.caption("Separate synthetic supporting-bank account")
            handlers[selected_page](controller)
    except (ValueError, RuntimeError, TimeoutError, KeyError, OSError):
        st.error(
            "The operation was not completed. Review current facts and retry from a fresh proposal."
        )
    st.divider()
    st.caption(
        "Financial effects come from verified receipts · "
        "synthetic data · simulated authentication · no real money · append-only audit"
    )


if __name__ == "__main__":
    main()
