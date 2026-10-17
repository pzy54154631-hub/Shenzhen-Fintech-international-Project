"""Read-only bilingual presentation of canonical gateway facts."""

from decimal import ROUND_HALF_EVEN, Decimal
from fractions import Fraction
from html import escape
from typing import Any

import streamlit as st

from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.facts import render_narrative
from corridor.schemas.narrative import FactRef, Narrative
from corridor.ui.messages import display_value, prose, tr
from corridor.ui.product_style import PRODUCT_STYLES, badge, contact_label, currency, product_label

STYLES = PRODUCT_STYLES


LABELS = {
    "kind": "Action",
    "amount": "Amount",
    "available": "Available balance",
    "fees": "Fees",
    "fee_breakdown": "Fee breakdown",
    "net_proceeds": "Net proceeds",
    "return_account_ref": "Return account",
    "settlement_date": "Settlement date (UTC+8)",
    "total_before": "Daily total · before",
    "total_after": "Daily total · after",
    "objects": "Business objects",
    "source_ref": "Source account",
    "contact_ref": "Recipient contact",
    "product_ref": "Product",
    "merchant_ref": "Merchant",
    "locked_ref": "Locked account",
    "tier_reasons": "Approval tier reasons",
    "execution_window": "Execution window / due time",
    "risk": "Risk and validity",
    "best_interest": "Best-interest certificate",
    "principal_token": "Masked customer",
    "business_date": "Business date",
    "spa_hash": "Scheduled authorization binding",
    "plan_hash": "Plan hash",
    "node_id": "Node ID",
    "device_session_id": "Device session",
    "dependency_hash": "Dependency hash",
    "ccy": "Currency",
    "rank": "Rank",
    "gap": "Gap from first place",
    "candidate_ids": "All eligible products",
    "chosen_product_id": "Selected product",
    "best_choice": "First in the standard ranking",
    "rows": "Complete ranking and calculations",
    "expected_net": "Net performance benchmark (not guaranteed)",
    "total_fee": "Projected total fees",
    "fee_buy": "Purchase fee",
    "fee_hold": "Holding fee",
    "fee_sell": "Redemption fee",
    "access_days": "Holding period + redemption delay (days)",
    "product_id": "Synthetic product ID",
    "created_at": "Created at",
    "start_at": "Starts at",
    "end_at": "Ends at",
    "due_at": "Current run due at",
    "max_runs": "Maximum runs",
    "run_index": "Current run",
    "creation_tier": "Approval tier at creation",
    "target": "Fixed recipient",
    "schedule": "Fixed execution schedule",
    "amount_bound": "Fixed amount limit",
    "expires_at": "Valid until",
    "level": "Risk level",
    "scope": "Authorization scope",
    "schedule_terms": "Scheduled authorization terms",
    "spa": "Scheduled payment authorization",
    "start": "Authorization starts at",
    "end": "Authorization ends at",
    "cadence": "Frequency",
    "interval_days": "Interval (days)",
    "at": "Fixed execution time",
    "destination_ref": "Fixed destination",
    "destination_version": "Destination version",
    "risk_level": "Product risk level",
    "risk_profile": "Customer risk profile",
    "assessment_expires_at": "Risk profile valid until",
    "mfa_expires_at": "Current run MFA valid until",
    "resume_scope": "Resume authorization scope",
    "status": "Status",
    "receipt_ref": "Bank receipt ID",
    "depends_on": "Dependencies",
    "first_due_at": "First due at",
    "recurrence": "Frequency",
    "fixed_amount": "Fixed amount per run",
    "scope_hash": "Authorization scope hash",
    "expiry": "Authorization expires at",
    "type": "Schedule type",
    "amount_ref": "Device-confirmed amount source",
    "schedule_ref": "Fixed schedule ID",
    "offer_ref": "Merchant order quote",
    "purpose_ref": "Device-confirmed business scope",
    "control": "Control request",
    "ownership_epoch": "Current handoff version",
    "plan_id": "Plan ID",
    "card_change": "Card change facts",
    "card_ref": "Simulated card ID",
    "card_token": "Simulated card token",
    "account_ref": "Account",
    "before": "Before",
    "after": "After",
    "limit": "Card transaction limit",
    "restrictions": "Restricted transaction categories",
    "preference_ref": "Signed preference reference",
    "assessment_ref": "Risk assessment reference",
    "raw_level": "Signed questionnaire risk level",
    "effective_level": "Effective risk level",
    "reason_codes": "Assessment reasons",
    "clarification": "Suitability clarification",
    "total_debit": "Total debit",
    "total_principal": "Total principal",
    "total_buy_fees": "Total purchase fees",
    "liquid_principal": "Liquid net principal",
    "projected_net": "Net performance benchmark (not guaranteed)",
}
KINDS = {
    "balance_query": "Balance query",
    "transactions_query": "Transaction history",
    "bill_analyze": "Billing analysis",
    "bill_report": "Bill report",
    "anomaly_query": "Unusual transaction review",
    "sandbox_analyze": "Exploratory sandbox analysis",
    "risk_assess": "Risk assessment",
    "product_compare": "Product comparison",
    "allocation_compare": "Allocation comparison",
    "investment_income_query": "Investment income query",
    "transfer": "Transfer",
    "purchase_product": "Product purchase",
    "redeem_product": "Product redemption",
    "subscription_query": "Subscription lookup",
    "subscription_reminders": "Renewal reminders",
    "cancel_subscription": "Cancel subscription",
    "lock_funds": "Lock budget",
    "unlock_funds": "Unlock budget",
    "schedule_transfer": "Scheduled payment authorization",
    "cancel_schedule": "Cancel scheduled authorization",
    "aa_request": "Split-bill collection request",
    "merchant_order": "Simulated merchant payment",
    "cancel_order": "Cancel merchant order",
    "refund_request": "Request a refund",
    "apply_virtual_card": "Apply for a simulated virtual card",
    "freeze_card": "Freeze card",
    "unfreeze_card": "Unfreeze card",
    "report_card_lost": "Report lost card",
    "restore_card": "Restore lost card (remain frozen)",
    "lower_card_limit": "Lower card limit",
    "raise_card_limit": "Raise card limit",
    "restrict_card": "Add transaction restrictions",
    "relax_card_restriction": "Relax transaction restrictions",
    "password_change_request": "Request a password change",
    "register_contact_request": "Request contact registration",
    "set_policy": "Attempted policy override (prohibited)",
    "set_permission": "Attempted permission override (prohibited)",
    "set_risk_level": "Attempted risk-level override (prohibited)",
    "set_contact_verified": "Attempted contact-verification override (prohibited)",
    "set_mfa": "Attempted MFA override (prohibited)",
    "bypass_approval": "Attempted approval bypass (prohibited)",
    "request_secret": "Attempted secret collection (prohibited)",
}
STATUSES = {
    "pending": "Pending",
    "ready": "Ready",
    "running": "Running",
    "settled": "Settled",
    "completed": "Completed",
    "succeeded": "Completed",
    "controlled": "Scheduled authorization created",
    "interrupted": "Interrupted",
    "waiting_input": "Awaiting device input",
    "waiting_approval": "Awaiting device approval",
    "awaiting_approval": "Awaiting device approval",
    "waiting_mfa": "Awaiting MFA for this run",
    "waiting_settlement": "Awaiting settlement",
    "blocked": "Blocked",
    "failed": "Failed",
    "skipped": "Skipped",
    "unknown": "Awaiting reconciliation",
    "scheduled": "Scheduled",
    "handoff": "Operator has taken over",
    "handed_off": "Operator has taken over",
    "expired": "Expired",
    "cancelled": "Cancelled",
    "compensating": "Compensation in progress",
    "compensated": "Compensated",
    "non_reversible": "Cannot be reversed directly",
    "active": "Active",
    "frozen": "Frozen",
    "lost": "Reported lost",
}


def money(value: Any) -> str:
    return currency(value)


def text_value(value: Any) -> str:
    if isinstance(value, bool):
        return tr("Yes") if value else tr("No")
    if value is None:
        return tr("Not applicable")
    if isinstance(value, (dict, list)):
        return jcs_bytes(value).decode("utf-8")
    return tr(str(value))


_MONEY_FIELDS = {
    "amount",
    "available",
    "balance_before",
    "balance_after",
    "total_before",
    "total_after",
    "fees",
    "fixed_amount",
    "expected_net",
    "projected_net",
    "total_fee",
    "fee_buy",
    "fee_hold",
    "fee_sell",
    "amount_bound",
    "limit",
    "total_debit",
    "total_principal",
    "total_buy_fees",
    "liquid_principal",
    "liquid_net_principal",
    "net_proceeds",
    "principal",
}
_TECHNICAL_FIELDS = {
    "principal_token",
    "allocation",
    "allocation_execution",
    "best_interest",
    "schema_version",
    "selector_version",
    "ownership_epoch",
    "candidate_ids",
    "depends_on",
    "scope",
    "control",
}


def _is_technical(key: str, value: Any) -> bool:
    if key in _TECHNICAL_FIELDS or key.endswith(("_hash", "_token")):
        return True
    if key.endswith(("_id", "_ref", "_ids", "_refs")) and key not in {
        "product_ref",
        "product_id",
        "chosen_product_id",
        "source_ref",
        "account_ref",
        "return_account_ref",
        "contact_ref",
    }:
        return True
    return isinstance(value, (dict, list)) and key != "reason_codes"


def _display_fact(key: str, value: Any) -> str:
    if key in _MONEY_FIELDS and value is not None:
        return money(value)
    if key in {"product_ref", "product_id", "chosen_product_id"}:
        return product_label(value)
    if key == "contact_ref":
        return contact_label(value)
    if key in {"source_ref", "account_ref", "return_account_ref"}:
        return tr(
            {"A_CURRENT": "Current account", "A_SAVINGS": "Savings account"}.get(
                str(value), "Verified account"
            )
        )
    if key == "kind":
        return display_value(KINDS.get(str(value), str(value)))
    if key == "status":
        return tr(STATUSES.get(str(value), str(value)))
    if key == "reason_codes" and isinstance(value, list):
        return " · ".join(tr("reason." + str(reason)) for reason in value)
    if isinstance(value, str) and "/" in value:
        try:
            exact = Fraction(value)
            decimal = (Decimal(exact.numerator) / Decimal(exact.denominator)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_EVEN
            )
            return f"{decimal:,.2f}"
        except (ValueError, ZeroDivisionError):
            pass
    return text_value(value)


def fact_rows(facts: dict[str, Any]) -> None:
    html = []
    for key, value in facts.items():
        if value is None or _is_technical(key, value):
            continue
        shown = _display_fact(key, value)
        if not shown:
            continue
        label = display_value(LABELS.get(key, key))
        html.append(
            f'<div class="fact-row"><div class="fact-label">{escape(label)}</div>'
            f'<div class="fact-value">{escape(shown)}</div></div>'
        )
    if html:
        st.markdown('<div class="fact-panel">' + "".join(html) + "</div>", unsafe_allow_html=True)


def localized_facts(facts: list[dict[str, Any]], controller: Any) -> list[dict[str, Any]]:
    """Re-render original authenticated references without mutating state or audit."""
    if not facts:
        return []
    result = render_narrative(
        Narrative(
            fact_refs=[
                FactRef(
                    receipt_ref=fact["receipt_ref"],
                    field=fact["field"],
                    expected=fact["exact_value"],
                )
                for fact in facts
            ]
        ),
        controller.state,
        controller.device.principal,
        controller.gateway.vault,
    )
    return [fact.model_dump(mode="json") for fact in result.facts]


def render_fact_projection(projection: dict[str, Any], controller: Any) -> None:
    """Show trusted narrative facts as readable text, with raw evidence on demand."""
    facts = localized_facts(projection.get("facts", []), controller)
    fact_rows({fact["field"]: fact["exact_value"] for fact in facts})
    if projection.get("facts") and not facts:
        st.warning(tr("The requested facts could not be verified."))
    with st.expander(tr("Technical evidence"), expanded=False):
        st.json(projection)


def render_card(
    card: dict[str, Any], *, canonical: bool = True, planner_source: str = "scripted"
) -> None:
    """Present business facts from the unchanged gateway confirmation card."""
    if not card:
        st.info(tr("No business facts are ready for approval."))
        return
    st.caption(tr("Planner source") + ": " + planner_source)
    title = (
        tr("Purchase confirmation")
        if card.get("kind") == "purchase_product"
        else (
            tr("Gateway approval card")
            if canonical
            else tr("Facts for device review · not yet authorized")
        )
    )
    tier = str(card.get("tier", "yellow"))
    tier_text = {
        "green": tr("Green · automatic query"),
        "yellow": tr("Yellow · device approval required"),
        "red": tr("Red · independent simulated MFA required"),
        "black": tr("Black · execution prohibited"),
    }.get(tier, tier)
    objects = card.get("objects", {})
    product = product_label(objects["product_ref"]) if objects.get("product_ref") else ""
    if objects.get("contact_ref"):
        product = contact_label(objects["contact_ref"])
    amount = (
        money(card["amount"])
        if card.get("amount") is not None
        else display_value(KINDS.get(card.get("kind"), tr("Business approval")))
    )
    reason_keys = list(card.get("tier_reasons", []))
    reason = (
        tr("tier_reason." + str(reason_keys[0]))
        if reason_keys
        else tr("Review this purchase before approving.")
    )
    if card.get("kind") == "purchase_product":
        reason = tr("Investment purchases require separate device MFA.")
    execution = card.get("allocation_execution") or {}
    progress = ""
    if execution.get("remaining_item_refs"):
        settled = len(execution.get("settled_item_refs", []))
        total = settled + len(execution["remaining_item_refs"])
        progress = tr("Purchase {current} of {total}", current=settled + 1, total=total)
    costs = "".join(
        '<div class="cw-confirm-cost"><span>'
        + escape(tr(label))
        + "</span><strong>"
        + escape(money(card[key]))
        + "</strong></div>"
        for key, label in (("fees", "Fees"), ("total_debit", "Total debit"))
        if card.get(key) is not None
    )
    if card.get("kind") in {"transfer", "merchant_order"} and objects.get("source_ref"):
        costs += (
            '<div class="cw-confirm-cost"><span>'
            + escape(tr("Source account"))
            + "</span><strong>"
            + escape(_display_fact("source_ref", objects["source_ref"]))
            + "</strong></div>"
        )
    st.markdown(
        '<div class="fact-panel"><div class="fact-title">'
        + escape(title)
        + (" · " + escape(progress) if progress else "")
        + '</div><div class="cw-confirm-grid"><div><div class="fact-product">'
        + escape(product)
        + '</div><div class="fact-amount">'
        + escape(amount)
        + "</div></div><div>"
        + costs
        + '</div></div><div class="cw-confirm-foot">'
        + badge(tier_text, tier)
        + '<p class="fact-note">'
        + escape(reason)
        + "</p></div></div>",
        unsafe_allow_html=True,
    )
    if card.get("irreversible"):
        st.warning(tr("Settled purchases are not automatically reversed."))
    with st.expander(tr("Technical evidence"), expanded=False):
        st.caption(tr("permission_table"))
        st.json(card)


def render_bic(bic: dict[str, Any]) -> None:
    st.markdown(tr("#### All eligible products and selection evidence"))
    facts = {
        key: bic[key]
        for key in ("candidate_ids", "chosen_product_id", "best_choice", "rank", "gap")
        if key in bic
    }
    fact_rows(facts)
    if bic.get("best_choice") is False:
        st.warning(
            tr(
                "The selected product is not first in the standard ranking. Review"
                " its rank and gap. Continuing requires your explicit, active choi"
                "ce."
            )
        )
    for row in bic.get("rows", []):
        st.write(f"{tr('Rank ')}{row.get('rank', '—')} · {row.get('product_id', '—')}")
        fact_rows({key: value for key, value in row.items() if key != "product_id"})


def render_structured(facts: dict[str, Any]) -> None:
    """Render only readable business fields; callers retain canonical evidence separately."""
    flat = {key: value for key, value in facts.items() if not isinstance(value, dict)}
    fact_rows(flat)
    for key, value in facts.items():
        if isinstance(value, dict) and key not in _TECHNICAL_FIELDS and not key.endswith("_hash"):
            render_structured(value)


def render_plans(plans: list[dict[str, Any]]) -> None:
    for index, snapshot in enumerate(plans):
        plan = snapshot.get("plan", {})
        st.markdown(f"{tr('#### Plan ')}{index + 1}")
        if snapshot.get("blocked"):
            st.warning(tr("Automatic execution has stopped for this plan."))
        for ordinal, node in enumerate(plan.get("nodes", [])):
            identifier = node["node_id"]
            state = snapshot.get("nodes", {}).get(identifier, {})
            status = state.get("status", "pending")
            node_label = display_value(KINDS.get(node.get("tool"), node.get("tool", tr("Node"))))
            st.markdown(
                (
                    '<div class="node"><div class="node-title">'
                    f"{ordinal + 1}"
                    ". "
                    f"{escape(node_label)}"
                    '</div><div class="node-status">'
                    f"{escape(tr(STATUSES.get(status, status)))}"
                    "</div></div>"
                ),
                unsafe_allow_html=True,
            )
        with st.expander(tr("Technical evidence"), expanded=False):
            st.json(snapshot)


def render_result(result: dict[str, Any] | None) -> None:
    if not result:
        return
    status = str(result.get("status", "waiting"))
    receipt = result.get("receipt") or result.get("analysis_receipt")
    exploratory = isinstance(receipt, dict) and receipt.get("trust") == "exploratory"
    if status == "advanced":
        st.info(
            f"{tr('Simulated clock advanced to ')}"
            f"{result.get('clock', '—')}"
            " · "
            f"{result.get('events', 0)}"
            f"{tr(' due events processed')}"
        )
    if status in {"redisplay", "drift"}:
        st.warning(
            tr(
                "Business facts changed · the previous approval is invalid. Review"
                " the new card below and approve again."
            )
        )
    if result.get("results"):
        rows = result["results"]
        rows = rows.values() if isinstance(rows, dict) else rows
        st.write(tr("Execution results by node"))
        for row in rows:
            if isinstance(row, dict):
                render_result(row)
        return
    if status in {"settled", "complete", "executed"} and receipt:
        if exploratory:
            st.info(
                tr(
                    "Exploratory analysis ran · question semantics are unverified. Thi"
                    "s cannot authorize a payment."
                )
            )
        elif result.get("analysis_receipt"):
            st.success(tr("Analysis complete · computation receipt verified"))
        else:
            st.success(tr("Executed · bank receipt verified"))
    elif status in {"unknown", "pending"}:
        st.warning(
            tr(
                "Awaiting reconciliation · do not pay again. Wait for the bank rec"
                "eipt or operator review."
            )
        )
    elif status in {"handoff", "handed_off"}:
        st.warning(tr("Operator handoff · automatic execution paused"))
    elif status == "interrupted":
        st.warning(tr("Interrupted · automatic execution paused"))
    elif status == "resumed":
        st.info(
            tr(
                "Plan resumed within the device-approved scope. Every subsequent a"
                "ction still requires gateway checks."
            )
        )
    elif status == "no_active_plan":
        st.info(tr("No active plan. No plan was paused and no funds moved."))
    elif status == "no_compensation":
        st.info(
            tr(
                "No reversible compensation can be generated automatically. Settle"
                "d payments cannot be undone directly."
            )
        )
    elif status == "controlled":
        st.info(
            tr(
                "Control request recorded · see node status and bank receipts to c"
                "onfirm whether and when a payment occurred."
            )
        )
    elif status in {"redisplay", "drift"}:
        if result.get("card"):
            render_card(result["card"])
    elif status in {"rejected", "refused", "failed", "blocked"}:
        st.error(tr("Action not executed · review the reasons before approving again"))
    elif result.get("needs_mfa") or status in {"waiting_mfa", "escalated", "Escalate"}:
        st.warning(tr("Awaiting MFA · complete simulated verification on the Device page"))
    elif status != "advanced":
        st.info(tr("Awaiting approval · execution has not completed"))
    if result.get("rule_ids"):
        st.caption(tr("Rules: ") + " · ".join(result["rule_ids"]))
    if result.get("message") and not exploratory:
        st.write(prose(result["message"]))
    if receipt:
        st.markdown('<div id="receipt"></div>', unsafe_allow_html=True)
        if exploratory:
            projection = result.get("facts", {})
            if isinstance(projection, dict):
                if projection.get("status") == "rendered":
                    for fact in projection.get("facts", []):
                        st.write(fact["text"])
                if projection.get("note") or result.get("message"):
                    with st.expander(tr("Assistant note (unverified)"), expanded=True):
                        if projection.get("note"):
                            st.write(projection["note"])
                        if result.get("message"):
                            st.write(result["message"])
            with st.expander(tr("Raw exploratory evidence (semantics unverified)"), expanded=False):
                st.caption(
                    tr(
                        "Program labels and question semantics are unverified; the signatu"
                        "re authenticates only the computation source."
                    )
                )
                st.json(receipt)
        else:
            with st.expander(tr("Technical evidence"), expanded=False):
                st.json(receipt)
        st.markdown(tr("[This receipt](#receipt) · audit chain on the Evidence & Audit page"))
        st.button(tr("View audit chain"), key=f"audit-link:{H(receipt)}", on_click=open_audit)
    if result.get("audit_checkpoint"):
        with st.expander(tr("Technical evidence"), expanded=False):
            st.json(result["audit_checkpoint"])


def open_audit() -> None:
    st.session_state["page"] = "Evidence & Audit"
    st.session_state["active_page"] = "Evidence & Audit"
    st.session_state["supporting_page"] = "None"
