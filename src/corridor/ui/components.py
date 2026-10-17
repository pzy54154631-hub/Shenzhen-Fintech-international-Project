"""Read-only English presentation of canonical gateway facts."""

from decimal import ROUND_HALF_EVEN, Decimal
from fractions import Fraction
from html import escape
from typing import Any

import streamlit as st

from corridor.crypto.jcs import H, jcs_bytes

STYLES = """
<style>
:root { --ink: #292437; --muted: #766f83; --line: #e9e3ee; --accent: #584174; }
.stApp { background: #f7f5fa; color: var(--ink); }
.block-container { max-width: 1060px; padding-top: 3.5rem; padding-bottom: 3rem; }
header[data-testid="stHeader"] { background: #f7f5faee; }
h1,h2,h3 { color: var(--ink); letter-spacing: -.025em; }
h1 { font-size: 1.7rem !important; } h2 { font-size: 1.35rem !important; }
.bank-header { display:flex; align-items:center; gap:14px; margin-bottom:14px; }
.bank-mark { background:#392b49; color:#f3d39c; width:46px; height:46px; border-radius:15px;
display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:700; }
.bank-brand { font-size:11px; letter-spacing:2px; color:#766f83; }
.bank-name { font-size:23px; font-weight:750; letter-spacing:-.04em; }
.notice { padding:10px 14px; border:1px solid #ded4e8; border-radius:12px; background:#eee8f4;
font-size:12px; color:#554065; margin-bottom:18px; }
.hero { background:#392b49; color:#fff; padding:28px; border-radius:22px; margin:16px 0; }
.hero h2 { color:#fff; font-size:26px !important; margin:0 0 8px; }
.hero p { color:#ded2eb; max-width:650px; line-height:1.8; margin:0; }
.eyebrow { color:#f4d296; font-size:12px; letter-spacing:2px; margin-bottom:10px; }
.fact-panel { background:#fff; border:1px solid var(--line); border-radius:18px;
padding:20px; margin:12px 0; box-shadow:0 3px 10px #34244404; }
.fact-title { font-size:12px; color:var(--muted); letter-spacing:.06em; }
.fact-amount { font-size:34px; font-weight:750; margin:7px 0; letter-spacing:-.05em; }
.fact-row { display:grid; grid-template-columns:minmax(96px, .35fr) 1fr; gap:12px;
padding:9px 0; border-bottom:1px solid #f1edf4; font-size:13px; }
.fact-label { color:var(--muted); } .fact-value { overflow-wrap:anywhere; word-break:break-word; }
.tier { display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px;
background:#f9ebcf; color:#735116; margin:5px 0; }
.tier-red { background:#f9e2df; color:#923a33; } .tier-green { background:#dcefe8; color:#275d49; }
.danger { border-left:3px solid #c58d46; background:#fff6e7; padding:12px 14px;
font-size:13px; line-height:1.7; margin:12px 0; border-radius:0 10px 10px 0; }
.node { border-left:2px solid #c4b5d3; margin-left:8px; padding:4px 0 14px 18px; }
.node-title { font-size:15px; font-weight:650; }
.node-status { color:var(--muted); font-size:12px; }
[data-testid="stMetric"] { background:white; border:1px solid var(--line); padding:14px;
border-radius:15px; } [data-testid="stMetricValue"] { font-size:25px; }
[data-testid="stVerticalBlockBorderWrapper"] { border-radius:16px; }
.stButton > button { border-radius:10px; min-height:42px; }
button[kind="primary"] { background:#584174; border-color:#584174; }
.stMarkdown p, .stMarkdown li, code { overflow-wrap:anywhere; }
[data-testid="stCode"] pre { white-space:pre-wrap; overflow-wrap:anywhere; }
@media(max-width:640px) {
.block-container { padding:3.5rem .85rem 2rem; } .bank-name { font-size:19px; }
.hero { padding:22px 18px; } .hero h2 { font-size:23px !important; }
.fact-panel { padding:16px; } .fact-amount { font-size:29px; }
.fact-row { grid-template-columns:90px 1fr; } .notice { font-size:11px; }
[data-testid="stHorizontalBlock"] { flex-wrap:wrap; gap:12px; }
}
</style>
"""

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
}
KINDS = {
    "transfer": "Transfer",
    "purchase_product": "Product purchase",
    "redeem_product": "Product redemption",
    "subscription_query": "Subscription lookup",
    "subscription_reminders": "Renewal reminders",
    "cancel_subscription": "Cancel subscription",
    "lock_funds": "Lock budget",
    "unlock_funds": "Unlock budget",
    "schedule_transfer": "Scheduled payment authorization",
    "merchant_order": "Simulated merchant payment",
    "apply_virtual_card": "Apply for a simulated virtual card",
    "freeze_card": "Freeze card",
    "unfreeze_card": "Unfreeze card",
    "report_card_lost": "Report lost card",
    "restore_card": "Restore lost card (remain frozen)",
    "lower_card_limit": "Lower card limit",
    "raise_card_limit": "Raise card limit",
    "restrict_card": "Add transaction restrictions",
    "relax_card_restriction": "Relax transaction restrictions",
}


def money(value: Any) -> str:
    try:
        fraction = Fraction(value)
        display = (Decimal(fraction.numerator) / Decimal(fraction.denominator)).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_EVEN
        )
        return f"¥ {display:,.2f}"
    except (ValueError, TypeError, ZeroDivisionError):
        return str(value)


def text_value(value: Any) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if value is None:
        return "Not applicable"
    if isinstance(value, (dict, list)):
        return jcs_bytes(value).decode("utf-8")
    return str(value)


def fact_rows(facts: dict[str, Any]) -> None:
    html = []
    for key, value in facts.items():
        label = LABELS.get(key, key)
        if (
            key
            in {
                "amount",
                "available",
                "total_before",
                "total_after",
                "fees",
                "fixed_amount",
                "expected_net",
                "total_fee",
                "fee_buy",
                "fee_hold",
                "fee_sell",
                "amount_bound",
                "limit",
            }
            and value is not None
        ):
            shown = f"{money(value)} · canonical value {text_value(value)}"
        else:
            shown = KINDS.get(str(value), str(value)) if key == "kind" else text_value(value)
            if key == "status":
                shown = {"active": "Active", "frozen": "Frozen", "lost": "Reported lost"}.get(
                    shown, shown
                )
        html.append(
            f'<div class="fact-row"><div class="fact-label">{escape(label)}</div>'
            f'<div class="fact-value">{escape(shown)}</div></div>'
        )
    st.markdown('<div class="fact-panel">' + "".join(html) + "</div>", unsafe_allow_html=True)


def render_card(card: dict[str, Any], *, canonical: bool = True) -> None:
    if not card:
        st.info("No business facts are ready for approval.")
        return
    title = "Gateway approval card" if canonical else "Facts for device review · not yet authorized"
    tier = str(card.get("tier", "yellow"))
    tier_text = {
        "green": "Green · automatic query",
        "yellow": "Yellow · device approval required",
        "red": "Red · independent simulated MFA required",
        "black": "Black · execution prohibited",
    }.get(tier, tier)
    amount = (
        money(card["amount"])
        if card.get("amount") is not None
        else KINDS.get(card.get("kind"), "Business approval")
    )
    st.markdown(
        f'<div class="fact-panel"><div class="fact-title">{escape(title)}</div>'
        f'<div class="fact-amount">{escape(amount)}</div>'
        f'<span class="tier tier-{escape(tier)}">{escape(tier_text)}</span></div>',
        unsafe_allow_html=True,
    )
    if card.get("irreversible"):
        st.markdown(
            '<div class="danger">Irreversible: a settled payment cannot be undone directly. '
            "A refund request does not mean funds have been returned.</div>",
            unsafe_allow_html=True,
        )
    if tier == "red":
        st.warning(
            "Red-tier action: Complete independent simulated MFA, then approve on the device. "
            "Dispatch requires verification."
        )
    main = {
        key: value
        for key, value in card.items()
        if key
        not in {
            "plan_hash",
            "node_id",
            "dependency_hash",
            "device_session_id",
            "irreversible",
            "tier",
            "best_interest",
            "business_context_hash",
            "action_hash",
            "intent_id",
        }
    }
    render_structured(main)
    if card.get("kind") == "schedule_transfer":
        st.warning(
            "Authorization covers only the fixed scope, dates and runs shown above. "
            "Balance, destination, permissions and cumulative tier are checked at execution. "
            "A yellow-to-red change requires independent MFA for this run; without verification "
            "within 24 hours, the run expires. Previous codes are never reused."
        )
    if isinstance(card.get("best_interest"), dict):
        render_bic(card["best_interest"])
    with st.expander("Binding identifiers and complete canonical JSON", expanded=False):
        st.json(card)


def render_bic(bic: dict[str, Any]) -> None:
    st.markdown("#### All eligible products and selection evidence")
    facts = {
        key: bic[key]
        for key in ("candidate_ids", "chosen_product_id", "best_choice", "rank", "gap")
        if key in bic
    }
    fact_rows(facts)
    if bic.get("best_choice") is False:
        st.warning(
            "The selected product is not first in the standard ranking. Review its rank and gap. "
            "Continuing requires your explicit, active choice."
        )
    for row in bic.get("rows", []):
        st.write(f"Rank {row.get('rank', '—')} · {row.get('product_id', '—')}")
        fact_rows({key: value for key, value in row.items() if key != "product_id"})


def render_structured(facts: dict[str, Any]) -> None:
    """Keep nested business facts readable without hiding them in raw JSON."""
    flat = {key: value for key, value in facts.items() if not isinstance(value, dict)}
    if flat:
        fact_rows(flat)
    for key, value in facts.items():
        if isinstance(value, dict):
            st.write(LABELS.get(key, key))
            render_structured(value)


def render_plans(plans: list[dict[str, Any]]) -> None:
    labels = {
        "pending": "Pending",
        "ready": "Ready",
        "running": "Running",
        "settled": "Settled",
        "completed": "Completed",
        "succeeded": "Completed",
        "controlled": "Scheduled authorization created",
        "interrupted": "Interrupted",
        "waiting_mfa": "Awaiting MFA for this run",
        "blocked": "Blocked",
        "failed": "Failed",
        "skipped": "Skipped",
        "unknown": "Awaiting reconciliation",
        "scheduled": "Scheduled",
        "handed_off": "Operator has taken over",
        "expired": "Expired",
    }
    for index, snapshot in enumerate(plans):
        plan = snapshot.get("plan", {})
        st.markdown(f"#### Plan {index + 1}")
        if snapshot.get("blocked"):
            st.warning("Automatic execution has stopped for this plan.")
        for ordinal, node in enumerate(plan.get("nodes", [])):
            identifier = node["node_id"]
            state = snapshot.get("nodes", {}).get(identifier, {})
            status = state.get("status", "pending")
            st.markdown(
                '<div class="node"><div class="node-title">'
                f"{ordinal + 1}. {escape(KINDS.get(node.get('tool'), node.get('tool', 'Node')))}"
                '</div><div class="node-status">'
                f"{escape(labels.get(status, status))}</div></div>",
                unsafe_allow_html=True,
            )
            fact_rows({
                "node_id": identifier,
                "depends_on": node.get("depends_on", []),
                "receipt_ref": state.get("receipt_ref"),
            })
        with st.expander(f"Plan {index + 1}: canonical state and audit checkpoint"):
            st.json(snapshot)


def render_result(result: dict[str, Any] | None) -> None:
    if not result:
        return
    status = str(result.get("status", "waiting"))
    receipt = result.get("receipt") or result.get("analysis_receipt")
    exploratory = isinstance(receipt, dict) and receipt.get("trust") == "exploratory"
    if status == "advanced":
        st.info(
            f"Simulated clock advanced to {result.get('clock', '—')} · "
            f"{result.get('events', 0)} due events processed"
        )
    if status in {"redisplay", "drift"}:
        st.warning(
            "Business facts changed · the previous approval is invalid. "
            "Review the new card below and approve again."
        )
    if result.get("results"):
        rows = result["results"]
        rows = rows.values() if isinstance(rows, dict) else rows
        st.write("Execution results by node")
        for row in rows:
            if isinstance(row, dict):
                render_result(row)
        return
    if status in {"settled", "complete", "executed"} and receipt:
        if exploratory:
            st.info(
                "Exploratory analysis ran · question semantics are unverified. "
                "This cannot authorize a payment."
            )
        elif result.get("analysis_receipt"):
            st.success("Analysis complete · computation receipt verified")
        else:
            st.success("Executed · bank receipt verified")
    elif status in {"unknown", "pending"}:
        st.warning(
            "Awaiting reconciliation · do not pay again. "
            "Wait for the bank receipt or operator review."
        )
    elif status in {"handoff", "handed_off"}:
        st.warning("Operator handoff · automatic execution paused")
    elif status == "interrupted":
        st.warning("Interrupted · automatic execution paused")
    elif status == "resumed":
        st.info(
            "Plan resumed within the device-approved scope. "
            "Every subsequent action still requires gateway checks."
        )
    elif status == "no_active_plan":
        st.info("No active plan. No plan was paused and no funds moved.")
    elif status == "no_compensation":
        st.info(
            "No reversible compensation can be generated automatically. "
            "Settled payments cannot be undone directly."
        )
    elif status == "controlled":
        st.info(
            "Control request recorded · see node status and bank receipts "
            "to confirm whether and when a payment occurred."
        )
    elif status in {"redisplay", "drift"}:
        if result.get("card"):
            render_card(result["card"])
    elif status in {"rejected", "refused", "failed", "blocked"}:
        st.error("Action not executed · review the reasons before approving again")
    elif result.get("needs_mfa") or status in {"waiting_mfa", "escalated", "Escalate"}:
        st.warning("Awaiting MFA · complete simulated verification on the Device page")
    elif status != "advanced":
        st.info("Awaiting approval · execution has not completed")
    if result.get("rule_ids"):
        st.caption("Rules: " + " · ".join(result["rule_ids"]))
    if result.get("message") and not exploratory:
        st.write(result["message"])
    if receipt:
        st.markdown('<div id="receipt"></div>', unsafe_allow_html=True)
        if exploratory:
            projection = result.get("facts", {})
            if isinstance(projection, dict):
                if projection.get("status") == "rendered":
                    for fact in projection.get("facts", []):
                        st.write(fact["text"])
                if projection.get("note") or result.get("message"):
                    with st.expander("Assistant note (unverified)", expanded=True):
                        if projection.get("note"):
                            st.write(projection["note"])
                        if result.get("message"):
                            st.write(result["message"])
            with st.expander("Raw exploratory evidence (semantics unverified)", expanded=False):
                st.caption(
                    "Program labels and question semantics are unverified; "
                    "the signature authenticates only the computation source."
                )
                st.json(receipt)
        else:
            with st.expander("Verified receipt", expanded=False):
                st.json(receipt)
        st.markdown("[This receipt](#receipt) · audit chain on the Evidence & Audit page")
        st.button("View audit chain", key=f"audit-link:{H(receipt)}", on_click=open_audit)
    if result.get("audit_checkpoint"):
        with st.expander("Related audit checkpoint"):
            st.json(result["audit_checkpoint"])


def open_audit() -> None:
    st.session_state["supporting_page"] = "None"
    st.session_state["page"] = "Evidence & Audit"
