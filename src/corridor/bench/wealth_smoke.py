"""W04 dialogue smoke with explicit synthetic device gestures and real W2 execution."""

from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from typing import Any

from corridor.agent.llm import LLMClient
from corridor.agent.wealth_dialogue import (
    PreparedAllocationComparison,
    WealthCandidate,
    WealthConversation,
)
from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import RECEIPT, verify
from corridor.gateway.allocations import (
    advance_allocation,
    allocation_snapshot,
    draft_allocation,
    register_allocation,
)
from corridor.gateway.audit import AuditLog
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.runtime import create_gateway
from corridor.schemas.bank import AllocationArgs, BankAction, BankCertificate, BankReceipt
from corridor.schemas.money import fraction_string
from corridor.sim.keys import signing_key, stable_id
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.sim.wealth_device import WealthDevice
from corridor.stores.bank import BankStore, add_seconds, available


def make_wealth_conversation(
    *,
    client: LLMClient,
    evidence_dir: Path | None = None,
) -> tuple[WealthConversation, WealthDevice]:
    gateway = create_gateway(
        BankStore(make_wealth_state()),
        bank_key=signing_key("bank"),
        gateway_key=signing_key("gateway"),
        risk_key=signing_key("risk"),
        audit=AuditLog(),
        mfa=MFAVerifier(signing_key("mfa")),
        evidence_dir=evidence_dir / "pdr" if evidence_dir else None,
    )
    device = WealthDevice()
    session_id = stable_id("W04", 0, "device-session")
    authorization = device.login(
        session_id=session_id,
        expires_at=add_seconds(gateway.store.snapshot().now, 3600),
    )
    if gateway.login(authorization).status != "accepted":
        raise ValueError("Synthetic wealth device login failed")
    return WealthConversation(
        gateway,
        client,
        principal=device.principal,
        session_id=session_id,
    ), device


def confirm_wealth_goal(
    chat: WealthConversation,
    device: WealthDevice,
    candidate: WealthCandidate,
) -> PreparedAllocationComparison:
    """Explicit synthetic user answer; the dialogue has no device signing authority.

    The user chooses A_CURRENT, CNY 10,000, 365 days, cash access within three
    days, zero required liquid principal, wealth products, and projected net
    return. This gesture confirms comparison goals and does not approve purchase.
    """
    value = device.confirm_input(
        intent_id=candidate.intent_id,
        slot="allocation",
        value=allocation_request().model_dump(mode="json"),
        now=chat.state.now,
    )
    return chat.compare(candidate, value)


def _purchases(chat: WealthConversation) -> list[BankReceipt]:
    return [
        item
        for item in chat.state.receipts.values()
        if isinstance(item, BankReceipt) and item.kind == "purchase_product"
    ]


def _execute_confirmed_items(
    chat: WealthConversation,
    device: WealthDevice,
    comparison: PreparedAllocationComparison,
) -> tuple[dict[str, Any], list[str], int]:
    gateway = chat.gateway
    if not isinstance(comparison.action.args, AllocationArgs) or gateway.mfa is None:
        raise ValueError("Allocation comparison or MFA verifier unavailable")
    draft = draft_allocation(
        gateway,
        chat.principal,
        comparison.action.intent_id,
        comparison.action.args.request_ref,
    )
    # The synthetic user explicitly checks every displayed item. The model does
    # not choose this list and cannot call this controller through its schema.
    selected = [item.item_ref for item in draft.parent.items]
    signed = device.sign_allocation(draft, selected_items=selected, now=chat.state.now)
    registered = register_allocation(
        gateway,
        draft,
        selection=signed.selection,
        inputs=signed.inputs,
        authorizations=signed.authorizations,
    )
    if registered.status != "ready":
        raise ValueError(f"Allocation registration failed: {registered.rule_ids}")
    before_approval = len(_purchases(chat))
    grants = []
    for sequence, _ in enumerate(draft.parent.items):
        prepared = advance_allocation(gateway, draft.parent.id)
        if prepared.status not in {"waiting_mfa", "waiting_approval"}:
            raise ValueError(f"Allocation preparation failed: {prepared.rule_ids}")
        action = BankAction.model_validate(prepared.details["action"])
        cert = BankCertificate.model_validate(prepared.details["cert"])
        request_id = H({"action": action, "cert": cert})
        challenge = gateway.request_mfa(action, cert, request_id=request_id)
        if challenge is None:
            raise ValueError("Allocation MFA challenge unavailable")
        # Separate explicit device gestures are required for every current card.
        grant = device.complete_mfa(gateway.mfa, challenge, now=chat.state.now)
        if grant is None or gateway.submit_mfa(grant).status != "accepted":
            raise ValueError("Allocation MFA grant rejected")
        grants.append(grant.grant_id)
        cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
        proposal = gateway.propose(action, cert, request_id=request_id)
        if proposal.verdict.outcome == "Reject" or proposal.verdict.tier != "red":
            raise ValueError("Allocation approval card rejected")
        token = device.approve(action, cert, proposal.card, now=chat.state.now, sequence=sequence)
        result = gateway.dispatch(action, cert, token)
        if result.status != "settled" or result.receipt is None:
            raise ValueError(f"Allocation dispatch failed: {result.rule_ids}")
    return allocation_snapshot(gateway, draft.parent.id), grants, before_approval


def run_w04(
    client: LLMClient,
    evidence_dir: Path | None = None,
    *,
    execute: bool = True,
) -> dict[str, Any]:
    """Run three real model stages on a shared budget; W4 formal judge is separate."""
    start_calls, start_api = len(client.calls), client.api_calls
    chat, device = make_wealth_conversation(client=client, evidence_dir=evidence_dir)
    initial_hash = H(chat.state)
    candidate = chat.receive("I want something safe.", request_id="W04-vague-goal")
    before_user = len(_purchases(chat))
    comparison = confirm_wealth_goal(chat, device, candidate)
    receipt = comparison.result.analysis_receipt
    biac = comparison.cert.allocation
    if receipt is None or biac is None:
        raise ValueError("W04 comparison lacks its signed receipt or BIAC")
    narrative = chat.narrative(receipt.id)
    snapshot: dict[str, Any] = {"status": "comparison_only"}
    grants: list[str] = []
    before_approval = len(_purchases(chat))
    if execute:
        snapshot, grants, before_approval = _execute_confirmed_items(chat, device, comparison)
    purchases = _purchases(chat)
    calls = client.calls[start_calls:]
    sources = [row["source"] for row in calls]
    required_source = {"live": "live", "record": "live-recorded"}.get(client.mode)
    positions = {item.product_ref: item.principal_amount for item in chat.state.positions.values()}
    exact_comparison = (
        [(item.product_id, item.principal) for item in biac.allocation]
        == [("P_A", Fraction(5000)), ("P_C", Fraction(5000))]
        and biac.totals.principal == 10000
        and biac.totals.fee_buy == 0
        and biac.totals.projected_net == 350
    )
    passed = (
        before_user == before_approval == 0
        and exact_comparison
        and comparison.result.status == "settled"
        and narrative.status == "rendered"
        and verify(chat.state.roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
        and chat.gateway.audit.verify()
        and all(verify(chat.state.roots.bank_pubkey, RECEIPT, item, item.sig) for item in purchases)
        and (
            not execute
            and not purchases
            and not chat.state.allocation_plans
            or execute
            and snapshot["status"] == "completed"
            and len(purchases) == len(set(grants)) == 2
            and all(item.status == "settled" for item in purchases)
            and positions == {"P_A": 5000, "P_C": 5000}
            and available(chat.state, "A_CURRENT") == 2000
        )
        and (required_source is None or all(source == required_source for source in sources))
    )
    result = {
        "task_id": "W04",
        "passed": passed,
        "planner_mode": client.mode,
        "scope": "W6 dialogue smoke; W4 formal wealth judge not run",
        "sources": sources,
        "llm_calls": calls,
        "api_calls": client.api_calls - start_api,
        "input_tokens": sum(row.get("input_tokens", 0) for row in calls),
        "output_tokens": sum(row.get("output_tokens", 0) for row in calls),
        "comparison_receipt_id": receipt.id,
        "biac_hash": H(biac),
        "purchase_dispatches": len(purchases),
        "purchase_receipt_ids": [item.id for item in purchases],
        "mfa_grant_ids": grants,
        "before_user_confirmation_purchases": before_user,
        "before_item_approval_purchases": before_approval,
        "principal": fraction_string(biac.totals.principal),
        "buy_fees": fraction_string(biac.totals.fee_buy),
        "projected_net": fraction_string(biac.totals.projected_net),
        "balance": fraction_string(available(chat.state, "A_CURRENT")),
        "execution_status": snapshot["status"],
        "clarification": candidate.question,
        "narrative": narrative.text,
        "audit_checkpoint": chat.gateway.audit.checkpoint(),
    }
    chat.gateway.vault.ensure_safe(result, rule="PII-OUT")
    if evidence_dir is not None:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        source_root = Path(__file__).resolve().parents[1]
        code_hash = H({
            path.relative_to(source_root).as_posix(): sha256(path.read_bytes()).hexdigest()
            for path in sorted(source_root.rglob("*.py"))
        })
        artifacts = {
            "result": result,
            "comparison_receipt": receipt,
            "purchase_receipts": purchases,
            "allocation_snapshot": snapshot,
            "audit.checkpoint": chat.gateway.audit.checkpoint(),
            "manifest": {
                "task_id": "W04",
                "scope": result["scope"],
                "initial_hash": initial_hash,
                "final_hash": H(chat.state),
                "sources": sources,
                "code_hash": code_hash,
                "model_profile": {
                    "model": client.model,
                    "api": client.api,
                    "reasoning_effort": client.reasoning_effort,
                    "max_output_tokens": client.max_output_tokens,
                    "config": client.config,
                    "user_policy": client.user_policy,
                },
                "passed": passed,
                "biac_hash": H(biac),
                "comparison_receipt_hash": H(receipt),
                "purchase_receipt_hashes": [H(item) for item in purchases],
            },
        }
        for name, value in artifacts.items():
            chat.gateway.vault.ensure_safe(value, rule="PII-OUT")
            (evidence_dir / f"{name}.json").write_bytes(jcs_bytes(value))
        (evidence_dir / "audit.jsonl").write_bytes(
            b"".join(jcs_bytes(item) + b"\n" for item in chat.gateway.audit.records())
        )
    return result
