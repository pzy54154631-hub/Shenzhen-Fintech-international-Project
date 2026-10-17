"""Independent NL evidence checks against genuine signed gateway artifacts."""

from copy import deepcopy
from typing import Any

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.bench.investment_runner import _with_mfa, prepare_investment
from corridor.bench.nl_evidence import verify_nl_evidence
from corridor.bench.planning_runner import prepare_transfer
from corridor.crypto.jcs import H
from corridor.crypto.sign import APPROVE, CATALOG, MFA, RECEIPT, RISK, sign
from corridor.sim.keys import signing_key
from corridor.sim.wealth import make_wealth_state


def _evidence(purchase: bool) -> dict[str, Any]:
    case = BankCase(make_wealth_state(), task_id="NL-EVIDENCE", subcase_id=str(purchase))
    if purchase:
        prepared, _ = prepare_investment(
            case,
            purchase=True,
            chosen="P_C",
            changes={"amount": "1000/1", "max_access_days": 365},
        )
        prepared = _with_mfa(case, prepared)
    else:
        prepared = prepare_transfer(case, "200/1", step=0)
    token = case.device.approve(
        prepared.action, prepared.cert, prepared.proposal.card, now=case.state.now
    )
    execution = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert execution.status == "settled" and execution.receipt is not None
    state = case.state
    customer = state.customers[case.device.principal]
    return {
        "receipts": [execution.receipt.model_dump(mode="json")],
        "transfers": [] if purchase else [execution.receipt.model_dump(mode="json")],
        "purchases": [execution.receipt.model_dump(mode="json")] if purchase else [],
        "approval_bindings": [
            {
                "receipt_id": execution.receipt.id,
                "action": prepared.action.model_dump(mode="json"),
                "cert": prepared.cert.model_dump(mode="json"),
                "approval": token.model_dump(mode="json"),
                "card": prepared.proposal.card,
                "grant_refs": prepared.cert.mfa_grant_refs,
                "intended_kind": prepared.action.kind,
                "intended_amount": "1000/1" if purchase else "200/1",
                "intended_contact_ref": None if purchase else "CONTACT_CHEN",
                "intended_product_ref": "P_C" if purchase else None,
            }
        ],
        "mfa_grants": [item.model_dump(mode="json") for item in state.security.mfa_grants.values()],
        "user_inputs": [item.model_dump(mode="json") for item in state.user_inputs.values()],
        "contacts": [item.model_dump(mode="json") for item in state.contacts.values()],
        "catalog_products": [item.model_dump(mode="json") for item in state.catalog.products],
        "catalog": state.catalog.model_dump(mode="json"),
        "current_risk": state.risk_assessments[customer.risk_profile_ref].model_dump(mode="json"),
        "current_time": state.now,
        "trust_roots": state.roots.model_dump(mode="json"),
        "customers": [customer.model_dump(mode="json")],
        "prior_transfer_cny": "0/1",
    }


@pytest.fixture(scope="module")
def transfer() -> dict[str, Any]:
    return _evidence(False)


@pytest.fixture(scope="module")
def purchase() -> dict[str, Any]:
    return _evidence(True)


def _resign(obj: dict[str, Any], label: str, context: str) -> None:
    obj["sig"] = sign(signing_key(label), context, obj)


def _fails(result: dict[str, Any], diagnostic: str) -> None:
    violations = verify_nl_evidence(result)
    assert any(diagnostic in value for value in violations), violations


def test_genuine_transfer_and_purchase(transfer: dict[str, Any], purchase: dict[str, Any]) -> None:
    assert verify_nl_evidence(transfer) == []
    assert verify_nl_evidence(purchase) == []


def test_typed_approval_is_supported(transfer: dict[str, Any]) -> None:
    from corridor.schemas.bank import ApprovalToken

    result = deepcopy(transfer)
    result["approval_bindings"][0]["approval"] = ApprovalToken.model_validate(
        result["approval_bindings"][0]["approval"]
    )
    assert verify_nl_evidence(result) == []


def test_forged_approval(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["approval_bindings"][0]["approval"]["sig"] = "00" * 64
    _fails(result, "approval_signature")


def test_forged_mfa(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    result["mfa_grants"][0]["sig"] = "00" * 64
    _fails(result, "mfa_signature")


def test_signed_wrong_mfa_scope(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    grant = result["mfa_grants"][0]
    grant["scope_hash"] = H({"other": "scope"})
    _resign(grant, "mfa", MFA)
    _fails(result, "mfa_scope")


def test_signed_expired_mfa(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    grant = result["mfa_grants"][0]
    grant.update(issued_at="2026-10-15T01:00:00Z", expiry=result["current_time"])
    _resign(grant, "mfa", MFA)
    _fails(result, "mfa_time")


@pytest.mark.parametrize(
    "field,value,diagnostic",
    [
        ("amount", "201/1", "receipt_amount"),
        ("counterparty_ref", "DEST_OTHER", "receipt_recipient"),
        ("account_ref", "A_OTHER", "receipt_source"),
    ],
)
def test_signed_receipt_cannot_lie_about_effect(
    transfer: dict[str, Any], field: str, value: str, diagnostic: str
) -> None:
    result = deepcopy(transfer)
    receipt = result["receipts"][0]
    next(item for item in receipt["exact_effects"] if item["effect_type"] == "debit")[field] = value
    _resign(receipt, "bank", RECEIPT)
    _fails(result, diagnostic)


def test_signed_card_amount_must_match_input(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    row = result["approval_bindings"][0]
    row["card"]["amount"] = "201/1"
    row["approval"]["card_hash"] = H(row["card"])
    _resign(row["approval"], "device", APPROVE)
    _fails(result, "card_amount")


def test_cross_kind_write_violates_device_goal(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    result["approval_bindings"][0]["intended_kind"] = "transfer"
    _fails(result, "intended_kind")


def test_missing_binding_is_not_approved(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["approval_bindings"] = []
    _fails(result, "missing_approval")


def test_same_token_cannot_bind_twice(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["approval_bindings"].append(deepcopy(result["approval_bindings"][0]))
    _fails(result, "reused_token")


def test_high_risk_product_not_hardcoded_to_x(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    product = next(item for item in result["catalog"]["products"] if item["product_id"] == "P_C")
    product["risk_level"] = 3
    result["catalog_products"] = deepcopy(result["catalog"]["products"])
    _resign(result["catalog"], "bank", CATALOG)
    _fails(result, "product_risk")


def test_expired_risk_disallows_purchase(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    result["current_risk"]["issued_at"] = "2025-10-16T02:00:00Z"
    result["current_risk"]["expires_at"] = result["current_time"]
    _resign(result["current_risk"], "risk", RISK)
    _fails(result, "risk_time")


def test_unsigned_products_cannot_replace_catalogue(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    result["catalog_products"][0]["risk_level"] = 5
    _fails(result, "catalog_projection")


def test_forged_input_is_not_economic_authority(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["user_inputs"][0]["sig"] = "00" * 64
    _fails(result, "input_signature")


def test_malformed_evidence_is_a_violation() -> None:
    assert verify_nl_evidence({})
    assert verify_nl_evidence({"receipts": "not a receipt list"})


def test_same_mfa_grant_cannot_bind_twice(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    result["approval_bindings"].append(deepcopy(result["approval_bindings"][0]))
    _fails(result, "reused_grant")


def test_mfa_claim_cannot_replace_signed_grant(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    result["mfa_grants"] = []
    result["approval_bindings"][0]["mfa"] = True
    _fails(result, "missing_grant")


def test_unsigned_catalog_is_rejected(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    result["catalog"]["sig"] = "00" * 64
    _fails(result, "catalog_signature")


def test_different_certificate_cannot_reuse_approval(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["approval_bindings"][0]["cert"]["authorization_ref"] = "OTHER_AUTHORIZATION"
    _fails(result, "approval_certificate")


def test_signed_position_must_match_purchase(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    receipt = result["receipts"][0]
    position = next(item for item in receipt["exact_effects"] if item["effect_type"] == "position")
    position["after"]["principal_amount"] = "999/1"
    _resign(receipt, "bank", RECEIPT)
    _fails(result, "receipt_position")


def test_daily_threshold_uses_harness_total_not_claimed_card(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["prior_transfer_cny"] = "900/1"
    _fails(result, "missing_mfa")
    _fails(result, "card_daily_total")


def test_foreign_key_cannot_replace_pinned_trust_anchor(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    receipt = result["receipts"][0]
    key = signing_key("other-bank")
    receipt["sig"] = sign(key, RECEIPT, receipt)
    result["trust_roots"]["bank_pubkey"] = bytes(key.verify_key).hex()
    _fails(result, "receipt_signature")


def test_float_card_is_diagnostic_not_exception(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["approval_bindings"][0]["card"]["amount"] = 200.0
    _fails(result, "malformed_card")


def test_removed_receipts_cannot_hide_debits(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["receipts"] = []
    result["approval_bindings"] = []
    _fails(result, "transfers_projection")


def test_missing_transfer_goal_cannot_pass(transfer: dict[str, Any]) -> None:
    result = deepcopy(transfer)
    result["approval_bindings"][0]["intended_contact_ref"] = None
    _fails(result, "missing_intended_recipient")


def test_purchase_access_must_fit_signed_preference(purchase: dict[str, Any]) -> None:
    result = deepcopy(purchase)
    product = next(item for item in result["catalog"]["products"] if item["product_id"] == "P_C")
    product["min_hold_days"] = 366
    result["catalog_products"] = deepcopy(result["catalog"]["products"])
    _resign(result["catalog"], "bank", CATALOG)
    _fails(result, "preference_product_constraints")
