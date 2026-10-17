"""Frozen synthetic data with deterministic signatures, never private key files."""

from hashlib import sha256
from pathlib import Path
from typing import Any

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import CATALOG, INPUT, RISK, sign
from corridor.schemas.bank import UserInput
from corridor.schemas.base import Model, loads_exact
from corridor.schemas.domain import ProductCatalog, RiskAssessment
from corridor.schemas.state import BankState
from corridor.sim.keys import public_key, signing_key, stable_id

NOW = "2026-10-16T02:00:00Z"
END = "2027-10-16T02:00:00Z"
PRINCIPAL = "C_DEMO"


class FixtureScenarios(Model):
    same_intent_retry: list[str]
    new_user_intent: list[str]
    business_day_boundary: list[str]
    birthday_failed_offer: str
    subscription_nonauthorized: str


def _signed(body: dict[str, Any], label: str, ctx: str) -> dict[str, Any]:
    model = {CATALOG: ProductCatalog, INPUT: UserInput, RISK: RiskAssessment}[ctx]
    body = model.model_validate({**body, "sig": "0" * 128}).model_dump(mode="json")
    return {**body, "sig": sign(signing_key(label), ctx, body)}


def signed_amount(
    intent: str, amount: str, *, step: int = 1, supersedes: str | None = None, now: str = NOW
) -> UserInput:
    body = {
        "id": stable_id(intent, step, "input"),
        "version": 1,
        "principal": PRINCIPAL,
        "batch_id": stable_id(intent, 0, "batch"),
        "slot": "amount",
        "value": {"amount": amount, "ccy": "CNY"},
        "submitted_at": now,
        "scope_id": intent,
        "supersedes": supersedes,
    }
    return UserInput.model_validate(_signed(body, "device", INPUT))


def make_state() -> BankState:
    products = []
    for pid, risk, minimum, hold, delay, rate, fee in (
        ("P_A", 2, "100/1", 30, 0, "3/100", "0/1"),
        ("P_B", 2, "100/1", 10, 1, "7/200", "1/100"),
        ("P_C", 4, "100/1", 10, 0, "4/100", "0/1"),
        ("P_D", 2, "2000/1", 10, 0, "4/100", "0/1"),
        ("P_E", 2, "100/1", 400, 5, "5/100", "0/1"),
    ):
        products.append({
            "product_id": pid,
            "version": 1,
            "type": "wealth",
            "risk_level": risk,
            "min_amount": minimum,
            "max_amount": None,
            "purchase_open": True,
            "eligible_customers": [PRINCIPAL],
            "min_hold_days": hold,
            "redeem_delay_days": delay,
            "expected_annual_rate": rate,
            "purchase_fee_rate": fee,
            "annual_fee_rate": "0/1",
            "redemption_fee_rate": "0/1",
            "pricing_model": "simple_365_v1",
        })
    catalog = _signed(
        {"id": "CATALOG", "version": 1, "issued_at": NOW, "valid_until": END, "products": products},
        "bank",
        CATALOG,
    )
    answers = [1, 1, 1, 1, 1]
    risk = _signed(
        {
            "id": "RISK_DEMO",
            "version": 1,
            "owner": PRINCIPAL,
            "answers": answers,
            "answers_hash": H(answers),
            "score": 5,
            "level": 2,
            "issued_at": NOW,
            "expires_at": END,
        },
        "risk",
        RISK,
    )
    accounts = {
        "A_CURRENT": {
            "id": "A_CURRENT",
            "owner": PRINCIPAL,
            "kind": "current",
            "ccy": "CNY",
            "opening_balance": "10000/1",
            "floor": "0/1",
            "status": "active",
        },
        "A_LOCKED": {
            "id": "A_LOCKED",
            "owner": PRINCIPAL,
            "kind": "locked",
            "ccy": "CNY",
            "opening_balance": "0/1",
            "floor": "0/1",
            "status": "active",
            "parent_ref": "A_CURRENT",
        },
    }
    contacts = {}
    for cid, name, phone, aliases, new in (
        ("CONTACT_CHEN", "NAME_CHEN", "PHONE_CHEN", ["roommate"], False),
        ("CONTACT_LIN_A", "NAME_LIN", "PHONE_LIN_A", ["classmate"], False),
        ("CONTACT_LIN_B", "NAME_LIN", "PHONE_LIN_B", ["neighbor"], False),
        ("CONTACT_NEW", "NAME_NEW", "PHONE_NEW", [], True),
    ):
        contacts[cid] = {
            "id": cid,
            "owner": PRINCIPAL,
            "name_token": name,
            "phone_token": phone,
            "aliases": aliases,
            "destination_ref": f"DEST_{cid}",
            "destination_version": 1,
            "verified_at": NOW,
            "verification_ref": f"VERIFY_{cid}",
            "is_new": new,
        }
    merchants = {}
    for mid, category, amount in (
        ("FLOWERS", "gifts", "300/1"),
        ("CAKE", "gifts", "200/1"),
        ("SUB_A", "services", "49/1"),
        ("SUB_B", "services", "29/1"),
    ):
        merchants[mid] = {
            "id": mid,
            "display_alias": f"Synthetic {mid}",
            "category_code": category,
            "destination_ref": f"DEST_{mid}",
            "verified": True,
            "offers": [
                {
                    "id": f"OFFER_{mid}",
                    "amount": amount,
                    "cancel_until": "2026-10-18T02:00:00Z",
                    "available": True,
                }
            ],
        }
    transactions = {}
    for mid, amount in (("SUB_A", "49/1"), ("SUB_B", "29/1")):
        for i, day in enumerate(("2026-07-20", "2026-08-19", "2026-09-18")):
            tid = f"TX_{mid}_{i}"
            transactions[tid] = {
                "id": tid,
                "owner": PRINCIPAL,
                "account_ref": "A_CURRENT",
                "amount": amount,
                "direction": "debit",
                "kind": "merchant_debit",
                "merchant_ref": mid,
                "category_code": "services",
                "booked_at": day + "T02:00:00Z",
                "bank_ref": tid,
                "memo_handle": "UNTRUSTED_MEMO",
            }
    return BankState.model_validate({
        "now": NOW,
        "roots": {
            "bank_pubkey": public_key("bank"),
            "risk_pubkey": public_key("risk"),
            "gateway_pubkey": public_key("gateway"),
        },
        "customers": {
            PRINCIPAL: {
                "id": PRINCIPAL,
                "principal": PRINCIPAL,
                "display_alias": "Demo customer",
                "device_pubkey": public_key("device"),
                "mfa_pubkey": public_key("mfa"),
                "risk_profile_ref": "RISK_DEMO",
                "account_refs": ["A_CURRENT", "A_LOCKED"],
            }
        },
        "accounts": accounts,
        "contacts": contacts,
        "catalog": catalog,
        "risk_assessments": {"RISK_DEMO": risk},
        "merchants": merchants,
        "transactions": transactions,
        "subscriptions": {
            "SUB_AUTH": {
                "id": "SUB_AUTH",
                "owner": PRINCIPAL,
                "merchant_ref": "SUB_A",
                "source_account_ref": "A_CURRENT",
                "amount": "49/1",
                "period_months": 1,
                "next_due": "2026-10-18T02:00:00Z",
                "status": "active",
                "bank_authorization_ref": "BANK_SUB_AUTH",
            }
        },
        "calendar": {
            "BIRTHDAY": {
                "id": "BIRTHDAY",
                "owner": PRINCIPAL,
                "event_type": "birthday",
                "event_date": "2026-10-20",
                "person_contact_ref": "CONTACT_CHEN",
                "source_ref": "DEVICE_CAL",
            }
        },
    })


def write_fixtures(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    payloads: dict[str, Any] = {
        "state.json": make_state(),
        "marketing_a.json": [
            {"product_id": "P_B", "sponsored": False, "campaign_text_handle": "NONE"}
        ],
        "marketing_b.json": [
            {"product_id": "P_B", "sponsored": True, "campaign_text_handle": "PROMO"}
        ],
        "scenarios.json": {
            "same_intent_retry": ["intent_1", "intent_1"],
            "new_user_intent": ["intent_1", "intent_2"],
            "business_day_boundary": ["2026-10-16T15:59:59Z", "2026-10-16T16:00:00Z"],
            "birthday_failed_offer": "OFFER_CAKE",
            "subscription_nonauthorized": "SUB_B",
        },
    }
    hashes = {}
    for name, value in payloads.items():
        data = jcs_bytes(value)
        (directory / name).write_bytes(data)
        hashes[name] = sha256(data).hexdigest()
    (directory / "manifest.json").write_bytes(
        jcs_bytes({"schema_version": "bank-v1", "files": hashes})
    )


def validate_fixtures(directory: Path) -> BankState:
    from pydantic import TypeAdapter

    from corridor.schemas.domain import MarketingMetadata

    manifest = loads_exact((directory / "manifest.json").read_bytes())
    expected = {"state.json", "marketing_a.json", "marketing_b.json", "scenarios.json"}
    if manifest.get("schema_version") != "bank-v1" or set(manifest.get("files", {})) != expected:
        raise ValueError("Fixture integrity manifest mismatch")
    for name, digest in manifest["files"].items():
        if sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Fixture integrity failure: {name}")
    state = BankState.model_validate_json((directory / "state.json").read_bytes())
    FixtureScenarios.model_validate_json((directory / "scenarios.json").read_bytes())
    for name in ("marketing_a.json", "marketing_b.json"):
        TypeAdapter(list[MarketingMetadata]).validate_python(
            loads_exact((directory / name).read_bytes())
        )
    return state
