"""Bank domain contracts reject invalid money, states and signed-data shapes."""

from fractions import Fraction

import pytest
from pydantic import ValidationError

from corridor.crypto.jcs import jcs_bytes
from corridor.schemas import domain as d
from corridor.schemas.base import Model

NOW = "2026-10-16T02:00:00Z"
END = "2026-11-16T02:00:00Z"
HASH = "a" * 64
SIG = "b" * 128


def product(**changes: object) -> d.Product:
    body = {
        "product_id": "P_A",
        "type": "wealth",
        "risk_level": 2,
        "min_amount": "100/1",
        "max_amount": None,
        "purchase_open": True,
        "eligible_customers": ["C"],
        "min_hold_days": 30,
        "redeem_delay_days": 0,
        "expected_annual_rate": "3/100",
        "purchase_fee_rate": "0/1",
        "annual_fee_rate": "0/1",
        "redemption_fee_rate": "0/1",
        "pricing_model": "simple_365_v1",
    }
    body.update(changes)
    return d.Product.model_validate(body)


def domain_samples() -> list[Model]:
    return [
        d.Customer(
            id="C",
            principal="C",
            display_alias="Demo customer",
            device_pubkey=HASH,
            mfa_pubkey=HASH,
            risk_profile_ref=None,
            account_refs=["A"],
            credential_version=1,
        ),
        d.Account(
            id="A",
            owner="C",
            kind="current",
            ccy="CNY",
            opening_balance=Fraction(10000),
            floor=Fraction(0),
            status="active",
        ),
        d.Contact(
            id="P",
            owner="C",
            name_token="NAME_1",
            phone_token="PHONE_1",
            aliases=["friend"],
            destination_ref="D",
            destination_version=1,
            verified_at=NOW,
            verification_ref="V",
            is_new=False,
        ),
        d.Transaction(
            id="T",
            owner="C",
            account_ref="A",
            amount=Fraction(10),
            direction="debit",
            kind="merchant_debit",
            status="settled",
            merchant_ref="M",
            category_code="food",
            booked_at=NOW,
            bank_ref="BT",
            memo_handle="MEMO_1",
        ),
        d.Card(
            id="K",
            owner="C",
            account_ref="A",
            kind="virtual",
            status="active",
            limit=Fraction(1000),
            restrictions=[],
            card_token="CARD_1",
        ),
        d.SubscriptionAuthorization(
            id="U",
            owner="C",
            merchant_ref="M",
            source_account_ref="A",
            amount=Fraction(49),
            period_months=1,
            next_due=END,
            status="active",
            bank_authorization_ref="BU",
        ),
        d.Position(
            id="P1",
            owner="C",
            product_ref="P_A",
            principal_amount=Fraction(1000),
            units=Fraction(1000),
            reserved_units=Fraction(0),
            nav=Fraction(1),
            acquired_at=NOW,
            redeemable_at=END,
            status="active",
        ),
        d.ScheduledTask(
            id="S",
            owner="C",
            plan_id="PLAN",
            node_id="NODE",
            spa_ref="SPA",
            run_index=0,
            action_template={"kind": "transfer"},
            input_refs=[],
            due_at=NOW,
            expires_at=END,
            commitment_id="COMMIT",
            status="pending",
        ),
        d.Merchant(
            id="M",
            display_alias="Demo florist",
            category_code="gifts",
            destination_ref="D",
            verified=True,
            offers=[
                d.MerchantOffer(id="O", amount=Fraction(300), cancel_until=END, available=True)
            ],
        ),
        d.MerchantOrder(
            id="O1",
            owner="C",
            merchant_ref="M",
            offer_ref="O",
            amount=Fraction(300),
            status="draft",
        ),
        d.CalendarEvent(
            id="E",
            owner="C",
            event_type="birthday",
            event_date="2026-10-20",
            person_contact_ref="P",
            source_ref="INPUT",
        ),
        d.RiskAssessment(
            id="R",
            owner="C",
            answers_hash=HASH,
            answers=[1, 1, 1, 1, 1],
            score=5,
            level=2,
            issued_at=NOW,
            expires_at=END,
            sig=SIG,
        ),
        product(),
        d.ProductCatalog(id="CAT", issued_at=NOW, valid_until=END, products=[product()], sig=SIG),
        d.InvestmentPreference(
            id="PREF",
            source_account_ref="A",
            amount=Fraction(1000),
            horizon_days=365,
            max_access_days=3,
            allowed_types=["wealth"],
            objective="net_return",
            selection_mode="default",
        ),
        d.MarketingMetadata(product_id="P_A", sponsored=True, campaign_text_handle="AD_1"),
    ]


@pytest.mark.parametrize("index", range(16))
def test_domain_roundtrip_is_canonical(index: int) -> None:
    original = domain_samples()[index]
    restored = type(original).model_validate_json(original.model_dump_json())
    assert original == restored
    assert jcs_bytes(original) == jcs_bytes(restored)


@pytest.mark.parametrize("value", ["-1/1", "1/1000", 1, True, 0.25])
def test_account_rejects_invalid_amount_wire_values(value: object) -> None:
    body = domain_samples()[1].model_dump(mode="json")
    body["opening_balance"] = value
    with pytest.raises(ValidationError):
        d.Account.model_validate(body)


def test_domain_rejects_unknown_fields_and_non_cny() -> None:
    body = domain_samples()[1].model_dump(mode="json")
    for field, value in [("ccy", "USD"), ("balance", "10000/1")]:
        with pytest.raises(ValidationError):
            d.Account.model_validate({**body, field: value})


def test_locked_account_and_position_constraints() -> None:
    body = domain_samples()[1].model_dump(mode="json")
    with pytest.raises(ValidationError):
        d.Account.model_validate({**body, "kind": "locked"})
    assert d.Account.model_validate({**body, "kind": "locked", "parent_ref": "P"})
    position = domain_samples()[6].model_dump(mode="json")
    with pytest.raises(ValidationError):
        d.Position.model_validate({**position, "reserved_units": "1001/1"})


@pytest.mark.parametrize(
    "updates",
    [
        {"max_amount": "99/1"},
        {"risk_level": 6},
        {"min_hold_days": -1},
        {"purchase_fee_rate": "-1/1"},
        {"sponsored": True},
        {"pricing_model": "unknown"},
    ],
)
def test_product_rejects_invalid_contracts(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        product(**updates)


def test_catalog_rejects_duplicates_and_invalid_lifetime() -> None:
    body = domain_samples()[13].model_dump(mode="json")
    with pytest.raises(ValidationError):
        d.ProductCatalog.model_validate({**body, "products": [product(), product()]})
    with pytest.raises(ValidationError):
        d.ProductCatalog.model_validate({**body, "valid_until": NOW})


def test_calendar_and_risk_require_real_dates_and_valid_questionnaire() -> None:
    calendar = domain_samples()[10].model_dump(mode="json")
    with pytest.raises(ValidationError):
        d.CalendarEvent.model_validate({**calendar, "event_date": "2026-02-30"})
    risk = domain_samples()[11].model_dump(mode="json")
    for updates in [{"answers": [1]}, {"answers": [5, 1, 1, 1, 1]}, {"expires_at": NOW}]:
        with pytest.raises(ValidationError):
            d.RiskAssessment.model_validate({**risk, **updates})


def test_explicit_preference_cannot_omit_selected_product() -> None:
    body = domain_samples()[14].model_dump(mode="json")
    with pytest.raises(ValidationError):
        d.InvestmentPreference.model_validate({**body, "selection_mode": "explicit"})


def test_unverified_contact_is_representable_without_fake_verification() -> None:
    body = domain_samples()[2].model_dump(mode="json")
    contact = d.Contact.model_validate({**body, "verified_at": None, "verification_ref": None})
    assert contact.verified_at is None
    assert contact.verification_ref is None


def test_state_rejects_private_or_untrusted_top_level_fields() -> None:
    from corridor.schemas.state import BankState, Policy, Security, TrustRoots

    state = BankState(
        now=NOW,
        policy=Policy(),
        roots=TrustRoots(bank_pubkey=HASH, risk_pubkey=HASH, gateway_pubkey=HASH),
        catalog=domain_samples()[13],
        security=Security(),
    )
    assert BankState.model_validate_json(state.model_dump_json()) == state
    for forbidden in ["pii_vault", "marketing", "financial_versions"]:
        with pytest.raises(ValidationError):
            BankState.model_validate({**state.model_dump(mode="json"), forbidden: {}})


@pytest.mark.parametrize(
    "collection,index",
    [
        ("customers", 0),
        ("accounts", 1),
        ("contacts", 2),
        ("transactions", 3),
        ("cards", 4),
        ("subscriptions", 5),
        ("positions", 6),
        ("schedules", 7),
        ("merchants", 8),
        ("orders", 9),
        ("calendar", 10),
        ("risk_assessments", 11),
    ],
)
def test_state_rejects_identity_aliases(collection: str, index: int) -> None:
    from corridor.schemas.state import BankState

    body = {
        "now": NOW,
        "roots": {"bank_pubkey": HASH, "risk_pubkey": HASH, "gateway_pubkey": HASH},
        "catalog": domain_samples()[13].model_dump(mode="json"),
        collection: {"WRONG_KEY": domain_samples()[index].model_dump(mode="json")},
    }
    with pytest.raises(ValidationError, match="identity"):
        BankState.model_validate(body)


def test_state_rejects_receipt_and_authorization_aliases() -> None:
    from corridor.schemas.bank import BankReceipt, SessionAuthorization
    from corridor.schemas.state import BankState

    base = {
        "now": NOW,
        "roots": {"bank_pubkey": HASH, "risk_pubkey": HASH, "gateway_pubkey": HASH},
        "catalog": domain_samples()[13].model_dump(mode="json"),
    }
    receipt = BankReceipt(
        receipt_id="R",
        intent_key=HASH,
        kind="transfer",
        status="failed",
        exact_effects=[],
        executed_at=NOW,
        sig=SIG,
    )
    authorization = SessionAuthorization(
        id="A",
        principal="C",
        device_session_id="S",
        read_kinds=["balance_query"],
        expires_at=END,
        sig=SIG,
    )
    for collection, record in [("receipts", receipt), ("authorizations", authorization)]:
        with pytest.raises(ValidationError, match="identity"):
            BankState.model_validate({**base, collection: {"ALIAS": record}})


def test_customer_principal_must_match_identity() -> None:
    body = domain_samples()[0].model_dump(mode="json")
    with pytest.raises(ValidationError, match="identity"):
        d.Customer.model_validate({**body, "principal": "OTHER"})
