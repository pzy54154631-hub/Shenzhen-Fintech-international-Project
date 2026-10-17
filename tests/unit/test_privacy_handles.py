import pytest

from corridor.gateway.handles import available_handles, find_contacts
from corridor.gateway.privacy import PIIVault
from corridor.sim.device import Device
from corridor.sim.fixtures import make_state
from corridor.stores.bank import add_seconds


@pytest.mark.rule("PII-CTX")
def test_known_and_unknown_numeric_pii_are_tokenized_deterministically():
    vault = PIIVault({"NAME_CHEN": "小陈", "PHONE_CHEN": "13900001001"})
    text = "给小陈13900001001转200元，另一个账号6222 0000 1234 5678"
    safe = vault.tokenize(text)
    assert "NAME_CHEN" in safe and "PHONE_CHEN" in safe and "200元" in safe
    assert "小陈" not in safe and "13900001001" not in safe and "6222" not in safe
    assert PIIVault({"NAME_CHEN": "小陈", "PHONE_CHEN": "13900001001"}).tokenize(text) == safe
    vault.ensure_safe({"text": safe})
    with pytest.raises(ValueError, match="PII-CTX") as error:
        vault.ensure_safe({"prompt": text})
    assert str(error.value) == "PII-CTX"
    assert "小陈" not in repr(vault)


@pytest.mark.parametrize(
    "raw",
    [
        "13812345678",
        "6222000012345678",
        "138-1234-5678",
        "１３８１２３４５６７８",
        "account13812345678",
        "ID_6222000012345678",
        "138.1234.5678",
        "(138)/1234/5678",
        "138\u200b1234\u200d5678",
        "6222\u20600000\u20601234\u20605678",
    ],
)
def test_numeric_pii_never_passes_output_scan(raw):
    vault = PIIVault()
    with pytest.raises(ValueError, match="PII-OUT"):
        vault.ensure_safe(raw, rule="PII-OUT")
    vault.ensure_safe(vault.tokenize(raw), rule="PII-OUT")


def _session_state():
    state = make_state()
    auth = Device().login(session_id="SESSION_HANDLES", expires_at=add_seconds(state.now, 300))
    return state.model_copy(
        update={
            "authorizations": {auth.id: auth},
            "security": state.security.model_copy(
                update={"active_device_sessions": {"C_DEMO": "SESSION_HANDLES"}}
            ),
        }
    )


@pytest.mark.rule("READ-ROLE")
def test_handles_need_active_signed_session_and_preserve_ambiguity():
    state = _session_state()
    views = available_handles(state, "C_DEMO", "SESSION_HANDLES")
    assert {view.id for view in find_contacts(views, "NAME_LIN")} == {
        "CONTACT_LIN_A",
        "CONTACT_LIN_B",
    }
    assert [view.id for view in find_contacts(views, "PHONE_CHEN")] == ["CONTACT_CHEN"]
    assert [view.id for view in find_contacts(views, "roommate")] == ["CONTACT_CHEN"]
    assert find_contacts(views, "UNTRUSTED_MEMO") == []
    for principal, session in [("OTHER", "SESSION_HANDLES"), ("C_DEMO", "OTHER")]:
        with pytest.raises(ValueError, match="READ-ROLE") as error:
            available_handles(state, principal, session)
        assert str(error.value) == "READ-ROLE"


def test_handles_never_expose_transaction_memos_and_recheck_shallow_models():
    state = _session_state()
    views = available_handles(state, "C_DEMO", "SESSION_HANDLES")
    assert "UNTRUSTED_MEMO" not in str(views)
    auth = next(iter(state.authorizations.values()))
    bad = auth.model_copy(update={"sig": "0" * 128})
    state = state.model_copy(update={"authorizations": {bad.id: bad}})
    with pytest.raises(ValueError, match="READ-ROLE"):
        available_handles(state, "C_DEMO", "SESSION_HANDLES")


def test_gateway_rejects_raw_private_inputs_before_store_or_audit():
    from tests.gateway_cases import gateway_case

    gateway, device, action, cert = gateway_case()
    gateway.vault = PIIVault({"NAME_CHEN": "小陈"})
    raw = device.confirm_input(
        intent_id="PRIVATE", slot="purpose", value="联系小陈", now=gateway.store.snapshot().now
    )
    assert gateway.submit_input(raw).rule_ids == ["PII-CTX"]
    assert raw.id not in gateway.store.snapshot().user_inputs
    poisoned = action.model_copy(update={"action_id": "13900001001"})
    assert gateway.propose(poisoned, cert).verdict.rule_ids == ["PII-CTX"]
    assert gateway.dispatch(poisoned, cert).rule_ids == ["PII-CTX"]
    assert "小陈" not in str(gateway.audit.records())
    assert "13900001001" not in str(gateway.audit.records())


def test_gateway_output_guard_rejects_sensitive_state_projection():
    from tests.bank_cases import recertify
    from tests.gateway_cases import gateway_case

    gateway, _, action, cert = gateway_case()
    state = gateway.store.snapshot()
    contact = state.contacts["CONTACT_CHEN"].model_copy(update={"destination_ref": "13900001001"})
    gateway.store.update(contacts={**state.contacts, contact.id: contact})
    action, cert, _ = recertify(action, cert, gateway.store.snapshot())
    proposal = gateway.propose(action, cert)
    assert proposal.verdict.rule_ids == ["PII-OUT"]
    assert proposal.card == {}


@pytest.mark.parametrize(
    "raw",
    [
        "synthetic@example.invalid",
        "password:demonstration-secret",
        "验证码:123456",
        "api_key:synthetic-key",
        "动态码654321",
        "校验码是654321",
        "短信码为654321",
        "one-time code is 654321",
        "passcode654321",
        "PIN:654321",
        "otp:synthetic-code",
        "-----BEGIN PRIVATE KEY-----synthetic-incomplete-key",
    ],
)
def test_email_and_labeled_secrets_are_quarantined(raw):
    vault = PIIVault()
    with pytest.raises(ValueError, match="PII-CTX"):
        vault.ensure_safe(raw)
    tokenized = vault.tokenize(raw)
    assert raw not in tokenized
    vault.ensure_safe(tokenized)


@pytest.mark.parametrize("key", ["otp", "password", "pin", "private_key", "api_key", "raw_phone"])
def test_secret_fields_are_rejected_without_exposing_their_values(key):
    with pytest.raises(ValueError, match="^PII-CTX$"):
        PIIVault().ensure_safe({key: "synthetic-private-value"})
    PIIVault().ensure_safe({"phone_token": "PHONE_CHEN", "credential_version": 1})


def test_hex_padding_does_not_hide_unknown_phone_as_plain_text():
    with pytest.raises(ValueError, match="PII-CTX"):
        PIIVault().ensure_safe("13900001001" + "a" * 21)


@pytest.mark.parametrize(
    "separator", [".", "/", "()", "\u200b", "\u200d", "\u2060", "\u202e", "\t"]
)
def test_formatted_private_values_keep_mapped_token_and_surrounding_text(separator):
    vault = PIIVault({"PHONE_CHEN": "13900001001", "ACCOUNT_TEST": "AC6222000012345678"})
    phone = separator.join(["139", "0000", "1001"])
    account = separator.join(["AC", "6222", "0000", "1234", "5678"])
    raw = f"给{phone}转200元，账号{account}。"
    with pytest.raises(ValueError, match="^PII-CTX$"):
        vault.ensure_safe(raw)
    safe = vault.tokenize(raw)
    assert safe == "给PHONE_CHEN转200元,账号ACCOUNT_TEST。"
    assert vault.tokenize(safe) == safe
    vault.ensure_safe(safe)


def test_numeric_privacy_projection_preserves_safe_ids_and_amounts():
    vault = PIIVault()
    for raw in ["给PII_1234567890123456转200元", "139a0000b1001", "2026-10-16T08:00:00Z"]:
        assert vault.tokenize(raw) == raw
        vault.ensure_safe(raw)
