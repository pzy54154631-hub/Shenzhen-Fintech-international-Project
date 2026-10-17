"""Display language must never confer authority or change receipt verification."""

from contextvars import Context
from string import Formatter

import pytest

from corridor.crypto.jcs import H
from corridor.gateway.facts import render_narrative
from corridor.gateway.output_guard import guard_prose, render_guarded
from corridor.gateway.privacy import PIIVault
from corridor.i18n import get_locale, reset_locale, set_locale, tr
from corridor.messages import MESSAGES
from corridor.schemas.narrative import FactRef, Narrative
from corridor.schemas.state import ApprovalRequest
from tests.gateway_cases import approve, gateway_case
from tests.wealth_execution_cases import wealth_execution_case


@pytest.fixture(autouse=True)
def restore_locale():
    token = set_locale(None)
    yield
    reset_locale(token)


def test_default_locale_and_context_isolation(monkeypatch):
    monkeypatch.delenv("CORRIDOR_LOCALE", raising=False)
    assert Context().run(get_locale) == "en"
    monkeypatch.setenv("CORRIDOR_LOCALE", "en")
    assert Context().run(get_locale) == "en"
    set_locale("zh-CN")
    assert get_locale() == "zh-CN"
    assert Context().run(get_locale) == "en"
    with pytest.raises(ValueError):
        set_locale("unsupported")
    monkeypatch.setenv("CORRIDOR_LOCALE", "unsupported")
    assert Context().run(get_locale) == "en"


def test_bilingual_catalog_and_named_formatting():
    catalog = {"greeting": {"zh-CN": "你好，{name}", "en": "Hello, {name}"}}
    assert tr("greeting", locale="zh-CN", catalog=catalog, name="C_DEMO") == "你好，C_DEMO"
    assert tr("greeting", locale="en", catalog=catalog, name="C_DEMO") == "Hello, C_DEMO"
    with pytest.raises(KeyError):
        tr("missing", catalog=catalog)


def test_gateway_catalog_has_complete_locales_and_matching_placeholders():
    formatter = Formatter()
    for variants in MESSAGES.values():
        assert set(variants) == {"zh-CN", "en"}
        placeholders = [
            {field for _, field, _, _ in formatter.parse(text) if field is not None}
            for text in variants.values()
        ]
        assert placeholders[0] == placeholders[1]


def _render_both(narrative, state):
    outputs = []
    for locale in ("zh-CN", "en"):
        set_locale(locale)
        outputs.append(render_narrative(narrative, state, "C_DEMO", PIIVault()))
    return outputs


def _projection(result):
    return [
        fact.model_dump(include={"receipt_ref", "field", "exact_value"}) for fact in result.facts
    ]


def test_localized_facts_preserve_receipts_canonical_cards_and_hashes():
    gateway, device, action, cert = gateway_case()
    set_locale("zh-CN")
    before = gateway.propose(action, cert)
    set_locale("en")
    after = gateway.propose(action, cert)
    assert before.card == after.card
    assert H(before.card) == H(after.card)
    result = gateway.dispatch(action, cert, approve(gateway, device, action, cert))
    assert result.status == "settled" and result.receipt is not None
    narrative = Narrative(
        fact_refs=[
            FactRef(receipt_ref=result.receipt.id, field="status"),
            FactRef(receipt_ref=result.receipt.id, field="amount", expected="200/1"),
        ]
    )
    state = gateway.store.snapshot()
    state_hash = H(state)
    chinese, english = _render_both(narrative, state)
    assert chinese.status == english.status == "rendered"
    assert chinese.rule_ids == english.rule_ids == []
    assert _projection(chinese) == _projection(english)
    assert H(_projection(chinese)) == H(_projection(english))
    assert chinese.text != english.text and "转账" in chinese.text
    assert chinese.facts[1].display_value == english.facts[1].display_value == "200.00"
    assert H(state) == state_hash


@pytest.mark.parametrize("mutation", ["value", "signature", "missing", "note"])
def test_locale_cannot_make_a_forged_fact_or_private_note_acceptable(mutation):
    gateway, device, action, cert = gateway_case()
    result = gateway.dispatch(action, cert, approve(gateway, device, action, cert))
    receipt = result.receipt
    state = gateway.store.snapshot()
    ref = FactRef(receipt_ref=receipt.id, field="amount", expected="200/1")
    note = ""
    if mutation == "value":
        ref = ref.model_copy(update={"expected": "201/1"})
    elif mutation == "signature":
        state.receipts[receipt.id] = receipt.model_copy(update={"sig": "0" * 128})
    elif mutation == "missing":
        ref = ref.model_copy(update={"receipt_ref": "MISSING"})
    else:
        note = "Contact private@example.test"
    chinese, english = _render_both(Narrative(fact_refs=[ref], note=note), state)
    assert chinese.status == english.status == "rejected"
    assert chinese.rule_ids == english.rule_ids
    assert _projection(chinese) == _projection(english)
    assert "private@example.test" not in chinese.text + english.text


def test_wealth_guard_decisions_do_not_depend_on_display_locale():
    results = []
    for locale in ("zh-CN", "en"):
        set_locale(locale)
        result = guard_prose("Your return is guaranteed at 5%.")
        results.append(result)
    assert results[0].status == results[1].status == "rewritten"
    assert results[0].reasons == results[1].reasons
    assert results[0].text != results[1].text


def test_guarded_bank_facts_are_structurally_identical_in_both_languages():
    gateway, device, action, cert = gateway_case()
    receipt = gateway.dispatch(action, cert, approve(gateway, device, action, cert)).receipt
    results = []
    for locale in ("zh-CN", "en"):
        set_locale(locale)
        results.append(
            render_guarded(
                Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field="amount")]),
                gateway.store.snapshot(),
                "C_DEMO",
                gateway.vault,
            )
        )
    assert results[0].status == results[1].status == "rendered"
    assert _projection(results[0]) == _projection(results[1])
    assert results[0].text != results[1].text


def test_locale_does_not_change_dispatch_or_narrative_audit_hashes():
    audits = []
    for locale in ("zh-CN", "en"):
        set_locale(locale)
        gateway, device, action, cert = gateway_case()
        receipt = gateway.dispatch(action, cert, approve(gateway, device, action, cert)).receipt
        result = gateway.render_narrative(
            Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field="status")]), "C_DEMO"
        )
        assert result.status == "rendered"
        assert gateway.audit.verify()
        event = gateway.audit.records()[-1]
        assert event["event"] == "narrative_rendered"
        assert event["payload"]["fact_hash"] == H(_projection(result))
        audits.append(gateway.audit.checkpoint())
    assert audits[0] == audits[1]


def test_allocation_confirmation_and_device_signatures_remain_canonical_english():
    snapshots = []
    for locale in ("zh-CN", "en"):
        set_locale(locale)
        case = wealth_execution_case()
        draft = case.draft
        assert draft.overview["notice"] == (
            "Each purchase requires separate MFA and approval. "
            "Settled purchases are not automatically reversed."
        )
        signing = case.device.sign_allocation(
            draft,
            [item.item_ref for item in draft.parent.items],
            now=case.state.now,
        )
        snapshots.append((draft.overview, draft.parent, signing))
    assert snapshots[0] == snapshots[1]


def test_explicit_english_guard_locale_does_not_change_validation_or_context():
    set_locale("zh-CN")
    accepted = guard_prose("Returns can vary and losses are possible.", locale="en")
    assert accepted.status == "accepted"
    assert accepted.text == "Returns can vary and losses are possible."
    rejected = guard_prose("Funds are there.", locale="en")
    assert rejected.status == "rewritten"
    assert rejected.reasons == ("unverified_prose",)
    assert rejected.text == "Please review the verified facts."
    assert get_locale() == "zh-CN"


def test_budget_rejection_audit_hash_does_not_include_translated_message():
    checkpoints = []
    messages = []
    for locale in ("zh-CN", "en"):
        set_locale(locale)
        case = wealth_execution_case()
        assert case.start()[0].status == "ready"
        case.gateway.store.update(
            security=case.state.security.model_copy(
                update={
                    "approval_requests": {
                        "C_DEMO": [
                            ApprovalRequest(request_id=f"PRIOR_{index}", ts=case.state.now)
                            for index in range(4)
                        ]
                    },
                }
            )
        )
        result = case.gateway.advance_allocation(case.parent_id)
        assert result.status == "rejected" and result.rule_ids == ["APR-BUDGET"]
        assert case.gateway.bank.execute_count == 0
        checkpoints.append(case.gateway.audit.checkpoint())
        messages.append(result.details["message"])
    assert checkpoints[0] == checkpoints[1]
    assert messages[0] != messages[1]


def test_bill_field_labels_localize_without_changing_authenticated_fields():
    from tests.e2e.test_billing_gateway import analysis_case

    gateway, _, action, cert = analysis_case()
    receipt = gateway.query(action, cert).analysis_receipt
    narrative = Narrative(
        fact_refs=[
            FactRef(receipt_ref=receipt.id, field=field)
            for field in ("gross_spend", "refunds", "net_spend", "category_totals.dining")
        ]
    )
    chinese, english = _render_both(narrative, gateway.store.snapshot())
    assert chinese.status == english.status == "rendered"
    assert _projection(chinese) == _projection(english)
    assert [fact.field for fact in chinese.facts] == [ref.field for ref in narrative.fact_refs]
    assert "支出总额" in chinese.facts[0].text
    assert "退款" in chinese.facts[1].text
    assert "净支出" in chinese.facts[2].text
    assert "餐饮" in chinese.facts[3].text
    assert "gross_spend" not in chinese.text and "category_totals.dining" not in chinese.text
