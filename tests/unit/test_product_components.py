"""Readable product surfaces retain full canonical evidence on demand."""

from copy import deepcopy
from html import unescape
from re import sub
from unittest.mock import MagicMock

from corridor.crypto.jcs import H
from corridor.i18n import reset_locale, set_locale
from corridor.ui import components, wealth_statement
from tests.e2e.test_exploratory_display import DisplayRecorder
from tests.unit.test_ui_wealth_statement import statement_inputs
from tests.wealth_execution_cases import wealth_execution_case


def test_purchase_card_hides_machine_values_but_preserves_exact_evidence(monkeypatch):
    case = wealth_execution_case()
    case.start()
    card = case.prepare().card
    original = deepcopy(card)
    display = DisplayRecorder()
    monkeypatch.setattr(components, "st", display)
    components.render_card(card)
    primary = " ".join(str(value) for _, value, context in display.events if not context)
    assert "CNY 5,000.00" in primary
    assert "CNY 0.00" in primary
    assert "Product A" in primary
    assert card["node_id"] not in primary
    assert card["action_hash"] not in primary
    assert "5000/1" not in primary
    assert "canonical value" not in primary
    assert any(
        name == "json" and value == card and context for name, value, context in display.events
    )
    assert card == original
    assert sum(name == "markdown" and not context for name, _, context in display.events) == 1


def test_transfer_card_keeps_distinct_readable_recipient_labels(monkeypatch):
    displayed = []
    for reference in ("CONTACT_LIN_B", "CONTACT_CHEN"):
        display = DisplayRecorder()
        monkeypatch.setattr(components, "st", display)
        card = {
            "kind": "transfer",
            "amount": "801/4",
            "fees": "0/1",
            "tier": "yellow",
            "objects": {"contact_ref": reference, "source_ref": "A_CURRENT"},
        }
        components.render_card(card)
        primary = " ".join(str(value) for _, value, context in display.events if not context)
        assert "CNY 200.25" in primary
        assert reference not in primary
        assert display.events[-1][1] == card
        displayed.append(primary)
    assert "Contact Lin · B" in displayed[0]
    assert "Contact Chen" in displayed[1]


def test_nested_business_facts_do_not_escape_as_json_or_machine_ids(monkeypatch):
    display = DisplayRecorder()
    monkeypatch.setattr(components, "st", display)
    components.render_structured({
        "amount": "9000/1",
        "objects": {"product_ref": "P_A", "amount_ref": "MACHINE_ID"},
        "allocation": {"hash": "a" * 64, "weights": ["1/2", "1/2"]},
    })
    primary = " ".join(str(value) for _, value, context in display.events if not context)
    assert "CNY 9,000.00" in primary
    assert "Product A" in primary
    assert "9000/1" not in primary and "1/2" not in primary
    assert "MACHINE_ID" not in primary and "a" * 64 not in primary


def test_primary_statement_is_product_readable_and_export_keeps_proof():
    inputs = statement_inputs()
    for locale in ("en", "zh-CN"):
        token = set_locale(locale)
        try:
            statement = wealth_statement.build_statement(*inputs)
            visible = unescape(sub(r"<[^>]*>", "", statement.summary_html))
            assert H(inputs[0]) not in visible
            assert "5000/1" not in visible
            assert "cw-chip" in statement.summary_html
            assert "selected-product" in statement.summary_html
            assert "sleeve-fill" in statement.summary_html
            assert H(inputs[0]) in statement.html
            assert statement.numeric_sources["item.0.principal"]["exact"] == "5000/1"
            assert "CNY 5,000.00" in visible if locale == "en" else "5,000.00" in visible
        finally:
            reset_locale(token)


def test_statement_evidence_stays_collapsed_and_downloadable(monkeypatch):
    display = MagicMock()
    monkeypatch.setattr(wealth_statement, "st", display)
    statement = wealth_statement.render_biac(*statement_inputs())
    assert display.markdown.call_args_list[0].args[0].endswith(statement.summary_html)
    assert any(call.args[0] == "Technical evidence" for call in display.expander.call_args_list)
    assert any(
        call.kwargs["data"] == statement.html for call in display.download_button.call_args_list
    )
