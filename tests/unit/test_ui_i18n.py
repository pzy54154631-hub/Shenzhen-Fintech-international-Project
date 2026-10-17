"""Display languages retain the international routes and canonical wire values."""

from corridor.i18n import reset_locale, set_locale
from corridor.ui.app import PAGES, SUPPORTING_PAGES
from corridor.ui.components import money
from corridor.ui.messages import UI_MESSAGES, tr


def test_international_navigation_is_preserved():
    assert PAGES == ("Advisor", "Proposal & Certificate", "Device", "Evidence & Audit")
    assert "Transfers" in SUPPORTING_PAGES


def test_ui_translation_changes_copy_without_rewriting_identifiers():
    token = set_locale("zh-CN")
    try:
        assert tr("Proposal & Certificate") != "Proposal & Certificate"
        assert tr("A_CURRENT") == "A_CURRENT"
        assert tr("9000/1") == "9000/1"
        assert tr("Corridor Wealth") == "Corridor Wealth"
    finally:
        reset_locale(token)


def test_ui_catalog_has_both_languages_without_domestic_branding():
    assert all(set(value) == {"en", "zh-CN"} for value in UI_MESSAGES.values())
    assert UI_MESSAGES["home_title"]["en"] == "Wealth advice with verifiable evidence."


def test_currency_display_is_localized_without_changing_exact_input():
    for locale, expected in (("en", "CNY 9,000.00"), ("zh-CN", "¥9,000.00")):
        token = set_locale(locale)
        try:
            assert money("9000/1") == expected
        finally:
            reset_locale(token)
