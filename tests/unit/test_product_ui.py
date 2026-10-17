"""Product views guide the user while keeping canonical evidence inspectable."""

import re
from html.parser import HTMLParser

import pytest

from tests.e2e.test_demo_ui import app

TECHNICAL_VALUE = re.compile(
    r"(?<![\w.])-?\d+/\d+(?![\w.])|"
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|"
    r"\b[0-9a-f]{32,}\b",
    re.IGNORECASE,
)


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def primary_nodes(node):
    """Walk user-visible content without opening technical evidence expanders."""
    if node.type == "expander":
        return
    children = getattr(node, "children", None)
    if children is not None:
        for child in children.values():
            yield from primary_nodes(child)
    else:
        yield node


def assert_primary_clean(page):
    assert not page.exception
    for node in primary_nodes(page.main):
        assert node.type != "json", "Canonical JSON must be inside technical evidence."
        if node.type in {
            "markdown",
            "caption",
            "text",
            "info",
            "warning",
            "success",
            "error",
            "header",
            "subheader",
            "title",
            "metric",
            "dataframe",
            "arrow_data_frame",
            "button",
            "checkbox",
        }:
            value = str(getattr(node, "value", ""))
            if node.type == "markdown":
                parser = VisibleText()
                parser.feed(value)
                value = " ".join(parser.parts)
            if node.type in {"button", "checkbox", "metric"}:
                value += str(getattr(node, "label", ""))
            assert not TECHNICAL_VALUE.search(value), (node.type, value)


def assert_progress(page, current, *, completed=None):
    rows = [
        row.value
        for row in page.markdown
        if 'class="cw-progress"' in row.value or "class='cw-progress'" in row.value
    ]
    assert len(rows) == 1
    steps = re.findall(r'data-step=["\']([^"\']+)["\']\s+data-state=["\']([^"\']+)["\']', rows[0])
    names = ["goals", "risk", "proposal", "approvals", "receipts"]
    assert [name for name, _ in steps] == names
    index = names.index(current)
    if completed is None:
        completed = names[:index]
    assert [state for _, state in steps] == [
        "current" if name == current else "complete" if name in completed else "pending"
        for name in names
    ]


@pytest.mark.parametrize("locale", ["en", "zh-CN"])
def test_advisor_example_stays_unsigned_and_progress_matches_actual_state(monkeypatch, locale):
    monkeypatch.setenv("CORRIDOR_LOCALE", locale)
    page = app()
    page.button(key="enter").click().run()
    assert_progress(page, "goals")
    columns = page.get("column")
    chat_column = next(
        column
        for column in columns
        if any(field.key == "wealth_message" for field in column.text_input)
    )
    assert chat_column.weight == pytest.approx(0.6)
    assert chat_column.chat_message
    assert any(column.weight == pytest.approx(0.4) for column in columns)
    assert_primary_clean(page)
    page.button(key="wealth_example:one_year").click().run()
    controller = page.session_state["wealth_controller"]
    assert page.text_input(key="wealth_message").value
    assert controller.dialogue_result is None
    assert not controller.state.user_inputs
    page.button(key="wealth_discuss").click().run()
    assert controller.dialogue_result["slots"]["amount"]["value"] == "10000/1"
    assert controller.dialogue_result["slots"]["amount"]["source"] == "heard, not signed"
    assert not controller.state.user_inputs
    assert controller.gateway.bank.execute_count == 0
    assert_progress(page, "risk", completed=[])
    assert_primary_clean(page)
