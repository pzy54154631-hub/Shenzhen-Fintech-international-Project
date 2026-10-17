"""Suitability statements expose only sourced comparison and execution numbers."""

from fractions import Fraction
from html.parser import HTMLParser
from io import BytesIO
from re import sub
from unittest.mock import MagicMock
from zipfile import ZipFile

import pytest

from corridor.crypto.jcs import H, jcs_bytes
from corridor.kernel.allocation import build_allocation
from corridor.kernel.binding import intent_key
from corridor.schemas.allocation import AllocationRequest
from corridor.schemas.money import fraction_string
from corridor.stores.bank import available
from corridor.ui import wealth_statement
from tests.unit.test_allocation_selector import INTENT, explicit_case
from tests.wealth_cases import allocation_case
from tests.wealth_execution_cases import wealth_execution_case


def statement_inputs():
    action, certificate, state = allocation_case()
    request = AllocationRequest.model_validate(state.user_inputs[action.args.request_ref].value)
    return (
        certificate.allocation,
        request,
        state.allocation_policies[request.allocation_policy_ref],
        state.risk_assessments[state.customers[action.principal].risk_profile_ref],
    )


def resolve(documents, path):
    value = documents
    for part in path.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def test_every_numeric_projection_has_recomputable_signed_sources():
    inputs = statement_inputs()
    statement = wealth_statement.build_statement(*inputs)
    documents = dict(
        zip(
            ("biac", "request", "policy", "profile"),
            (item.model_dump(mode="json") for item in inputs),
            strict=True,
        )
    )
    assert statement.numeric_sources
    for key, projection in statement.numeric_sources.items():
        assert projection["sources"], key
        values = [resolve(documents, path) for path in projection["sources"]]
        operation = projection["operation"]
        if operation == "value":
            expected = Fraction(values[0])
        elif operation == "count":
            expected = Fraction(len(values[0]))
        elif operation == "count_sum":
            expected = Fraction(sum(len(value) for value in values))
        elif operation == "sum":
            expected = sum(map(Fraction, values), Fraction())
        elif operation == "ratio":
            expected = Fraction(values[0]) / Fraction(values[1])
        elif operation == "cent_ratio":
            expected = Fraction(values[0], 100) / Fraction(values[1])
        else:
            pytest.fail(f"Unreviewed display calculation: {operation}")
        assert Fraction(projection["exact"]) == expected, key
        assert f'data-number="{key}"' in statement.html, key
        assert projection["display"] in statement.html, key


def test_visible_numbers_cannot_bypass_the_source_projection():
    inputs = statement_inputs()
    statement = wealth_statement.build_statement(*inputs)

    class VisibleNumbers(HTMLParser):
        def __init__(self):
            super().__init__()
            self.sourced = 0
            self.ignore = False
            self.outside = []

        def handle_starttag(self, tag, attrs):
            if tag == "style":
                self.ignore = True
            if tag == "span" and "data-number" in dict(attrs):
                self.sourced += 1

        def handle_endtag(self, tag):
            if tag == "style":
                self.ignore = False
            if tag == "span" and self.sourced:
                self.sourced -= 1

        def handle_data(self, data):
            if not self.sourced and not self.ignore:
                self.outside.append(data)

    parser = VisibleNumbers()
    parser.feed(statement.html)
    text = " ".join(parser.outside)
    # Identifiers, timestamps, the BIAC hash and fixed C/R legend codes are not quantities.
    text = text.replace(H(inputs[0]), "")
    text = text.replace(inputs[3].expires_at, "")
    text = sub(r"\b[CR][1-5]\b", "", text)
    assert not any(char.isdigit() for char in text), text


def test_comparison_statement_has_scoped_verdict_and_no_purchase_claim():
    inputs = statement_inputs()
    statement = wealth_statement.build_statement(*inputs)
    assert "Suitable for C2 (Cautious)" in statement.text
    assert "all 4 eligible products considered" in statement.text
    assert "6/6 checked, 4 eligible, 2 excluded" in statement.text
    assert "ranked by your objective" in statement.text
    assert "sponsor-independent within the declared catalogue and policy" in statement.text
    assert "policy-checked heuristic" in statement.text
    assert "performance benchmark (not guaranteed)" in statement.text
    assert "Comparison complete – no purchase executed" in statement.text
    assert "portfolio-optimal" not in statement.text
    assert H(inputs[0]) in statement.html
    assert 'href="#audit-entry"' in statement.summary_html
    assert 'href="#audit-entry"' not in statement.html
    assert (
        "Audit evidence is available in the application or statement + audit bundle"
        in statement.html
    )
    assert "Policy version" in statement.text and "Catalogue version" in statement.text


def test_statement_renders_summary_before_json_and_has_download(monkeypatch):
    display = MagicMock()
    monkeypatch.setattr(wealth_statement, "st", display)
    statement = wealth_statement.render_biac(*statement_inputs())
    calls = display.mock_calls
    assert calls[0][0] == "markdown"
    assert "Suitable for" in calls[0].args[0]
    assert "allocation" not in str(calls[0].kwargs)
    assert any(call[0] == "expander" for call in calls)
    assert any(call[0] == "download_button" for call in calls)
    assert display.download_button.call_args.kwargs["data"] == statement.html


def test_partial_execution_uses_supplied_account_cash_and_keeps_settled_leg():
    execution = {
        "status": "partially_executed",
        "available_balance": "7000/1",
        "items": [
            {"product_ref": "P_A", "principal": "5000/1", "status": "settled"},
            {"product_ref": "P_C", "principal": "5000/1", "status": "failed"},
        ],
    }
    statement = wealth_statement.build_statement(*statement_inputs(), execution=execution)
    assert "A5000 + CNY 7,000 cash, Partially executed" in statement.text
    assert "1 of 2 settled" in statement.text
    assert "nothing reversed automatically" in statement.text
    assert statement.numeric_sources["execution.cash"]["sources"] == ["execution.available_balance"]


def test_missing_cash_is_not_inferred_and_unknown_never_invites_retry():
    statement = wealth_statement.build_statement(
        *statement_inputs(), execution={"status": "unknown", "items": []}
    )
    assert "Outcome pending reconciliation – do not retry" in statement.text
    assert "7,000" not in statement.text
    assert "cash" not in statement.numeric_sources


def test_mismatched_context_cannot_be_presented_as_suitable():
    biac, request, policy, profile = statement_inputs()
    with pytest.raises(ValueError, match="statement context"):
        wealth_statement.build_statement(
            biac, request, policy.model_copy(update={"version": policy.version + 1}), profile
        )


def test_signed_adjustment_warning_and_all_differences_remain_visible():
    ref, state, _ = explicit_case()
    biac = build_allocation("C_DEMO", INTENT, ref, state)
    request = AllocationRequest.model_validate(state.user_inputs[ref].value)
    policy = state.allocation_policies[request.allocation_policy_ref]
    profile = state.risk_assessments[state.customers["C_DEMO"].risk_profile_ref]
    statement = wealth_statement.build_statement(biac, request, policy, profile)
    assert "Deviation from model allocation" in statement.summary_html
    assert statement.numeric_sources["deviation.projected_net_delta"]["exact"] == "-20/1"
    assert statement.numeric_sources["deviation.sleeves.0.weight"]["display"] == "10.00 pp"
    assert all(
        f"deviation.products.{index}.principal" in statement.numeric_sources
        for index in range(len(biac.deviations.products))
    )


def test_w11_real_second_leg_failure_has_receipt_backed_partial_statement():
    case = wealth_execution_case()
    assert case.start()[0].status in {"registered", "ready"}
    assert case.execute_next()[0].status == "settled"
    approval = case.approve(sequence=1)
    case.gateway.bank.faults[intent_key(approval.action, case.state)] = "failed"
    assert case.gateway.dispatch(approval.action, approval.cert, approval.token).status == "failed"
    request = AllocationRequest.model_validate(
        case.state.user_inputs[case.comparison_action.args.request_ref].value
    )
    execution = {
        **case.snapshot(),
        "available_balance": fraction_string(available(case.state, request.source_account_ref)),
    }
    statement = wealth_statement.build_statement(
        case.comparison_cert.allocation,
        request,
        case.state.allocation_policies[request.allocation_policy_ref],
        case.state.risk_assessments[case.state.customers["C_DEMO"].risk_profile_ref],
        execution=execution,
    )
    assert "A5000 + CNY 7,000 cash, Partially executed" in statement.text
    assert case.gateway.bank.execute_count == 2


def test_statement_bundle_contains_the_real_unchanged_audit_and_resolvable_link(monkeypatch):
    from tests.unit.test_ui_wealth_controller import prepared_controller

    controller = prepared_controller()
    request = controller.signed_goals.value
    args = (
        controller.comparison.cert.allocation,
        request,
        controller.state.allocation_policies[request["allocation_policy_ref"]],
        controller.risk_profile(),
    )
    records = controller.gateway.audit.records()
    assert records and controller.gateway.verify_log()
    audit = b"".join(jcs_bytes(record) + b"\n" for record in records)
    display = MagicMock()
    monkeypatch.setattr(wealth_statement, "st", display)
    original = wealth_statement.build_statement(*args)
    rendered = wealth_statement.render_biac(*args, audit_href="#wealth-audit", audit_jsonl=audit)
    downloads = {call.args[0]: call.kwargs for call in display.download_button.call_args_list}
    assert rendered.numeric_sources == original.numeric_sources
    assert 'href="#wealth-audit"' in rendered.summary_html
    assert 'href="#wealth-audit"' not in downloads["Download Suitability Statement"]["data"]
    bundle = downloads["Download statement + audit"]
    assert bundle["mime"] == "application/zip"
    with ZipFile(BytesIO(bundle["data"])) as archive:
        assert archive.namelist() == ["suitability-statement.html", "audit.jsonl"]
        assert archive.read("audit.jsonl") == audit
        exported = archive.read("suitability-statement.html").decode("utf-8")
        assert 'href="audit.jsonl"' in exported
        assert H(args[0]) in exported
    display.reset_mock()
    wealth_statement.render_biac(*args, audit_jsonl=audit)
    assert display.download_button.call_args.kwargs["data"] == bundle["data"]


@pytest.mark.parametrize("audit", [None, b"", ""])
def test_no_bundle_or_invented_records_when_audit_is_absent(monkeypatch, audit):
    display = MagicMock()
    monkeypatch.setattr(wealth_statement, "st", display)
    wealth_statement.render_biac(*statement_inputs(), audit_jsonl=audit)
    assert [call.args[0] for call in display.download_button.call_args_list] == [
        "Download Suitability Statement"
    ]


@pytest.mark.parametrize("target", ["../audit.jsonl", "https://example.com/audit", "javascript:x"])
def test_statement_only_allows_local_audit_fragments_or_exact_bundled_filename(target):
    with pytest.raises(ValueError, match="audit link"):
        wealth_statement.build_statement(*statement_inputs(), audit_href=target)
