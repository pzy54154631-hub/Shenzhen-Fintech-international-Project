"""Test configuration must report missing coverage honestly."""

from types import SimpleNamespace

import pytest
from hypothesis import settings

from tests._pytest_plugin import (
    asserted_rule_ids,
    missing_rule_ids,
    pytest_collection_modifyitems,
    require_rule_assertions,
)


def test_rule_coverage_is_a_sorted_set_difference() -> None:
    assert missing_rule_ids(["C", "A", "B"], ["B", "B"]) == ["A", "C"]
    assert missing_rule_ids(["A"], ["A"]) == []


def test_hypothesis_profiles_have_required_example_counts() -> None:
    assert settings.get_profile("dev").max_examples == 100
    assert settings.get_profile("full").max_examples == 10_000


def test_unknown_rule_marker_fails_collection() -> None:
    marker = SimpleNamespace(args=("UNKNOWN-MIGRATION-RULE",), kwargs={})
    item = SimpleNamespace(nodeid="probe", iter_markers=lambda name: [marker])
    with pytest.raises(pytest.UsageError, match="invalid rule marker"):
        pytest_collection_modifyitems(None, [item])


@pytest.mark.parametrize(
    "expression,explanation,expected",
    [
        ("rule in result.rule_ids", "'AUTH-SCOPE' in ['AUTH-SCOPE']", {"AUTH-SCOPE"}),
        ("result.rule_ids == [rule]", "['APR-SWAP'] == ['APR-SWAP']", {"APR-SWAP"}),
        ("str(error.value) == 'PII-CTX'", "'PII-CTX' == 'PII-CTX'", {"PII-CTX"}),
        (
            "set(result.rule_ids) == {'DOMAIN-STATE', 'DOMAIN-COMPENSATION'}",
            "{'DOMAIN-COMP...DOMAIN-STATE'} == {'DOMAIN-COMP...DOMAIN-STATE'}",
            {"DOMAIN-STATE", "DOMAIN-COMPENSATION"},
        ),
        ("result.outcome == 'Reject'", "'Reject' == 'Reject'\n + where AUTH-SCOPE", set()),
        ("'AUTH-SCOPE' not in result.rule_ids", "'AUTH-SCOPE' not in []", set()),
        ("result.status != 'AUTH-SCOPE'", "'accepted' != 'AUTH-SCOPE'", set()),
        ("True", "True", set()),
        ("True or 'AUTH-SCOPE' in result.rule_ids", "True", set()),
        ("'AUTH-SCOPE' in result.rule_ids or True", "([] or True)", set()),
        ("'AUTH-SCOPE' in result.rule_ids if False else True", "True", set()),
        ("all('AUTH-SCOPE' in x for x in [])", "True", set()),
        ("bool('AUTH-SCOPE') == True", "True == True", set()),
        (
            "'PII-OUT' in result.rule_ids and 'private' not in result.text",
            "('PII-OUT' in ['PII-OUT'] and 'private' not in 'safe')",
            {"PII-OUT"},
        ),
        (
            "result.status == 'accepted' and 'AUTH-SCOPE' not in result.rule_ids",
            "('accepted' == 'accepted' and 'AUTH-SCOPE' not in [])",
            set(),
        ),
    ],
)
def test_coverage_requires_a_successful_positive_rule_assertion(expression, explanation, expected):
    assert asserted_rule_ids(expression, explanation) == expected


def test_marker_only_or_other_rule_assertion_does_not_count():
    with pytest.raises(AssertionError, match="AUTH-SCOPE"):
        require_rule_assertions({"AUTH-SCOPE"}, set())
    with pytest.raises(AssertionError, match="AUTH-SCOPE"):
        require_rule_assertions({"AUTH-SCOPE"}, {"SCHEMA-INVALID"})
    require_rule_assertions({"AUTH-SCOPE"}, {"AUTH-SCOPE"})
