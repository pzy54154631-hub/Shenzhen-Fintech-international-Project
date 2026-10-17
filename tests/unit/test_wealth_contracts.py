"""Frozen wealth-policy input contracts, independent of the future BIAC schema."""

import json
from fractions import Fraction
from pathlib import Path

import pytest

POLICY_PATH = Path("data/wealth/allocation-policy-v1.json")
SLEEVES = [f"R{level}" for level in range(1, 6)]


def _reject_json_number(value: str) -> None:
    raise ValueError(f"Non-integral JSON number in frozen policy: {value}")


def _policy():
    return json.loads(
        POLICY_PATH.read_text(encoding="utf-8"),
        parse_float=_reject_json_number,
        parse_constant=_reject_json_number,
    )


def _rational(value: str) -> Fraction:
    assert isinstance(value, str)
    result = Fraction(value)
    assert value == f"{result.numerator}/{result.denominator}"
    return result


def test_frozen_policy_has_bounded_explicit_profiles_and_selector():
    policy = _policy()
    assert policy["schema_version"] == "allocation-policy-v1"
    assert policy["selector_version"] == "greedy-sleeves-v1"
    assert policy["currency"] == "CNY"
    assert policy["ranking_basis"] == "request_principal"
    assert policy["max_products"] == 12
    assert _rational(policy["concentration_cap"]) == Fraction(1, 2)
    assert set(policy["profiles"]) == {f"C{level}" for level in range(1, 6)}


@pytest.mark.parametrize("level", range(1, 6))
def test_frozen_model_weights_obey_bands_groups_and_client_suitability(level):
    profile = _policy()["profiles"][f"C{level}"]
    assert set(profile) == {"bands", "group_bounds", "model_weights"}
    assert [band["sleeve"] for band in profile["bands"]] == SLEEVES
    assert set(profile["model_weights"]) == set(SLEEVES)
    weights = {key: _rational(value) for key, value in profile["model_weights"].items()}
    assert sum(weights.values(), Fraction()) == 1
    for band in profile["bands"]:
        assert set(band) == {"sleeve", "lower", "upper"}
        lower, upper = _rational(band["lower"]), _rational(band["upper"])
        assert 0 <= lower <= weights[band["sleeve"]] <= upper <= 1
        if int(band["sleeve"][1:]) > level:
            assert lower == upper == weights[band["sleeve"]] == 0
    groups = set()
    for group in profile["group_bounds"]:
        assert set(group) == {"sleeves", "lower", "upper"}
        sleeves = group["sleeves"]
        assert sleeves and len(sleeves) == len(set(sleeves))
        assert set(sleeves) <= set(SLEEVES)
        identity = tuple(sorted(sleeves))
        assert identity not in groups
        groups.add(identity)
        lower, upper = _rational(group["lower"]), _rational(group["upper"])
        actual = sum((weights[sleeve] for sleeve in sleeves), Fraction())
        assert 0 <= lower <= actual <= upper <= 1


def test_frozen_policy_contains_no_secret_or_marketing_keys():
    forbidden = {
        "api_key",
        "apikey",
        "secret",
        "private_key",
        "signing_key",
        "password",
        "otp",
        "sponsored",
        "sponsor",
        "featured",
        "marketing",
        "marketing_text",
        "llm_note",
    }

    def inspect(value):
        if isinstance(value, dict):
            assert not forbidden.intersection(key.lower() for key in value)
            for nested in value.values():
                inspect(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect(nested)

    inspect(_policy())
