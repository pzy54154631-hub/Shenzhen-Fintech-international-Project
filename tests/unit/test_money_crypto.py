"""Exact numeric boundaries, RFC vectors and domain-separated signatures."""

import struct
from decimal import Decimal
from fractions import Fraction
from typing import Any

import pytest
import rfc8785
from hypothesis import given
from hypothesis import strategies as st
from nacl.signing import SigningKey
from pydantic import TypeAdapter

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import APPROVE, CONTEXTS, INPUT, sign, verify
from corridor.schemas.base import Model
from corridor.schemas.money import (
    Money,
    ceil_minor,
    display_amount,
    floor_minor,
    loads_exact,
    parse_fraction,
)
from corridor.schemas.time import Timestamp, deadline_utc, parse_time


@given(st.integers(min_value=0, max_value=10**18), st.integers(min_value=1, max_value=10**9))
def test_money_canonical_roundtrip(n: int, d: int) -> None:
    money = Money(amount=Fraction(n, d), ccy="CNY")
    assert H(money) == H(Money.model_validate_json(money.model_dump_json()))
    assert (
        money.model_dump(mode="json")["amount"]
        == f"{money.amount.numerator}/{money.amount.denominator}"
    )


@pytest.mark.parametrize("value", [1, 1.1, True, "1/0", " 2", "nan", "1e3", "1_000", "-1"])
def test_invalid_money(value: object) -> None:
    with pytest.raises(ValueError):
        Money(amount=value, ccy="CNY")


@pytest.mark.parametrize("text", ['{"x":1.1}', '{"x":NaN}', '{"x":Infinity}', '{"x":1,"x":2}'])
def test_json_rejects_ambiguous_values(text: str) -> None:
    with pytest.raises(ValueError):
        loads_exact(text)


def test_rounding_is_exact_and_half_even() -> None:
    assert parse_fraction("1.25") == Fraction(5, 4)
    assert display_amount(Fraction(1005, 1000)) == "1.00"
    assert display_amount(Fraction(1015, 1000)) == "1.02"
    assert Money(amount="0.01", ccy="CNY").is_minor_unit()
    assert not Money(amount="0.001", ccy="CNY").is_minor_unit()


def test_model_canonical_bytes_use_the_wire_fraction_serializer() -> None:
    money = Money(amount="100.00", ccy="CNY")
    assert jcs_bytes(money) == b'{"amount":"100/1","ccy":"CNY"}'
    assert jcs_bytes(money) == jcs_bytes(money.model_dump(mode="json"))


def test_rfc8785_sorting_and_string_vector() -> None:
    # RFC 8785 section 3.2.3: sort UTF-16 code units, not Unicode scalar values.
    sample = {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }
    expected = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"]
    assert list(loads_exact(jcs_bytes(sample))) == expected
    assert (
        jcs_bytes({"s": '\u20ac$\x0f\nA\'B"\\\\"/'})
        == b'{"s":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0, b"0"),
        (-0.0, b"0"),
        (1e30, b"1e+30"),
        (4.5, b"4.5"),
        (0.002, b"0.002"),
        (1e-27, b"1e-27"),
    ],
)
def test_official_number_vectors_only_in_upstream(value: float, expected: bytes) -> None:
    # Floating-point RFC interoperability vectors never enter business serialization.
    assert rfc8785.dumps(value) == expected
    with pytest.raises(ValueError):
        jcs_bytes({"number": value})


def test_signature_domains_and_nested_signatures() -> None:
    key = SigningKey(bytes(range(32)))
    body = {"amount": "1/1", "records": [{"sig": "inner"}]}
    sig = sign(key, APPROVE, body)
    assert verify(key.verify_key, APPROVE, body, sig)
    assert not verify(key.verify_key, INPUT, body, sig)
    assert not verify(key.verify_key, APPROVE, {**body, "amount": "2/1"}, sig)
    assert H({**body, "sig": "outer1"}) == H({**body, "sig": "outer2"})
    assert H(body) != H({**body, "records": [{"sig": "changed"}]})
    with pytest.raises(ValueError):
        sign(key, APPROVE, {"ctx": INPUT})


@pytest.mark.parametrize(
    "value",
    ["2026-10-16", "2026-10-16T00:00:00+00:00", "2026-02-30T00:00:00Z", "2026-10-16T00:00:00.1Z"],
)
def test_time_format_is_strict(value: str) -> None:
    with pytest.raises(ValueError):
        parse_time(value)


def test_local_deadline_uses_start_of_day() -> None:
    assert deadline_utc("2026-10-31", "America/New_York") == "2026-10-31T04:00:00Z"


# All IEEE 754 rows of RFC 8785, Appendix B, including the two forbidden values.
# Source: https://www.rfc-editor.org/rfc/rfc8785.html#appendix-B
@pytest.mark.parametrize(
    ("bits", "expected"),
    [
        ("0000000000000000", "0"),
        ("8000000000000000", "0"),
        ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("7fffffffffffffff", None),
        ("7ff0000000000000", None),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ],
)
def test_complete_rfc8785_appendix_b(bits: str, expected: str | None) -> None:
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    if expected is None:
        with pytest.raises(rfc8785.FloatDomainError):
            rfc8785.dumps(value)
    else:
        assert rfc8785.dumps(value) == expected.encode("ascii")
    with pytest.raises(ValueError, match="Floats are forbidden"):
        jcs_bytes({"nested": [value]})


@pytest.mark.parametrize("surrogate", ["\ud800", "\udead", "\udfff"])
def test_jcs_rejects_invalid_unicode_values_and_keys(surrogate: str) -> None:
    for value in ({"value": surrogate}, {surrogate: "value"}, [surrogate]):
        with pytest.raises(ValueError):
            jcs_bytes(value)


def test_jcs_preserves_unicode_and_array_order() -> None:
    assert H({"label": "\u00e9"}) != H({"label": "e\u0301"})
    assert jcs_bytes([{"z": 0, "a": True}, None, False]) == b'[{"a":true,"z":0},null,false]'
    assert H([1, 2]) != H([2, 1])
    assert jcs_bytes({"ratio": Fraction(4, 6)}) == b'{"ratio":"2/3"}'


@pytest.mark.parametrize("value", [Decimal("1"), b"one", {1: "one"}, {"a", "b"}, 2**53])
def test_jcs_rejects_non_wire_values(value: Any) -> None:
    with pytest.raises(ValueError):
        jcs_bytes(value)


@pytest.mark.parametrize("ctx", sorted(CONTEXTS))
def test_all_signature_domains_are_separated(ctx: str) -> None:
    key = SigningKey(bytes(range(32)))
    body = {"amount": "3/1", "records": [{"sig": "inner"}]}
    signature = sign(key, ctx, body)
    assert verify(bytes(key.verify_key), ctx, body, signature)
    assert verify(bytes(key.verify_key).hex(), ctx, body, signature)
    for other in CONTEXTS - {ctx}:
        assert not verify(key.verify_key, other, body, signature)
    assert not verify(SigningKey(bytes(reversed(range(32)))).verify_key, ctx, body, signature)
    assert not verify(key.verify_key, ctx, {**body, "records": [{"sig": "changed"}]}, signature)
    assert sign(key, ctx, {"records": body["records"], "amount": "3/1"}) == signature
    assert sign(key, ctx, {**body, "sig": "outer"}) == signature


@pytest.mark.parametrize(
    "signature",
    [None, 42, "", "x" * 128, "00" * 63, "00" * 65, "00" * 64],
)
def test_verify_rejects_malformed_signatures(signature: Any) -> None:
    assert not verify(SigningKey(bytes(32)).verify_key, APPROVE, {}, signature)


@pytest.mark.parametrize("pubkey", [None, 42, "", "x" * 64, b"\x00" * 31, b"\x00" * 33])
def test_verify_rejects_malformed_public_keys(pubkey: Any) -> None:
    assert not verify(pubkey, APPROVE, {}, "00" * 64)


@pytest.mark.parametrize("body", [None, [], {"ctx": APPROVE}, {"x": 1.0}, {"x": "\ud800"}])
def test_signature_rejects_invalid_payloads(body: Any) -> None:
    key = SigningKey(bytes(32))
    with pytest.raises(ValueError):
        sign(key, APPROVE, body)
    assert not verify(key.verify_key, APPROVE, body, "00" * 64)


def test_unregistered_signature_context_is_rejected() -> None:
    key = SigningKey(bytes(32))
    with pytest.raises(ValueError):
        sign(key, "corridor/unknown/v0", {})
    assert not verify(key.verify_key, "corridor/unknown/v0", {}, "00" * 64)


@pytest.mark.parametrize(
    "text",
    [
        '{"outer":[{"x":1,"x":2}]}',
        '{"x":1,"\\u0078":2}',
        '{"x":-Infinity}',
        '{"x":1e999}',
        '{"x":1.0}',
    ],
)
def test_json_rejects_nested_duplicates_and_noncanonical_numbers(text: str) -> None:
    with pytest.raises(ValueError):
        loads_exact(text)


@pytest.mark.parametrize("text", [b'{"amount":1,"ccy":"CNY"}', b'{"amount":1.0,"ccy":"CNY"}'])
def test_money_json_rejects_both_numeric_forms(text: bytes) -> None:
    with pytest.raises(ValueError):
        Money.model_validate_json(text)


def test_model_rejects_nested_floats_and_float_keys() -> None:
    class OpaquePayload(Model):
        payload: Any

    for value in ({"x": [1.0]}, {1.0: "x"}):
        with pytest.raises(ValueError):
            OpaquePayload(payload=value)


@pytest.mark.parametrize("value", ["01", "+1", "1/-2", "1/00", "1.", ".1", "1\n", "1/2\n"])
def test_rational_grammar_rejects_noncanonical_syntax(value: str) -> None:
    with pytest.raises(ValueError):
        parse_fraction(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (Fraction(-1005, 1000), "-1.00"),
        (Fraction(-1015, 1000), "-1.02"),
        (Fraction(1005, 1000) + Fraction(1, 10**60), "1.01"),
        (Fraction(1015, 1000) - Fraction(1, 10**60), "1.01"),
        (Fraction(10**40) + Fraction(1, 100), "1" + "0" * 40 + ".01"),
    ],
)
def test_display_does_not_round_through_floating_point(value: Fraction, expected: str) -> None:
    assert display_amount(value) == expected


@given(st.integers(-(10**18), 10**18), st.integers(1, 10**9))
def test_minor_unit_rounding_bounds(numerator: int, denominator: int) -> None:
    value = Fraction(numerator, denominator)
    assert floor_minor(value) <= value <= ceil_minor(value)
    assert ceil_minor(value) - floor_minor(value) < Fraction(2, 100)
    assert (floor_minor(value) * 100).denominator == 1
    assert (ceil_minor(value) * 100).denominator == 1


def test_timestamp_and_deadline_validation() -> None:
    timestamp = "2024-02-29T23:59:59Z"
    assert TypeAdapter(Timestamp).validate_python(timestamp) == timestamp
    assert parse_time(timestamp).utcoffset().total_seconds() == 0
    assert deadline_utc("2026-11-02", "America/New_York") == "2026-11-02T05:00:00Z"
    assert deadline_utc("2026-03-09", "America/New_York") == "2026-03-09T04:00:00Z"
    for day, zone in [("2026-2-1", "UTC"), ("2026-02-30", "UTC"), ("2026-01-01", "fake/zone")]:
        with pytest.raises(ValueError):
            deadline_utc(day, zone)


def test_money_json_schema_uses_ecmascript_anchors() -> None:
    pattern = Money.model_json_schema()["properties"]["amount"]["pattern"]
    assert pattern.startswith("^") and pattern.endswith("$")
    assert "\\Z" not in pattern
