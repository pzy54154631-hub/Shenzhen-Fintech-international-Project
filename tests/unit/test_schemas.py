"""Generic strict-schema contracts survive the bank-domain migration."""

from fractions import Fraction
from typing import get_args

import pytest
from pydantic import TypeAdapter, ValidationError

from corridor.schemas import models as m
from corridor.schemas.base import Model
from corridor.schemas.money import Money

NOW = "2026-10-16T00:00:00Z"
HEX = "a" * 64


def schema_samples(amount: Fraction = Fraction(1450)) -> list[Model]:
    return [
        Money(amount=amount, ccy="CNY"),
        m.Accept(),
        m.Reject(
            rule_ids=["SCHEMA-INVALID"],
            first="SCHEMA-INVALID",
            obligation="SCHEMA",
            counterexample_code="invalid",
        ),
        m.Escalate(rule_ids=["TIER-MFA-REQUIRED"], reasons=["MFA required"]),
        m.VerdictDetails(
            tier="yellow",
            required_factors=["device"],
            dependency_hash=HEX,
            tier_basis={"total_after": f"{amount.numerator}/{amount.denominator}"},
            verified_facts={"card_core": {"ccy": "CNY"}},
        ),
        m.AuditRecord(seq=1, ts=NOW, prev_hash=HEX, event="approved", record_hash=HEX),
    ]


@pytest.mark.parametrize("index", range(6))
def test_schema_samples_accept_and_roundtrip(index: int) -> None:
    instance = schema_samples()[index]
    assert type(instance).model_validate_json(instance.model_dump_json()) == instance


def test_missing_and_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        m.AuditRecord.model_validate({})
    body = schema_samples()[-1].model_dump(mode="json")
    body["untrusted"] = True
    with pytest.raises(ValidationError):
        m.AuditRecord.model_validate(body)


def test_verdict_discriminator_rejects_unknown_outcomes() -> None:
    adapter = TypeAdapter(m.Verdict)
    assert adapter.validate_python({"outcome": "Accept"}) == m.Accept()
    with pytest.raises(ValidationError):
        adapter.validate_python({"outcome": "Success"})
    with pytest.raises(ValidationError):
        adapter.validate_python({"outcome": "Reject"})


def test_reject_first_rule_must_be_reported() -> None:
    body = schema_samples()[2].model_dump(mode="json")
    body["first"] = "unknown"
    with pytest.raises(ValidationError):
        m.Reject.model_validate(body)


def test_recursive_json_contract_rejects_floats() -> None:
    adapter = TypeAdapter(m.JsonValue)
    sample = {"items": ["value", 3, True, None, {"amount": "1/1"}]}
    assert adapter.validate_python(sample) == sample
    with pytest.raises(ValidationError):
        adapter.validate_python({"items": [1.1]})


def test_no_model_field_contains_float_annotation() -> None:
    def contains_float(annotation: object) -> bool:
        return annotation is float or any(contains_float(arg) for arg in get_args(annotation))

    for item in vars(m).values():
        if isinstance(item, type) and issubclass(item, Model):
            assert all(not contains_float(field.annotation) for field in item.model_fields.values())
