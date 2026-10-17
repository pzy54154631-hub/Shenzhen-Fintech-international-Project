"""All concrete schema classes preserve their canonical bytes through JSON."""

from fractions import Fraction

from hypothesis import given
from hypothesis import strategies as st

from corridor.crypto.jcs import H
from corridor.schemas import models
from corridor.schemas.base import Model
from tests.unit.test_schemas import schema_samples


def nested_models(value: object) -> list[Model]:
    if isinstance(value, Model):
        return [value] + [
            child
            for name in type(value).model_fields
            for child in nested_models(getattr(value, name))
        ]
    if isinstance(value, dict):
        return [child for item in value.values() for child in nested_models(item)]
    if isinstance(value, list):
        return [child for item in value for child in nested_models(item)]
    return []


@given(st.integers(min_value=1, max_value=100_000_000))
def test_all_schemas_roundtrip_without_hash_drift(cents: int) -> None:
    instances = nested_models(schema_samples(Fraction(cents, 100)))
    for instance in instances:
        restored = type(instance).model_validate_json(instance.model_dump_json())
        assert H(restored) == H(instance)


def test_roundtrip_examples_cover_every_concrete_model() -> None:
    covered = {type(instance) for instance in nested_models(schema_samples())}
    declared = {
        value
        for value in vars(models).values()
        if isinstance(value, type) and issubclass(value, Model) and value is not Model
    }
    assert declared <= covered
