"""Strict wire models and an exact, duplicate-free JSON decoder."""

import json
from collections.abc import Mapping
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, model_validator


def _reject_number(value: str) -> Any:
    raise ValueError(f"JSON floating-point numbers are forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON property: {key}")
        result[key] = value
    return result


def loads_exact(data: str | bytes | bytearray) -> Any:
    return json.loads(
        data,
        parse_float=_reject_number,
        parse_constant=_reject_number,
        object_pairs_hook=_unique_object,
    )


def reject_floats(value: Any) -> Any:
    if isinstance(value, float):
        raise ValueError("Floating-point values are forbidden")
    if isinstance(value, Mapping):
        for key, item in value.items():
            reject_floats(key)
            reject_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            reject_floats(item)
    return value


class Model(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
        populate_by_name=True,
        serialize_by_alias=True,
    )

    @model_validator(mode="before")
    @classmethod
    def no_floats(cls, value: Any) -> Any:
        return reject_floats(value)

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        return cls.model_validate(loads_exact(json_data), **kwargs)
