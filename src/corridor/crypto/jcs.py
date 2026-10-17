"""RFC 8785 adapter. Only the outer signature is excluded from H."""

from collections.abc import Mapping
from fractions import Fraction
from hashlib import sha256
from typing import Any

import rfc8785
from pydantic import BaseModel


def json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)
    if isinstance(value, float):
        raise ValueError("Floats are forbidden in signed business data")
    if isinstance(value, Fraction):
        return f"{value.numerator}/{value.denominator}"
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        return {key: json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    raise ValueError(f"Unsupported canonical value type: {type(value).__name__}")


def jcs_bytes(value: Any) -> bytes:
    return rfc8785.dumps(json_value(value))


def H(value: Any) -> str:
    body = json_value(value)
    if isinstance(body, dict):
        body = {key: item for key, item in body.items() if key != "sig"}
    return sha256(jcs_bytes(body)).hexdigest()
