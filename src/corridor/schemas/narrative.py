"""Untrusted fact references and the gateway's verified display projection."""

from typing import Literal

from pydantic import Field

from corridor.schemas.base import Model
from corridor.schemas.models import Identifier, JsonValue


class FactRef(Model):
    receipt_ref: Identifier
    field: Identifier
    expected: JsonValue = None


class Narrative(Model):
    fact_refs: list[FactRef] = Field(default_factory=list, max_length=32)
    note: str = Field(default="", max_length=4000)


class RenderedFact(Model):
    receipt_ref: Identifier
    field: Identifier
    exact_value: JsonValue
    display_value: str
    text: str


class NarrativeResult(Model):
    status: Literal["rendered", "rejected"]
    rule_ids: list[str] = Field(default_factory=list)
    facts: list[RenderedFact] = Field(default_factory=list)
    note: str = ""
    text: str
