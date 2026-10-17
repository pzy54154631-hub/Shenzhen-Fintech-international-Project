"""Domain-neutral primitives retained for the domestic banking contracts."""

from typing import TYPE_CHECKING, Annotated, Literal, Self, TypeAlias

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator
from typing_extensions import TypeAliasType

from corridor.schemas.base import Model
from corridor.schemas.time import Timestamp

Identifier = Annotated[str, Field(min_length=1)]
Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Signature = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
NonnegativeInt = Annotated[StrictInt, Field(ge=0)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
if TYPE_CHECKING:
    JsonValue: TypeAlias = str | int | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
else:
    JsonValue = TypeAliasType(
        "JsonValue",
        StrictStr | StrictInt | StrictBool | None | list["JsonValue"] | dict[str, "JsonValue"],
    )


class VerdictDetails(Model):
    tier: Literal["green", "yellow", "red", "black"] | None = None
    required_factors: list[str] = Field(default_factory=list)
    dependency_hash: Hash | None = None
    tier_basis: dict[str, JsonValue] = Field(default_factory=dict)
    verified_facts: dict[str, JsonValue] = Field(default_factory=dict)


class Accept(VerdictDetails):
    outcome: Literal["Accept"] = "Accept"


class Reject(VerdictDetails):
    outcome: Literal["Reject"] = "Reject"
    rule_ids: Annotated[list[str], Field(min_length=1)]
    first: str
    obligation: str
    counterexample_code: str

    @model_validator(mode="after")
    def first_rule(self) -> Self:
        if self.first not in self.rule_ids:
            raise ValueError("Reject.first must be included in rule_ids")
        return self


class Escalate(VerdictDetails):
    outcome: Literal["Escalate"] = "Escalate"
    rule_ids: Annotated[list[str], Field(min_length=1)]
    reasons: list[str]


Verdict = Annotated[Accept | Reject | Escalate, Field(discriminator="outcome")]


class AuditRecord(Model):
    seq: NonnegativeInt
    ts: Timestamp
    prev_hash: Hash
    event: str
    action_hash: Hash | None = None
    cert_hash: Hash | None = None
    rule_ids: list[str] | None = None
    token_id: str | None = None
    record_hash: Hash
