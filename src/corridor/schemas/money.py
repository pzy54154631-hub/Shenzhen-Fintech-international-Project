"""Exact rational money; Decimal is confined to display formatting."""

import re
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from fractions import Fraction
from typing import Annotated, Literal

from pydantic import AfterValidator, BeforeValidator, PlainSerializer, WithJsonSchema

from corridor.schemas.base import Model
from corridor.schemas.base import loads_exact as loads_exact

Currency = Literal["CNY"]
_RATIONAL = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*|\.[0-9]+)?$")


def parse_fraction(value: object) -> Fraction:
    if isinstance(value, Fraction):
        return value
    if not isinstance(value, str) or not _RATIONAL.fullmatch(value):
        raise ValueError("Money and rates require a rational or decimal string")
    try:
        return Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError("Invalid rational value") from exc


def fraction_string(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def _nonnegative(value: Fraction) -> Fraction:
    if value < 0:
        raise ValueError("Value must be nonnegative")
    return value


def _positive(value: Fraction) -> Fraction:
    if value <= 0:
        raise ValueError("Value must be positive")
    return value


Rational = Annotated[
    Fraction,
    BeforeValidator(parse_fraction),
    PlainSerializer(fraction_string, return_type=str, when_used="json"),
    WithJsonSchema({"type": "string", "pattern": _RATIONAL.pattern}),
]
NonnegativeRational = Annotated[Rational, AfterValidator(_nonnegative)]
PositiveRational = Annotated[Rational, AfterValidator(_positive)]


class Money(Model):
    amount: NonnegativeRational
    ccy: Currency

    def is_minor_unit(self) -> bool:
        return (self.amount * 100).denominator == 1


def ceil_minor(value: Fraction) -> Fraction:
    scaled = value * 100
    return Fraction(-(-scaled.numerator // scaled.denominator), 100)


def floor_minor(value: Fraction) -> Fraction:
    scaled = value * 100
    return Fraction(scaled.numerator // scaled.denominator, 100)


def display_amount(value: Fraction) -> str:
    # Round the rational to cents exactly before Decimal formatting, avoiding double rounding.
    sign = -1 if value < 0 else 1
    scaled = abs(value) * 100
    quotient, remainder = divmod(scaled.numerator, scaled.denominator)
    if 2 * remainder > scaled.denominator or (2 * remainder == scaled.denominator and quotient % 2):
        quotient += 1
    with localcontext() as ctx:
        ctx.prec = max(28, len(str(quotient)) + 4)
        return format(
            (Decimal(sign * quotient) / Decimal(100)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_EVEN
            ),
            ".2f",
        )
