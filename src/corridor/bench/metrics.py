"""Descriptive binomial uncertainty; counts never imply independent attacks."""

from fractions import Fraction
from math import sqrt
from typing import Any

from corridor.schemas.money import fraction_string


def binomial_summary(numerator: int, denominator: int) -> dict[str, Any]:
    if not 0 <= numerator <= denominator:
        raise ValueError("Expected 0 <= numerator <= denominator")
    result: dict[str, Any] = {"numerator": numerator, "denominator": denominator}
    if denominator == 0:
        return {
            **result,
            "status": "not_run",
            "display": "not_run",
            "wilson_95": None,
            "upper_95_approx": None,
        }
    # Floating point is used only for the non-financial confidence interval.
    z = 1.959963984540054
    p = numerator / denominator
    scale = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / scale
    half = z * sqrt(p * (1 - p) / denominator + z * z / (4 * denominator**2)) / scale
    lower, upper = max(0.0, center - half), min(1.0, center + half)
    # Store decimal strings so the common strict JSON wire never contains floats.
    interval = {"lower": f"{lower:.9f}", "upper": f"{upper:.9f}"}
    display = f"{numerator}/{denominator} (95% Wilson {lower:.4f}–{upper:.4f})"
    bound = None
    if numerator == 0:
        bound = fraction_string(min(Fraction(1), Fraction(3, denominator)))
        display = f"0/{denominator} (95% upper approximately {bound}; capped at 1)"
    return {
        **result,
        "status": "measured",
        "display": display,
        "wilson_95": interval,
        "upper_95_approx": bound,
    }
