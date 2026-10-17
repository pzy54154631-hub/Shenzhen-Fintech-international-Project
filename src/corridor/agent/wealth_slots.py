"""Deterministic extraction of untrusted, unsigned wealth-goal drafts.

This parser does not infer suitability, choose products, create authority, or read
state. Every result still requires a device review and a signed AllocationRequest.
Only explicit values and a narrow set of ordinary language units are recognized.
"""

import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

GoalField = Literal[
    "amount",
    "horizon_days",
    "liquidity_days",
    "liquidity_amount",
    "objective",
    "allowed_types",
]
UtteranceKind = Literal["answer", "correction", "what_if", "new_intent"]
DraftValue = str | int | list[str]
_FIELDS: tuple[GoalField, ...] = (
    "amount",
    "liquidity_amount",
    "liquidity_days",
    "horizon_days",
    "objective",
    "allowed_types",
)
_NUMBER = r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?"
_MONEY = re.compile(
    rf"(?<![0-9a-z_.])(?:cny\s*|rmb\s*|[¥￥])?"
    rf"(?P<number>[+-]?{_NUMBER})\s*(?P<scale>[kmw万千]?)(?:元)?(?![0-9a-z_.])",
    re.IGNORECASE,
)
_WORDS = {
    "a": 1,
    "an": 1,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "一": 1,
    "两": 2,
    "二": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
}
_DURATION = re.compile(
    r"(?<![0-9a-z_.])(?P<count>\d+|"
    + "|".join(_WORDS)
    + r")\s*(?P<unit>days?|weeks?|years?|months?|天|日|周|星期|年|个月)(?![a-z])",
    re.IGNORECASE,
)
_INVEST = re.compile(
    r"\b(?:have|invest|invset|allocate|allocation amount|budget|principal|amount|"
    r"put|save|tou)\b|投资|投入|本金|金额",
    re.IGNORECASE,
)
_LIQUID = re.compile(
    r"\b(?:need|withdraw|access|liquid|liquidity|emergency|cash)\b|需要|取出|流动",
    re.IGNORECASE,
)
_NEGATED = re.compile(r"\b(?:not|never|don't|do not|won't|no)\b|不要|不需要", re.IGNORECASE)
_CORRECTION = re.compile(
    r"\b(?:actually|instead|correct|correction|change|drop|remove|replace)\b|改成|改为|纠正|去掉",
    re.IGNORECASE,
)
_ADJUSTMENT = re.compile(r"\b(?:drop|remove|replace|weights?|sleeves?)\b|去掉|权重", re.IGNORECASE)


@dataclass(frozen=True)
class DraftSlot:
    field: GoalField
    value: DraftValue
    source_text: str


@dataclass(frozen=True)
class ParsedUtterance:
    kind: UtteranceKind
    slots: tuple[DraftSlot, ...]
    adjustment_requested: bool = False
    errors: tuple[str, ...] = ()


def _kind(text: str) -> UtteranceKind:
    if re.search(
        r"\bwhat[ -]?if\b|\bhypothetic\w*\b|\bsuppose\b|^\s*if\b|"
        r"\bwhat (?:changes|happens|would happen) if\b|假如|假设|如果",
        text,
        re.I,
    ):
        return "what_if"
    if re.search(
        r"\bnew (?:plan|intent|investment|goal)\b|\bstart (?:over|again)\b|重新开始", text, re.I
    ):
        return "new_intent"
    return "correction" if _CORRECTION.search(text) else "answer"


def _context(text: str, start: int) -> str:
    return re.split(r"[,;!?，；。！？]", text[:start])[-1][-80:]


def _whole_money(text: str) -> bool:
    cleaned = re.sub(
        r"^(?:actually|instead|correct(?:ion)?|改成|改为)\s*[:,]?\s*", "", text, flags=re.I
    )
    return _MONEY.fullmatch(cleaned.strip().rstrip(".!。")) is not None


def parse_utterance(text: str, *, pending_field: GoalField | None = None) -> ParsedUtterance:
    """Return heard values only; unknown or ambiguous language remains missing.

    ``errors`` identifies drafts that need correction (including horizons beyond
    the supported 365 days). No invalid value is silently rounded or clamped.
    A pending field interprets a bare answer, never an account or phone number.
    """
    if pending_field is not None and pending_field not in _FIELDS:
        raise ValueError("Unknown pending goal field")
    kind = _kind(text)
    candidates: dict[GoalField, list[DraftSlot]] = {}
    errors: list[str] = []

    def add(field: GoalField, value: DraftValue, source: str) -> None:
        candidates.setdefault(field, []).append(DraftSlot(field, value, source))

    for match in _MONEY.finditer(text):
        number = match["number"].replace(",", "")
        # Long identifier-like digits do not become financial drafts.
        if len(re.sub(r"\D", "", number)) > 10:
            continue
        after = text[match.end() :]
        if re.match(
            r"\s*(?:%|days?\b|weeks?\b|years?\b|months?\b|天|日|周|星期|年|个月)", after, re.I
        ):
            continue
        context = _context(text, match.start())
        if _NEGATED.search(context):
            continue
        field: GoalField | None = None
        if _LIQUID.search(context):
            field = "liquidity_amount"
        elif _INVEST.search(context):
            field = "amount"
        elif _whole_money(text):
            if pending_field in {"amount", "liquidity_amount"}:
                field = pending_field
            elif kind == "correction" and pending_field is None:
                field = "amount"
        if field is None:
            continue
        scales = {"": 1, "k": 1000, "m": 1_000_000, "w": 10_000, "万": 10_000, "千": 1000}
        value = Fraction(number) * scales[match["scale"].lower()]
        add(field, f"{value.numerator}/{value.denominator}", match.group().strip())
        if value < 0 or field == "amount" and value == 0:
            errors.append(f"{field}_out_of_range")
        if (value * 100).denominator != 1:
            errors.append(f"{field}_not_whole_cents")

    for match in _DURATION.finditer(text):
        context = _context(text, match.start())
        if _NEGATED.search(context):
            continue
        count_text = match["count"].lower()
        count = int(count_text) if count_text.isdigit() else _WORDS[count_text]
        unit = match["unit"].lower()
        if unit.startswith("month") or unit == "个月":
            errors.append("calendar_period_requires_days")
            continue
        multiplier = (
            365
            if unit.startswith("year") or unit == "年"
            else 7
            if unit.startswith("week") or unit in {"周", "星期"}
            else 1
        )
        days = count * multiplier
        liquidity = bool(
            re.search(r"\bwithin\b|\baccess\b|\bliquid\w*\b", context, re.I)
            or _LIQUID.search(context)
            or text[match.end() :].startswith("内")
            or pending_field == "liquidity_days"
            and not _INVEST.search(context)
        )
        duration_field: GoalField = "liquidity_days" if liquidity else "horizon_days"
        add(duration_field, days, match.group())
        if days < 0 or days > 365 or duration_field == "horizon_days" and days == 0:
            errors.append(f"{duration_field}_out_of_range")

    if pending_field in {"horizon_days", "liquidity_days"} and re.fullmatch(r"\s*\d+\s*", text):
        days = int(text.strip())
        add(pending_field, days, text.strip())
        if days > 365 or pending_field == "horizon_days" and days == 0:
            errors.append(f"{pending_field}_out_of_range")

    objectives = {
        "total_fee": (
            r"\blow(?:est)? fees?\b|\blow(?:est)? (?:total )?costs?\b"
            r"|\btotal_fee\b|费用最低|低费用"
        ),
        "net_return": r"\bnet[ _]return\b|\b(?:highest|maximi[sz]e) (?:net )?returns?\b|净收益",
        "liquidity": (
            r"\b(?:prefer|prioriti[sz]e|priority(?: is)?) liquidity\b"
            r"|^\s*liquidity\s*[.!]?\s*$|优先流动性"
        ),
    }
    for objective, pattern in objectives.items():
        for match in re.finditer(pattern, text, re.I):
            if not _NEGATED.search(_context(text, match.start())):
                add("objective", objective, match.group())

    type_matches = list(
        re.finditer(r"\bdeposits?\b|\bwealth(?: products?)?\b|存款|理财", text, re.I)
    )
    positive_types = [
        match for match in type_matches if not _NEGATED.search(_context(text, match.start()))
    ]
    if positive_types:
        types = sorted({
            "deposit" if re.match(r"deposits?|存款", match.group(), re.I) else "wealth"
            for match in positive_types
        })
        add("allowed_types", types, text[positive_types[0].start() : positive_types[-1].end()])

    slots = []
    for goal_field in _FIELDS:
        found = candidates.get(goal_field, [])
        if found and any(slot.value != found[0].value for slot in found[1:]):
            errors.append(f"{goal_field}_ambiguous")
        elif found:
            slots.append(found[0])
    return ParsedUtterance(
        kind,
        tuple(slots),
        adjustment_requested=bool(_ADJUSTMENT.search(text)),
        errors=tuple(dict.fromkeys(errors)),
    )
