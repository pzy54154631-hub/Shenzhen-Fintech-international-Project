"""Deterministic English prose guard and receipt-authenticated wealth displays.

Display reasons are diagnostics, not kernel rule IDs. Model prose is never a
source of numeric facts, even when a numeral happens to match a signed value.
"""

import re
import unicodedata
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal, TypeAlias

from corridor.gateway.facts import render_narrative
from corridor.gateway.privacy import PIIVault
from corridor.schemas.bank import AnalysisReceipt
from corridor.schemas.models import JsonValue
from corridor.schemas.money import display_amount, fraction_string
from corridor.schemas.narrative import FactRef, Narrative, RenderedFact
from corridor.schemas.state import BankState

BENCHMARK_LABEL = "performance benchmark (not guaranteed)"
_SAFE_NOTE = "Please review the verified facts."
_EMPTY = "No verified facts are available."
_APPROVED_PROSE = frozenset({
    "",
    _SAFE_NOTE,
    "Returns can vary and losses are possible.",
    "Returns are a performance benchmark (not guaranteed).",
    "Which goal would you like to revise?",
    "I can help you compare the verified product facts.",
    "Please confirm your goals on the simulated device.",
    "Please complete the risk questionnaire on the simulated device.",
    "Your request needs a new device confirmation.",
    "I can help you review the verified allocation.",
    "An advisor can help you review this request.",
})
_RETURN_ANSWER = (
    "I cannot promise a return. Losses are possible. "
    "Returns are a performance benchmark (not guaranteed). Review the verified facts."
)
_PROTECTION_ANSWER = (
    "The signed product facts do not establish principal protection. Losses are possible. "
    "Returns are a performance benchmark (not guaranteed). Review the verified facts."
)
_NUMBER_WORD = re.compile(
    r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
    r"thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|"
    r"forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|billion|"
    r"trillion|first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|"
    r"half|halves|quarter|quarters|dozen|double|triple|twice|thrice)\b",
    re.IGNORECASE,
)
_ROMAN_NUMBER = re.compile(
    r"\b[ivxlcdm]+\s*(?:percent\b|per\s*cent\b|%|basis\s*points\b)", re.IGNORECASE
)
_PROMISES = (
    "guarantee",
    "riskfree",
    "norisk",
    "capitalprotected",
    "principalprotected",
    "capitalisprotected",
    "principalisprotected",
    "willearn",
    "willprofit",
    "willreceive",
    "promise",
    "assuredreturn",
    "returnsareassured",
    "returnisassured",
    "assuredprofit",
    "cannotlose",
    "cantlose",
    "neverlose",
    "noloss",
    "lossfree",
    "alwaysprofit",
    "certainreturn",
    "sureprofit",
    "capitalissafe",
    "principalissafe",
    "nochanceofloss",
    "cannotsufferaloss",
    "willmakeaprofit",
    "保本",
    "稳赚",
    "剛兌",
    "刚兑",
    "保证收益",
    "保證收益",
    "保证回报",
    "保證回報",
    "收益有保障",
    "收益保障",
    "本金保障",
    "本金安全",
    "無風險",
    "无风险",
    "零风险",
)
_RETURN_FIELDS = frozenset({
    "expected_net",
    "projected_net",
    "projected_net_delta",
    "projected_income",
    "realized_income",
    "expected_annual_rate",
    "annual_return",
    "return",
    "returns",
    "yield",
    "income",
    "profit",
    "gap",
})
_LABELS = {
    "amount": "Amount",
    "balance_before": "Balance before execution",
    "balance_after": "Verified balance",
    "source_ref": "Source account reference",
    "destination_ref": "Destination reference",
    "executed_at": "Execution time",
    "status": "Verified status",
    "total_principal": "Total principal",
    "principal": "Principal",
    "total_buy_fees": "Total purchase fees",
    "total_debit": "Total debit",
    "fee_buy": "Purchase fee",
    "fee_hold": "Holding fee",
    "fee_sell": "Redemption fee",
    "total_fee": "Total fees",
    "projected_fees": "Projected fees",
    "liquid_principal": "Liquid net principal",
    "liquid_net_principal": "Liquid net principal",
    "biac_hash": "Allocation certificate hash",
    "allocation": "Verified allocation certificate",
    "projection_notice": "Projection notice",
    "access_days": "Access period in days",
    "rank": "Comparison rank",
    "reference_amount": "Comparison reference principal",
    "weight": "Allocation weight",
    "model_weight": "Model weight",
    "product_id": "Product reference",
    "candidate_ids": "Eligible product references",
    "reason_codes": "Exclusion reasons",
    "selection_reason": "Selection reason",
    "sleeve": "Risk sleeve",
    "score": "Questionnaire score",
    "level": "Risk level",
    "issued_at": "Issued at",
    "expires_at": "Valid until",
}
_MONEY_FIELDS = frozenset({
    "amount",
    "balance_before",
    "balance_after",
    "total_principal",
    "principal",
    "total_buy_fees",
    "total_debit",
    "fee_buy",
    "fee_hold",
    "fee_sell",
    "total_fee",
    "projected_fees",
    "liquid_principal",
    "liquid_net_principal",
    "reference_amount",
    "expected_net",
    "projected_net",
    "projected_net_delta",
    "projected_income",
    "realized_income",
})
FactPath: TypeAlias = tuple[str | int, ...]


@dataclass(frozen=True)
class GuardedProse:
    text: str
    status: Literal["accepted", "rewritten"]
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class GuardedOutput:
    status: Literal["rendered", "rejected"]
    facts: list[RenderedFact]
    note: str
    text: str
    rule_ids: list[str]
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProjectedFact:
    source_ref: FactRef
    path: FactPath
    exact_value: JsonValue
    label: str
    display_value: str
    text: str


@dataclass(frozen=True)
class DerivedFact:
    field: str
    product_id: str | None
    source_refs: tuple[FactRef, FactRef]
    paths: tuple[FactPath | None, FactPath | None]
    before: str
    after: str
    exact_value: str
    label: str
    display_value: str
    text: str


def _normalized(text: str) -> str:
    return "".join(
        character
        for character in unicodedata.normalize("NFKC", text)
        if unicodedata.category(character) != "Cf"
    )


def _promissory(text: str) -> bool:
    # Only this exact negated phrase is a permitted occurrence of "guaranteed".
    without_disclaimer = text.casefold().replace(BENCHMARK_LABEL, "benchmark")
    compact = "".join(character for character in without_disclaimer if character.isalnum())
    return any(word in compact for word in _PROMISES)


def guard_prose(note: str, vault: PIIVault | None = None) -> GuardedProse:
    """Rewrite unsafe notes without ever attempting to match their numbers to facts."""
    normalized = _normalized(note)
    reasons: list[str] = []
    try:
        (vault or PIIVault()).ensure_safe(normalized, rule="PII-OUT")
    except ValueError:
        reasons.append("private_content")
    if _promissory(normalized):
        reasons.append("unsupported_promise")
    if (
        any(character.isnumeric() for character in normalized)
        or _NUMBER_WORD.search(normalized)
        or _ROMAN_NUMBER.search(normalized)
    ):
        reasons.append("unverified_number")
    if not normalized.isascii():
        reasons.append("non_english_prose")
    if any(not character.isprintable() and character not in "\n\t" for character in normalized):
        reasons.append("unsupported_format")
    # A blacklist cannot establish English or exclude every promissory paraphrase.
    # Keep publication fail-closed; dialogue questions come from deterministic templates.
    if not reasons and normalized not in _APPROVED_PROSE:
        reasons.append("unverified_prose")
    return GuardedProse(
        text=_SAFE_NOTE if reasons else normalized,
        status="rewritten" if reasons else "accepted",
        reasons=tuple(reasons),
    )


def _label(field: str) -> str:
    leaf = field.rsplit(".", 1)[-1]
    if leaf in _RETURN_FIELDS:
        return BENCHMARK_LABEL
    return _LABELS.get(leaf, "Verified fact")


def _display(value: JsonValue, field: str) -> str:
    leaf = field.rsplit(".", 1)[-1]
    if (
        isinstance(value, dict)
        or isinstance(value, list)
        and any(isinstance(item, (list, dict)) for item in value)
    ):
        # Nested values are exposed only through authenticated leaf projections.
        return "Verified structured facts; returns are a " + BENCHMARK_LABEL
    if leaf == "projection_notice":
        return "Synthetic new-money allocation; returns are a " + BENCHMARK_LABEL
    if leaf in _MONEY_FIELDS and isinstance(value, (str, int)) and not isinstance(value, bool):
        return display_amount(Fraction(value))
    if isinstance(value, list):
        display = ", ".join(str(item) for item in value)
    elif value is None:
        display = "Not available"
    elif isinstance(value, bool):
        display = "Yes" if value else "No"
    else:
        display = str(value)
    # A signed string is data, not authorization to publish a promise or another language.
    if not display.isascii() or _promissory(_normalized(display)):
        raise ValueError("RCPT-MISMATCH")
    return display


def _english_fact(fact: RenderedFact) -> RenderedFact:
    label = _label(fact.field)
    display = _display(fact.exact_value, fact.field)
    return fact.model_copy(update={"display_value": display, "text": f"{label}: {display}."})


def render_guarded(
    narrative: Narrative, state: BankState, principal: str, vault: PIIVault
) -> GuardedOutput:
    """Verify original FactRefs, then replace only presentation with fixed English labels."""
    try:
        validated = Narrative.model_validate(
            narrative.model_dump(mode="python", exclude_unset=True, warnings=False)
        )
    except (ValueError, TypeError, AttributeError):
        return GuardedOutput("rejected", [], "", _EMPTY, ["RCPT-MISMATCH"])
    prose = guard_prose(validated.note, vault)
    verified = render_narrative(validated.model_copy(update={"note": ""}), state, principal, vault)
    if verified.status == "rendered" and any(
        isinstance(receipt := state.receipts.get(ref.receipt_ref), AnalysisReceipt)
        and receipt.trust != "builtin"
        for ref in validated.fact_refs
    ):
        # Exploratory numerical results have unverified semantics. Their legacy
        # renderer retains that warning; this wealth-only path never upgrades them.
        return GuardedOutput("rejected", [], "", _EMPTY, ["RCPT-MISMATCH"])
    rules = list(verified.rule_ids)
    if "private_content" in prose.reasons:
        rules.append("PII-OUT")
    try:
        facts = [_english_fact(fact) for fact in verified.facts]
    except (ValueError, TypeError, ArithmeticError):
        rules.append("RCPT-MISMATCH")
        facts = []
    note = f"Assistant (unverified): {prose.text}" if prose.text else ""
    text = "\n".join([*(fact.text for fact in facts)] or [_EMPTY])
    if note:
        text += "\n" + note
    try:
        vault.ensure_safe({"facts": facts, "note": note, "text": text}, rule="PII-OUT")
    except ValueError:
        rules.append("PII-OUT")
        facts, note, text = [], "", _EMPTY
    return GuardedOutput(
        status="rejected" if rules else "rendered",
        facts=facts,
        note=note,
        text=text,
        rule_ids=list(dict.fromkeys(rules)),
        reasons=prose.reasons,
    )


def answer_guarantee(
    question: str, fact_refs: list[FactRef], state: BankState, principal: str, vault: PIIVault
) -> GuardedOutput:
    """Answer guarantee requests using fixed truthful prose and available verified facts."""
    result = render_guarded(Narrative(fact_refs=fact_refs), state, principal, vault)
    compact = "".join(
        character for character in _normalized(question).casefold() if character.isalnum()
    )
    protection = any(word in compact for word in ("capital", "principal", "保本", "本金"))
    note = _PROTECTION_ANSWER if protection else _RETURN_ANSWER
    return GuardedOutput(
        status=result.status,
        facts=result.facts,
        note=note,
        text=note + "\n" + result.text,
        rule_ids=result.rule_ids,
        reasons=result.reasons,
    )


def _verified_allocation(
    ref: FactRef, state: BankState, principal: str, vault: PIIVault
) -> dict[str, JsonValue]:
    if ref.field != "allocation":
        raise ValueError("RCPT-MISMATCH")
    rendered = render_guarded(Narrative(fact_refs=[ref]), state, principal, vault)
    if rendered.status != "rendered" or len(rendered.facts) != 1:
        raise ValueError("RCPT-MISMATCH")
    receipt = state.receipts.get(ref.receipt_ref)
    if not isinstance(receipt, AnalysisReceipt) or receipt.function_id != "allocation_compare_v1":
        raise ValueError("RCPT-MISMATCH")
    value = rendered.facts[0].exact_value
    if not isinstance(value, dict):
        raise ValueError("RCPT-MISMATCH")
    return value


def _at_path(value: JsonValue, path: FactPath) -> JsonValue:
    if not path:
        raise ValueError("RCPT-MISMATCH")
    for part in path:
        if isinstance(value, dict) and isinstance(part, str) and part in value:
            value = value[part]
        elif isinstance(value, list) and type(part) is int and 0 <= part < len(value):
            value = value[part]
        else:
            raise ValueError("RCPT-MISMATCH")
    return value


def project_allocation_fact(
    ref: FactRef, path: FactPath, state: BankState, principal: str, vault: PIIVault
) -> ProjectedFact:
    """Project a leaf of a verified full BIAC while retaining its original receipt ref."""
    value = _at_path(_verified_allocation(ref, state, principal, vault), path)
    if (
        isinstance(value, dict)
        or isinstance(value, list)
        and any(isinstance(item, (list, dict)) for item in value)
    ):
        raise ValueError("RCPT-MISMATCH")
    field = next((part for part in reversed(path) if isinstance(part, str)), "")
    label, display = _label(field), _display(value, field)
    text = f"{label}: {display}."
    vault.ensure_safe({"value": value, "text": text}, rule="PII-OUT")
    return ProjectedFact(ref.model_copy(deep=True), path, value, label, display, text)


def _allocation_rows(value: dict[str, JsonValue]) -> dict[str, tuple[int, dict[str, JsonValue]]]:
    rows = value.get("allocation")
    if not isinstance(rows, list):
        raise ValueError("RCPT-MISMATCH")
    found: dict[str, tuple[int, dict[str, JsonValue]]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("product_id"), str):
            raise ValueError("RCPT-MISMATCH")
        product_id = str(row["product_id"])
        if product_id in found:
            raise ValueError("RCPT-MISMATCH")
        found[product_id] = (index, row)
    return found


def _derived(
    field: str,
    product_id: str | None,
    refs: tuple[FactRef, FactRef],
    paths: tuple[FactPath | None, FactPath | None],
    values: tuple[JsonValue, JsonValue],
) -> DerivedFact:
    if any(not isinstance(value, str) for value in values):
        raise ValueError("RCPT-MISMATCH")
    before, after = (
        fraction_string(Fraction(str(values[0]))),
        fraction_string(Fraction(str(values[1]))),
    )
    delta = fraction_string(Fraction(after) - Fraction(before))
    label, display = "Change in " + _label(field), display_amount(Fraction(delta))
    return DerivedFact(
        field, product_id, refs, paths, before, after, delta, label, display, f"{label}: {display}."
    )


def allocation_diff(
    before_ref: FactRef, after_ref: FactRef, state: BankState, principal: str, vault: PIIVault
) -> tuple[DerivedFact, ...]:
    """Compute exact differences only after both entire allocation receipts authenticate.

    A missing product contributes zero only here, from its absence in the complete
    authenticated allocation. Its absent path remains None instead of a fabricated ref.
    """
    before = _verified_allocation(before_ref, state, principal, vault)
    after = _verified_allocation(after_ref, state, principal, vault)
    refs = (before_ref.model_copy(deep=True), after_ref.model_copy(deep=True))
    before_rows, after_rows = _allocation_rows(before), _allocation_rows(after)
    changes: list[DerivedFact] = []
    for product_id in sorted(before_rows.keys() | after_rows.keys()):
        for field in (
            "principal",
            "fee_buy",
            "fee_hold",
            "fee_sell",
            "expected_net",
            "liquid_net_principal",
        ):
            left, right = before_rows.get(product_id), after_rows.get(product_id)
            paths: tuple[FactPath | None, FactPath | None] = (
                ("allocation", left[0], field) if left else None,
                ("allocation", right[0], field) if right else None,
            )
            values = (
                left[1].get(field) if left else "0/1",
                right[1].get(field) if right else "0/1",
            )
            changes.append(_derived(field, product_id, refs, paths, values))
    for field in (
        "principal",
        "fee_buy",
        "total_debit",
        "projected_fees",
        "projected_net",
        "liquid_net_principal",
    ):
        path: FactPath = ("totals", field)
        values = (_at_path(before, path), _at_path(after, path))
        changes.append(_derived(field, None, refs, (path, path), values))
    for change in changes:
        vault.ensure_safe({"product": change.product_id, "text": change.text}, rule="PII-OUT")
    return tuple(changes)
