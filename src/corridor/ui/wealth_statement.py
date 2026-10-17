"Read-only suitability statements projected from gateway-verified BIAC facts."

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from fractions import Fraction
from html import escape, unescape
from io import BytesIO
from re import sub
from typing import Any, cast
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import streamlit as st

from corridor.crypto.jcs import H
from corridor.schemas.allocation import (
    AllocationPolicy,
    AllocationRequest,
    BestInterestAllocationCertificate,
    ClientProfile,
)
from corridor.schemas.domain import RiskAssessment
from corridor.ui.messages import display_value, tr
from corridor.ui.product_style import badge, currency, product_label

PROFILE_NAMES = {1: "Conservative", 2: "Cautious", 3: "Balanced", 4: "Growth", 5: "Aggressive"}
OBJECTIVES = {
    "net_return": "net performance benchmark (not guaranteed)",
    "total_fee": "lowest total fees",
    "liquidity": "earliest access",
}
REASONS = {
    "objective_rank": "Chosen by the objective ranking within its risk sleeve.",
    "liquidity_requirement": "Chosen to meet the signed liquidity requirement.",
    "sleeve_fill": "Chosen to fill the remaining policy sleeve allocation.",
    "explicit_item": "Chosen through your explicit device-confirmed adjustment.",
}
EXCLUSIONS = {
    "purchase_closed": "Closed to purchases",
    "customer_ineligible": "Customer not eligible",
    "risk": "Risk exceeds your profile",
    "product_type": "Outside your allowed product types",
    "holding_period": "Holding period exceeds your horizon",
    "minimum_amount": "Minimum purchase cannot be met",
    "maximum_amount": "Product maximum cannot accommodate an allocation",
    "concentration": "Concentration cap prevents the minimum purchase",
    "available_balance": "Insufficient available balance including fees",
}
CHECK_LABELS = {
    "principal_sum": "Principal conserved",
    "total_debit": "Debit within available funds",
    "product_minimum": "Minimum purchase",
    "product_maximum": "Maximum purchase",
    "concentration": "Product concentration",
    "sleeve_lower": "Sleeve minimum",
    "sleeve_upper": "Sleeve maximum",
    "group_lower": "Group minimum",
    "group_upper": "Group maximum",
    "liquidity": "Required net liquidity",
    "nonnegative_liquid_principal": "Nonnegative net redemption principal",
}
RULE_REASONS = {
    "ALLOC-BAND": "Outside the risk band your policy allows",
    "ALLOC-CONC": "A product exceeds the concentration limit",
    "ALLOC-LIQ": "Net liquidity falls below your signed requirement",
    "ALLOC-SUM": "The principal, fees or total debit do not reconcile",
    "ALLOC-SELECT": "No allocation was constructed under this policy and these inputs",
    "ALLOC-POLICY": "The allocation policy is not valid for this comparison",
    "BIC-RISK": "A current device risk questionnaire is required",
    "BIC-NOFEASIBLE": "No eligible products were found in the declared catalogue",
    "BIC-COMPLETE": "The complete catalogue comparison could not be verified",
}

STYLE = """
<style>
.suitability{font-family:Arial,sans-serif;color:#173735;line-height:1.45;width:100%;max-width:none}
.suitability h2{font-size:23px;margin:0 0 10px}.suitability h3{font-size:16px;margin:20px 0 9px}
.suitability .verdict{background:#e6f3ec;padding:14px;border-radius:12px}
.suitability .muted{color:#617b7b;font-size:12px}.suitability .warning{background:#fff3db;
padding:10px;border-left:4px solid #b48d52;margin:8px 0}.suitability .metrics{display:grid;
grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:17px 0}
.suitability .metric{background:white;border:1px solid #dce7e5;border-radius:12px;
padding:15px;font-size:12px;color:#647b7b}.suitability .metric strong{display:block;
font-size:21px;line-height:1.3;color:#173735;margin-top:8px;white-space:nowrap}
.suitability .table-wrap{overflow-x:auto;
border:1px solid #e0e9e7;
border-radius:12px;
background:white}
.suitability table{width:100%;border-collapse:collapse;font-size:15px}
.suitability th,.suitability td{text-align:left;padding:11px 13px;border-bottom:1px solid #edf2f0;
vertical-align:top}.suitability th{background:#f0f6f3;color:#5a7470;font-weight:600;font-size:11px}
.suitability tr:last-child td{border-bottom:0}.suitability .selected-product{background:#edf8f1}
.suitability small{display:block;color:#6c807c;font-size:15px;max-width:440px}
.suitability footer{font-size:10px;overflow-wrap:anywhere;margin-top:15px}
.suitability .two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.suitability .sleeve-bar{height:9px;
border-radius:5px;
background:#e8efeb;
margin:5px 0;
position:relative;
min-width:130px}
.suitability .sleeve-fill{height:9px;border-radius:5px;background:#168570}
.suitability .band-marker{height:13px;position:absolute;top:-2px;border-left:1px solid #b48d52;
border-right:1px solid #b48d52;background:#b48d5210}
.suitability .cw-chip{display:inline-block;
padding:4px 10px;
border-radius:999px;
font-size:11px;
font-weight:600}
.suitability .cw-chip-green{background:#def1e5;
color:#1e7252}
.suitability .cw-chip-red{background:#fce8e5;
color:#a44840}
.suitability .cw-chip-neutral{background:#edf1f2;color:#5a737a}
@media(max-width:900px){.suitability .metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:640px){.suitability .two-col{grid-template-columns:1fr}
.suitability .metric strong{font-size:18px}}
@media print{@page{size:A4 landscape;margin:10mm}.suitability{font-size:10px;max-width:none}
.suitability h2{font-size:17px}.suitability h3{font-size:12px}.suitability table{font-size:9px}
.suitability th,.suitability td{padding:3px 4px}.suitability details{display:none}
.suitability .metric{padding:6px}.suitability footer{font-size:8px}}
</style>
"""


@dataclass(frozen=True)
class Statement:
    """The downloadable page and inspectable sources for each displayed quantity."""

    html: str
    text: str
    summary_html: str
    details: dict[str, str]
    numeric_sources: dict[str, dict[str, Any]]


def _resolve(documents: dict[str, Any], path: str) -> Any:
    value: Any = documents
    for part in path.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _display(value: Fraction, style: str) -> str:
    if style == "integer":
        return str(value.numerator) if value.denominator == 1 else str(value)
    factor = 100 if style in {"percent", "points"} else 1
    decimal = (Decimal(value.numerator) * factor / Decimal(value.denominator)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_EVEN
    )
    if style == "compact":
        return f"{decimal:,.0f}" if value.denominator == 1 else f"{decimal:,.2f}"
    if style == "percent":
        return f"{decimal:,.2f}%"
    if style == "points":
        return f"{decimal:,.2f} pp"
    return currency(value)


class _Projection:
    def __init__(self, documents: dict[str, Any]):
        self.documents = documents
        self.sources: dict[str, dict[str, Any]] = {}

    def number(self, key: str, *paths: str, operation: str = "value", style: str = "money") -> str:
        values = [_resolve(self.documents, path) for path in paths]
        if operation == "count":
            value = Fraction(len(values[0]))
        elif operation == "count_sum":
            value = Fraction(sum(len(item) for item in values))
        elif operation == "sum":
            value = sum(map(Fraction, values), Fraction())
        elif operation == "ratio":
            value = Fraction(values[0]) / Fraction(values[1])
        elif operation == "cent_ratio":
            value = Fraction(values[0], 100) / Fraction(values[1])
        elif operation == "settled_count":
            value = Fraction(sum(item["status"] == "settled" for item in values[0]))
        else:
            value = Fraction(values[0])
        display = _display(value, style)
        self.sources[key] = {
            "sources": list(paths),
            "operation": operation,
            "exact": f"{value.numerator}/{value.denominator}",
            "display": display,
        }
        return (
            '<span data-number="'
            f"{escape(key)}"
            '" data-source="'
            f"{escape(';'.join(paths))}"
            '">'
            f"{display}"
            "</span>"
        )


def _table(headers: list[str], rows: list[list[str]]) -> str:
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + "".join(f"<th>{escape(header)}</th>" for header in headers)
        + "</tr></thead><tbody>"
        + "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
        + "</tbody></table></div>"
    )


def _execution(projection: _Projection, execution: dict[str, Any] | None) -> str:
    if not execution:
        return tr("Comparison complete – no purchase executed")
    status = execution.get("status")
    if status == "unknown":
        return tr("Outcome pending reconciliation – do not retry")
    if status in {"completed", "partially_executed", "executing"}:
        settled = projection.number(
            "execution.settled", "execution.items", operation="settled_count", style="integer"
        )
        total = projection.number(
            "execution.total", "execution.items", operation="count", style="integer"
        )
        state = tr("Completed") if status == "completed" else tr("Partially executed")
        message = (
            f"{state}"
            " – "
            f"{settled}"
            f"{tr(' of ')}"
            f"{total}"
            f"{tr(' settled; nothing reversed automatically')}"
        )
        if "available_balance" in execution:
            cash = projection.number("execution.cash", "execution.available_balance")
            positions = []
            for index, item in enumerate(execution.get("items", [])):
                if item.get("status") == "settled":
                    amount = projection.number(
                        f"execution.position.{index}",
                        f"execution.items.{index}.principal",
                    )
                    positions.append(escape(product_label(item["product_ref"])) + " " + amount)
            if positions:
                message += "<br>" + " + ".join(positions) + f" + {cash}{tr(' cash, ')}{state}"
            message += f"<br>{cash}{tr(' remains in your account.')}"
        return message
    if status in {"failed", "cancelled"}:
        return tr("Plan stopped – no purchase executed")
    return tr("Awaiting device approval – no purchase executed")


def build_statement(
    biac: BestInterestAllocationCertificate | dict[str, Any],
    request: AllocationRequest | dict[str, Any],
    policy: AllocationPolicy | dict[str, Any],
    profile: RiskAssessment | dict[str, Any],
    execution: dict[str, Any] | None = None,
    audit_href: str = "#audit-entry",
    *,
    suitability: dict[str, Any] | None = None,
) -> Statement:
    "Project already verified inputs without constructing or authorizing an allocation."
    biac = BestInterestAllocationCertificate.model_validate(biac)
    request = AllocationRequest.model_validate(request)
    policy = AllocationPolicy.model_validate(policy)
    profile = RiskAssessment.model_validate(profile)
    effective_level = profile.level
    if suitability is not None:
        effective_level = suitability.get("effective_level")
        if (
            suitability.get("raw_level") != profile.level
            or type(effective_level) is not int
            or not 1 <= effective_level <= profile.level
        ):
            raise ValueError("Signed suitability metadata does not match the profile")
    if (
        biac.policy_hash != H(policy)
        or biac.risk_assessment_hash != H(profile)
        or request.allocation_policy_ref != policy.id
        or request.source_account_ref != biac.source_account_ref
        or request.amount != biac.totals.principal
        or request.selection_mode != biac.selection_mode
        or not biac.checks
        or not all(check.satisfied for check in biac.checks)
        or (execution is not None and execution.get("biac_hash", H(biac)) != H(biac))
    ):
        raise ValueError("Verified statement context does not match the certificate")
    if not audit_href.startswith("#") and audit_href != "audit.jsonl":
        raise ValueError("Statement audit link must refer to local or bundled evidence")
    documents = {
        "biac": biac.model_dump(mode="json"),
        "request": request.model_dump(mode="json"),
        "policy": policy.model_dump(mode="json"),
        "profile": profile.model_dump(mode="json"),
        "execution": execution,
        "suitability": suitability,
    }
    projection = _Projection(documents)
    number = projection.number
    count = number("eligible", "biac.candidate_ids", operation="count", style="integer")
    excluded = number("excluded", "biac.exclusions", operation="count", style="integer")
    checked = number(
        "checked", "biac.candidate_ids", "biac.exclusions", operation="count_sum", style="integer"
    )
    raw_level = number("profile.level", "profile.level", style="integer")
    level = (
        number("suitability.effective_level", "suitability.effective_level", style="integer")
        if suitability is not None
        else raw_level
    )
    profile_id = cast(ClientProfile, f"C{effective_level}")
    policy_version = number("policy.version", "policy.version", style="integer")
    catalog_version = number("catalog.version", "policy.catalog_version", style="integer")
    horizon = number("request.horizon", "request.horizon_days", style="integer")
    status = _execution(projection, execution)
    catalogue_summary = tr(
        " eligible products considered · ranked by your objective</strong><br>"
        "sponsor-independent within the declared catalogue and policy<br>Complete: "
    )
    questionnaire_notice = tr(
        " · synthetic questionnaire, not a professional suitability assessment</p><p><strong>"
    )
    summary = (
        f"""{tr('<h2>Suitability Statement</h2><div class="verdict"><strong>Suitable for C')}"""
        f"{level}"
        " ("
        f"{display_value(PROFILE_NAMES[effective_level])}"
        f"{tr(') · all ')}"
        f"{count}"
        f"{catalogue_summary}"
        f"{checked}"
        "/"
        f"{checked}"
        f"{tr(' checked, ')}"
        f"{count}"
        f"{tr(' eligible, ')}"
        f"{excluded}"
        f"""{tr(' excluded</div><p class="muted">Policy version ')}"""
        f"{policy_version}"
        f"{tr(' · policy-checked heuristic · Objective: ')}"
        f"{escape(display_value(OBJECTIVES[request.objective]))}"
        f"{tr(' · horizon ')}"
        f"{horizon}"
        f"{tr(' days<br>Profile valid until ')}"
        f"{escape(profile.expires_at)}"
        f"{questionnaire_notice}"
        f"{status}"
        "</strong></p>"
    )
    if suitability is not None:
        summary += (
            f"{tr('<p>Signed questionnaire level: C')}"
            f"{raw_level}"
            f"{tr(' · Effective risk level: C')}"
            f"{level}"
            "</p>"
        )
        if suitability.get("clarification"):
            summary += '<p class="warning">' + escape(suitability["clarification"]) + "</p>"
    if biac.selection_mode != "default":
        summary += tr('<div class="warning"><strong>Deviation from model allocation</strong>')
        summary += tr(" · Your active adjustment remains subject to the same policy checks.</div>")
    summary += '<div class="metrics">'
    for label, field in (
        (tr("Principal"), "principal"),
        (tr("Purchase fees"), "fee_buy"),
        (tr("Total debit"), "total_debit"),
        (tr("Net performance benchmark (not guaranteed)"), "projected_net"),
    ):
        summary += (
            f'<div class="metric">{label}<strong>'
            f"{number(f'total.{field}', f'biac.totals.{field}')}</strong></div>"
        )
    summary += tr("</div><h3>Your allocation</h3>")
    allocation_rows, fee_rows, ranking_rows = [], [], []
    for index, item in enumerate(biac.allocation):
        path = f"biac.allocation.{index}"
        why = display_value(REASONS[item.selection_reason])
        sleeve_index = next(
            i for i, sleeve in enumerate(biac.sleeves) if sleeve.sleeve == item.sleeve
        )
        ranking = biac.sleeves[sleeve_index].ranking_rows
        own_rank = next(
            (i for i, row in enumerate(ranking) if row.product_id == item.product_id), None
        )
        if own_rank is not None:
            rank_path = f"biac.sleeves.{sleeve_index}.ranking_rows.{own_rank}"
            rank = number(f"item.{index}.rank", rank_path + ".rank", style="integer")
            why += f"{tr(' Reference rank ')}{rank}."
        runner_up = next((i for i, row in enumerate(ranking) if row.rank == 2), None)
        if runner_up is not None:
            runner = ranking[runner_up]
            runner_path = f"biac.sleeves.{sleeve_index}.ranking_rows.{runner_up}"
            gap_style = "integer" if request.objective == "liquidity" else "money"
            gap = number(f"item.{index}.runner_gap", runner_path + ".gap", style=gap_style)
            why += (
                f"{tr(' Runner-up: ')}{escape(product_label(runner.product_id))}"
                f"{tr('; gap from first ')}{gap}"
            )
            why += tr(" days.") if gap_style == "integer" else "."
        allocation_rows.append([
            f"{escape(product_label(item.product_id))}<br><small>{why}</small>",
            escape(item.sleeve),
            number(f"item.{index}.principal", path + ".principal"),
            number(f"item.{index}.weight", path + ".weight", style="percent"),
            number(f"item.{index}.fee_buy", path + ".fee_buy"),
            "T+" + number(f"item.{index}.access", path + ".access_days", style="integer"),
        ])
        for field, label in (
            ("fee_buy", tr("Buy")),
            ("fee_hold", tr("Hold")),
            ("fee_sell", tr("Sell")),
        ):
            fee_rows.append([
                escape(item.product_id),
                label,
                number(f"fee.{index}.{field}", path + "." + field),
                number(
                    f"fee.{index}.{field}.rate",
                    path + "." + field,
                    path + ".principal",
                    operation="ratio",
                    style="percent",
                ),
            ])
    allocation_table = _table(
        [
            tr("Product and why"),
            tr("Risk"),
            tr("Principal"),
            tr("Weight"),
            tr("Buy fee"),
            tr("Access"),
        ],
        allocation_rows,
    )
    summary += allocation_table
    sleeve_rows = []
    bands = policy.profiles[profile_id].bands
    for index, sleeve in enumerate(biac.sleeves):
        path = f"biac.sleeves.{index}"
        band = bands[index]
        band_path = f"policy.profiles.{profile_id}.bands.{index}"
        target = number(
            f"sleeve.{index}.target",
            path + ".target_cents",
            "biac.totals.principal",
            operation="cent_ratio",
            style="percent",
        )
        actual = number(
            f"sleeve.{index}.actual",
            path + ".actual_cents",
            "biac.totals.principal",
            operation="cent_ratio",
            style="percent",
        )
        lower = number(f"sleeve.{index}.lower", band_path + ".lower", style="percent")
        upper = number(f"sleeve.{index}.upper", band_path + ".upper", style="percent")
        # Bar geometry is the same exact weight projection, rounded only for CSS display.
        actual_css = _display(Fraction(sleeve.actual_cents, 100) / biac.totals.principal, "percent")
        lower_css = _display(band.lower, "percent")
        width_css = _display(band.upper - band.lower, "percent")
        bar = (
            f"""{tr('<div class="sleeve-bar" aria-label="Actual ')}"""
            f"{actual_css}"
            f"{tr('; policy ')}"
            f"{lower_css}"
            f"{tr(' to ')}"
            f"{_display(band.upper, 'percent')}"
            '"><div class="sleeve-fill" style="width:'
            f"{actual_css}"
            '"></div><div class="band-marker" style="left:'
            f"{lower_css}"
            ";width:"
            f"{width_css}"
            '"></div></div>'
        )
        sleeve_rows.append([escape(sleeve.sleeve), target, actual + bar, f"{lower}–{upper}"])
        for row_index, row in enumerate(sleeve.ranking_rows):
            rp = f"{path}.ranking_rows.{row_index}"
            key = f"ranking.{index}.{row_index}"
            ranking_rows.append([
                escape(sleeve.sleeve),
                escape(row.product_id),
                number(key + ".rank", rp + ".rank", style="integer"),
                number(key + ".reference", rp + ".reference_amount"),
                number(key + ".net", rp + ".expected_net"),
                number(key + ".fee", rp + ".total_fee"),
                number(key + ".access", rp + ".access_days", style="integer"),
                number(
                    key + ".gap",
                    rp + ".gap",
                    style="integer" if request.objective == "liquidity" else "money",
                ),
            ])
    summary += tr('<div class="two-col"><section><h3>Risk sleeves</h3>')
    risk_table = _table([tr("Risk"), tr("Target"), tr("Actual"), tr("Allowed band")], sleeve_rows)
    summary += risk_table
    checks = []
    for index, check in enumerate(biac.checks):
        style = "percent" if check.constraint_id.startswith(("sleeve_", "group_")) else "money"
        lhs = number(f"check.{index}.lhs", f"biac.checks.{index}.lhs", style=style)
        rhs = number(f"check.{index}.rhs", f"biac.checks.{index}.rhs", style=style)
        checks.append([
            display_value(CHECK_LABELS[check.constraint_id])
            + (f" · {escape(check.subject_ref)}" if check.subject_ref else ""),
            lhs + " " + escape(check.comparator) + " " + rhs + " ✓",
        ])
    groups = (
        ("principal_sum",),
        ("total_debit",),
        ("concentration",),
        ("liquidity",),
        ("product_minimum", "product_maximum"),
        ("sleeve_lower", "sleeve_upper", "group_lower", "group_upper"),
    )
    summary_checks = []
    for group in groups:
        first = next(
            (i for i, check in enumerate(biac.checks) if check.constraint_id in group), None
        )
        if first is not None:
            summary_checks.append(checks[first])
    summary += tr("</section><section><h3>Policy checks</h3>")
    summary += _table([tr("Constraint"), tr("Verified comparison")], summary_checks)
    summary += tr(
        '<p class="muted">Representative checks; expand all constraints below.</p></section></div>'
    )
    days = number("liquidity.days", "request.liquidity_days", style="integer")
    required = number("liquidity.required", "request.liquidity_amount")
    available = number("liquidity.available", "biac.totals.liquid_net_principal")
    liquidity_notice = tr(
        " required. Based on the synthetic contract and earliest redemption, after fees. "
        "Performance benchmarks and uninvested account cash do not count toward this "
        "requirement. Market losses, default and liquidity stress are not modelled."
    )
    liquidity = (
        f"{tr('Within ')}"
        f"{days}"
        f"{tr(' days: ')}"
        f"{available}"
        f"{tr(' net principal available against ')}"
        f"{required}"
        f"{liquidity_notice}"
    )
    summary += f'<p class="muted">{liquidity}</p>'
    details = {
        tr("Full rankings · comparison only"): (
            tr(
                "Rankings use the same signed reference principal and horizon; the"
                "y do not establish a globally optimal allocation. Net values are "
                "a performance benchmark (not guaranteed)."
            )
            + _table(
                [
                    tr("Sleeve"),
                    tr("Product"),
                    tr("Rank"),
                    tr("Reference principal"),
                    tr("Net benchmark"),
                    tr("Fees"),
                    tr("Access days"),
                    tr("Gap from first"),
                ],
                ranking_rows,
            )
        ),
        tr("Excluded products"): _table(
            [tr("Product"), tr("All exclusion reasons")],
            [
                [
                    escape(item.product_id),
                    "; ".join(display_value(EXCLUSIONS[reason]) for reason in item.reason_codes),
                ]
                for item in biac.exclusions
            ],
        )
        if biac.exclusions
        else tr("No products were excluded."),
        tr("Cost table · actual allocation"): _table(
            [tr("Product"), tr("Fee"), "CNY", tr("% of product principal")], fee_rows
        ),
        tr("All constraint checks"): _table(
            [tr("Constraint"), tr("Exact comparison (display rounded)")], checks
        ),
        tr("Liquidity and risk legend"): liquidity
        + (
            tr(
                "<p>C means client risk profile: C1 Conservative; C2 Cautious; C3 "
                "Balanced; C4 Growth; C5 Aggressive. R means product risk: R1 Low;"
                " R2 Lower; R3 Moderate; R4 Higher; R5 High. Products may not exce"
                "ed the client's level.</p>"
            )
        ),
    }
    if biac.deviations is not None:
        rows = []
        for field, label in (
            ("projected_fees_delta", tr("Projected fees")),
            ("projected_net_delta", tr("Net performance benchmark (not guaranteed)")),
            ("liquid_net_principal_delta", tr("Net liquid principal")),
            ("total_debit_delta", tr("Total debit")),
        ):
            rows.append([label, number("deviation." + field, "biac.deviations." + field)])
        details[tr("Deviation from model allocation · signed differences")] = _table(
            [tr("Fact"), tr("Change")], rows
        )
        for collection, label in (("products", tr("Product")), ("sleeves", tr("Sleeve"))):
            deltas = getattr(biac.deviations, collection)
            delta_rows = []
            for index, delta in enumerate(deltas):
                path = f"biac.deviations.{collection}.{index}"
                identifier = delta.product_id if collection == "products" else delta.sleeve
                delta_rows.append([
                    escape(identifier),
                    number(f"deviation.{collection}.{index}.principal", path + ".principal_delta"),
                    number(
                        f"deviation.{collection}.{index}.weight",
                        path + ".weight_delta",
                        style="points",
                    ),
                ])
            details[tr("Deviation from model allocation · signed differences")] += _table(
                [label, tr("Principal change"), tr("Weight change")], delta_rows
            )
    footer_facts = (
        f"{tr('<footer>BIAC hash: ')}"
        f"{H(biac)}"
        f"{tr('<br>Policy ')}"
        f"{escape(policy.id)}"
        f"{tr(' · Policy version ')}"
        f"{policy_version}"
        f"{tr(' · Catalogue ')}"
        f"{escape(policy.catalog_id)}"
        f"{tr(' · Catalogue version ')}"
        f"{catalog_version}"
        "<br>"
    )
    audit_link = f'''<a href="{escape(audit_href, quote=True)}{tr('">Audit evidence</a>')}'''
    footer_notice = tr(" · synthetic data · simulated authentication · no real money</footer>")
    exported_audit = (
        tr("Audit evidence is available in the application or statement + audit bundle")
        if audit_href.startswith("#")
        else audit_link
    )
    export_footer = footer_facts + exported_audit + footer_notice
    detail_html = "".join(
        f"<details><summary>{escape(title)}</summary>{value}</details>"
        for title, value in details.items()
    )
    body = '<article class="suitability">' + summary + detail_html + export_footer + "</article>"
    html = (
        tr(
            '<!doctype html><html lang="en"><meta charset="utf-8"><title>Suita'
            "bility Statement</title>"
        )
        + STYLE
        + "<body>"
        + body
        + "</body></html>"
    )
    text = unescape(sub(r"<[^>]*>", "", body)).replace("\n", " ")
    selected = {item.product_id: item for item in biac.allocation}
    comparison_rows = []
    for sleeve in biac.sleeves:
        for row in sleeve.ranking_rows:
            item = selected.get(row.product_id)
            status_badge = badge(
                tr("Selected") if item else tr("Eligible"), "green" if item else "neutral"
            )
            reason = (
                display_value(REASONS[item.selection_reason])
                if item
                else tr("Eligible for your signed goals.")
            )
            row_class = ' class="selected-product"' if item else ""
            comparison_rows.append(
                f"<tr{row_class}><td>{escape(product_label(row.product_id))}</td>"
                f"<td>{status_badge}</td><td>{escape(sleeve.sleeve)}</td>"
                f"<td>{escape(reason)}</td></tr>"
            )
    for item in biac.exclusions:
        reason = "; ".join(display_value(EXCLUSIONS[code]) for code in item.reason_codes)
        comparison_rows.append(
            f"<tr><td>{escape(product_label(item.product_id))}</td>"
            f"<td>{badge(tr('Excluded'), 'red')}</td><td>—</td><td>{escape(reason)}</td></tr>"
        )
    product_summary = (
        f"<h2>{tr('Your proposal')}</h2>"
        '<div class="proposal-heading">'
        + badge(tr("Within your signed policy"), "green")
        + f' <span class="muted">C{level} · '
        + f"{display_value(PROFILE_NAMES[effective_level])}</span></div>"
        + f'<p class="muted">{status}</p><div class="metrics">'
    )
    for label, key, path in (
        (tr("Investing"), "total.principal", "biac.totals.principal"),
        (tr("Purchase fees"), "total.fee_buy", "biac.totals.fee_buy"),
        (tr("Net liquidity"), "liquidity.available", "biac.totals.liquid_net_principal"),
        (
            tr("Performance benchmark, not guaranteed"),
            "total.projected_net",
            "biac.totals.projected_net",
        ),
    ):
        product_summary += (
            f'<div class="metric">{escape(label)}<strong>{number(key, path)}</strong></div>'
        )
    compact_allocations = [
        [
            escape(product_label(item.product_id)),
            *row[1:],
        ]
        for item, row in zip(biac.allocation, allocation_rows, strict=True)
    ]
    product_summary += f"</div><h3>{tr('Your allocation')}</h3>" + _table(
        [tr("Product"), tr("Risk"), tr("Principal"), tr("Weight"), tr("Buy fee"), tr("Access")],
        compact_allocations,
    )
    product_summary += f"<h3>{tr('Product comparison')}</h3>"
    product_summary += (
        '<div class="table-wrap"><table><thead><tr>'
        + "".join(
            f"<th>{escape(label)}</th>"
            for label in (tr("Product"), tr("Status"), tr("Risk"), tr("Why it fits"))
        )
        + "</tr></thead><tbody>"
        + "".join(comparison_rows)
        + "</tbody></table></div>"
    )
    product_summary += f"<h3>{tr('Risk allocation')}</h3>" + risk_table
    product_summary += (
        f'<p class="muted">{tr("Net principal available within the signed liquidity deadline.")} '
        f"{days}{tr(' days.')}</p>"
        f'<p class="muted">{tr("sponsor-independent within the declared catalogue and policy")}</p>'
    )
    if biac.selection_mode != "default":
        product_summary += '<p class="warning">' + tr("Deviation from model allocation") + "</p>"
    if suitability is not None and suitability.get("clarification"):
        product_summary += '<p class="warning">' + escape(suitability["clarification"]) + "</p>"
    product_summary += f'<p class="muted">{audit_link}</p>'
    return Statement(
        html,
        text,
        '<article class="suitability">' + product_summary + "</article>",
        details,
        projection.sources,
    )


def render_biac(
    biac: BestInterestAllocationCertificate | dict[str, Any],
    request: AllocationRequest | dict[str, Any],
    policy: AllocationPolicy | dict[str, Any],
    profile: RiskAssessment | dict[str, Any],
    execution: dict[str, Any] | None = None,
    audit_href: str = "#audit-entry",
    audit_jsonl: str | bytes | None = None,
    *,
    suitability: dict[str, Any] | None = None,
) -> Statement:
    """Show a compact verdict first; detailed evidence is available on demand."""
    statement = build_statement(
        biac, request, policy, profile, execution, audit_href, suitability=suitability
    )
    st.markdown(STYLE + statement.summary_html, unsafe_allow_html=True)
    with st.expander(tr("Technical evidence"), expanded=False):
        for title, html in statement.details.items():
            st.markdown(
                '<div class="suitability"><h3>' + escape(title) + "</h3>" + html + "</div>",
                unsafe_allow_html=True,
            )
        st.json(statement.numeric_sources)
        st.json(
            biac.model_dump(mode="json")
            if isinstance(biac, BestInterestAllocationCertificate)
            else biac
        )
    st.download_button(
        tr("Download Suitability Statement"),
        data=statement.html,
        file_name="suitability-statement.html",
        mime="text/html",
        key="download-suitability",
    )
    if audit_jsonl:
        bundled_statement = build_statement(
            biac,
            request,
            policy,
            profile,
            execution,
            audit_href="audit.jsonl",
            suitability=suitability,
        )
        audit_bytes = audit_jsonl.encode("utf-8") if isinstance(audit_jsonl, str) else audit_jsonl
        bundle = BytesIO()
        with ZipFile(bundle, "w") as archive:
            for name, content in (
                ("suitability-statement.html", bundled_statement.html.encode("utf-8")),
                ("audit.jsonl", audit_bytes),
            ):
                # Fixed archive metadata avoids introducing wall-clock timestamps.
                info = ZipInfo(name)
                info.compress_type = ZIP_DEFLATED
                archive.writestr(info, content)
        st.download_button(
            tr("Download statement + audit"),
            data=bundle.getvalue(),
            file_name="suitability-statement-audit.zip",
            mime="application/zip",
            key="download-suitability-audit",
        )
        st.caption(
            tr("The bundle preserves the supplied audit log and links to it from the statement.")
        )
    return statement


def rule_reason(rule_id: str) -> str:
    """Keep the machine rule ID beside a plain-English reason."""
    reason = display_value(
        RULE_REASONS.get(rule_id, tr("The gateway did not authorize this request"))
    )
    return f"{reason} ({rule_id})"
