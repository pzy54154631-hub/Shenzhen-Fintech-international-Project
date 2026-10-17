"""Display-only product styling and exact localized money formatting."""

import re
from decimal import ROUND_HALF_EVEN, Decimal
from fractions import Fraction
from html import escape
from typing import Any

from corridor.i18n import get_locale
from corridor.ui.messages import tr

PRODUCT_STYLES = """
<style>
:root{--ink:#162c36;--muted:#657b83;--line:#dfe8e9;--accent:#13786c}
.stApp{background:#f5f8f8;color:var(--ink)}
.block-container{max-width:1600px;padding:1.6rem 2.5rem 3rem}
header[data-testid="stHeader"]{background:#f5f8f8ee}
h1,h2,h3{color:var(--ink);letter-spacing:-.025em}
h1{font-size:1.85rem!important}h2{font-size:1.35rem!important}h3{font-size:1.1rem!important}
.bank-header{display:flex;align-items:center;gap:14px;margin:4px 0 14px}
.bank-mark{background:#133c3c;color:#b8e8d4;width:46px;height:46px;border-radius:14px;
display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700}
.bank-brand{font-size:11px;letter-spacing:2px;color:var(--muted)}
.bank-name{font-size:25px;font-weight:750;letter-spacing:-.04em}
.notice{font-size:12px;color:var(--muted);margin:4px 0 20px}
.hero{background:#173f3f;color:white;padding:26px;border-radius:18px;margin:14px 0}
.hero h2{color:white}.hero p{color:#d2e6e2;line-height:1.6;margin:0}
.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:#a8d8cc}
.fact-panel,.cw-context,.cw-attack-card{background:white;border:1px solid var(--line);
border-radius:16px;padding:20px;margin:12px 0;box-shadow:0 3px 12px #173f3f05}
.fact-title{font-size:12px;color:var(--muted);letter-spacing:.04em}
.fact-product{font-size:20px;font-weight:650;margin-top:12px}
.fact-amount{font-size:34px;font-weight:750;letter-spacing:-.04em;margin:4px 0 10px}
.fact-row{display:grid;grid-template-columns:minmax(120px,.45fr) 1fr;gap:16px;
padding:10px 0;border-bottom:1px solid #edf2f2;font-size:15px}
.fact-row:last-child{border:0}.fact-label{color:var(--muted)}
.fact-value{overflow-wrap:anywhere}.fact-note{color:var(--muted);font-size:15px;margin:9px 0 0}
.cw-confirm-grid{display:grid;grid-template-columns:1.2fr 1fr;gap:32px;align-items:center}
.cw-confirm-grid .fact-product{margin-top:5px}.cw-confirm-grid .fact-amount{margin-bottom:0}
.cw-confirm-cost{display:flex;justify-content:space-between;gap:20px;padding:7px 0;font-size:15px}
.cw-confirm-cost span{color:var(--muted)}.cw-confirm-cost strong{white-space:nowrap}
.cw-confirm-foot{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:14px;
padding-top:12px;border-top:1px solid var(--line)}.cw-confirm-foot .fact-note{margin:0}
.cw-chip,.tier{display:inline-block;border-radius:999px;padding:4px 10px;font-size:11px;
font-weight:650;line-height:1.5;background:#edf2f3;color:#47616b;white-space:nowrap}
.cw-chip-green,.tier-green{background:#e0f3e9;color:#176d4d}
.cw-chip-yellow,.tier-yellow{background:#fff2d6;color:#8c6512}
.cw-chip-red,.tier-red{background:#fde9e7;color:#a3453d}
.cw-chip-neutral{background:#edf2f3;color:#47616b}.tier-black{background:#263c44;color:white}
.danger{border-left:3px solid #d4a548;background:#fff7e8;padding:10px 14px;
font-size:13px;border-radius:0 10px 10px 0;margin:12px 0}
.node,.cw-timeline{border-left:2px solid #b9dacf;margin-left:8px;padding:4px 0 18px 20px}
.node-title{font-size:15px;font-weight:650}.node-status{color:var(--muted);font-size:12px}
[data-testid="stMetric"]{background:white;border:1px solid var(--line);padding:15px;
border-radius:14px}[data-testid="stMetricValue"]{font-size:25px}
[data-testid="stVerticalBlockBorderWrapper"]{border-radius:16px}
[data-testid="stChatMessage"]{border:1px solid var(--line);background:white;border-radius:15px}
.stButton>button{border-radius:9px;min-height:40px;font-size:13px}
button[kind="primary"]{background:#13786c;border-color:#13786c}
.stMarkdown p,.stMarkdown li,code{overflow-wrap:anywhere}
[data-testid="stCode"] pre{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:760px){.block-container{padding:1.1rem .9rem 2rem}.bank-name{font-size:21px}
.fact-panel,.cw-context,.cw-attack-card{padding:15px}.fact-amount{font-size:28px}
.fact-row{grid-template-columns:100px 1fr}.hero{padding:20px}
.cw-confirm-grid{grid-template-columns:1fr;gap:8px}
[data-testid="stHorizontalBlock"]{flex-wrap:wrap;gap:12px}}
</style>
"""


def currency(value: Any) -> str:
    """Round exact values only for display, retaining all canonical values elsewhere."""
    try:
        if isinstance(value, (float, bool)):
            raise ValueError("An exact money value is required")
        fraction = Fraction(value)
        decimal = (Decimal(fraction.numerator) / Decimal(fraction.denominator)).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_EVEN
        )
        return f"\N{YEN SIGN}{decimal:,.2f}" if get_locale() == "zh-CN" else f"CNY {decimal:,.2f}"
    except (ValueError, TypeError, ZeroDivisionError):
        return tr("Not available")


def product_label(reference: object) -> str:
    """Give synthetic catalogue product codes a readable label without exposing UUIDs."""
    value = str(reference)
    match = re.fullmatch(r"P_([A-Z][A-Z0-9_]{0,20})", value)
    return tr("Product {name}", name=match[1].replace("_", " ")) if match else tr("Product")


def contact_label(reference: object) -> str:
    """Retain a distinct readable label for each declared synthetic contact code."""
    value = str(reference)
    if re.fullmatch(r"CONTACT_[A-Z][A-Z0-9_]{0,40}", value):
        name = value.removeprefix("CONTACT_").replace("_", " · ").title()
        return tr("Contact {name}", name=name)
    return tr("Review the recipient in technical evidence")


def badge(text: str, tone: str = "neutral") -> str:
    """Return a small escaped HTML status label; callers provide trusted display copy."""
    tone = tone if tone in {"green", "yellow", "red", "neutral"} else "neutral"
    return f'<span class="cw-chip cw-chip-{tone}">{escape(text)}</span>'
