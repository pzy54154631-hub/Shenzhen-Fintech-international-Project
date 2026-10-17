"""The sole bank-v1 obligation registry, matching DESIGN-BANK section 5.3."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class RuleMeta:
    obligation: str
    outcome: Literal["Reject", "Escalate"]
    enforced_by: Literal["kernel", "gateway", "sandbox"]


RULES: dict[str, RuleMeta] = {}
_KERNEL = (
    "SCHEMA-INVALID SCHEMA-TIME SCHEMA-UNIT CERT-HASH TIER-BLACK-KIND "
    "AUTH-PRINCIPAL AUTH-SCOPE AUTH-SIG AUTH-CONSUMED PROV-MISSING PROV-LITERAL PROV-FIELD "
    "PROV-MISMATCH PROV-STALE PROV-COHERENCE PROV-AMBIGUOUS IDEM-KEY BAL-AVAILABLE "
    "DOMAIN-STATE DOMAIN-SCHEDULE DOMAIN-SPA DOMAIN-AA DOMAIN-COMPENSATION "
    "BIC-CATALOG BIC-PREFERENCE BIC-RISK BIC-COMPLETE BIC-SCORE BIC-CHOICE "
    "BIC-NOFEASIBLE ALLOC-POLICY ALLOC-BAND ALLOC-CONC ALLOC-LIQ ALLOC-SUM ALLOC-SELECT "
    "MFA-INVALID RISK-ANSWERS-CONSUMED RISK-ANSWERS-STALE RISK-RETAKE-LIMIT"
)
for _id in _KERNEL.split():
    RULES[_id] = RuleMeta(_id.split("-")[0], "Reject", "kernel")
for _id in (
    "IDEM-DUP MFA-REUSE APR-REQUIRED APR-SIG APR-ROLE APR-EXPIRED APR-SWAP APR-REUSE "
    "APR-VOID APR-DRIFT APR-LOCK APR-BUDGET READ-ROLE PII-CTX PII-OUT RCPT-MISMATCH AUD-CHAIN "
    "AUD-WRITE BANK-RECEIPT PLAN-SCHEMA PLAN-CYCLE PLAN-SCOPE PLAN-OWNER "
    "TOOL-UNAVAILABLE CTRL-MFA"
).split():
    RULES[_id] = RuleMeta(_id.split("-")[0], "Reject", "gateway")
for _id in ("TIER-MFA-REQUIRED", "DOMAIN-SPA-TIER", "RISK-UPGRADE-REVIEW"):
    RULES[_id] = RuleMeta(_id.split("-")[0], "Escalate", "kernel")
for _id in ("SBX-SYNTAX", "SBX-LIMIT", "SBX-TIMEOUT"):
    RULES[_id] = RuleMeta("SBX", "Reject", "sandbox")
