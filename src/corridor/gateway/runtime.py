"""Construct an in-process synthetic bank behind the authorized gateway boundary."""

from pathlib import Path

from nacl.signing import SigningKey

from corridor.eval.mockbank.exec import MockBank
from corridor.gateway.audit import AuditLog
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.privacy import PIIVault
from corridor.gateway.service import Gateway
from corridor.stores.bank import BankStore


def create_gateway(
    store: BankStore,
    *,
    bank_key: SigningKey,
    gateway_key: SigningKey | None = None,
    risk_key: SigningKey | None = None,
    audit: AuditLog | None = None,
    mfa: MFAVerifier | None = None,
    evidence_dir: Path | None = None,
    vault: PIIVault | None = None,
) -> Gateway:
    return Gateway(
        store,
        MockBank(store.snapshot(), bank_key),
        audit=audit,
        mfa=mfa,
        evidence_dir=evidence_dir,
        vault=vault,
        analysis_key=gateway_key,
        risk_key=risk_key,
    )
