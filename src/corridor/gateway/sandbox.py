"""Immutable, owner-bound sandbox snapshots and signed exploratory results.

The restricted language supplies capability isolation. Its Python subprocess is
not an operating-system security boundary, especially on Windows.
"""

import ast
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from fractions import Fraction
from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from nacl.signing import SigningKey

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import CONTROL, RECEIPT, sign, verify
from corridor.gateway.analysis import _category, _debit, _original, _refund, period_bounds
from corridor.gateway.privacy import PIIVault
from corridor.schemas.bank import (
    AnalysisReceipt,
    AnalysisResult,
    AuthorizationRevocation,
    BankAction,
    SessionAuthorization,
)
from corridor.schemas.money import fraction_string
from corridor.schemas.state import BankState
from corridor.schemas.time import parse_time

_NAMESPACE = uuid5(NAMESPACE_URL, "corridor-demo-v0")


def _opaque(value: object) -> str:
    return H(value).translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))


@dataclass(frozen=True)
class Dataset:
    principal: str
    account_ref: str
    period: str
    rows: list[dict[str, Any]]
    source_ids: list[str]


def _authorized(state: BankState, principal: str) -> bool:
    customer = state.customers.get(principal)
    session = state.security.active_device_sessions.get(principal)
    return (
        customer is not None
        and session is not None
        and any(
            isinstance(auth, SessionAuthorization)
            and auth.principal == principal
            and auth.device_session_id == session
            and auth.expires_at > state.now
            and "sandbox_analyze" in auth.read_kinds
            and verify(customer.device_pubkey, CONTROL, auth, auth.sig)
            and not any(
                isinstance(record, AuthorizationRevocation)
                and record.authorization_ref == auth.id
                and record.revoked_at <= state.now
                for record in state.authorizations.values()
            )
            for auth in state.authorizations.values()
        )
    )


class SandboxRegistry:
    """No model source, raw PII, or mutable handles enter BankState."""

    def __init__(self, vault: PIIVault) -> None:
        self.vault = vault
        self._datasets: dict[str, Dataset] = {}
        self._programs: dict[str, tuple[str, str]] = {}

    def register_dataset(
        self, state: BankState, principal: str, account_ref: str, period: str
    ) -> str:
        account = state.accounts.get(account_ref)
        if not _authorized(state, principal) or account is None or account.owner != principal:
            raise ValueError("READ-ROLE")
        start, end = period_bounds(period)
        rows: list[dict[str, Any]] = []
        source_ids: list[str] = []
        for tx in sorted(state.transactions.values(), key=lambda item: (item.booked_at, item.id)):
            if (
                tx.owner != principal
                or tx.account_ref != account_ref
                or tx.status != "settled"
                or not start <= tx.booked_at < end
                or tx.booked_at > state.now
            ):
                continue
            if len(rows) == 1000:
                raise ValueError("SBX-LIMIT")
            local = parse_time(tx.booked_at) + timedelta(hours=8)
            original = _original(tx, state.transactions) if _refund(tx) else None
            category = _category(original or tx, state.merchants)
            if _refund(tx) and original is None:
                category = "unmatched_refund"
            net = tx.amount if _debit(tx) else -tx.amount if _refund(tx) else Fraction()
            rows.append({
                "tx_id": "TX_" + _opaque({"ref": tx.id})[:16],
                "merchant_ref": "M_" + _opaque({"ref": tx.merchant_ref})[:16],
                "category": category,
                "amount": fraction_string(tx.amount),
                "net_amount": fraction_string(net),
                "booked_at": tx.booked_at,
                "business_date": local.strftime("%Y-%m-%d"),
                "day_of_week": local.weekday(),
                "is_weekend": local.weekday() >= 5,
            })
            source_ids.append(tx.id)
        self.vault.ensure_safe(rows)
        if len(jcs_bytes(rows)) > 256 * 1024:
            raise ValueError("SBX-LIMIT")
        ref = "DSET_" + _opaque({
            "principal": principal,
            "account_ref": account_ref,
            "period": period,
            "rows": rows,
        })
        self._datasets[ref] = Dataset(principal, account_ref, period, rows, source_ids)
        return ref

    def register_program(self, state: BankState, principal: str, program: str) -> str:
        if not _authorized(state, principal):
            raise ValueError("READ-ROLE")
        if not isinstance(program, str):
            raise ValueError("SBX-SYNTAX")
        if len(program.encode("utf-8")) > 8192:
            raise ValueError("SBX-LIMIT")
        self.vault.ensure_safe(program)
        try:
            tree = ast.parse(program)
            constants = [
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, (str, int))
            ]
        except Exception:
            # Parser resource failures are untrusted-input errors, not gateway failures.
            raise ValueError("SBX-SYNTAX") from None
        for value in constants:
            self.vault.ensure_safe(value)
        ref = "PROG_" + _opaque({"principal": principal, "program": program})
        self._programs[ref] = (principal, program)
        return ref

    def resolve(self, action: BankAction, state: BankState) -> tuple[Dataset, str]:
        args = action.args.model_dump()
        dataset = self._datasets.get(args["dataset_ref"])
        program = self._programs.get(args["program_ref"])
        if (
            dataset is None
            or program is None
            or dataset.principal != action.principal
            or program[0] != action.principal
        ):
            raise ValueError("PROV-FIELD")
        account = state.accounts.get(dataset.account_ref)
        if (
            not _authorized(state, action.principal)
            or account is None
            or account.owner != action.principal
        ):
            raise ValueError("READ-ROLE")
        return deepcopy(dataset), program[1]

    def has_handle(self, principal: str, field: str, ref: object) -> bool:
        if not isinstance(ref, str):
            return False
        if field == "dataset_ref":
            dataset = self._datasets.get(ref)
            return dataset is not None and dataset.principal == principal
        if field == "program_ref":
            program = self._programs.get(ref)
            return program is not None and program[0] == principal
        return False


def exploratory_receipt(
    action: BankAction,
    state: BankState,
    dataset: Dataset,
    program: str,
    results: dict[str, Any],
    key: SigningKey,
) -> AnalysisReceipt:
    receipt = AnalysisReceipt(
        receipt_id=str(uuid5(_NAMESPACE, f"{action.action_id}:0:exploratory")),
        dataset_hash=H(dataset.rows),
        function_id="restricted_analysis_v1",
        parameters={
            "principal": action.principal,
            "action_hash": H(action),
            "account_ref": dataset.account_ref,
            "period": dataset.period,
            "row_count": len(dataset.rows),
        },
        results={
            field: AnalysisResult(value=value, unit="number", source_tx_ids=dataset.source_ids)
            for field, value in results.items()
        },
        program_hash=sha256(program.encode("utf-8")).hexdigest(),
        trust="exploratory",
        computed_at=state.now,
        sig="0" * 128,
    )
    return receipt.model_copy(update={"sig": sign(key, RECEIPT, receipt)})
