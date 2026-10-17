"""A separate simulated device identity; signing represents an explicit user gesture."""

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from corridor.crypto.jcs import H
from corridor.crypto.sign import APPROVE, CONTROL, INPUT, SPA, sign
from corridor.schemas.bank import (
    ApprovalToken,
    BankAction,
    BankCertificate,
    MFAGrant,
    OperationAuthorization,
    ScheduledPaymentAuthorization,
    SessionAuthorization,
    UserInput,
)
from corridor.schemas.models import JsonValue
from corridor.schemas.time import parse_time
from corridor.sim.keys import signing_key, stable_id

if TYPE_CHECKING:
    from corridor.gateway.mfa import MFAVerifier


class Device:
    def __init__(self, principal: str = "C_DEMO", *, key_label: str = "device") -> None:
        self.principal = principal
        self._key = signing_key(key_label)

    def confirm_input(
        self,
        *,
        intent_id: str,
        slot: str,
        value: Any,
        now: str,
        step: int = 1,
        supersedes: str | None = None,
    ) -> UserInput:
        item = UserInput.model_validate({
            "id": stable_id(intent_id, step, f"input-{slot}"),
            "principal": self.principal,
            "batch_id": stable_id(intent_id, 0, "batch"),
            "slot": slot,
            "value": value,
            "submitted_at": now,
            "scope_id": intent_id,
            "supersedes": supersedes,
            "sig": "0" * 128,
        })
        return item.model_copy(update={"sig": sign(self._key, INPUT, item)})

    def authorize(self, body: dict[str, Any]) -> OperationAuthorization:
        item = OperationAuthorization.model_validate({
            **body,
            "principal": self.principal,
            "sig": "0" * 128,
        })
        return item.model_copy(update={"sig": sign(self._key, CONTROL, item)})

    def login(self, *, session_id: str, expires_at: str) -> SessionAuthorization:
        item = SessionAuthorization(
            id=stable_id(session_id, 0, "session-authorization"),
            principal=self.principal,
            device_session_id=session_id,
            read_kinds=[
                "balance_query",
                "transactions_query",
                "bill_analyze",
                "bill_report",
                "anomaly_query",
                "risk_assess",
                "product_compare",
                "investment_income_query",
            ],
            expires_at=expires_at,
            sig="0" * 128,
        )
        return item.model_copy(update={"sig": sign(self._key, CONTROL, item)})

    def approve(
        self,
        action: BankAction,
        cert: BankCertificate,
        card: dict[str, JsonValue],
        *,
        now: str,
        sequence: int = 0,
        ownership_epoch: int = 0,
    ) -> ApprovalToken:
        """Sign the displayed canonical card after an explicit simulated user gesture."""
        if action.principal != self.principal or cert.action_hash != H(action):
            raise ValueError("Device approval identity or action mismatch")
        if type(sequence) is not int or sequence < 0:
            raise ValueError("Invalid device approval sequence")
        context = {
            "kind": action.kind,
            "plan_hash": action.plan_hash,
            "node_id": action.node_id,
            "device_session_id": action.device_session_id,
        }
        if any(card.get(key) != value for key, value in context.items()):
            raise ValueError("Displayed card context does not match the action")
        tier = card.get("tier")
        if not isinstance(tier, str) or tier not in {"yellow", "red"}:
            raise ValueError("Device approval requires a yellow or red card")
        now_time = parse_time(now)
        action_hash, cert_hash, card_hash = H(action), H(cert), H(card)
        nonce = H({
            "intent_id": action.intent_id,
            "action_hash": action_hash,
            "cert_hash": cert_hash,
            "card_hash": card_hash,
            "sequence": sequence,
            "ownership_epoch": ownership_epoch,
            "kind": "approval_nonce",
        })[:32]
        item = ApprovalToken.model_validate({
            "token_id": stable_id(action.intent_id, sequence, f"approval-{action.action_id}"),
            "principal": self.principal,
            "device_session_id": action.device_session_id,
            "action_hash": action_hash,
            "cert_hash": cert_hash,
            "card_hash": card_hash,
            "plan_id": action.plan_id,
            "plan_hash": action.plan_hash,
            "node_id": action.node_id,
            "ownership_epoch": ownership_epoch,
            "tier": tier,
            "nonce": nonce,
            "issued_at": now,
            "expiry": (now_time + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sig": "0" * 128,
        })
        return item.model_copy(update={"sig": sign(self._key, APPROVE, item)})

    def complete_mfa(
        self, verifier: "MFAVerifier", challenge_id: str, *, now: str
    ) -> MFAGrant | None:
        """Synthetic device-panel control; never expose this operation to a planner."""
        return verifier.verify(challenge_id, verifier.test_code(challenge_id), now=now)

    def sign_spa(self, body: dict[str, Any]) -> ScheduledPaymentAuthorization:
        """Confirm a narrow persistent payment authorization on the device."""
        item = ScheduledPaymentAuthorization.model_validate({
            **body,
            "principal": self.principal,
            "sig": "0" * 128,
        })
        return item.model_copy(update={"sig": sign(self._key, SPA, item)})
