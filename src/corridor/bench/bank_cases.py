"""Deterministic synthetic-device helpers for real gateway judge cases.

These helpers register plans and obtain real kernel verdicts. They provide no
alternative execution path and never import the MockBank execution module.
"""

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import CONTROL, RECEIPT, sign, verify
from corridor.eval.mockbank.oracle import available_balances
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.runtime import create_gateway
from corridor.gateway.service import GatewayResult, Proposal
from corridor.kernel.binding import dependency_hashes
from corridor.schemas.bank import (
    BankAction,
    BankCertificate,
    BankReceipt,
    BestInterestCertificate,
    OperationAuthorization,
    Plan,
    PlanNode,
    ScheduledPaymentAuthorization,
    Term,
    UserInput,
)
from corridor.schemas.state import BankState
from corridor.sim.device import Device
from corridor.sim.keys import SEED, signing_key, stable_id
from corridor.stores.bank import BankStore, add_seconds


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(jcs_bytes(value))


@dataclass
class PreparedCase:
    action: BankAction
    cert: BankCertificate
    plan: Plan
    proposal: Proposal


class BankCase:
    """A synthetic user session; signing methods represent explicit gestures."""

    def __init__(
        self,
        state: BankState,
        *,
        task_id: str,
        subcase_id: str,
        evidence_dir: Path | None = None,
    ) -> None:
        self.initial = state
        self.task_id = task_id
        self.subcase_id = subcase_id
        self.evidence_dir = evidence_dir
        if evidence_dir is not None:
            # Each execution replaces its own report; do not reuse a stale full oracle.
            oracle_path = evidence_dir / "oracle.json"
            if oracle_path.is_file():
                oracle_path.unlink()
        self.identity = f"{task_id}:{subcase_id}"
        self.device = Device()
        self.gateway = create_gateway(
            BankStore(state),
            bank_key=signing_key("bank"),
            gateway_key=signing_key("gateway"),
            risk_key=signing_key("risk"),
            mfa=MFAVerifier(signing_key("mfa")),
            evidence_dir=evidence_dir / "decisions" if evidence_dir else None,
        )
        self.session = stable_id(self.identity, 0, "session")
        login = self.device.login(session_id=self.session, expires_at=add_seconds(state.now, 3600))
        login = login.model_copy(
            update={
                "read_kinds": [
                    "balance_query",
                    "transactions_query",
                    "bill_analyze",
                    "bill_report",
                    "anomaly_query",
                    "product_compare",
                    "investment_income_query",
                    "risk_assess",
                    "sandbox_analyze",
                ]
            }
        )
        login = login.model_copy(update={"sig": sign(signing_key("device"), CONTROL, login)})
        result = self.gateway.login(login)
        if result.status != "accepted":
            raise ValueError(f"Device session rejected: {result.rule_ids}")
        self.session_authorization = login
        self.initial = self.gateway.store.snapshot()
        self.preparations: list[PreparedCase] = []

    @property
    def state(self) -> BankState:
        return self.gateway.store.snapshot()

    def intent(self, step: int = 0) -> str:
        return stable_id(self.identity, step, "intent")

    def operation(
        self,
        kind: str,
        object_refs: list[str],
        inputs: list[UserInput],
        *,
        step: int = 0,
        amount_bound: str | None = None,
    ) -> OperationAuthorization:
        for item in inputs:
            existing = self.state.user_inputs.get(item.id)
            if existing is not None:
                if existing != item:
                    raise ValueError("Device input identity was reused with different content")
                continue
            result = self.gateway.submit_input(item)
            if result.status != "accepted":
                raise ValueError(f"Device input rejected: {result.rule_ids}")
        body: dict[str, Any] = {
            "id": stable_id(self.identity, step, "authorization"),
            "intent_id": self.intent(step),
            "allowed_kind": kind,
            "object_refs": object_refs,
            "expires_at": add_seconds(self.state.now, 3600),
            "input_hashes": [H(item) for item in inputs],
        }
        if amount_bound is not None:
            body["amount_bound"] = amount_bound
        authorization = self.device.authorize(body)
        result = self.gateway.submit_authorization(authorization)
        if result.status != "accepted":
            raise ValueError(f"Operation authority rejected: {result.rule_ids}")
        return authorization

    def prepare(
        self,
        kind: str,
        args: dict[str, Any],
        terms: dict[str, Term],
        *,
        inputs: list[UserInput] | None = None,
        authorization: OperationAuthorization | ScheduledPaymentAuthorization | None = None,
        best_interest: BestInterestCertificate | None = None,
        best_interest_builder: Callable[[BankAction, BankState], BestInterestCertificate | None]
        | None = None,
        step: int = 0,
    ) -> PreparedCase:
        node_args: dict[str, Any] = {}
        for key, term in terms.items():
            if "." in key and key.rsplit(".", 1)[1].isdigit():
                field, raw_index = key.rsplit(".", 1)
                values = node_args.setdefault(field, [])
                index = int(raw_index)
                if index != len(values):
                    raise ValueError("Indexed plan terms must be contiguous and ordered")
                values.append(term)
            else:
                node_args[key] = term
        node = PlanNode.model_validate({
            "node_id": stable_id(self.identity, step, "node"),
            "tool": kind,
            "args": node_args,
        })
        plan = Plan(
            plan_id=stable_id(self.identity, step, "plan"),
            revision=1,
            principal=self.device.principal,
            device_session_id=self.session,
            intent_id=self.intent(step),
            goal_input_refs=[item.id for item in inputs or []],
            nodes=[node],
            ownership_epoch=0,
        )
        registration = self.gateway.submit_plan(plan)
        if registration.status != "registered":
            raise ValueError(f"Judge plan rejected: {registration.rule_ids}")
        action = BankAction.model_validate({
            "action_id": stable_id(self.identity, step, "action"),
            "intent_id": self.intent(step),
            "principal": self.device.principal,
            "device_session_id": self.session,
            "plan_id": plan.plan_id,
            "plan_hash": H(plan),
            "node_id": node.node_id,
            "kind": kind,
            "args": args,
        })
        cert = BankCertificate(
            action_hash=H(action),
            authorization_ref=authorization.id if authorization else self.session_authorization.id,
            derivations={f"args.{name}": term for name, term in terms.items()},
            dependency_hashes={},
            best_interest=best_interest_builder(action, self.state)
            if best_interest_builder
            else best_interest,
        )
        cert = cert.model_copy(
            update={
                "dependency_hashes": dependency_hashes(action, cert, self.state),
            }
        )
        prepared = PreparedCase(action, cert, plan, self.gateway.propose(action, cert))
        self.preparations.append(prepared)
        return prepared

    def dispatch(self, prepared: PreparedCase) -> GatewayResult:
        if prepared.proposal.verdict is None:
            raise ValueError("Proposal has no kernel verdict")
        if prepared.proposal.verdict.tier == "green":
            return self.gateway.query(prepared.action, prepared.cert)
        token = self.device.approve(
            prepared.action,
            prepared.cert,
            prepared.proposal.card,
            now=self.state.now,
        )
        return self.gateway.dispatch(prepared.action, prepared.cert, token)

    def export(self) -> None:
        if self.evidence_dir is None:
            return
        root = self.evidence_dir
        root.mkdir(parents=True, exist_ok=True)
        write_json(root / "initial_state.json", self.initial)
        write_json(root / "final_state.json", self.state)
        write_json(root / "mockbank_final.json", self.gateway.bank.final_state())
        write_json(root / "plans.json", [item.plan for item in self.preparations])
        write_json(root / "verdicts.json", [item.proposal.verdict for item in self.preparations])
        write_json(root / "plan.json", [item.plan for item in self.preparations])
        write_json(root / "verdict.json", [item.proposal.verdict for item in self.preparations])
        write_json(
            root / "decisions.json",
            [
                {"action": item.action, "cert": item.cert, "verdict": item.proposal.verdict}
                for item in self.preparations
            ],
        )
        write_json(root / "receipts.json", self.state.receipts)
        write_json(root / "audit.checkpoint.json", self.gateway.audit.checkpoint())
        (root / "audit.jsonl").write_bytes(
            b"".join(jcs_bytes(record) + b"\n" for record in self.gateway.audit.records())
        )
        if not (root / "oracle.json").exists():
            balances = available_balances(self.initial, self.state.ledger)
            final = self.gateway.bank.final_state()
            write_json(
                root / "oracle.json",
                {
                    "scope": "independent account projection and bank receipt signatures",
                    "balances": balances,
                    "bank_receipts_valid": all(
                        verify(self.state.roots.bank_pubkey, RECEIPT, receipt, receipt.sig)
                        for receipt in self.state.receipts.values()
                        if isinstance(receipt, BankReceipt)
                    ),
                    "account_balances_match": all(
                        str(final["balances"].get(ref)) == f"{value.numerator}/{value.denominator}"
                        for ref, value in balances.items()
                    ),
                    "task_complete": "see task-level executable checks; not inferred from balances",
                },
            )
        source = Path(__file__).resolve().parents[1]
        write_json(
            root / "manifest.json",
            {
                "schema_version": "bank-v1",
                "task_id": self.task_id,
                "subcase_id": self.subcase_id,
                "seed": SEED,
                "clock": self.initial.now,
                "initial_hash": H(self.initial),
                "final_hash": H(self.state),
                "code_hash": H({
                    path.relative_to(source).as_posix(): sha256(path.read_bytes()).hexdigest()
                    for path in sorted(source.rglob("*.py"))
                }),
                "audit_checkpoint": self.gateway.audit.checkpoint(),
                "planner_provenance": "see parent task manifest",
            },
        )
        (root / "transcript.md").write_text(
            f"Synthetic task {self.task_id}/{self.subcase_id}.\n\n"
            "Signed inputs, canonical proposals, receipts and audit records are adjacent JSON.\n"
            "Planner provenance and executable assertions are in the parent task result.\n",
            encoding="utf-8",
        )
