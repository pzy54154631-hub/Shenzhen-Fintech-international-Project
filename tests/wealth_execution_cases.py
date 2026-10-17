"""Real gateway/device allocation flows for independent W2 execution tests."""

from dataclasses import dataclass
from pathlib import Path

from corridor.crypto.jcs import H
from corridor.gateway.allocations import (
    advance_allocation,
    allocation_snapshot,
    draft_allocation,
    register_allocation,
)
from corridor.gateway.audit import AuditLog
from corridor.gateway.mfa import MFAVerifier
from corridor.gateway.runtime import create_gateway
from corridor.gateway.service import Gateway
from corridor.kernel.allocation import build_allocation
from corridor.schemas.bank import (
    ApprovalToken,
    BankAction,
    BankCertificate,
    InputTerm,
    MFAGrant,
    Plan,
    PlanNode,
)
from corridor.sim.keys import signing_key, stable_id
from corridor.sim.wealth_device import WealthDevice
from corridor.stores.bank import BankStore
from tests.bank_cases import recertify
from tests.wealth_cases import allocation_case


@dataclass
class PreparedAllocation:
    action: BankAction
    cert: BankCertificate
    card: dict


@dataclass
class ApprovedAllocation:
    action: BankAction
    cert: BankCertificate
    card: dict
    token: ApprovalToken
    grant: MFAGrant


class WealthExecutionCase:
    def __init__(self, *, path=None, state=None, request=None, intent="WEALTH_EXEC"):
        action, cert, seeded = allocation_case(request=request, state=state, intent=intent)
        self.device = WealthDevice()
        self.path = path
        initial = seeded.model_copy(
            update={
                "user_inputs": {},
                "authorizations": {},
                "security": seeded.security.model_copy(update={"active_device_sessions": {}}),
            }
        )
        self.gateway = create_gateway(
            BankStore(initial, path=path / "state.jsonl" if path else None),
            bank_key=signing_key("bank"),
            gateway_key=signing_key("gateway"),
            risk_key=signing_key("risk"),
            mfa=MFAVerifier(signing_key("mfa")),
            audit=AuditLog(
                path / "audit.jsonl" if path else None,
                path / "checkpoint.json" if path else None,
            ),
            evidence_dir=path / "decisions" if path else None,
        )
        auth = seeded.authorizations[cert.authorization_ref]
        assert self.gateway.login(auth).status == "accepted"
        for item in seeded.user_inputs.values():
            assert self.gateway.submit_input(item).status == "accepted"
        plan = Plan(
            plan_id=action.plan_id,
            revision=1,
            principal=action.principal,
            device_session_id=action.device_session_id,
            intent_id=action.intent_id,
            goal_input_refs=[action.args.request_ref],
            nodes=[
                PlanNode(
                    node_id=action.node_id,
                    tool=action.kind,
                    args={
                        key.removeprefix("args."): term for key, term in cert.derivations.items()
                    },
                )
            ],
            ownership_epoch=0,
        )
        action = action.model_copy(update={"plan_hash": H(plan)})
        action, cert, _ = recertify(action, cert, self.state)
        assert self.gateway.submit_plan(plan).status == "registered"
        self.comparison_action, self.comparison_cert = action, cert
        self.comparison = self.gateway.query(action, cert)
        assert self.comparison.analysis_receipt is not None, self.comparison
        self.draft = draft_allocation(
            self.gateway, action.principal, action.intent_id, action.args.request_ref
        )

    @property
    def state(self):
        return self.gateway.store.snapshot()

    @property
    def parent_id(self):
        return self.draft.parent.id

    def start(self, *, selected=None):
        selected = (
            [item.item_ref for item in self.draft.parent.items] if selected is None else selected
        )
        signatures = self.device.sign_allocation(
            self.draft, selected_items=selected, now=self.state.now
        )
        result = register_allocation(
            self.gateway,
            self.draft,
            selection=signatures.selection,
            inputs=signatures.inputs,
            authorizations=signatures.authorizations,
        )
        return result, signatures

    def prepare(self):
        result = advance_allocation(self.gateway, self.parent_id)
        assert result.status in {"waiting_mfa", "waiting_approval"}, result
        return PreparedAllocation(
            BankAction.model_validate(result.details["action"]),
            BankCertificate.model_validate(result.details["cert"]),
            result.details["card"],
        )

    def approve(self, prepared=None, *, sequence=0):
        prepared = prepared or self.prepare()
        request_id = H({"action": prepared.action, "cert": prepared.cert})
        challenge = self.gateway.request_mfa(prepared.action, prepared.cert, request_id=request_id)
        assert challenge is not None
        grant = self.device.complete_mfa(self.gateway.mfa, challenge, now=self.state.now)
        assert self.gateway.submit_mfa(grant).status == "accepted"
        cert = prepared.cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
        token = self.device.approve(
            prepared.action, cert, prepared.card, now=self.state.now, sequence=sequence
        )
        return ApprovedAllocation(prepared.action, cert, prepared.card, token, grant)

    def execute_next(self, *, sequence=0):
        approved = self.approve(sequence=sequence)
        return self.gateway.dispatch(approved.action, approved.cert, approved.token), approved

    def snapshot(self):
        return allocation_snapshot(self.gateway, self.parent_id)

    def replace_request(self, request, *, step=2):
        """A new device gesture supersedes a draft before any child is dispatched."""
        old = self.state.user_inputs[self.comparison_action.args.request_ref]
        value = self.device.confirm_input(
            intent_id=old.scope_id,
            slot="allocation",
            value=request.model_dump(mode="json"),
            now=self.state.now,
            step=step,
            supersedes=old.id,
        )
        assert self.gateway.submit_input(value).status == "accepted"
        term = InputTerm(input_ref=value.id, slot="allocation")
        plan = Plan(
            plan_id=stable_id(old.scope_id, step, "comparison-plan"),
            revision=1,
            principal=old.principal,
            device_session_id=self.comparison_action.device_session_id,
            intent_id=old.scope_id,
            goal_input_refs=[value.id],
            nodes=[
                PlanNode(node_id="COMPARE", tool="allocation_compare", args={"request_ref": term})
            ],
            ownership_epoch=0,
        )
        assert self.gateway.submit_plan(plan).status == "registered"
        action = BankAction.model_validate({
            **self.comparison_action.model_dump(mode="python"),
            "action_id": stable_id(old.scope_id, step, "comparison-action"),
            "plan_id": plan.plan_id,
            "plan_hash": H(plan),
            "node_id": "COMPARE",
            "args": {"request_ref": value.id},
        })
        cert = BankCertificate(
            action_hash=H(action),
            authorization_ref=self.comparison_cert.authorization_ref,
            derivations={"args.request_ref": term},
            dependency_hashes={},
            allocation=build_allocation(old.principal, old.scope_id, value.id, self.state),
        )
        action, cert, _ = recertify(action, cert, self.state)
        self.comparison = self.gateway.query(action, cert)
        assert self.comparison.analysis_receipt is not None, self.comparison
        self.comparison_action, self.comparison_cert = action, cert
        self.draft = draft_allocation(self.gateway, old.principal, old.scope_id, value.id)

    def reopen(self):
        if self.path is None:
            raise ValueError("Reopen requires a persisted execution case")
        self.gateway = Gateway(
            BankStore(self.state, path=self.path / "state.jsonl"),
            self.gateway.bank,
            audit=AuditLog(self.path / "audit.jsonl", self.path / "checkpoint.json"),
            mfa=MFAVerifier(signing_key("mfa")),
            evidence_dir=self.path / "decisions",
            analysis_key=signing_key("gateway"),
            risk_key=signing_key("risk"),
        )


def wealth_execution_case(
    *, path: Path | None = None, state=None, request=None, intent="WEALTH_EXEC"
):
    return WealthExecutionCase(path=path, state=state, request=request, intent=intent)
