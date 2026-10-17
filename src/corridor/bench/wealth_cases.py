"""Device-signed allocation comparison triples for the real kernel."""

from dataclasses import dataclass
from pathlib import Path

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, sign
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
from corridor.kernel.binding import dependency_hashes
from corridor.schemas.bank import (
    ApprovalToken,
    BankAction,
    BankCertificate,
    InputTerm,
    MFAGrant,
    Plan,
    PlanNode,
)
from corridor.sim.device import Device
from corridor.sim.keys import signing_key, stable_id
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.sim.wealth_device import WealthDevice
from corridor.stores.bank import BankStore, add_seconds

PRINCIPAL = "C_DEMO"
SESSION = stable_id("WEALTH_JUDGE", 0, "device-session")


def signed(model, ctx, label="device"):
    return model.model_copy(update={"sig": sign(signing_key(label), ctx, model)})


def recertify(action, cert, state):
    cert = cert.model_copy(update={"action_hash": H(action)})
    cert = cert.model_copy(update={"dependency_hashes": dependency_hashes(action, cert, state)})
    return action, cert, state


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def allocation_case(
    *, request=None, state=None, intent="WEALTH_TEST", build=True, step=1, supersedes=None
):
    state = state or make_wealth_state()
    request = request or allocation_request()
    device = Device()
    value = device.confirm_input(
        intent_id=intent,
        slot="allocation",
        value=request.model_dump(mode="json"),
        now=state.now,
        step=step,
        supersedes=supersedes,
    )
    auth = device.login(session_id=SESSION, expires_at=add_seconds(state.now, 3600))
    auth = signed(auth.model_copy(update={"read_kinds": ["allocation_compare"]}), CONTROL)
    state = state.model_copy(
        update={
            "user_inputs": {**state.user_inputs, value.id: value},
            "authorizations": {**state.authorizations, auth.id: auth},
            "security": state.security.model_copy(
                update={"active_device_sessions": {PRINCIPAL: SESSION}}
            ),
        }
    )
    action = BankAction.model_validate({
        "action_id": stable_id(intent, step, "allocation-action"),
        "intent_id": intent,
        "principal": PRINCIPAL,
        "device_session_id": SESSION,
        "plan_id": stable_id(intent, step, "allocation-plan"),
        "plan_hash": H({"plan": "wealth"}),
        "node_id": stable_id(intent, step, "allocation-node"),
        "kind": "allocation_compare",
        "args": {"request_ref": value.id},
    })
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=auth.id,
        derivations={"args.request_ref": InputTerm(input_ref=value.id, slot="allocation")},
        dependency_hashes={},
        allocation=build_allocation(PRINCIPAL, intent, value.id, state) if build else None,
    )
    return recertify(action, cert, state)


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


class WealthCase:
    def __init__(
        self,
        *,
        path=None,
        state=None,
        request=None,
        intent="WEALTH_EXEC",
        build=True,
        require_success=True,
    ):
        action, cert, seeded = allocation_case(
            request=request, state=state, intent=intent, build=build
        )
        self.device = WealthDevice()
        self.path = path
        self.approvals = []
        initial = seeded.model_copy(
            update={
                "user_inputs": {},
                "authorizations": {},
                "security": seeded.security.model_copy(update={"active_device_sessions": {}}),
            }
        )
        self.initial = initial
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
        _require(self.gateway.login(auth).status == "accepted", "Device login rejected")
        for item in seeded.user_inputs.values():
            _require(self.gateway.submit_input(item).status == "accepted", "Signed input rejected")
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
        _require(self.gateway.submit_plan(plan).status == "registered", "Comparison plan rejected")
        self.comparison_action, self.comparison_cert = action, cert
        self.comparison = self.gateway.query(action, cert)
        self.draft = None
        if self.comparison.analysis_receipt is None:
            if require_success:
                raise ValueError(f"Comparison failed: {self.comparison.rule_ids}")
            return
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
        _require(result.status in {"waiting_mfa", "waiting_approval"}, "Child preparation rejected")
        return PreparedAllocation(
            BankAction.model_validate(result.details["action"]),
            BankCertificate.model_validate(result.details["cert"]),
            result.details["card"],
        )

    def approve(self, prepared=None, *, sequence=0):
        prepared = prepared or self.prepare()
        request_id = H({"action": prepared.action, "cert": prepared.cert})
        challenge = self.gateway.request_mfa(prepared.action, prepared.cert, request_id=request_id)
        _require(challenge is not None, "MFA challenge unavailable")
        grant = self.device.complete_mfa(self.gateway.mfa, challenge, now=self.state.now)
        _require(self.gateway.submit_mfa(grant).status == "accepted", "MFA grant rejected")
        cert = prepared.cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
        token = self.device.approve(
            prepared.action, cert, prepared.card, now=self.state.now, sequence=sequence
        )
        approved = ApprovedAllocation(prepared.action, cert, prepared.card, token, grant)
        self.approvals.append(approved)
        return approved

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
        _require(
            self.gateway.submit_input(value).status == "accepted", "Signed adjustment rejected"
        )
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
        _require(self.gateway.submit_plan(plan).status == "registered", "Adjustment plan rejected")
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
        _require(self.comparison.analysis_receipt is not None, "Adjustment comparison rejected")
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
    return WealthCase(path=path, state=state, request=request, intent=intent)


def products(state, changes=None, *, only=None, reverse=False):
    """Synthetic issuer gesture: change and re-sign a complete catalogue."""
    from corridor.crypto.sign import CATALOG

    values = [
        item.model_copy(update=(changes or {}).get(item.id, {}))
        for item in state.catalog.products
        if only is None or item.id in only
    ]
    if reverse:
        values.reverse()
    catalog = signed(state.catalog.model_copy(update={"products": values}), CATALOG, "bank")
    return state.model_copy(update={"catalog": catalog})


def weights(r1, r2):
    from fractions import Fraction

    return {f"R{i}": Fraction(value) for i, value in enumerate((r1, r2, 0, 0, 0), 1)}


def policy(state, *, model_weights=None, bands=None):
    """Synthetic issuer gesture; ADR-012 permits explicitly signed weights."""
    from fractions import Fraction

    from corridor.crypto.sign import ALLOCATION_POLICY

    value = next(iter(state.allocation_policies.values()))
    profile = value.profiles["C2"]
    changes = {}
    if model_weights is not None:
        changes["model_weights"] = model_weights
    if bands is not None:
        changes["bands"] = [
            band.model_copy(
                update={
                    "lower": Fraction(bands.get(band.sleeve, (band.lower, band.upper))[0]),
                    "upper": Fraction(bands.get(band.sleeve, (band.lower, band.upper))[1]),
                }
            )
            for band in profile.bands
        ]
    value = signed(
        value.model_copy(
            update={"profiles": {**value.profiles, "C2": profile.model_copy(update=changes)}}
        ),
        ALLOCATION_POLICY,
        "bank",
    )
    return state.model_copy(update={"allocation_policies": {value.id: value}})


def vector(biac):
    return {row.product_id: row.principal for row in biac.allocation}


def replace_vector(cert, state, amounts, *, horizon=365, liquidity_days=3):
    """Adversarial fully priced vector, independent of trusted pricing functions."""
    from fractions import Fraction

    def ceil(value):
        scaled = value * 100
        return Fraction(-(-scaled.numerator // scaled.denominator), 100)

    biac = cert.allocation
    catalogue = {item.id: item for item in state.catalog.products}
    rows = []
    total = sum(amounts.values(), Fraction())
    for product_id, principal in sorted(amounts.items()):
        principal = Fraction(principal)
        product = catalogue[product_id]
        buy = ceil(principal * product.purchase_fee_rate)
        hold = ceil(principal * product.annual_fee_rate * Fraction(horizon, 365))
        sell = ceil(principal * product.redemption_fee_rate)
        access = product.min_hold_days + product.redeem_delay_days
        liquid = (
            principal
            - ceil(principal * product.annual_fee_rate * Fraction(product.min_hold_days, 365))
            - sell
            if access <= liquidity_days
            else Fraction()
        )
        rows.append(
            biac.allocation[0].model_copy(
                update={
                    "product_id": product_id,
                    "sleeve": f"R{product.risk_level}",
                    "principal": principal,
                    "weight": principal / total,
                    "fee_buy": buy,
                    "fee_hold": hold,
                    "fee_sell": sell,
                    "expected_net": principal
                    * product.expected_annual_rate
                    * Fraction(horizon, 365)
                    - buy
                    - hold
                    - sell,
                    "access_days": access,
                    "liquid_net_principal": liquid,
                }
            )
        )
    totals = biac.totals.model_copy(
        update={
            "principal": total,
            "fee_buy": sum((row.fee_buy for row in rows), Fraction()),
            "total_debit": total + sum((row.fee_buy for row in rows), Fraction()),
            "projected_fees": sum(
                (row.fee_buy + row.fee_hold + row.fee_sell for row in rows), Fraction()
            ),
            "projected_net": sum((row.expected_net for row in rows), Fraction()),
            "liquid_net_principal": sum((row.liquid_net_principal for row in rows), Fraction()),
        }
    )
    sleeves = [
        sleeve.model_copy(
            update={
                "actual_cents": int(
                    sum((row.principal for row in rows if row.sleeve == sleeve.sleeve), Fraction())
                    * 100
                )
            }
        )
        for sleeve in biac.sleeves
    ]
    return cert.model_copy(
        update={
            "allocation": biac.model_copy(
                update={
                    "allocation": rows,
                    "totals": totals,
                    "sleeves": sleeves,
                }
            )
        }
    )
