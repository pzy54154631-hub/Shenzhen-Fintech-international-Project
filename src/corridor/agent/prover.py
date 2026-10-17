"""Untrusted certificate construction; the kernel independently checks every field."""

from corridor.crypto.jcs import H
from corridor.kernel.binding import dependency_hashes
from corridor.schemas.bank import BankAction, BankCertificate, InputTerm, Plan, PlanNode, StateTerm
from corridor.schemas.state import BankState
from corridor.sim.keys import stable_id


def transfer_triple(
    *,
    state: BankState,
    principal: str,
    session_id: str,
    intent_id: str,
    source_ref: str,
    contact_ref: str,
    amount_ref: str,
    selection_ref: str,
    authorization_ref: str,
) -> tuple[Plan, BankAction, BankCertificate]:
    terms = {
        "source_ref": StateTerm(
            collection="accounts",
            object_ref=source_ref,
            field="id",
            version=state.accounts[source_ref].version,
        ),
        "contact_ref": StateTerm(
            collection="contacts",
            object_ref=contact_ref,
            field="id",
            version=state.contacts[contact_ref].version,
        ),
        "amount_ref": InputTerm(input_ref=amount_ref, slot="amount"),
    }
    node_id = stable_id(intent_id, 0, "transfer-node")
    plan = Plan(
        plan_id=stable_id(intent_id, 0, "plan"),
        revision=1,
        principal=principal,
        device_session_id=session_id,
        intent_id=intent_id,
        goal_input_refs=[amount_ref, selection_ref],
        nodes=[PlanNode(node_id=node_id, tool="transfer", args=terms)],
        ownership_epoch=0,
    )
    action = BankAction(
        action_id=stable_id(intent_id, 0, "transfer-action"),
        intent_id=intent_id,
        principal=principal,
        device_session_id=session_id,
        plan_id=plan.plan_id,
        plan_hash=H(plan),
        node_id=node_id,
        kind="transfer",
        args={"source_ref": source_ref, "contact_ref": contact_ref, "amount_ref": amount_ref},
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=authorization_ref,
        derivations={f"args.{key}": value for key, value in terms.items()},
        dependency_hashes={},
    )
    cert = cert.model_copy(update={"dependency_hashes": dependency_hashes(action, cert, state)})
    return plan, action, cert
