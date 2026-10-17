"""Deterministic legal bank triples for kernel and gateway integration tests."""

from fractions import Fraction
from typing import Any

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT, MFA, SPA, sign
from corridor.kernel.binding import binding, dependency_hashes, mfa_scope
from corridor.schemas.bank import (
    BankAction,
    BankCertificate,
    BusinessEvent,
    InputTerm,
    MFAGrant,
    OperationAuthorization,
    ScheduledPaymentAuthorization,
    SessionAuthorization,
    StateTerm,
    UserInput,
)
from corridor.schemas.domain import ScheduledTask
from corridor.schemas.state import BankState
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds

PRINCIPAL = "C_DEMO"
SESSION = "SESSION_TEST"
ZERO_SIG = "0" * 128


def signed(model: Any, ctx: str, label: str = "device") -> Any:
    return model.model_copy(update={"sig": sign(signing_key(label), ctx, model)})


def recertify(
    action: BankAction, cert: BankCertificate, state: BankState
) -> tuple[BankAction, BankCertificate, BankState]:
    cert = cert.model_copy(update={"action_hash": H(action)})
    cert = cert.model_copy(update={"dependency_hashes": dependency_hashes(action, cert, state)})
    return action, cert, state


def transfer_case(
    amount: Fraction = Fraction(200),
    *,
    contact_ref: str = "CONTACT_CHEN",
    source_ref: str = "A_CURRENT",
    intent_id: str = "INTENT_TEST",
    state: BankState | None = None,
) -> tuple[BankAction, BankCertificate, BankState]:
    state = state or make_state()
    state = state.model_copy(
        update={
            "security": state.security.model_copy(
                update={
                    "active_device_sessions": {PRINCIPAL: SESSION},
                }
            )
        }
    )
    user_input = signed(
        UserInput(
            id=f"INPUT_{intent_id}",
            principal=PRINCIPAL,
            batch_id=f"BATCH_{intent_id}",
            slot="amount",
            value={"amount": f"{amount.numerator}/{amount.denominator}", "ccy": "CNY"},
            submitted_at=state.now,
            scope_id=intent_id,
            sig=ZERO_SIG,
        ),
        INPUT,
    )
    authorization = signed(
        OperationAuthorization(
            id=f"AUTH_{intent_id}",
            principal=PRINCIPAL,
            intent_id=intent_id,
            allowed_kind="transfer",
            object_refs=[source_ref, contact_ref],
            amount_bound=amount,
            expires_at=add_seconds(state.now, 3600),
            input_hashes=[H(user_input)],
            sig=ZERO_SIG,
        ),
        CONTROL,
    )
    state = state.model_copy(
        update={
            "user_inputs": {**state.user_inputs, user_input.id: user_input},
            "authorizations": {**state.authorizations, authorization.id: authorization},
        }
    )
    action = BankAction(
        action_id=f"ACTION_{intent_id}",
        intent_id=intent_id,
        principal=PRINCIPAL,
        device_session_id=SESSION,
        plan_id="PLAN_TEST",
        plan_hash=H({"plan": "test"}),
        node_id="NODE_TEST",
        kind="transfer",
        args={
            "source_ref": source_ref,
            "contact_ref": contact_ref,
            "amount_ref": user_input.id,
        },
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=authorization.id,
        dependency_hashes={},
        derivations={
            "args.source_ref": StateTerm(
                collection="accounts",
                object_ref=source_ref,
                field="id",
                version=state.accounts[source_ref].version,
            ),
            "args.contact_ref": StateTerm(
                collection="contacts",
                object_ref=contact_ref,
                field="id",
                version=state.contacts[contact_ref].version,
            ),
            "args.amount_ref": InputTerm(input_ref=user_input.id, slot="amount"),
        },
    )
    return recertify(action, cert, state)


def query_case(kind: str = "balance_query") -> tuple[BankAction, BankCertificate, BankState]:
    action, cert, state = transfer_case()
    args: dict[str, Any] = {"account_ref": "A_CURRENT"}
    derivations: dict[str, Any] = {
        "args.account_ref": StateTerm(
            collection="accounts", object_ref="A_CURRENT", field="id", version=1
        ),
    }
    authority = signed(
        SessionAuthorization(
            id="SESSION_AUTH",
            principal=PRINCIPAL,
            device_session_id=SESSION,
            read_kinds=["balance_query", "transactions_query"],
            expires_at=add_seconds(state.now, 3600),
            sig=ZERO_SIG,
        ),
        CONTROL,
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": kind,
        "args": args,
    })
    state = state.model_copy(
        update={"authorizations": {**state.authorizations, authority.id: authority}}
    )
    cert = cert.model_copy(update={"authorization_ref": authority.id, "derivations": derivations})
    return recertify(action, cert, state)


def with_mfa(
    action: BankAction, cert: BankCertificate, state: BankState
) -> tuple[BankAction, BankCertificate, BankState]:
    facts = binding(action, cert, state)
    grant = signed(
        MFAGrant(
            grant_id="GRANT_TEST",
            principal=action.principal,
            device_session_id=action.device_session_id,
            scope_hash=mfa_scope(action, H(facts.card_core)),
            method="sms_sim",
            challenge_id="CHALLENGE_TEST",
            issued_at=state.now,
            expiry=add_seconds(state.now, 120),
            sig=ZERO_SIG,
        ),
        MFA,
        "mfa",
    )
    state = state.model_copy(
        update={
            "security": state.security.model_copy(
                update={
                    "mfa_grants": {**state.security.mfa_grants, grant.grant_id: grant},
                }
            )
        }
    )
    cert = cert.model_copy(update={"mfa_grant_refs": [grant.grant_id]})
    return recertify(action, cert, state)


def spa_case(amount: Fraction = Fraction(200), *, execution: bool = False):
    action, cert, state = transfer_case(amount, intent_id="SPA_TEST")
    spa = signed(
        ScheduledPaymentAuthorization(
            id="SPA_TEST",
            principal=action.principal,
            source_ref="A_CURRENT",
            target={"kind": "transfer", "contact_ref": "CONTACT_CHEN"},
            destination_version=1,
            amount=amount,
            schedule={"type": "once"},
            start=add_seconds(state.now, 86400),
            end=add_seconds(state.now, 86400 * 30),
            max_runs=1,
            creation_tier="red" if amount > 1000 else "yellow",
            plan_id=action.plan_id,
            node_id=action.node_id,
            sig=ZERO_SIG,
        ),
        SPA,
    )
    state = state.model_copy(update={"authorizations": {**state.authorizations, spa.id: spa}})
    if not execution:
        action = BankAction.model_validate({
            **action.model_dump(mode="python"),
            "kind": "schedule_transfer",
            "args": {**action.args.model_dump(mode="python"), "schedule_ref": spa.id},
        })
        cert = cert.model_copy(
            update={
                "derivations": {
                    **cert.derivations,
                    "args.schedule_ref": StateTerm(
                        collection="authorizations", object_ref=spa.id, field="id", version=1
                    ),
                }
            }
        )
    else:
        run_key = H({"spa_id": spa.id, "run_index": 0})
        run = ScheduledTask(
            id="SPA_RUN",
            owner=action.principal,
            plan_id=spa.plan_id,
            node_id=spa.node_id,
            spa_ref=spa.id,
            run_index=0,
            action_template={},
            input_refs=[action.args.amount_ref],
            due_at=spa.start,
            expires_at=add_seconds(spa.start, 86400),
            commitment_id=run_key,
            status="due",
        )
        event = BusinessEvent(
            id="SPA_CREATED",
            intent_key=H({
                "principal": spa.principal,
                "intent_id": spa.id,
                "node_id": spa.node_id,
                "kind": "schedule_transfer",
            }),
            event="settled",
            kind="schedule_transfer",
            principal=spa.principal,
            ts=state.now,
            object_delta={
                "spa_hash": H(spa),
                "source_version": state.accounts[spa.source_ref].version,
                "destination_version": spa.destination_version,
                "creation_tier": spa.creation_tier,
                "approval_verified": True,
                "approval_hash": H("creation_approval"),
                "mfa_verified": spa.creation_tier == "red",
                "mfa_hash": H("creation_mfa") if spa.creation_tier == "red" else None,
            },
        )
        action = action.model_copy(update={"action_id": run.id})
        state = state.model_copy(
            update={"now": spa.start, "schedules": {run.id: run}, "ledger": [event]}
        )
    cert = cert.model_copy(update={"authorization_ref": spa.id})
    return recertify(action, cert, state)
