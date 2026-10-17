"""End-to-end: one signed transfer intent must not move money twice (DESIGN-BANK 3.2, 4.2, 5.3).

The planner is untrusted. After the user's single "transfer 200" intent settles, the planner
registers a second single-node plan for the SAME intent (new plan_id / node_id) that reuses
the same signed amount input and OperationAuthorization (amount_bound = 200). The kernel
must refuse because that authority is already spent, and gateway IDEM-DUP must
use the same key despite the planner's replacement identifiers.
"""

from fractions import Fraction

from corridor.crypto.jcs import H
from corridor.schemas.bank import Plan, PlanNode
from corridor.stores.bank import available
from tests.bank_cases import recertify
from tests.gateway_cases import approve, gateway_case


def test_same_intent_authority_cannot_settle_two_transfers() -> None:
    gateway, device, action, cert = gateway_case(Fraction(200))
    token = approve(gateway, device, action, cert)
    first = gateway.dispatch(action, cert, token)
    assert first.status == "settled", first
    state = gateway.store.snapshot()
    assert available(state, "A_CURRENT") == Fraction(9800)

    replay_plan = Plan(
        plan_id="PLAN_REPLAY",
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=action.intent_id,
        goal_input_refs=[action.args.amount_ref],
        nodes=[
            PlanNode(
                node_id="NODE_REPLAY",
                tool="transfer",
                args={key.removeprefix("args."): term for key, term in cert.derivations.items()},
            )
        ],
        ownership_epoch=0,
    )
    assert gateway.submit_plan(replay_plan).status == "registered"
    replay = action.model_copy(
        update={
            "action_id": "ACTION_REPLAY",
            "plan_id": replay_plan.plan_id,
            "plan_hash": H(replay_plan),
            "node_id": "NODE_REPLAY",
        }
    )
    replay, replay_cert, _ = recertify(replay, cert, state)
    proposal = gateway.propose(replay, replay_cert)
    replay_token = device.approve(
        replay,
        replay_cert,
        proposal.card
        or {
            "tier": "yellow",
            **{
                "kind": replay.kind,
                "plan_hash": replay.plan_hash,
                "node_id": replay.node_id,
                "device_session_id": replay.device_session_id,
            },
        },
        now=gateway.store.snapshot().now,
        sequence=1,
    )
    second = gateway.dispatch(replay, replay_cert, replay_token)
    after = available(gateway.store.snapshot(), "A_CURRENT")
    assert (second.status, after) == ("rejected", Fraction(9800)), (
        f"propose={proposal.verdict.outcome} dispatch={second.status} available={after}"
    )
