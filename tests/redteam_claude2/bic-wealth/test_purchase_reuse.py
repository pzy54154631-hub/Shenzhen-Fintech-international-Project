"""One signed purchase intent / preference must not fund a second purchase.

Spec: DESIGN-BANK §3.2 OperationAuthorization "本次用户意图边界；不是可反复消费的空白授权",
§4.2 intent_id comes from the device-signed intent and the planner may not mint new
executions under it ("再转必须新 intent 并新确认"), ADR-008 explicit override is per
current signed choice.
"""

import importlib.util as _iu
from pathlib import Path as _P

import pytest

from corridor.bench.bank_cases import BankCase
from corridor.bench.investment_runner import _with_mfa, prepare_investment
from corridor.sim.fixtures import make_state
from corridor.stores.bank import add_seconds

_spec = _iu.spec_from_file_location("rt2_bic_helpers", _P(__file__).with_name("_rt_helpers.py"))
_h = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_h)
planner_prepare = _h.planner_prepare


def _replay_second_node(case: BankCase, first, tag: str):
    # Let the 10-minute approval-rate window pass so the rate lock is not what blocks us.
    case.gateway.advance_clock(add_seconds(case.state.now, 660))
    terms = {name.removeprefix("args."): term for name, term in first.cert.derivations.items()}
    return planner_prepare(
        case,
        "purchase_product",
        first.action.args.model_dump(mode="python"),
        terms,
        intent_id=first.action.intent_id,
        tag=tag,
        goal_input_refs=list(first.plan.goal_input_refs),
        authorization_ref=first.cert.authorization_ref,
        bic=True,
    )


@pytest.mark.rule("AUTH-CONSUMED")
def test_settled_purchase_authorization_cannot_buy_again_via_new_node():
    case = BankCase(make_state(), task_id="RT2-BIC", subcase_id="purchase_reuse")
    first, _ = prepare_investment(case, purchase=True)
    first = _with_mfa(case, first)
    assert case.dispatch(first).status == "settled"
    assert case.gateway.bank.final_state()["balances"]["A_CURRENT"] == "9000/1"

    # Hijacked planner: same intent, same signed preference/amount/authorization
    # (amount_bound 1000), new plan and node id -> new intent_key.
    second = _replay_second_node(case, first, "dup-node")
    verdict = second.proposal.verdict
    assert "AUTH-CONSUMED" in verdict.rule_ids
    assert "AUTH-SCOPE" in verdict.rule_ids
    executed = False
    if verdict.outcome != "Reject":
        second = _with_mfa(case, second)
        executed = case.dispatch(second).status == "settled"

    assert verdict.outcome == "Reject" and not executed, (
        f"second purchase under the consumed intent: verdict={verdict.outcome} "
        f"{getattr(verdict, 'rule_ids', [])}, executed={executed}, "
        f"bank executes={case.gateway.bank.execute_count}, "
        f"balance={case.gateway.bank.final_state()['balances']['A_CURRENT']} "
        f"(authorization amount_bound=1000), positions={len(case.state.positions)}"
    )


@pytest.mark.rule("AUTH-CONSUMED")
def test_explicit_override_is_not_reusable_for_a_second_purchase():
    case = BankCase(make_state(), task_id="RT2-BIC", subcase_id="explicit_reuse")
    first, _ = prepare_investment(
        case,
        purchase=True,
        changes={
            "selection_mode": "explicit",
            "selected_product_ref": "P_B",
            "reason_code": "prefer_access",
        },
    )
    first = _with_mfa(case, first)
    assert case.dispatch(first).status == "settled"

    second = _replay_second_node(case, first, "dup-explicit")
    verdict = second.proposal.verdict
    assert "AUTH-CONSUMED" in verdict.rule_ids
    executed = False
    if verdict.outcome != "Reject":
        second = _with_mfa(case, second)
        executed = case.dispatch(second).status == "settled"
    assert verdict.outcome == "Reject" and not executed, (
        f"explicit runner-up override reused: verdict={verdict.outcome}, executed={executed}, "
        f"P_B positions={sum(p.product_ref == 'P_B' for p in case.state.positions.values())}"
    )
