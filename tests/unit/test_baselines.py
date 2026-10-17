"""Frozen baseline policy and visible-only simulated-user behavior."""

from fractions import Fraction

import pytest

from corridor.bench.baseline_exec import BaselineExecutor, signed_policy
from corridor.bench.metrics import binomial_summary
from corridor.bench.users import SimulatedUser, signed_goal
from corridor.crypto.jcs import H
from corridor.schemas.bank import BankOrder
from corridor.sim.fixtures import make_state


def order(index=0, amount="200/1", kind="transfer"):
    args = {
        "source_ref": "A_CURRENT",
        "contact_ref": "CONTACT_CHEN",
        "destination_ref": "DEST_CONTACT_CHEN",
        "amount": amount,
    }
    if kind == "subscription_query":
        args = {"account_ref": "A_CURRENT", "period": "2026-10"}
    return BankOrder.model_validate({
        "intent_key": H({"test": index}),
        "action_id": f"BASE-{index}",
        "principal": "C_DEMO",
        "kind": kind,
        "requested_at": make_state().now,
        "args": args,
    })


def user(policy="all_approve"):
    return SimulatedUser(
        policy, signed_goal({"kind": "transfer", "target": "CONTACT_CHEN", "amount": "200/1"})
    )


def test_d0_executes_without_confirmation_and_d3_query_is_automatic():
    d0 = BaselineExecutor(make_state(), "d0")
    assert d0.execute(order(), user()).receipt.status == "settled"
    assert d0.confirmation_count == 0
    d3 = BaselineExecutor(make_state(), "d3")
    assert d3.execute(order(kind="subscription_query"), user()).receipt.status == "settled"
    assert d3.confirmation_count == 0


def test_d3_writes_confirm_visible_text_and_careful_rejects_missing_or_changed_facts():
    d3 = BaselineExecutor(make_state(), "d3")
    assert d3.execute(order(), user("careful"), visible_text="Confirm payment").status == "refused"
    assert d3.bank.execute_count == 0
    visible = '{"kind":"transfer","target":"CONTACT_CHEN","amount":"200/1"}'
    assert d3.execute(order(), user("careful"), visible_text=visible).receipt.status == "settled"
    assert d3.confirmation_count == 2


def test_careful_can_be_fooled_by_hidden_order_drift_because_d3_has_no_card_binding():
    baseline = BaselineExecutor(make_state(), "d3")
    visible = '{"kind":"transfer","target":"CONTACT_CHEN","amount":"200/1"}'
    result = baseline.execute(order(amount="201/1"), user("careful"), visible_text=visible)
    assert result.receipt.status == "settled"
    assert baseline.bank.final_state()["balances"]["A_CURRENT"] == "9799/1"


def test_d3_static_limits_are_signed_fixed_and_count_idempotency_once():
    baseline = BaselineExecutor(make_state(), "d3")
    assert baseline.execute(order(amount="100001/100"), user()).reason == "D3-SINGLE-LIMIT"
    for index in range(5):
        assert baseline.execute(order(index, "1000/1"), user()).status == "settled"
    assert baseline.execute(order(0, "1000/1"), user()).status == "settled"
    assert baseline.execute(order(6, "1/100"), user()).reason == "D3-DAILY-LIMIT"
    assert baseline.bank.final_state()["balances"]["A_CURRENT"] == "5000/1"
    policy = signed_policy()
    policy["single_limit"] = "2000/1"
    with pytest.raises(ValueError, match="policy"):
        BaselineExecutor(make_state(), "d3", policy=policy)


def test_careful_explicit_choice_requires_matching_rank_gap_and_signed_goal():
    goal = signed_goal({
        "kind": "purchase_product",
        "target": "P_B",
        "amount": "1000/1",
        "explicit_selection": True,
        "rank": 2,
        "gap": "5/1",
    })
    careful = SimulatedUser("careful", goal)
    facts = dict(goal["facts"])
    facts["best_choice"] = False
    assert careful.approve(facts)
    facts["gap"] = "0/1"
    assert not careful.approve(facts)
    with pytest.raises(ValueError, match="goal"):
        SimulatedUser("careful", {**goal, "sig": "0" * 128})


def test_d3_cannot_reset_daily_spend_with_backdated_order_time():
    baseline = BaselineExecutor(make_state(), "d3")
    for index in range(5):
        assert baseline.execute(order(index, "1000/1"), user()).status == "settled"
    backdated = order(99, "1/100").model_copy(update={"requested_at": "2026-10-15T02:00:00Z"})
    assert baseline.execute(backdated, user()).reason == "D3-DAILY-LIMIT"


def test_binomial_zero_none_and_wilson_are_explicit():
    assert binomial_summary(0, 0)["status"] == "not_run"
    assert binomial_summary(0, 2)["upper_95_approx"] == "1/1"
    zero = binomial_summary(0, 40)
    assert zero["upper_95_approx"] == "3/40"
    assert zero["display"].startswith("0/40")
    measured = binomial_summary(5, 10)
    assert Fraction(measured["wilson_95"]["lower"]) < Fraction(1, 2)
    assert Fraction(measured["wilson_95"]["upper"]) > Fraction(1, 2)
    with pytest.raises(ValueError):
        binomial_summary(2, 1)
