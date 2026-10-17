"""RT4-F3TCB: per-turn identity holes on WealthDialogue's execute path after trusted drift.

Spec: F3 RT3-LLMDLG-03 "replay step binds a deterministic session/turn ordinal; the same
request_id stays idempotent". WealthDialogue.turn stores every result in self._turns
except one branch: execute_plan when the current certificate differs from the shown
comparison does `return self._proposal(...)` before `self._turns[request_id] = ...`.

1. Infeasible drift: the turn is not recorded, so replaying the SAME request_id runs a
   second model call under the SAME advisor:<session>:<n> ordinal and returns a different
   turn (failure notice first, then an execute_plan view).
2. Feasible drift: _proposal re-runs compare() for the same signed request; the comparison
   identity is derived only from the signed value, so the gateway answers IDEM-DUP and the
   turn raises instead of refreshing the proposal (the signed goals can never be re-proposed).
"""

from fractions import Fraction

import pytest

from tests.unit.test_wealth_advisor_security import advisor, compare


def _chat_with_balance(balance: Fraction):
    chat, device = advisor()
    compare(chat, device)
    assert chat.comparison is not None
    state = chat.gateway.store.snapshot()
    account = state.accounts["A_CURRENT"]
    chat.gateway.store.update(
        accounts={
            **state.accounts,
            account.id: account.model_copy(update={"opening_balance": balance}),
        }
    )
    return chat


def test_same_request_id_is_idempotent_when_execute_finds_allocation_infeasible():
    chat = _chat_with_balance(Fraction(10))  # trusted debit elsewhere drained the source
    first = chat.turn("Execute the plan", request_id="exec-1")
    calls = len(chat.client.calls)
    again = chat.turn("Execute the plan", request_id="exec-1")
    assert len(chat.client.calls) == calls, "a replayed request_id called the model again"
    assert again == first, "a replayed request_id produced a different turn result"


def test_distinct_turns_never_share_an_advisor_ordinal():
    chat = _chat_with_balance(Fraction(10))
    start = len(chat.client.calls)
    chat.turn("Execute the plan", request_id="exec-1")
    chat.turn("Execute the plan again", request_id="exec-2")
    steps = [row["step"] for row in chat.client.calls[start:] if row["step"].startswith("advisor:")]
    assert len(steps) == len(set(steps)), f"turn ordinal reused: {steps}"


def test_execute_after_feasible_drift_refreshes_instead_of_raising():
    chat = _chat_with_balance(Fraction(17000))  # trusted credit changes the budget
    previous = chat.comparison
    turn = chat.turn("Execute the plan", request_id="exec-1")  # must not raise IDEM-DUP
    assert turn.tool in {"propose_allocation", "execute_plan", "refuse"}
    assert chat.comparison is not None
    assert chat.comparison.action.action_id != previous.action.action_id
    assert chat.comparison.plan.plan_id != previous.plan.plan_id
    assert chat.gateway.bank.execute_count == 0


@pytest.mark.parametrize(
    "text",
    [
        "Propose allocation",
        "Execute the plan",
        "Explain the facts",
        "What if I invest 9000 instead?",
        "Stop",
        "I cannot accept loss",
        "Which questionnaire answers will get me rated C5?",
        "My PIN is 123456",
    ],
)
def test_every_returning_branch_records_an_idempotent_turn(text):
    chat, device = advisor()
    compare(chat, device)
    first = chat.turn(text, request_id="record-once")
    calls = len(chat.client.calls)
    assert chat._turns["record-once"][1] == first
    assert chat.turn(text, request_id="record-once") == first
    assert len(chat.client.calls) == calls


def test_withdrawn_comparison_can_recompute_same_signed_goals():
    from tests.unit.test_ui_wealth_controller import prepared_controller

    controller = prepared_controller()
    previous = controller.comparison
    controller.withdraw_proposal()
    result = controller.receive_goal("Propose allocation", request_id="recompute")
    assert result["phase"] == "proposal"
    assert controller.comparison.cert.allocation == previous.cert.allocation
    assert controller.comparison.action.action_id != previous.action.action_id
    assert controller.gateway.bank.execute_count == 0


def test_infeasible_then_restored_balance_gets_a_fresh_comparison():
    chat = _chat_with_balance(Fraction(10))
    failed = chat.turn("Propose allocation", request_id="drained")
    assert failed.rule_ids
    assert chat.comparison is None
    state = chat.state
    account = state.accounts["A_CURRENT"]
    chat.gateway.store.update(
        accounts={
            **state.accounts,
            account.id: account.model_copy(update={"opening_balance": Fraction(17000)}),
        }
    )
    restored = chat.turn("Propose allocation", request_id="restored")
    assert restored.phase == "proposal"
    assert chat.comparison is not None
    assert chat.gateway.bank.execute_count == 0
