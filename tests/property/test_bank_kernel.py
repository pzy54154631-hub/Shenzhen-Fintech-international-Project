"""Random exact-cent histories agree with the independent business-day oracle."""

from fractions import Fraction

from hypothesis import given
from hypothesis import strategies as st

from corridor.crypto.jcs import H, jcs_bytes
from corridor.eval.mockbank.oracle import daily_outgoing
from corridor.kernel import check
from corridor.schemas.bank import AccountMovement, BusinessEvent
from corridor.sim.fixtures import make_state
from tests.bank_cases import recertify, transfer_case


@given(
    previous=st.lists(
        st.tuples(
            st.integers(1, 40000),
            st.sampled_from([
                "settled",
                "reserved",
                "unknown",
                "failed",
            ]),
        ),
        max_size=4,
    ),
    cents=st.integers(1, 300000),
)
def test_exact_tier_and_determinism_match_independent_oracle(previous, cents):
    state = make_state()
    events = [
        BusinessEvent(
            id=f"E_{index}",
            intent_key=H({"past": index}),
            event=status,
            kind="transfer",
            principal="C_DEMO",
            debit=AccountMovement(account_ref="A_CURRENT", amount=Fraction(value, 100)),
            ts=state.now,
        )
        for index, (value, status) in enumerate(previous)
    ]
    state = state.model_copy(update={"ledger": events})
    action, cert, state = transfer_case(Fraction(cents, 100), state=state)
    expected = daily_outgoing(state, "C_DEMO", state.now, candidate_amount=Fraction(cents, 100))
    verdict = check(action, cert, state, phase="propose")
    assert verdict.tier == ("red" if expected > 1000 else "yellow")
    assert verdict.outcome == ("Escalate" if expected > 1000 else "Accept")
    assert jcs_bytes(verdict) == jcs_bytes(check(action, cert, state, phase="propose"))


@given(amount=st.integers(1, 99999))
def test_input_scope_tampering_never_becomes_authorization(amount):
    action, cert, state = transfer_case(Fraction(amount, 100))
    item = state.user_inputs[action.args.amount_ref]
    forged = item.model_copy(update={"scope_id": "OTHER_INTENT"})
    state = state.model_copy(update={"user_inputs": {item.id: forged}})
    action, cert, state = recertify(action, cert, state)
    verdict = check(action, cert, state, phase="dispatch")
    assert verdict.outcome == "Reject"
    assert "AUTH-SIG" in verdict.rule_ids or "PROV-COHERENCE" in verdict.rule_ids
