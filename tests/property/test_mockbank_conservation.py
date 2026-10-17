"""The independent backend preserves cents and idempotency across transfer sequences."""

from fractions import Fraction

from hypothesis import given
from hypothesis import strategies as st

from corridor.crypto.jcs import H
from corridor.eval.mockbank.exec import MockBank
from corridor.schemas.bank import BankOrder
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key


@given(st.lists(st.integers(min_value=1, max_value=200000), min_size=1, max_size=4))
def test_transfer_conservation_and_retry(cents):
    initial = make_state()
    bank = MockBank(initial, signing_key("bank"))
    for index, value in enumerate(cents):
        order = BankOrder.model_validate({
            "intent_key": H({"sequence": index}),
            "action_id": f"transfer-{index}",
            "principal": "C_DEMO",
            "kind": "transfer",
            "requested_at": initial.now,
            "args": {
                "source_ref": "A_CURRENT",
                "contact_ref": "CONTACT_CHEN",
                "destination_ref": "DEST_CONTACT_CHEN",
                "amount": Fraction(value, 100),
            },
        })
        receipt = bank.execute(order)
        assert receipt.status == "settled"
        assert bank.execute(order) == receipt
    final = bank.final_state()
    total = sum((Fraction(value) for value in final["balances"].values()), Fraction(0))
    total += sum((Fraction(value) for value in final["destinations"].values()), Fraction(0))
    assert total == 10000
