"""Red-team: AA split exactness (DESIGN-BANK 4.3)."""

from fractions import Fraction

import pytest

from corridor.bench.planning_runner import _case, _state_term
from corridor.schemas.bank import InputTerm


def _aa(name, total, participants):
    case = _case("RT2", name, None)
    value = case.device.confirm_input(
        intent_id=case.intent(),
        slot="total",
        value={"amount": total, "ccy": "CNY"},
        now=case.state.now,
    )
    authority = case.operation("aa_request", participants, [value], amount_bound=total)
    terms = {
        "source_bill_ref": InputTerm(input_ref=value.id, slot="total"),
        "total_ref": InputTerm(input_ref=value.id, slot="total"),
    }
    terms.update({
        f"participant_refs.{i}": _state_term(case, "contacts", ref)
        for i, ref in enumerate(participants)
    })
    prepared = case.prepare(
        "aa_request",
        {"source_bill_ref": value.id, "total_ref": value.id, "participant_refs": participants},
        terms,
        inputs=[value],
        authorization=authority,
    )
    return case, prepared


@pytest.mark.parametrize("total", ["100/1", "0.05", "1000.01", "7/100"])
def test_aa_shares_sum_exactly_and_ascii_order(total):
    participants = ["CONTACT_LIN_B", "CONTACT_CHEN", "CONTACT_LIN_A"]
    case, prepared = _aa(f"aa-{total.replace('/', '_')}", total, participants)
    result = case.dispatch(prepared)
    assert result.status == "settled"
    receipt = result.analysis_receipt
    shares = [Fraction(receipt.results[f"shares.{p}"].value) for p in sorted(participants)]
    assert sum(shares) == Fraction(total)
    assert max(shares) - min(shares) <= Fraction(1, 100)
    assert shares == sorted(shares, reverse=True)
    assert case.gateway.bank.execute_count == 0


def test_aa_total_below_one_cent_each_rejected():
    participants = ["CONTACT_CHEN", "CONTACT_LIN_A", "CONTACT_LIN_B"]
    case, prepared = _aa("aa-tiny", "0.02", participants)
    assert prepared.proposal.verdict.outcome == "Reject"
    assert case.dispatch(prepared).status == "rejected"


def test_aa_sub_cent_total_rejected():
    participants = ["CONTACT_CHEN", "CONTACT_LIN_A"]
    with pytest.raises(ValueError):
        _aa("aa-subcent", "1.005", participants)
