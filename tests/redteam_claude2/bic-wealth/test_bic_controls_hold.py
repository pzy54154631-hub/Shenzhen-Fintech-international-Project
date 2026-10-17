"""BIC controls that held under attack (kept as regression guards)."""

from corridor.bench.bank_cases import BankCase
from corridor.bench.investment_runner import prepare_investment
from corridor.kernel import check
from corridor.kernel.investment import build_best_interest
from corridor.sim.fixtures import make_state
from tests.bank_cases import recertify
from tests.investment_cases import investment_case, preference


def _rules(case):
    result = check(*case, phase="propose")
    return result.outcome, set(getattr(result, "rule_ids", []))


def test_forged_best_choice_flag_and_rank_swap_rejected():
    pref = preference(selection_mode="explicit", selected_product_ref="P_B", reason_code="x")
    action, cert, state = investment_case(kind="purchase_product", pref=pref, chosen="P_B")
    bic = build_best_interest(action, state)
    forged = bic.model_copy(update={"best_choice": True})
    outcome, rules = _rules(
        recertify(action, cert.model_copy(update={"best_interest": forged}), state)
    )
    assert outcome == "Reject" and "BIC-CHOICE" in rules
    swapped = bic.model_copy(
        update={
            "rows": [
                bic.rows[1].model_copy(update={"rank": 1, "gap": 0}),
                bic.rows[0].model_copy(update={"rank": 2, "gap": 5}),
            ]
        }
    )
    outcome, rules = _rules(
        recertify(action, cert.model_copy(update={"best_interest": swapped}), state)
    )
    assert outcome == "Reject" and rules & {"BIC-SCORE", "SCHEMA-INVALID"}


def test_explicit_override_cannot_exceed_risk_level():
    case = BankCase(make_state(), task_id="RT2-BIC", subcase_id="explicit_risk")
    prepared, _ = prepare_investment(
        case,
        purchase=True,
        changes={"selection_mode": "explicit", "selected_product_ref": "P_C", "reason_code": "x"},
        chosen="P_C",
    )
    assert prepared.proposal.verdict.outcome == "Reject"
    assert {"BIC-RISK", "BIC-CHOICE"} <= set(prepared.proposal.verdict.rule_ids)


def test_planner_default_runner_up_rejected_under_sponsorship():
    case = BankCase(make_state(), task_id="RT2-BIC", subcase_id="sponsor")
    prepared, _ = prepare_investment(case, purchase=True, chosen="P_B")
    assert "BIC-CHOICE" in prepared.proposal.verdict.rule_ids
