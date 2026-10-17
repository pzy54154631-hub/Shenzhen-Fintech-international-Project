"""Further BIC/wealth probes: lock-time re-rating, redemption card fees, explicit override.

Spec refs inline.
"""

import importlib.util as _iu
import json
from fractions import Fraction
from pathlib import Path as _P

from corridor.bench.bank_cases import BankCase
from corridor.bench.investment_runner import (
    _modified_catalog,
    _position_state,
    prepare_investment,
    prepare_redemption,
)
from corridor.crypto.sign import CATALOG, sign
from corridor.schemas.bank import InputTerm
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import add_seconds

_spec = _iu.spec_from_file_location("rt2_bic_helpers", _P(__file__).with_name("_rt_helpers.py"))
_h = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_h)
current_risk_level = _h.current_risk_level


def test_risk_profile_cannot_be_rewritten_while_principal_is_safety_locked():
    """§8.3: during a lock no new business write / structured input takes effect;
    only green *reads*. risk_assess mutates customer.risk_profile_ref."""
    case = BankCase(make_state(), task_id="RT2-BIC", subcase_id="lock_rerate")
    case.gateway.advance_clock(add_seconds(case.state.now, 1))
    answers = case.device.confirm_input(
        intent_id=case.intent(0), slot="answers", value=[4, 4, 4, 4, 4], now=case.state.now
    )
    assert case.gateway.submit_input(answers).status == "accepted"
    prepared = case.prepare(
        "risk_assess",
        {"answers_input_ref": answers.id},
        {"answers_input_ref": InputTerm(input_ref=answers.id, slot="answers")},
        inputs=[answers],
    )
    case.gateway.lock(case.device.principal, "injection_flag")
    assert case.device.principal in case.state.security.locked_at
    result = case.gateway.query(prepared.action, prepared.cert)
    assert "APR-LOCK" in result.rule_ids
    assert current_risk_level(case) == 2, (
        f"risk level rewritten during safety lock: status={result.status}, "
        f"level={current_risk_level(case)}"
    )


def test_redemption_card_discloses_fees_deducted_from_principal():
    """§8.2 CardCore must carry 金额/费用; §6.4 proceeds B - ceilcent(hold) - ceilcent(sell)."""
    state = _position_state()
    catalog = state.catalog.model_copy(
        update={
            "products": [
                p.model_copy(update={"redemption_fee_rate": Fraction(1, 100)})
                if p.product_id == "P_A"
                else p
                for p in state.catalog.products
            ]
        }
    )
    catalog = catalog.model_copy(update={"sig": sign(signing_key("bank"), CATALOG, catalog)})
    state = state.model_copy(update={"catalog": catalog})
    case = BankCase(state, task_id="RT2-BIC", subcase_id="redeem_card")
    prepared = prepare_redemption(case, "1000/1")
    card = prepared.proposal.card
    assert prepared.proposal.verdict.outcome == "Accept"
    facts = json.dumps(card, default=str)
    # Either the fee (10) or the net proceeds (990) must be a displayed card fact.
    assert card.get("fees") == "10/1" or "990/1" in facts, (
        f"redemption card hides the 10 CNY fee / 990 proceeds: amount={card.get('amount')}, "
        f"fees={card.get('fees')}"
    )


def test_explicit_override_without_prior_receipt_discloses_comparison_and_requires_mfa():
    """BIC-4 was rejected: the signed choice and complete approval card are required;
    a separate prior comparison receipt is not required by DESIGN-BANK section 6.3.
    The synthetic device signature below represents the user's explicit choice.
    """
    case = BankCase(_modified_catalog({}), task_id="RT2-BIC", subcase_id="explicit_nocard")
    prepared, _ = prepare_investment(
        case,
        purchase=True,
        changes={
            "selection_mode": "explicit",
            "selected_product_ref": "P_B",
            "reason_code": "prefer_access",
        },
    )
    compared = any(
        getattr(r, "function_id", None) == "product_compare_v1"
        for r in case.state.receipts.values()
    )
    assert not compared
    verdict = prepared.proposal.verdict
    assert verdict.outcome == "Escalate"
    assert "TIER-MFA-REQUIRED" in verdict.rule_ids
    assert prepared.proposal.card["tier"] == "red"
    assert prepared.proposal.card["best_interest"]["best_choice"] is False
    assert prepared.proposal.card["best_interest"]["chosen_rank"] == 2
    assert prepared.proposal.card["best_interest"]["chosen_gap"] == "5/1"
    assert case.dispatch(prepared).status == "rejected"
    assert case.gateway.bank.execute_count == 0
