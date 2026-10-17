"""Complete-set, exact-price and signed-choice BIC security obligations."""

from fractions import Fraction

import pytest

from corridor.crypto.sign import CATALOG, INPUT, RISK
from corridor.eval.mockbank.oracle import rank_products
from corridor.kernel import check
from corridor.kernel.binding import binding
from corridor.kernel.investment import (
    build_best_interest,
    evaluate_investment,
    price_product,
    risk_score,
)
from corridor.schemas.domain import MarketingMetadata
from corridor.schemas.models import Accept, Escalate, Reject
from tests.bank_cases import recertify, signed, with_mfa
from tests.investment_cases import investment_case, preference, redemption_case


def reject(case, rule):
    result = check(*case, phase="propose")
    assert isinstance(result, Reject), result
    assert rule in result.rule_ids


def test_manual_complete_certificate_passes_and_selector_equals_hand_values():
    action, cert, state = investment_case()
    assert build_best_interest(action, state) == cert.best_interest
    assert isinstance(check(action, cert, state, phase="propose"), Accept)
    assert check(action, cert, state, phase="dispatch").tier == "green"


@pytest.mark.parametrize(
    "objective,order,gaps",
    [
        ("net_return", ["P_A", "P_B"], [0, 5]),
        ("total_fee", ["P_A", "P_B"], [0, 10]),
        ("liquidity", ["P_B", "P_A"], [0, 19]),
    ],
)
def test_three_objectives_match_hand_calculation_and_independent_oracle(objective, order, gaps):
    pref = preference(objective=objective)
    action, _, state = investment_case(pref=pref)
    bic = build_best_interest(action, state)
    assert bic.candidate_ids == ["P_A", "P_B"]
    assert [row.product_id for row in bic.rows] == order
    assert [row.gap for row in bic.rows] == gaps
    oracle = rank_products(state, state.catalog, action.principal, pref, state.now)
    assert [row.product_id for row in oracle] == order
    assert [row.expected_net for row in oracle] == [row.expected_net for row in bic.rows]


@pytest.mark.parametrize("objective", ["net_return", "total_fee", "liquidity"])
def test_ties_use_ascii_product_id(objective):
    action, _, state = investment_case(pref=preference(objective=objective))
    products = [
        state.catalog.products[0].model_copy(update={"product_id": "Z"}),
        state.catalog.products[0].model_copy(update={"product_id": "A"}),
    ]
    catalog = signed(state.catalog.model_copy(update={"products": products}), CATALOG, "bank")
    bic = build_best_interest(action, state.model_copy(update={"catalog": catalog}))
    assert [row.product_id for row in bic.rows] == ["A", "Z"]
    assert [row.gap for row in bic.rows] == [0, 0]


def test_contract_fees_round_up_individually_before_exact_ranking():
    _, _, state = investment_case()
    product = state.catalog.products[0].model_copy(
        update={
            "purchase_fee_rate": Fraction(1, 300),
            "annual_fee_rate": Fraction(1, 300),
            "redemption_fee_rate": Fraction(1, 300),
        }
    )
    row = price_product(product, Fraction(1), 1)
    assert (row.fee_buy, row.fee_hold, row.fee_sell, row.total_fee) == (
        Fraction(1, 100),
        Fraction(1, 100),
        Fraction(1, 100),
        Fraction(3, 100),
    )
    assert row.expected_net == Fraction(3, 36500) - Fraction(3, 100)


@pytest.mark.rule("BIC-COMPLETE")
@pytest.mark.parametrize(
    "candidates", [["P_B"], ["P_A", "P_B", "P_B"], ["P_A", "P_B", "P_C"], ["P_B", "P_A"]]
)
def test_candidate_omission_duplicate_extra_and_noncanonical_order_rejected(candidates):
    action, cert, state = investment_case()
    cert = cert.model_copy(
        update={
            "best_interest": cert.best_interest.model_copy(update={"candidate_ids": candidates})
        }
    )
    reject((action, cert, state), "BIC-COMPLETE")


@pytest.mark.rule("BIC-SCORE")
@pytest.mark.parametrize(
    "field,value",
    [
        ("fee_buy", Fraction(1)),
        ("expected_net", Fraction(31)),
        ("rank", 2),
        ("gap", Fraction(1)),
        ("access_days", 31),
    ],
)
def test_every_price_rank_and_gap_is_recomputed(field, value):
    action, cert, state = investment_case()
    rows = cert.best_interest.rows
    cert = cert.model_copy(
        update={
            "best_interest": cert.best_interest.model_copy(
                update={"rows": [rows[0].model_copy(update={field: value}), rows[1]]}
            )
        }
    )
    reject((action, cert, state), "BIC-SCORE")


@pytest.mark.rule("BIC-CATALOG")
@pytest.mark.parametrize(
    "change",
    [
        {"sig": "0" * 128},
        {"valid_until": "2026-10-16T02:00:00Z"},
        {"issued_at": "2026-10-16T02:00:01Z"},
    ],
)
def test_catalog_signature_and_validity_required(change):
    action, cert, state = investment_case()
    catalog = state.catalog.model_copy(update=change)
    if "sig" not in change:
        catalog = signed(catalog, CATALOG, "bank")
    state = state.model_copy(update={"catalog": catalog})
    reject(recertify(action, cert, state), "BIC-CATALOG")


@pytest.mark.rule("BIC-RISK")
@pytest.mark.parametrize(
    "change",
    [
        {"sig": "0" * 128},
        {"score": 20, "level": 5},
        {"answers_hash": "0" * 64},
        {"expires_at": "2026-10-16T02:00:00Z"},
        {"owner": "OTHER"},
    ],
)
def test_risk_signature_answers_score_ownership_and_expiry_recomputed(change):
    action, cert, state = investment_case()
    risk = state.risk_assessments["RISK_DEMO"].model_copy(update=change)
    if "sig" not in change:
        risk = signed(risk, RISK, "risk")
    state = state.model_copy(update={"risk_assessments": {risk.id: risk}})
    reject(recertify(action, cert, state), "BIC-RISK")


@pytest.mark.rule("BIC-PREFERENCE")
def test_preference_requires_current_device_signature_and_exact_amount_source():
    action, cert, state = investment_case(kind="purchase_product")
    user_input = state.user_inputs[action.args.preference_ref]
    state = state.model_copy(
        update={
            "user_inputs": {
                **state.user_inputs,
                user_input.id: user_input.model_copy(update={"sig": "0" * 128}),
            }
        }
    )
    reject(recertify(action, cert, state), "BIC-PREFERENCE")
    action, cert, state = investment_case(kind="purchase_product")
    amount = state.user_inputs[action.args.amount_ref]
    changed = signed(amount.model_copy(update={"value": {"amount": "999/1", "ccy": "CNY"}}), INPUT)
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, amount.id: changed}})
    reject(recertify(action, cert, state), "BIC-PREFERENCE")


@pytest.mark.rule("BIC-CHOICE")
def test_agent_default_runner_up_rejected_but_device_explicit_choice_disclosed():
    action, cert, state = investment_case(kind="purchase_product", chosen="P_B")
    reject((action, cert, state), "BIC-CHOICE")
    pref = preference(
        selection_mode="explicit",
        selected_product_ref="P_B",
        reason_code="user_liquidity_preference",
    )
    action, cert, state = investment_case(kind="purchase_product", pref=pref, chosen="P_B")
    bic = build_best_interest(action, state)
    cert = cert.model_copy(update={"best_interest": bic})
    card = binding(action, cert, state).card_core
    assert bic.selection_mode == "explicit" and bic.best_choice is False
    assert card["best_interest"]["chosen_rank"] == 2
    assert card["best_interest"]["chosen_gap"] == "5/1"
    assert isinstance(check(*with_mfa(action, cert, state), phase="dispatch"), Accept)


@pytest.mark.rule("BIC-NOFEASIBLE")
def test_empty_feasible_set_rejects_with_complete_exclusion_reasons():
    action, cert, state = investment_case(pref=preference(amount="50/1"))
    evaluation = evaluate_investment(action, state)
    assert evaluation.certificate is None
    assert set(evaluation.exclusions) == {"P_A", "P_B", "P_C", "P_D", "P_E"}
    assert all(evaluation.exclusions.values())
    reject((action, cert, state), "BIC-NOFEASIBLE")


@pytest.mark.parametrize(
    "update,reason",
    [
        ({"purchase_open": False}, "purchase_closed"),
        ({"eligible_customers": []}, "customer_ineligible"),
        ({"risk_level": 3}, "risk"),
        ({"min_amount": Fraction(100001, 100)}, "minimum_amount"),
        ({"max_amount": Fraction(99999, 100)}, "maximum_amount"),
        ({"type": "deposit"}, "product_type"),
        ({"min_hold_days": 366}, "holding_period"),
        ({"redeem_delay_days": 2}, "access_delay"),
    ],
)
def test_each_eligibility_condition_is_independently_enforced(update, reason):
    action, _, state = investment_case()
    products = [state.catalog.products[0].model_copy(update=update), *state.catalog.products[1:]]
    state = state.model_copy(
        update={
            "catalog": signed(
                state.catalog.model_copy(update={"products": products}), CATALOG, "bank"
            )
        }
    )
    evaluation = evaluate_investment(action, state)
    assert reason in evaluation.exclusions["P_A"]
    assert evaluation.certificate.candidate_ids == ["P_B"]


def test_purchase_fees_participate_in_balance_eligibility():
    action, _, state = investment_case()
    account = state.accounts["A_CURRENT"].model_copy(update={"opening_balance": Fraction(1000)})
    state = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
    evaluation = evaluate_investment(action, state)
    assert evaluation.certificate.candidate_ids == ["P_A"]
    assert "available_balance" in evaluation.exclusions["P_B"]


def test_marketing_metadata_cannot_enter_selector_and_economic_change_changes_rank():
    action, _, state = investment_case()
    expected = build_best_interest(action, state)
    for sponsored in (True, False):
        MarketingMetadata(product_id="P_B", sponsored=sponsored, campaign_text_handle="UNTRUSTED")
        assert build_best_interest(action, state) == expected
    products = [
        state.catalog.products[0],
        state.catalog.products[1].model_copy(update={"expected_annual_rate": Fraction(1, 10)}),
        *state.catalog.products[2:],
    ]
    state = state.model_copy(
        update={
            "catalog": signed(
                state.catalog.model_copy(update={"products": products}), CATALOG, "bank"
            )
        }
    )
    assert build_best_interest(action, state).chosen_product_id == "P_B"


@pytest.mark.parametrize(
    "answers,score,level",
    [
        ([0] * 5, 0, 1),
        ([0, 1, 1, 1, 1], 4, 1),
        ([1] * 5, 5, 2),
        ([0, 2, 2, 2, 2], 8, 2),
        ([1, 2, 2, 2, 2], 9, 3),
        ([4, 2, 2, 2, 2], 12, 3),
        ([1, 3, 3, 3, 3], 13, 4),
        ([4, 3, 3, 3, 3], 16, 4),
        ([1, 4, 4, 4, 4], 17, 5),
        ([4] * 5, 20, 5),
    ],
)
def test_risk_questionnaire_score_boundaries(answers, score, level):
    _, _, state = investment_case()
    assert risk_score(answers, state) == (score, level)


def test_red_purchase_requires_mfa_and_revalidates_catalog_after_card():
    action, cert, state = investment_case(kind="purchase_product")
    result = check(action, cert, state, phase="propose")
    assert isinstance(result, Escalate) and result.tier == "red"
    assert isinstance(check(*with_mfa(action, cert, state), phase="dispatch"), Accept)


def test_redeem_full_mature_position_and_income_query_allow_existing_lot_exit():
    for kind in ("redeem_product", "investment_income_query"):
        case = redemption_case(kind=kind)
        result = check(*case, phase="dispatch")
        assert isinstance(result, Accept), result
        assert result.tier == ("yellow" if kind == "redeem_product" else "green")


@pytest.mark.parametrize(
    "change,rule",
    [
        ({"redeemable_at": "2026-10-16T02:00:01Z"}, "DOMAIN-STATE"),
        ({"status": "closed"}, "DOMAIN-STATE"),
        ({"reserved_units": Fraction(1)}, "BAL-AVAILABLE"),
        ({"owner": "OTHER"}, "AUTH-PRINCIPAL"),
        (
            {"acquired_at": "2026-10-16T02:00:00Z", "redeemable_at": "2026-10-16T02:00:00Z"},
            "DOMAIN-STATE",
        ),
    ],
)
def test_redemption_state_and_reserved_share_boundaries(change, rule):
    action, cert, state = redemption_case()
    position = state.positions["LOT_A"].model_copy(update=change)
    state = state.model_copy(update={"positions": {position.id: position}})
    reject(recertify(action, cert, state), rule)


def test_redemption_cannot_exceed_units_and_negative_net_proceeds_rejected():
    reject(redemption_case(amount=Fraction(100001, 100)), "BAL-AVAILABLE")
    action, cert, state = redemption_case()
    products = [
        state.catalog.products[0].model_copy(update={"redemption_fee_rate": Fraction(2)}),
        *state.catalog.products[1:],
    ]
    state = state.model_copy(
        update={
            "catalog": signed(
                state.catalog.model_copy(update={"products": products}), CATALOG, "bank"
            )
        }
    )
    reject(recertify(action, cert, state), "DOMAIN-STATE")


def test_expired_sales_catalog_and_risk_do_not_lock_mature_existing_assets():
    action, cert, state = redemption_case()
    catalog = state.catalog.model_copy(
        update={"issued_at": "2025-10-16T02:00:00Z", "valid_until": state.now}
    )
    risk = state.risk_assessments["RISK_DEMO"].model_copy(
        update={"issued_at": "2025-10-16T02:00:00Z", "expires_at": state.now}
    )
    state = state.model_copy(
        update={
            "catalog": signed(catalog, CATALOG, "bank"),
            "risk_assessments": {risk.id: signed(risk, RISK, "risk")},
        }
    )
    assert isinstance(check(*recertify(action, cert, state), phase="dispatch"), Accept)
    state = state.model_copy(
        update={"catalog": state.catalog.model_copy(update={"sig": "0" * 128})}
    )
    reject(recertify(action, cert, state), "BIC-CATALOG")


def test_income_query_does_not_use_unsigned_product_projection():
    action, cert, state = redemption_case(kind="investment_income_query")
    state = state.model_copy(
        update={"catalog": state.catalog.model_copy(update={"sig": "0" * 128})}
    )
    reject(recertify(action, cert, state), "BIC-CATALOG")


@pytest.mark.parametrize(
    "answers", [[0] * 4, [0] * 6, [0, 0, 0, 0, True], [0, 0, 0, 0, 5], [0, 0, 0, 0, -1], ["1"] * 5]
)
def test_invalid_questionnaire_answers_rejected_without_coercion(answers):
    _, _, state = investment_case()
    with pytest.raises(ValueError, match="BIC-RISK"):
        risk_score(answers, state)


def test_eligible_boundary_equalities_and_one_cent_balance_edge():
    action, _, state = investment_case(
        pref=preference(amount="100/1", horizon_days=30, max_access_days=0)
    )
    product = state.catalog.products[0].model_copy(update={"max_amount": Fraction(100)})
    account = state.accounts["A_CURRENT"].model_copy(update={"opening_balance": Fraction(100)})
    catalog = signed(state.catalog.model_copy(update={"products": [product]}), CATALOG, "bank")
    state = state.model_copy(
        update={"catalog": catalog, "accounts": {**state.accounts, account.id: account}}
    )
    assert build_best_interest(action, state).candidate_ids == ["P_A"]
    account = account.model_copy(update={"opening_balance": Fraction(9999, 100)})
    state = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
    assert evaluate_investment(action, state).errors == ("BIC-NOFEASIBLE",)
