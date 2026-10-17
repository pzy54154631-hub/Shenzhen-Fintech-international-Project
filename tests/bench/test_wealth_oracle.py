"""Hand-calculated public-spec checks, without importing a trusted selector."""

import ast
from fractions import Fraction
from pathlib import Path

import pytest

from corridor.bench.wealth_oracle import (
    allocation_constraints,
    evaluate_allocation,
    price,
    verify_biac,
    verify_execution,
)
from corridor.crypto.jcs import H
from corridor.crypto.sign import CATALOG, CONTROL, INPUT, RECEIPT, sign
from corridor.schemas.bank import BankReceipt, OperationAuthorization, UserInput
from corridor.schemas.domain import Product
from corridor.sim.fixtures import END, NOW, PRINCIPAL
from corridor.sim.keys import signing_key
from corridor.sim.wealth import allocation_request, make_wealth_state


def changed_product(state, product_id, **changes):
    catalog = state.catalog.model_copy(
        update={
            "products": [
                Product.model_validate({**p.model_dump(mode="python"), **changes})
                if p.id == product_id
                else p
                for p in state.catalog.products
            ]
        }
    )
    catalog = catalog.model_copy(update={"sig": sign(signing_key("bank"), CATALOG, catalog)})
    return state.model_copy(update={"catalog": catalog})


def test_public_default_is_hand_calculated_not_a_kernel_copy():
    result = evaluate_allocation(make_wealth_state(), allocation_request(), principal=PRINCIPAL)
    assert result.constructed and result.violations == ()
    assert result.candidate_ids == ("P_A", "P_B", "P_C", "P_D")
    assert result.allocation == {"P_A": Fraction(5000), "P_C": Fraction(5000)}
    assert result.totals["projected_net"] == 350
    assert result.totals["total_debit"] == 10000
    assert result.totals["liquid_net_principal"] == 0
    assert result.exclusions["P_X"] == ("risk",)
    assert result.exclusions["P_Y"] == ("available_balance", "concentration", "minimum_amount")


@pytest.mark.parametrize(
    "objective,expected",
    [
        ("net_return", ("P_A", "P_C")),
        ("total_fee", ("P_A", "P_C")),
        ("liquidity", ("P_B", "P_D")),
    ],
)
def test_rankings_use_shared_principal_and_objective_then_ascii(objective, expected):
    result = evaluate_allocation(
        make_wealth_state(), allocation_request(objective=objective), principal=PRINCIPAL
    )
    assert tuple(result.rankings[s][0]["product_id"] for s in ("R1", "R2")) == expected
    assert all(
        row["reference_amount"] == 10000 and row["comparison_only"] is True
        for rows in result.rankings.values()
        for row in rows
    )


def test_nonzero_buy_fee_ranking_and_actual_amounts_differ():
    state = changed_product(make_wealth_state(), "P_C", purchase_fee_rate=Fraction(1, 100))
    result = evaluate_allocation(state, allocation_request(), principal=PRINCIPAL)
    first, second = result.rankings["R2"]
    assert first["product_id"] == "P_C"
    assert first["expected_net"] == second["expected_net"] == 300
    assert first["fee_buy"] == 100 and first["gap"] == second["gap"] == 0
    assert result.totals["fee_buy"] == 50
    assert result.totals["total_debit"] == 10050
    assert result.totals["projected_net"] == 300


def test_individual_fee_components_round_up_and_expected_return_stays_exact():
    product = (
        make_wealth_state()
        .catalog.products[0]
        .model_copy(
            update={
                "purchase_fee_rate": Fraction(1, 10000),
                "annual_fee_rate": Fraction(1, 10000),
                "redemption_fee_rate": Fraction(1, 10000),
            }
        )
    )
    result = price(product, Fraction(1, 100), 1)
    assert result["fee_buy"] == result["fee_hold"] == result["fee_sell"] == Fraction(1, 100)
    assert result["total_fee"] == Fraction(3, 100)
    assert result["expected_net"] == Fraction(3, 3650000) - Fraction(3, 100)


def test_liquidity_uses_net_principal_and_excludes_uninvested_cash():
    state = make_wealth_state()
    request = allocation_request(liquidity_amount="5000/1")
    plain = evaluate_allocation(state, request, principal=PRINCIPAL)
    assert plain.allocation == {"P_A": 5000, "P_D": 5000}
    assert plain.totals["projected_net"] == 300
    state = changed_product(
        state,
        "P_D",
        expected_annual_rate=Fraction(1, 25),
        redemption_fee_rate=Fraction(1, 100),
    )
    fees = evaluate_allocation(state, request, principal=PRINCIPAL)
    assert fees.allocation == {"P_B": 5000, "P_D": 5000}
    assert fees.totals["liquid_net_principal"] == 9950
    assert fees.totals["projected_net"] == 250
    assert "ALLOC-LIQ" in allocation_constraints(
        state, request, {"P_A": Fraction(5000), "P_D": Fraction(5000)}, principal=PRINCIPAL
    )


def test_limits_are_per_product_and_candidate_amount_is_not_entire_request():
    state = changed_product(make_wealth_state(), "P_A", max_amount=Fraction(4000))
    result = evaluate_allocation(state, allocation_request(), principal=PRINCIPAL)
    assert "P_A" in result.candidate_ids
    assert result.allocation == {"P_A": 4000, "P_B": 1000, "P_C": 5000}
    errors = allocation_constraints(
        state,
        allocation_request(),
        {"P_A": Fraction(6000), "P_C": Fraction(4000)},
        principal=PRINCIPAL,
    )
    assert "ALLOC-CONC" in errors


def test_policy_signature_and_exact_risk_expiry_fail_closed():
    state = make_wealth_state()
    policy = next(iter(state.allocation_policies.values())).model_copy(update={"sig": "0" * 128})
    bad = state.model_copy(update={"allocation_policies": {policy.id: policy}})
    assert (
        "ALLOC-POLICY"
        in evaluate_allocation(bad, allocation_request(), principal=PRINCIPAL).violations
    )
    risk = state.risk_assessments[state.customers[PRINCIPAL].risk_profile_ref]
    expired = state.model_copy(update={"now": risk.expires_at})
    assert (
        "BIC-RISK"
        in evaluate_allocation(expired, allocation_request(), principal=PRINCIPAL).violations
    )


def test_heuristic_failure_keeps_partial_construction_and_never_claims_impossibility():
    state = changed_product(make_wealth_state(), "P_A", max_amount=Fraction(4000))
    state = changed_product(state, "P_B", max_amount=Fraction(500), min_amount=Fraction(100))
    result = evaluate_allocation(state, allocation_request(), principal=PRINCIPAL)
    assert not result.constructed
    assert "ALLOC-SELECT" in result.violations
    assert result.allocation == {"P_A": 4000, "P_B": 500, "P_C": 5000}
    assert result.message == "No allocation was constructed under this policy and these inputs."


def receipt(product_id="P_A", amount=Fraction(5000), *, key="a" * 64, status="settled"):
    value = BankReceipt.model_validate({
        "receipt_id": "receipt-" + key[:8],
        "intent_key": key,
        "kind": "purchase_product",
        "status": status,
        "executed_at": NOW,
        "sig": "0" * 128,
        "exact_effects": []
        if status != "settled"
        else [
            {
                "effect_type": "debit",
                "object_ref": "A_CURRENT",
                "account_ref": "A_CURRENT",
                "counterparty_ref": product_id,
                "amount": amount,
            },
            {
                "effect_type": "position",
                "object_ref": "position-" + key[:8],
                "field": "position",
                "after": {
                    "id": "position-" + key[:8],
                    "owner": PRINCIPAL,
                    "product_ref": product_id,
                    "principal_amount": str(amount),
                    "units": str(amount),
                    "reserved_units": "0/1",
                    "nav": "1/1",
                    "acquired_at": NOW,
                    "redeemable_at": NOW,
                    "status": "active",
                },
            },
        ],
    })
    return value.model_copy(update={"sig": sign(signing_key("bank"), RECEIPT, value)})


def test_partial_execution_uses_signed_receipts_and_keeps_remaining_cash():
    report = verify_execution(
        make_wealth_state(),
        allocation_request(),
        [receipt(), receipt("P_C", key="b" * 64, status="failed")],
        principal=PRINCIPAL,
        expected_allocation={"P_A": Fraction(5000), "P_C": Fraction(5000)},
        check_authorization=False,
    )
    assert report.status == "partially_executed" and not report.completed
    assert report.allocation == {"P_A": 5000}
    assert report.remaining_cash == 7000
    assert report.settled_count == 1 and report.violations == ()
    assert report.projected_net_delta is None


def test_missing_receipt_and_tampered_signature_cannot_be_reported_as_completion():
    state = make_wealth_state()
    empty = verify_execution(
        state, allocation_request(), [], principal=PRINCIPAL, require_complete=True
    )
    assert not empty.completed and "ALLOC-SUM" in empty.violations
    bad = receipt().model_copy(update={"sig": "0" * 128})
    result = verify_execution(state, allocation_request(), [bad], principal=PRINCIPAL)
    assert "BANK-RECEIPT" in result.violations and result.settled_count == 0


def test_duplicate_receipt_is_not_counted_as_another_bank_execution():
    one = receipt()
    result = verify_execution(
        make_wealth_state(),
        allocation_request(),
        [one, one],
        principal=PRINCIPAL,
        check_authorization=False,
    )
    assert result.settled_count == 1 and result.debit == 5000
    assert "IDEM-DUP" in result.violations


def test_authorization_is_signed_scoped_and_bound_to_input_amount():
    state = make_wealth_state()
    intent = "oracle-child"
    user_input = UserInput.model_validate({
        "id": "input",
        "principal": PRINCIPAL,
        "batch_id": "batch",
        "slot": "amount",
        "value": {"amount": "5000/1", "ccy": "CNY"},
        "scope_id": intent,
        "submitted_at": NOW,
        "sig": "0" * 128,
    })
    user_input = user_input.model_copy(
        update={
            "sig": sign(signing_key("device"), INPUT, user_input),
        }
    )
    auth = OperationAuthorization.model_validate({
        "id": "auth",
        "principal": PRINCIPAL,
        "intent_id": intent,
        "allowed_kind": "purchase_product",
        "object_refs": ["A_CURRENT", "P_A"],
        "amount_bound": "5000/1",
        "expires_at": END,
        "input_hashes": [H(user_input)],
        "sig": "0" * 128,
    })
    auth = auth.model_copy(update={"sig": sign(signing_key("device"), CONTROL, auth)})
    key = H({"principal": PRINCIPAL, "intent_id": intent, "kind": "purchase_product"})
    result = verify_execution(
        state,
        allocation_request(),
        [receipt(key=key)],
        principal=PRINCIPAL,
        authorizations=[auth],
        inputs=[user_input],
    )
    assert "AUTH-SCOPE" not in result.violations
    wrong = auth.model_copy(update={"amount_bound": Fraction(4999)})
    wrong = wrong.model_copy(update={"sig": sign(signing_key("device"), CONTROL, wrong)})
    rejected = verify_execution(
        state,
        allocation_request(),
        [receipt(key=key)],
        principal=PRINCIPAL,
        authorizations=[wrong],
        inputs=[user_input],
    )
    assert "AUTH-SCOPE" in rejected.violations


def test_oracle_imports_no_trusted_algorithms():
    path = Path(__file__).resolve().parents[2] / "src/corridor/bench/wealth_oracle.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not any(
                part in (node.module or "").split(".") for part in ("kernel", "stores", "gateway")
            )
    assert ".checks" not in source


def test_real_biac_and_economic_mutations_do_not_trust_constraint_booleans():
    # The production implementation is only invoked as a black-box test subject.
    # The oracle module has no import of its algorithms or results.
    from corridor.bench.wealth_cases import allocation_case

    action, certificate, state = allocation_case()
    biac = certificate.allocation
    assert biac is not None
    request = allocation_request()
    assert verify_biac(state, request, biac, principal=PRINCIPAL) == ()
    mutations = [
        (biac.model_copy(update={"candidate_ids": ["P_B", "P_C", "P_D"]}), "BIC-COMPLETE"),
        (
            biac.model_copy(
                update={
                    "allocation": [
                        biac.allocation[0].model_copy(update={"principal": Fraction(6000)}),
                        biac.allocation[1],
                    ]
                }
            ),
            "ALLOC-CONC",
        ),
        (
            biac.model_copy(
                update={
                    "allocation": [
                        biac.allocation[0].model_copy(update={"fee_buy": Fraction(1)}),
                        biac.allocation[1],
                    ]
                }
            ),
            "BIC-SCORE",
        ),
        (
            biac.model_copy(
                update={
                    "allocation": [
                        biac.allocation[0].model_copy(update={"product_id": "P_X", "sleeve": "R3"}),
                        biac.allocation[1],
                    ]
                }
            ),
            "BIC-RISK",
        ),
        (
            biac.model_copy(
                update={
                    "sleeves": [
                        biac.sleeves[0].model_copy(update={"model_weight": Fraction(3, 5)}),
                        *biac.sleeves[1:],
                    ]
                }
            ),
            "ALLOC-SELECT",
        ),
        (
            biac.model_copy(
                update={
                    "allocation": [
                        biac.allocation[0].model_copy(update={"selection_reason": "explicit_item"}),
                        biac.allocation[1],
                    ]
                }
            ),
            "ALLOC-SELECT",
        ),
    ]
    for mutated, expected_rule in mutations:
        assert expected_rule in verify_biac(state, request, mutated, principal=PRINCIPAL)
    assert "BIC-PREFERENCE" in verify_biac(
        state,
        request,
        biac,
        principal=PRINCIPAL,
        request_scope_id=action.intent_id + "wrong",
    )


def test_deterministic_90_case_differential_sweep_includes_both_outcomes():
    from corridor.bench.wealth_cases import allocation_case
    from corridor.kernel.allocation import evaluate_allocation as production_evaluate

    counts = {"constructed": 0, "construction_failed": 0}
    for amount in (
        Fraction(200),
        Fraction(1000),
        Fraction(10000),
        Fraction(1000001, 100),
        Fraction(11999),
    ):
        for fee in (Fraction(), Fraction(1, 10000), Fraction(1, 100)):
            for liquidity in (Fraction(), Fraction(int(amount * 50), 100), amount):
                for horizon in (30, 365):
                    state = changed_product(
                        make_wealth_state(),
                        "P_C",
                        purchase_fee_rate=fee,
                    )
                    state = changed_product(state, "P_D", redemption_fee_rate=fee)
                    request = allocation_request(
                        amount=amount,
                        liquidity_amount=liquidity,
                        horizon_days=horizon,
                    )
                    action, _, state = allocation_case(request=request, state=state, build=False)
                    independent = evaluate_allocation(state, request, principal=PRINCIPAL)
                    production = production_evaluate(
                        PRINCIPAL,
                        action.intent_id,
                        action.args.request_ref,
                        state,
                    )
                    context = (amount, fee, liquidity, horizon)
                    if production.certificate is None:
                        counts["construction_failed"] += 1
                        assert not independent.constructed, context
                        assert production.failure is not None, context
                        assert independent.message.startswith("No allocation was constructed"), (
                            context
                        )
                    else:
                        counts["constructed"] += 1
                        assert independent.constructed, (context, independent.violations)
                        assert (
                            verify_biac(
                                state,
                                request,
                                production.certificate,
                                principal=PRINCIPAL,
                            )
                            == ()
                        ), context
    assert sum(counts.values()) == 90
    assert counts["constructed"] > 0 and counts["construction_failed"] > 0


def test_nonzero_fee_partial_execution_charges_only_the_settled_leg():
    state = changed_product(make_wealth_state(), "P_A", purchase_fee_rate=Fraction(1, 100))
    paid = receipt()
    charged = paid.model_copy(
        update={
            "exact_effects": [
                paid.exact_effects[0].model_copy(update={"amount": Fraction(5050)}),
                paid.exact_effects[1],
            ]
        }
    )
    charged = charged.model_copy(update={"sig": sign(signing_key("bank"), RECEIPT, charged)})
    result = verify_execution(
        state,
        allocation_request(),
        [charged, receipt("P_C", key="b" * 64, status="failed")],
        principal=PRINCIPAL,
        check_authorization=False,
    )
    assert result.status == "partially_executed"
    assert result.debit == 5050 and result.remaining_cash == 6950
    assert result.violations == () and result.projected_net_delta is None


def test_malformed_signed_receipt_cannot_hide_confirmed_debits():
    paid = receipt()
    paid = paid.model_copy(
        update={
            "exact_effects": [
                *paid.exact_effects,
                paid.exact_effects[0].model_copy(update={"amount": Fraction(50)}),
            ]
        }
    )
    paid = paid.model_copy(update={"sig": sign(signing_key("bank"), RECEIPT, paid)})
    result = verify_execution(
        make_wealth_state(),
        allocation_request(),
        [paid],
        principal=PRINCIPAL,
        check_authorization=False,
    )
    assert "BANK-RECEIPT" in result.violations
    assert result.debit == 5050 and result.remaining_cash == 6950
    assert not result.completed


def test_full_unauthorized_execution_is_reported_with_actual_effects():
    result = verify_execution(
        make_wealth_state(),
        allocation_request(),
        [receipt(), receipt("P_C", key="b" * 64)],
        principal=PRINCIPAL,
    )
    assert result.status == "executed_with_violations"
    assert "AUTH-SCOPE" in result.violations
    assert result.debit == 10000 and result.allocation == {"P_A": 5000, "P_C": 5000}
    assert not result.completed


def test_certificate_derived_expected_vector_cannot_override_independent_selection():
    selected = {"P_B": Fraction(5000), "P_C": Fraction(5000)}
    result = verify_execution(
        make_wealth_state(),
        allocation_request(),
        [receipt("P_B"), receipt("P_C", key="b" * 64)],
        principal=PRINCIPAL,
        expected_allocation=selected,
        check_authorization=False,
    )
    assert result.allocation == selected
    assert "ALLOC-SELECT" in result.violations
    assert result.projected_net_delta == -50
