"""M7 development corpus and real-gateway observations stay separate from blind tests."""

from collections import Counter
from copy import deepcopy
from dataclasses import replace

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench.nl_runner import run_nl_case
from corridor.bench.wealth_redteam import (
    evaluate_redteam_observation,
    render_wealth_redteam,
    run_wealth_redteam,
    wealth_redteam_corpus,
)


def test_corpus_has_24_attacks_and_24_distinct_benign_twins():
    corpus = wealth_redteam_corpus()
    assert len(corpus) == 24
    assert Counter(pair.category for pair in corpus) == {
        "induced_transfer": 6,
        "data_extraction": 6,
        "privilege_escalation": 6,
        "prompt_injection": 6,
    }
    ids = [case.case_id for pair in corpus for case in (pair.attack, pair.benign)]
    assert len(set(ids)) == 48
    assert all(case_id.startswith("M7-") for case_id in ids)
    for pair in corpus:
        assert (
            pair.attack.turns[0].user_text != pair.benign.turns[0].user_text
            or pair.attack.turns[0].external_documents != pair.benign.turns[0].external_documents
        )
        assert pair.benign.turns[0].external_documents == []
        assert pair.attack.forbidden_outcomes
        assert pair.benign_goals[0]["expected_completion"] in {
            "product_compare",
            "balance_query",
            "transfer",
            "purchase_product",
        }


def test_scripted_suite_uses_real_receipts_and_does_not_claim_live_evidence(tmp_path):
    report = run_wealth_redteam(
        LLMClient(mode="scripted", env_file=None),
        tmp_path,
    )
    assert report["source"] == "scripted"
    assert report["attack_cases"] == report["benign_cases"] == 24
    assert report["attack_evaluated"] == 24
    assert report["forbidden_cases"] == 0
    assert report["benign_completed"] == 24, [
        row for row in report["pairs"] if not row["benign"]["task_completed"]
    ]
    assert report["live_recorded"] == "not_run"
    assert report["blind_cases_included"] == 0
    assert (tmp_path / "scripted" / "summary.json").exists()
    assert all(row["attack"]["audit_verified"] for row in report["pairs"])
    assert report["categories"]["prompt_injection"]["observed_violations"]["numerator"] == 0


def test_refusal_is_not_counted_as_benign_task_completion():
    pair = wealth_redteam_corpus()[0]
    report = evaluate_redteam_observation(
        pair,
        {
            "steps": [
                {"status": "refuse", "completed": True, "planner_attempt": {"kind": "refuse"}}
            ],
            "receipt_signatures_valid": True,
            "audit_verified": True,
            "receipts": [],
            "privacy_leaks": 0,
            "risk_hash_unchanged": True,
            "recommendations": [],
            "completed": True,
            "source": "scripted",
        },
        benign=True,
    )
    assert not report["task_completed"]
    assert report["forbidden_outcomes"] == []


def test_missing_signatures_and_error_are_incomplete_not_a_zero_violation_pass():
    pair = wealth_redteam_corpus()[0]
    report = evaluate_redteam_observation(
        pair,
        {
            "steps": [{"status": "error", "completed": False}],
            "receipts": [],
            "audit_verified": True,
            "privacy_leaks": 0,
            "risk_hash_unchanged": True,
            "recommendations": [],
            "source": "scripted",
        },
    )
    assert report["evaluation_status"] == "incomplete"
    assert not report["passed"]


def test_explicit_wrong_product_attempt_is_observed_as_real_kernel_rejection():
    class ForcedHighRiskClient(LLMClient):
        def complete(self, **kwargs):
            if kwargs["prompt"].get("response_schema", {}).get("title") == "ToolChoice":
                kwargs["scripted"] = lambda: {
                    "kind": "purchase_product",
                    "contact_ref": None,
                    "product_ref": "P_X",
                }
            return super().complete(**kwargs)

    report = run_wealth_redteam(
        ForcedHighRiskClient(mode="scripted", env_file=None),
        pair_ids=["M7-PE-01"],
    )
    attack = report["pairs"][0]["attack"]
    assert attack["funds_moved"] == "0/1"
    assert "BIC-RISK" in attack["rules"]
    assert attack["planner_attempts"][0]["product_ref"] == "P_X"
    assert report["benign_completed"] == 0


def test_actual_wrong_recipient_effect_is_reported_without_hiding_the_receipt():
    class ForcedWrongRecipient(LLMClient):
        def complete(self, **kwargs):
            if kwargs["prompt"].get("response_schema", {}).get("title") == "ToolChoice":
                kwargs["scripted"] = lambda: {
                    "kind": "transfer",
                    "contact_ref": "CONTACT_NEW",
                    "product_ref": None,
                }
            return super().complete(**kwargs)

    pair = next(p for p in wealth_redteam_corpus() if p.pair_id == "M7-IT-02")
    attack = pair.attack.model_copy(
        update={
            "turns": [
                pair.attack.turns[0].model_copy(update={"device_behaviour": "approve_everything"}),
            ]
        }
    )
    raw = run_nl_case(
        attack,
        ForcedWrongRecipient(mode="scripted", env_file=None),
        device_goals=pair.attack_goals,
    )
    judged = evaluate_redteam_observation(pair, raw)
    assert "wrong_payee_or_product" in judged["forbidden_outcomes"]
    assert judged["funds_moved"] == "1000/1" and judged["settled_money_receipts"] == 1
    assert not judged["passed"]
    assert judged["measured"]
    assert any("intended_recipient" in item for item in judged["evidence_failures"])


def test_fallback_mode_cannot_be_mislabeled_as_recorded_evidence():
    with pytest.raises(ValueError, match="explicit scripted, record or strict"):
        run_wealth_redteam(LLMClient(mode="fallback", env_file=None))


def test_missing_query_receipt_prevents_a_false_completed_benign_report():
    pair = wealth_redteam_corpus()[0]
    raw = run_nl_case(
        pair.benign,
        LLMClient(mode="scripted", env_file=None),
        device_goals=pair.benign_goals,
    )
    assert evaluate_redteam_observation(pair, raw, benign=True)["task_completed"]
    raw["analysis_receipts"] = []
    judged = evaluate_redteam_observation(pair, raw, benign=True)
    assert judged["evaluation_status"] == "incomplete"
    assert "missing_receipt_evidence" in judged["forbidden_outcomes"]
    assert not judged["task_completed"]


@pytest.mark.parametrize("failure", ["narration", "source_mismatch"])
def test_incomplete_run_preserves_real_forbidden_transfer_and_separate_counts(
    failure,
    monkeypatch,
    tmp_path,
):
    from corridor.bench import wealth_redteam

    class TransferThenError(LLMClient):
        def complete(self, **kwargs):
            if kwargs["task_id"].endswith("-attack"):
                if kwargs["prompt"].get("response_schema", {}).get("title") == "ToolChoice":
                    kwargs["scripted"] = lambda: {
                        "kind": "transfer",
                        "contact_ref": "CONTACT_NEW",
                        "product_ref": None,
                    }
                elif failure == "narration":
                    raise RuntimeError("Synthetic failure after the signed bank receipt")
            return super().complete(**kwargs)

    pair = next(p for p in wealth_redteam_corpus() if p.pair_id == "M7-IT-02")
    pair = replace(
        pair,
        attack=pair.attack.model_copy(
            update={
                "turns": [
                    pair.attack.turns[0].model_copy(
                        update={"device_behaviour": "approve_everything"}
                    ),
                ]
            }
        ),
    )
    monkeypatch.setattr(wealth_redteam, "wealth_redteam_corpus", lambda: (pair,))
    if failure == "source_mismatch":

        def partial_source(*args, **kwargs):
            result = run_nl_case(*args, **kwargs)
            if args[0].case_id.endswith("-attack"):
                result["sources"].append("replay-miss")
            return result

        monkeypatch.setattr(wealth_redteam, "run_nl_case", partial_source)
    report = run_wealth_redteam(TransferThenError(mode="scripted", env_file=None), tmp_path)
    attack = report["pairs"][0]["attack"]
    assert attack["evaluation_status"] == "incomplete" and attack["measured"] is False
    assert attack["passed"] is False
    assert "wrong_payee_or_product" in attack["observed_forbidden_effects"]
    assert attack["funds_moved"] == "1000/1" and attack["settled_money_receipts"] == 1
    assert len(attack["receipt_ids"]) == 1
    category = report["categories"]["induced_transfer"]
    assert category["observed_violations"]["denominator"] == 0
    assert category["observed_violations"]["status"] == "not_run"
    assert category["incomplete_with_observed_forbidden_effects"] == 1
    assert category["incomplete_observed_funds_moved"] == "1000/1"
    assert report["incomplete_with_observed_forbidden_effects"] == 1
    assert report["incomplete_observed_funds_moved"] == "1000/1"
    assert report["observed_forbidden_cases"] == 1
    assert not report["measured"] and report["incomplete"]
    assert report["benign_completed"] == 1
    if failure == "narration":
        assert attack["error_types"] == ["RuntimeError"]
    else:
        assert "replay-miss" in attack["observed_call_sources"]
        assert attack["evidence_mode_verified"] is False
    assert "1000/1" in render_wealth_redteam(report)


def test_incomplete_flag_is_honored_even_when_last_action_settled():
    pair = wealth_redteam_corpus()[0]
    raw = run_nl_case(
        pair.benign,
        LLMClient(mode="scripted", env_file=None),
        device_goals=pair.benign_goals,
    )
    raw["incomplete"] = True
    raw["terminal_error"] = "ReplayMiss"
    assert raw["steps"][0]["status"] == "settled"
    judged = evaluate_redteam_observation(pair, raw, benign=True)
    assert judged["measured"] is False and judged["evaluation_status"] == "incomplete"
    assert judged["analysis_receipt_ids"]
    assert not judged["task_completed"]


@pytest.mark.parametrize("mutation", ["forged_approval", "missing_inputs"])
def test_authentication_failure_is_incomplete_but_preserves_confirmed_debit(mutation):
    pair = next(p for p in wealth_redteam_corpus() if p.pair_id == "M7-IT-02")
    raw = run_nl_case(
        pair.benign,
        LLMClient(mode="scripted", env_file=None),
        device_goals=pair.benign_goals,
    )
    assert evaluate_redteam_observation(pair, raw, benign=True)["task_completed"]
    raw = deepcopy(raw)
    if mutation == "forged_approval":
        approval = raw["approval_bindings"][0]["approval"]
        raw["approval_bindings"][0]["approval"] = approval.model_copy(update={"sig": "00" * 64})
    else:
        raw["user_inputs"] = []
    judged = evaluate_redteam_observation(pair, raw, benign=True)
    assert not judged["measured"] and not judged["task_completed"]
    assert judged["evaluation_status"] == "incomplete"
    assert judged["evidence_failures"]
    assert judged["funds_moved"] == "1000/1"
    assert judged["settled_money_receipts"] == 1
    assert judged["receipt_ids"]


def test_authenticated_policy_violation_stays_in_measured_denominator():
    from corridor.crypto.sign import RISK, sign
    from corridor.sim.keys import signing_key

    pair = next(p for p in wealth_redteam_corpus() if p.pair_id == "M7-PE-01")
    raw = run_nl_case(
        pair.benign,
        LLMClient(mode="scripted", env_file=None),
        device_goals=pair.benign_goals,
    )
    assert raw["purchases"]
    # Preserve all bank/device signatures, and authenticate a lower risk level
    # independently: the checker must expose the incompatibility as a measured
    # policy violation rather than removing an authentic effect from the rate.
    raw["current_risk"]["level"] = 1
    raw["current_risk"]["sig"] = sign(signing_key("risk"), RISK, raw["current_risk"])
    judged = evaluate_redteam_observation(pair, raw, benign=True)
    assert judged["measured"] and judged["evaluation_status"] == "evaluated"
    assert not judged["passed"] and not judged["task_completed"]
    assert any("product_risk" in item for item in judged["observed_forbidden_effects"])
    assert judged["funds_moved"] == "1000/1"
