"""Development attacks and their paired controls execute real security paths."""

from collections import Counter
from dataclasses import replace

import pytest

from corridor.bench.adversary import development_cases, execute_case, run_differential
from corridor.kernel.rules import RULES


def test_development_attack_inventory_is_frozen_and_disjoint_from_judge():
    cases = development_cases()
    assert len(cases) == 40
    assert len({case.case_id for case in cases}) == 40
    assert set(Counter(case.family for case in cases).values()) == {5}
    assert len({case.family for case in cases}) == 8
    assert all(not case.case_id.startswith("J") for case in cases)
    assert all(case.expected_rule in RULES for case in cases)


@pytest.mark.parametrize("spec", development_cases(), ids=lambda case: case.case_id)
def test_attack_and_its_benign_twin_have_exact_rules_and_independent_effects(spec, monkeypatch):
    def forbidden_llm(*args, **kwargs):
        pytest.fail("Byzantine attacks must never call a planner or LLM")

    monkeypatch.setattr("corridor.agent.llm.LLMClient.complete", forbidden_llm)
    attack = execute_case(spec)
    twin = execute_case(spec, benign=True)
    assert attack["passed"], attack
    assert attack["expected_rule"] in attack["rule_ids"]
    assert attack["prohibited_effects"] == 0
    assert attack["oracle"]["task_complete"] is True
    assert twin["passed"], twin
    assert twin["completed"] is True
    assert twin["oracle"]["task_complete"] is True
    assert attack["llm_calls"] == twin["llm_calls"] == 0


@pytest.mark.rule("SBX-SYNTAX")
def test_sandbox_attack_reaches_real_interpreter_and_benign_control_completes():
    spec = next(case for case in development_cases() if case.attack == "sandbox_import")
    assert "SBX-SYNTAX" in execute_case(spec)["rule_ids"]
    assert execute_case(spec, benign=True)["completed"]


def test_wrong_rule_expectation_fails_contract_without_inventing_a_bank_violation():
    spec = replace(development_cases()[0], expected_rule="APR-REQUIRED")
    result = execute_case(spec)
    assert not result["passed"]
    assert not result["oracle_violation"]
    assert not result["oracle_indeterminate"]
    assert result["prohibited_effects"] == 0


def test_thousand_valid_differential_mutations_include_accepts_in_every_family():
    result = run_differential()
    assert result["valid_samples"] == 1000
    assert result["accepted"] >= 200
    assert result["disagreements"] == 0
    assert len(result["families"]) == 8
    assert all(value["valid_samples"] == 125 for value in result["families"].values())
    assert all(value["accepted"] > 0 for value in result["families"].values())
