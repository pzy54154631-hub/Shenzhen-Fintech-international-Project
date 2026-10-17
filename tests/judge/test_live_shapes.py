"""Every J mechanism call declares the exact structured output it consumes."""

from types import SimpleNamespace

import pytest

from corridor.agent.llm import LLMClient
from corridor.bench import (
    billing_runner,
    investment_runner,
    judge_runner,
    planning_runner,
    sandbox_runner,
    security_runner,
    transfer_runner,
)
from corridor.schemas.base import loads_exact
from corridor.sim.fixtures import make_state


class Captured(Exception):
    pass


class ShapeClient:
    def __init__(self, *, invalid=False, capture_only=False):
        self.calls = []
        self.invalid = invalid
        self.capture_only = capture_only

    def complete(self, **kwargs):
        expected = kwargs["scripted"]()
        schema = kwargs["prompt"].get("response_schema")
        assert schema is not None, "Live provider was not given the consumed output shape"
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert set(schema["properties"]) == set(schema["required"]) == set(expected)
        for key, value in expected.items():
            field = schema["properties"][key]
            assert field["type"] == "string"
            if key != "program":
                assert field["enum"] == [value]
        if self.capture_only:
            raise Captured
        return SimpleNamespace(output={} if self.invalid else expected)


def case():
    return SimpleNamespace(
        task_id="J02",
        subcase_id="shape_probe",
        device=SimpleNamespace(principal="C_DEMO"),
        state=make_state(),
    )


@pytest.mark.parametrize(
    "module,kind",
    [
        (billing_runner, "bill_analyze"),
        (investment_runner, "product_compare"),
        (planning_runner, "spa_create"),
    ],
)
def test_plan_shape_exactly_matches_validated_handles(module, kind):
    module._plan(ShapeClient(), case(), kind)
    with pytest.raises(ValueError):
        module._plan(ShapeClient(invalid=True), case(), kind)


def test_j02_scenario_call_requires_scenario_object():
    run = judge_runner.JudgeRun("J02", ShapeClient(), None)
    assert run.case("ambiguity").subcase_id == "ambiguity"
    run = judge_runner.JudgeRun("J02", ShapeClient(invalid=True), None)
    with pytest.raises(ValueError, match="Unsupported judge scenario proposal"):
        run.case("ambiguity")


def test_security_intent_shape_is_supplied_before_any_mechanism():
    with pytest.raises(Captured):
        security_runner.run_security("J21", client=ShapeClient(capture_only=True))
    with pytest.raises(ValueError, match="Unexpected security intent"):
        security_runner.run_security("J21", client=ShapeClient(invalid=True))


def test_sandbox_program_shape_preserves_existing_parser_boundary():
    program = 'result = {"count": count(dataset)}'
    assert (
        sandbox_runner._program(ShapeClient(), case(), "Count rows", program, result_keys=["count"])
        == program
    )
    with pytest.raises(ValueError, match="restricted analysis program"):
        sandbox_runner._program(
            ShapeClient(invalid=True), case(), "Count rows", program, result_keys=["count"]
        )


def test_sandbox_prompt_declares_bound_dataset_signatures_and_output_labels():
    class ContractClient(ShapeClient):
        def complete(self, **kwargs):
            prompt = kwargs["prompt"]
            assert prompt["dataset_variable"] == "dataset"
            assert prompt["function_signatures"]["filter_rows"] == (
                "filter_rows(rows, field, operator, expected) -> rows"
            )
            assert prompt["function_signatures"]["count"] == "count(rows) -> integer"
            assert prompt["result_keys"] == ["sum", "count"]
            assert "positional" in prompt["language"]
            assert "A_CURRENT:2026-09" not in str(prompt)
            assert "never forward this scripted answer" not in str(prompt)
            return super().complete(**kwargs)

    sandbox_runner._program(
        ContractClient(),
        case(),
        "Calculate sum and count for an absent category.",
        "never forward this scripted answer",
        result_keys=["sum", "count"],
    )


def test_shared_client_keeps_only_each_task_calls_and_freezes_prior_reports(tmp_path):
    client = LLMClient(mode="scripted", env_file=None)
    prior = []
    for index, task in enumerate(("J01", "J07", "J02", "J22", "J01")):
        root = tmp_path / str(index)
        start = len(client.calls)
        if task == "J01":
            result = transfer_runner.run_j01(client, root)
        elif task == "J07":
            result = billing_runner.run_billing(task, client=client, evidence_dir=root)
        elif task == "J22":
            result = security_runner.run_security(task, client=client, evidence_dir=root)
        else:
            result = judge_runner.run_completion(task, client=client, evidence_dir=root)
        assert result["passed"]
        scoped = client.calls[start:]
        assert scoped
        assert result["llm_calls"] == scoped
        assert loads_exact((root / "result.json").read_bytes())["llm_calls"] == scoped
        for previous, saved in prior:
            assert previous["llm_calls"] == saved, "Later calls mutated an earlier report"
        prior.append((result, list(scoped)))
