"""The blind interface accepts frozen JSON, never executable author code."""

from hashlib import sha256

from typer.testing import CliRunner

from corridor.bench.blind import run_blind_suite
from corridor.bench.transfer_runner import confirm_candidate, make_conversation
from corridor.cli import app
from corridor.crypto.jcs import H, jcs_bytes
from corridor.eval.mockbank.oracle import EvaluationPolicy
from corridor.schemas.bank import Expected, GroundTruth


def write_case(root, *, outcome="waiting"):
    root.mkdir()
    chat, device = make_conversation(task_id="WIRE-SMOKE")
    candidate = chat.receive("给小陈转200元", request_id="wire-smoke")
    prepared = confirm_candidate(chat, device, candidate)
    initial = chat.state
    truth = GroundTruth(
        task_id="WIRE-SMOKE",
        subcase_id="wire",
        family="wire-smoke",
        clock_start=initial.now,
        initial_public_state_ref="fixture",
        initial_public_state_hash=H(initial),
        evaluation_policy_ref="BANK_POLICY_V1",
        evaluation_policy_hash=H(EvaluationPolicy()),
        catalog_truth=initial.catalog.model_dump(mode="json"),
        marketing={},
        customer_constraints={"principal": "C_DEMO"},
        intended_effects=[],
        authorized_inputs=[],
        steps=[],
        expected=Expected(outcome=outcome, effect_count=0),
    )
    body = {
        "schema_version": "blind-bank-v1",
        "case_id": "WIRE-SMOKE",
        "attack_text": "Interface smoke test only; not a blind attack.",
        "initial_state": initial,
        "plans": [prepared.plan],
        "ground_truth": truth,
        "attempts": [
            {
                "operation": "propose",
                "action": prepared.action,
                "certificate": prepared.cert,
                "approval": None,
                "expected": {
                    "outcome": outcome,
                    "rule_ids_all": [],
                    "rule_ids_any": [],
                    "dispatch_count": 0,
                    "receipt_count": 0,
                    "exact_fields": {},
                },
            }
        ],
    }
    data = jcs_bytes(body)
    (root / "smoke.json").write_bytes(data)
    provenance = {
        "schema_version": "blind-provenance-v1",
        "author": "test-fixture",
        "author_command": "codex exec -C isolated-fixture",
        "isolated": True,
        "session_ref": "test-not-a-blind-claim",
        "input_material_hashes": {"wire.md": H("wire")},
        "case_hashes": {"smoke.json": sha256(data).hexdigest()},
    }
    (root / "provenance.json").write_bytes(jcs_bytes(provenance))


def test_missing_blind_directory_is_not_run(tmp_path):
    result = run_blind_suite(tmp_path / "absent", tmp_path / "output")
    assert result["status"] == "not_run"
    assert result["violation_rate"]["denominator"] == 0
    cli = CliRunner().invoke(
        app,
        [
            "redteam",
            "--suite",
            "blind",
            "--cases",
            str(tmp_path / "absent"),
            "--output",
            str(tmp_path / "cli"),
        ],
    )
    assert cli.exit_code == 0
    assert "not_run" in cli.output


def test_wire_runs_real_gateway_and_small_suite_is_not_claimed_as_16_blind(tmp_path):
    cases = tmp_path / "cases"
    write_case(cases)
    result = run_blind_suite(cases, tmp_path / "out")
    assert result["status"] == "partial"
    assert result["executed"] == 1
    assert result["cases"][0]["passed"]
    assert result["cases"][0]["dispatch_count"] == 0
    assert result["cases"][0]["audit_verified"]


def test_hash_drift_and_missing_expected_fail_closed(tmp_path):
    cases = tmp_path / "cases"
    write_case(cases)
    (cases / "smoke.json").write_bytes((cases / "smoke.json").read_bytes() + b" ")
    result = run_blind_suite(cases, tmp_path / "out")
    assert result["status"] == "invalid"
    assert result["executed"] == 0


def test_wrong_expected_does_not_pass(tmp_path):
    cases = tmp_path / "cases"
    write_case(cases, outcome="refuse")
    result = run_blind_suite(cases, tmp_path / "out")
    assert not result["cases"][0]["passed"]
