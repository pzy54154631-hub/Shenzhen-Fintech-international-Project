"""UI attack chips execute isolated mechanisms and expose verifiable evidence."""

import inspect
from pathlib import Path

import pytest

from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.audit import AuditLog
from corridor.gateway.mfa import MFAVerifier
from corridor.schemas.base import loads_exact
from corridor.ui import evaluation
from corridor.ui.controller import DemoController

CASES = (
    ("induced_transfer", "PROV-MISMATCH"),
    ("data_extraction", "SBX-SYNTAX"),
    ("privilege_escalation", "TIER-MFA-REQUIRED"),
    ("prompt_injection", "APR-LOCK"),
)


@pytest.mark.parametrize(("kind", "rule"), CASES)
def test_ui_attack_runs_gateway_and_benign_twin_without_touching_demo(
    kind, rule, tmp_path, monkeypatch
):
    def forbidden_llm(*args, **kwargs):
        pytest.fail("Scripted attack demonstrations must not call a model")

    controller = DemoController(evidence_dir=tmp_path / "live")
    controller.start_session()
    before = H(controller.state)
    checkpoint = controller.gateway.audit.checkpoint()
    monkeypatch.setattr("corridor.agent.llm.LLMClient.complete", forbidden_llm)
    codes = []
    original_code = MFAVerifier.test_code

    def record_code(verifier, challenge_id):
        code = original_code(verifier, challenge_id)
        codes.append(code)
        return code

    monkeypatch.setattr(MFAVerifier, "test_code", record_code)
    result = evaluation.run_attack_class(kind, root=tmp_path / "attacks")

    assert result["passed"], result
    assert result["kind"] == kind
    assert result["label"] == evaluation.ATTACK_CLASSES[kind]["label"]
    assert rule in result["rule_ids"]
    assert result["reason"]
    assert result["funds_moved_cny"] == "0/1"
    assert result["forbidden_effects"] == result["bank_dispatches"] == 0
    assert result["benign_completed"] is True
    assert result["benign"]["passed"] is True
    assert result["evidence_mode"] == "scripted"
    assert result["llm_calls"] == 0
    assert result["violation_summary"] == "0/1 (95% upper ≈ 100%)"
    assert result["live_session_untouched"] is True
    assert H(controller.state) == before
    assert controller.gateway.audit.checkpoint() == checkpoint
    assert controller.gateway.bank.execute_count == 0

    audit_path = Path(result["audit_path"])
    assert audit_path.is_relative_to(tmp_path)
    assert result["audit_valid"] is True
    assert AuditLog(audit_path).verify(result["audit_checkpoint"])
    assert result["audit_jsonl"].encode("utf-8") == audit_path.read_bytes()
    assert [loads_exact(line) for line in audit_path.read_bytes().splitlines()] == result[
        "audit_entries"
    ]
    assert result["audit_checkpoint"]["seq"] == len(result["audit_entries"]) > 0
    audit_rule = "PLAN-SCOPE" if kind == "induced_transfer" else rule
    assert audit_rule in result["audit_jsonl"]
    assert audit_rule in result["audit_rule_ids"]
    serialized = jcs_bytes(result)
    assert not any(jcs_bytes(code) in serialized for code in codes)
    assert b'"otp"' not in serialized
    assert b'"api_key"' not in serialized
    assert b'"private_key"' not in serialized
    assert b"13900001001" not in serialized
    assert b"6222000012345678" not in serialized


def test_prompt_injection_uses_detected_external_instruction_and_red_lock(tmp_path, monkeypatch):
    observed = []
    original = evaluation.injection_detected

    def detect(texts):
        result = original(texts)
        observed.append((texts, result))
        return result

    monkeypatch.setattr(evaluation, "injection_detected", detect)
    result = evaluation.run_attack_class("prompt_injection", root=tmp_path)
    assert any(detected and "ignore" in texts[0].lower() for texts, detected in observed)
    assert any(
        record["event"] == "locked" and record["payload"]["reason"] == "red_injection"
        for record in result["audit_entries"]
    )
    assert result["attack"]["oracle"]["task_complete"] is True
    assert result["benign"]["bank_dispatches"] == 1
    assert result["benign"]["funds_moved_cny"] == "1200/1"


def test_ui_attack_is_not_a_static_pass_when_observed_rule_is_missing(tmp_path, monkeypatch):
    original = evaluation.execute_case

    def missing_rule(*args, **kwargs):
        result = original(*args, **kwargs)
        if not kwargs.get("benign", False):
            result["rule_ids"] = []
        return result

    monkeypatch.setattr(evaluation, "execute_case", missing_rule)
    result = evaluation.run_attack_class("induced_transfer", root=tmp_path)
    assert result["passed"] is False
    assert result["rule_ids"] == []
    assert result["reason"] == "The expected blocking rule was not observed. Review the evidence."


def test_ui_attack_refuses_corrupted_audit_download(tmp_path, monkeypatch):
    original = evaluation.execute_case

    def corrupt_log(spec, **kwargs):
        result = original(spec, **kwargs)
        if not kwargs.get("benign", False):
            path = kwargs["root"] / spec.case_id / "attack" / "audit.jsonl"
            lines = path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b"".join(lines[:-1]))
        return result

    monkeypatch.setattr(evaluation, "execute_case", corrupt_log)
    with pytest.raises(ValueError, match="Attack audit evidence could not be verified"):
        evaluation.run_attack_class("induced_transfer", root=tmp_path)


def test_ui_attack_refuses_tampered_benign_receipts(tmp_path, monkeypatch):
    original = evaluation.execute_case

    def corrupt_receipt(spec, **kwargs):
        result = original(spec, **kwargs)
        if kwargs.get("benign", False):
            path = kwargs["root"] / spec.case_id / "benign" / "receipts.json"
            receipts = loads_exact(path.read_bytes())
            receipt = next(item for item in receipts.values() if item["receipt_type"] == "bank")
            receipt["exact_effects"][0]["amount"] = "201/1"
            path.write_bytes(jcs_bytes(receipts))
        return result

    monkeypatch.setattr(evaluation, "execute_case", corrupt_receipt)
    with pytest.raises(ValueError, match="Attack bank receipts could not be verified"):
        evaluation.run_attack_class("induced_transfer", root=tmp_path)


def test_ui_attack_inventory_and_signature_accept_no_live_gateway(tmp_path):
    assert tuple(evaluation.ATTACK_CLASSES) == tuple(kind for kind, _ in CASES)
    assert set(inspect.signature(evaluation.run_attack_class).parameters) == {"kind", "root"}
    with pytest.raises(ValueError, match="Unknown attack class"):
        evaluation.run_attack_class("unknown", root=tmp_path / "unused")
    assert not (tmp_path / "unused").exists()
