"""The W04 smoke genuinely compares and optionally executes through W2."""

import pytest

from corridor.agent.llm import LLMClient, LLMResult
from corridor.bench.wealth_smoke import run_w04
from corridor.schemas.base import loads_exact


def test_w04_scripted_smoke_has_two_real_mfa_purchases_and_evidence(tmp_path):
    result = run_w04(LLMClient(mode="scripted"), evidence_dir=tmp_path)
    assert result["passed"], result
    assert result["sources"] == ["scripted"] * 3
    assert result["api_calls"] == 0
    assert len(result["llm_calls"]) == 3
    assert result["purchase_dispatches"] == 2
    assert len(set(result["purchase_receipt_ids"])) == 2
    assert len(set(result["mfa_grant_ids"])) == 2
    assert result["before_user_confirmation_purchases"] == 0
    assert result["before_item_approval_purchases"] == 0
    assert result["principal"] == "10000/1"
    assert result["buy_fees"] == "0/1"
    assert result["projected_net"] == "350/1"
    assert result["balance"] == "2000/1"
    assert result["execution_status"] == "completed"
    assert loads_exact((tmp_path / "result.json").read_bytes())["passed"]
    manifest = loads_exact((tmp_path / "manifest.json").read_bytes())
    assert len(manifest["code_hash"]) == 64
    assert manifest["sources"] == ["scripted"] * 3
    assert manifest["model_profile"]["model"] == "scripted-bank-v1"
    assert manifest["model_profile"]["api"] in {"chat", "responses"}
    assert (tmp_path / "audit.jsonl").read_bytes()
    assert len(list((tmp_path / "pdr").glob("*.json"))) >= 2


def test_w04_comparison_only_does_not_create_purchase_authority():
    result = run_w04(LLMClient(mode="scripted"), execute=False)
    assert result["passed"], result
    assert result["purchase_dispatches"] == 0
    assert result["mfa_grant_ids"] == []
    assert result["purchase_receipt_ids"] == []
    assert result["balance"] == "12000/1"
    assert result["execution_status"] == "comparison_only"


@pytest.mark.parametrize(
    ("mode", "source", "passed"),
    [
        ("record", "live-recorded", True),
        ("record", "live", False),
        ("live", "live", True),
        ("live", "scripted", False),
    ],
)
def test_w04_requires_mode_specific_live_provenance(monkeypatch, mode, source, passed):
    client = LLMClient(mode="scripted", env_file=None)
    client.mode = mode

    def transport_fixture(**kwargs):
        # This local transport fixture tests provenance classification only.
        client.calls.append({"source": source})
        return LLMResult(kwargs["scripted"](), source, "test-provenance")

    monkeypatch.setattr(client, "complete", transport_fixture)
    result = run_w04(client, execute=False)
    assert result["passed"] is passed
    assert result["sources"] == [source] * 3
    assert result["api_calls"] == 0
