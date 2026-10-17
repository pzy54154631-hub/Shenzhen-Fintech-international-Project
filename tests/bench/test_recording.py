"""Replay has no transport and all Lane E modes share a conservative call ceiling."""

import socket

import pytest

from corridor.agent.llm import BudgetExceeded, LLMClient
from corridor.bench.recording import LaneRecordingClient, network_disabled, observation_hash
from corridor.crypto.jcs import jcs_bytes


def test_network_disabled_blocks_low_level_connection():
    with network_disabled(), pytest.raises(RuntimeError, match="Network is disabled"):
        socket.create_connection(("example.invalid", 443))


def test_lane_and_blind_limits_persist_across_clients(tmp_path, monkeypatch):
    path = tmp_path / "budget.json"
    path.write_bytes(
        jcs_bytes({"schema_version": "lane-e-budget-v1", "attempts": 249, "groups": {"blind": 249}})
    )
    monkeypatch.setattr(LLMClient, "_live", lambda *args: {"ok": True})
    client = LaneRecordingClient(mode="scripted", budget_path=path, budget_group="blind")
    assert client._live({}, {}, {}) == {"ok": True}
    second = LaneRecordingClient(mode="scripted", budget_path=path, budget_group="blind")
    with pytest.raises(BudgetExceeded):
        second._live({}, {}, {})
    path.write_bytes(
        jcs_bytes({
            "schema_version": "lane-e-budget-v1",
            "attempts": 1200,
            "groups": {"blind": 250},
        })
    )
    third = LaneRecordingClient(mode="scripted", budget_path=path, budget_group="record")
    with pytest.raises(BudgetExceeded):
        third._live({}, {}, {})


def test_observation_hash_ignores_only_provenance():
    assert observation_hash({"passed": True, "sources": ["live-recorded"]}) == observation_hash({
        "passed": True,
        "sources": ["replay"],
    })
    assert observation_hash({"passed": False}) != observation_hash({"passed": True})
