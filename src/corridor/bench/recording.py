"""Shared recording budgets and a transport-disabled replay verification pass."""

from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch

from corridor.agent.llm import BudgetExceeded, LLMClient
from corridor.crypto.jcs import H, jcs_bytes
from corridor.schemas.base import loads_exact

LANE_CALL_LIMIT = 1200
BLIND_CALL_LIMIT = 250


class LaneRecordingClient(LLMClient):
    """Persist conservative attempts across sequential Lane E recording commands.

    This is an additional ceiling. The underlying llm.py guard still owns API
    credentials, dollar reservation, environment ceilings and the HTTP request.
    The journal is local run state; concurrent recording commands are unsupported.
    """

    def __init__(self, *, budget_path: Path, budget_group: str = "record", **kwargs: Any):
        self.budget_path, self.budget_group = budget_path, budget_group
        super().__init__(**kwargs)

    def _live(self, prompt: Any, tool_state: Any, trace: Any) -> Any:
        ledger = (
            loads_exact(self.budget_path.read_bytes())
            if self.budget_path.exists()
            else {
                "schema_version": "lane-e-budget-v1",
                "attempts": 0,
                "groups": {},
            }
        )
        if ledger.get("schema_version") != "lane-e-budget-v1":
            raise BudgetExceeded("Invalid Lane E budget journal")
        attempts, groups = ledger["attempts"], ledger["groups"]
        if type(attempts) is not int or attempts < 0 or not isinstance(groups, dict):
            raise BudgetExceeded("Invalid Lane E budget journal")
        group_attempts = groups.get(self.budget_group, 0)
        if type(group_attempts) is not int or group_attempts < 0:
            raise BudgetExceeded("Invalid Lane E budget journal")
        if attempts >= LANE_CALL_LIMIT or (
            self.budget_group == "blind" and group_attempts >= BLIND_CALL_LIMIT
        ):
            raise BudgetExceeded("Lane E aggregate call limit reached")
        ledger["attempts"] = attempts + 1
        ledger["groups"][self.budget_group] = group_attempts + 1
        self.budget_path.parent.mkdir(parents=True, exist_ok=True)
        self.budget_path.write_bytes(jcs_bytes(ledger))
        return super()._live(prompt, tool_state, trace)


@contextmanager
def network_disabled():
    """Forbid network transports even if a future strict runner regresses."""

    def denied(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Network is disabled during strict replay")

    with ExitStack() as stack:
        for target in (
            "socket.create_connection",
            "socket.getaddrinfo",
            "socket.socket.connect",
            "socket.socket.connect_ex",
            "httpx.Client.send",
            "httpx.AsyncClient.send",
        ):
            stack.enter_context(patch(target, denied))
        yield


def replay_client(client: LLMClient) -> LLMClient:
    return LLMClient(
        mode="strict",
        replay_dir=client.replay_dir,
        model=client.model,
        config=client.config,
        user_policy=client.user_policy,
        api=client.api,
        reasoning_effort=client.reasoning_effort,
        max_output_tokens=client.max_output_tokens,
        env_file=None,
    )


def observation_hash(result: Any) -> str:
    """Compare deterministic observations while keeping provenance outside the hash."""
    excluded = {
        "llm_calls",
        "api_calls",
        "input_tokens",
        "output_tokens",
        "cost_usd",
        "latency_ms",
        "planner_mode",
        "real_model_evaluation",
        "source",
        "sources",
        "evidence_source",
        "code_hash",
        "model_profile",
    }

    def projection(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: projection(child) for key, child in value.items() if key not in excluded}
        if isinstance(value, list):
            return [projection(child) for child in value]
        return value

    return H(projection(result))
