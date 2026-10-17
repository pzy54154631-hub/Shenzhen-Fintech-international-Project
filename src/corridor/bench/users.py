"""Frozen visible-field simulated users, independent of hidden attack truth."""

from typing import Any, Literal

from corridor.crypto.sign import CONTROL, sign, verify
from corridor.schemas.base import loads_exact
from corridor.sim.keys import signing_key

UserPolicy = Literal["all_approve", "careful"]


def signed_goal(facts: dict[str, Any]) -> dict[str, Any]:
    """Fixture-authorized intended facts; never populated from oracle outcomes."""
    body = {"purpose": "baseline-visible-goal-v1", "facts": facts}
    return {**body, "sig": sign(signing_key("device"), CONTROL, body)}


class SimulatedUser:
    def __init__(self, policy: UserPolicy, goal: dict[str, Any]) -> None:
        if policy not in {"all_approve", "careful"}:
            raise ValueError("Unknown simulated user policy")
        if goal.get("purpose") != "baseline-visible-goal-v1" or not verify(
            signing_key("device").verify_key, CONTROL, goal, goal.get("sig", "")
        ):
            raise ValueError("Invalid signed user goal")
        self.policy = policy
        self.facts = dict(goal["facts"])

    def approve(self, visible: dict[str, Any] | str) -> bool:
        if self.policy == "all_approve":
            return True
        if isinstance(visible, str):
            try:
                visible = loads_exact(visible)
            except (ValueError, TypeError):
                return False
        if not isinstance(visible, dict) or not self.facts:
            return False
        if any(key not in visible or visible[key] != value for key, value in self.facts.items()):
            return False
        if not self.facts.get("explicit_selection", False) and (
            visible.get("best_choice") is False or visible.get("rank", 1) != 1
        ):
            return False
        return True

    def complete_mfa(self, *, requested: bool, legal_simulated_challenge: bool) -> bool:
        """Respond only to an existing legal challenge; never invent a grant."""
        return requested and legal_simulated_challenge
