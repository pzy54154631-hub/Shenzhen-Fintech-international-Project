"""Deterministic development planner using the same typed proposal as replay/live."""

from typing import Literal

from corridor.schemas.bank import Handle
from corridor.schemas.base import Model


class TransferProposal(Model):
    tool: Literal["transfer"] = "transfer"
    source: Handle
    contact: Handle
    amount: Handle


class ScriptedPlanner:
    def transfer(self, source_ref: str, contact_ref: str, amount_ref: str) -> TransferProposal:
        return TransferProposal(
            source=Handle(handle_type="state", ref=source_ref),
            contact=Handle(handle_type="state", ref=contact_ref),
            amount=Handle(handle_type="input", ref=amount_ref),
        )
