"""Isolated synthetic planning state with no unrelated automatic debits."""

from corridor.schemas.state import BankState
from corridor.sim.fixtures import make_state

BIRTHDAY_DUE = "2026-10-17T16:00:00Z"


def make_planning_state() -> BankState:
    return make_state().model_copy(update={"subscriptions": {}})
