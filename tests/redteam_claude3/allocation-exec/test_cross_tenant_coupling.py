"""RT3-AX-1: another customer's allocation registration voids this customer's approved leg.

DESIGN-WEALTH 7.2 / allocation_dependency_projection: a child's approval
dependencies are its *own* parent scope and controls plus the ordinary
per-principal dependencies (financial_version is per principal). Registering
an unrelated allocation for a different customer is not a change to customer
A's parent, budget, inputs or controls, so it must not invalidate A's already
MFA-verified, device-approved purchase card, burn A's MFA grant, or count as
a kernel rejection against A (reject_limit=3 -> safety lock -> allocation void).
"""

import importlib
from fractions import Fraction

import pytest

from corridor.stores.bank import available
from tests.wealth_execution_cases import wealth_execution_case

tenant = importlib.import_module("tests.redteam_claude3.allocation-exec._tenant")


def _case(intents=(tenant.OTHER_INTENT,)):
    case = wealth_execution_case(state=tenant.two_tenant_state())
    other = tenant.OtherTenant(case.gateway, intents=intents)
    result, _ = case.start()
    assert result.status == "ready", result
    first, _ = case.execute_next()
    assert first.status == "settled", first
    return case, other


@pytest.mark.parametrize("other_intent", [tenant.OTHER_INTENT, "WEALTH_EXEC"])
def test_foreign_customer_registration_does_not_void_approved_leg(other_intent):
    case, other = _case((other_intent,))
    principal = case.draft.parent.principal
    approved = case.approve(sequence=1)
    streak = case.state.security.reject_streak.get(principal, 0)
    # Customer B, with B's own device, registers B's own allocation. Nothing of A changes.
    other.register(other_intent)
    assert available(case.state, "A_CURRENT") == 7000
    result = case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert result.status == "settled", result.rule_ids
    assert case.state.security.reject_streak.get(principal, 0) == streak
    assert case.snapshot()["status"] == "completed"


def test_foreign_registrations_cannot_drive_customer_into_safety_lock():
    intents = [f"WEALTH_OTHER_{index}" for index in range(3)]
    case, other = _case(intents)
    principal = case.draft.parent.principal
    for index, intent in enumerate(intents):
        # A successful second leg finishes this plan; no third approval exists.
        approved = (
            case.approve(sequence=index + 1) if case.snapshot()["status"] != "completed" else None
        )
        other.register(intent)
        if approved is not None:
            case.gateway.dispatch(approved.action, approved.cert, approved.token)
    assert principal not in case.state.security.locked_at
    assert case.snapshot()["status"] in {"ready", "executing", "completed"}
    assert case.snapshot()["settled_principal"] in {"5000/1", "10000/1"}
    assert available(case.state, "A_CURRENT") >= Fraction(2000)
