"""RT4-F3TCB-02 rejected finding: invalid stored policies must fail closed.

PROP-023 specifies one current allocation policy, replaced when rotated. PROP-027
requires ALLOC-POLICY for an invalid existing policy; authenticity does not excuse
expiry or a different catalogue. These retained reproducers assert that contract.
Legacy policies without optional retake limits and banks without any policy remain
supported, with the unchanged hard retake caps.
"""

import pytest

from corridor.crypto.sign import ALLOCATION_POLICY, RISK
from corridor.kernel.investment import risk_retake_errors
from corridor.sim.fixtures import make_state
from corridor.sim.wealth import make_wealth_state
from tests.bank_cases import signed


def _with_historical(update):
    state = make_wealth_state()
    current = next(iter(state.allocation_policies.values()))
    historical = signed(
        current.model_copy(update={"id": current.id + "_HISTORICAL", **update(state, current)}),
        ALLOCATION_POLICY,
        "bank",
    )
    return state.model_copy(
        update={"allocation_policies": {**state.allocation_policies, historical.id: historical}}
    )


def test_control_current_policy_alone_allows_first_retake():
    state = make_wealth_state()
    policy = next(iter(state.allocation_policies.values()))
    assert "risk_retake_limits" not in policy.model_dump(mode="json")
    assert risk_retake_errors("C_DEMO", state) == []


@pytest.mark.parametrize(
    "label, update",
    [
        ("expired-superseded", lambda state, policy: {"valid_until": state.now}),
        (
            "other-catalog-version",
            lambda state, policy: {"catalog_version": policy.catalog_version + 1},
        ),
    ],
)
@pytest.mark.rule("ALLOC-POLICY")
def test_authentic_historical_policy_beside_current_fails_closed(label, update):
    state = _with_historical(update)
    assert len(state.allocation_policies) == 2
    assert risk_retake_errors("C_DEMO", state) == ["ALLOC-POLICY"], label


@pytest.mark.rule("ALLOC-POLICY")
@pytest.mark.parametrize(
    "fault", ["expired", "other-catalog-id", "other-catalog-version", "signature"]
)
def test_invalid_single_policy_fails_closed(fault):
    state = make_wealth_state()
    policy = next(iter(state.allocation_policies.values()))
    updates = {
        "expired": {"valid_until": state.now},
        "other-catalog-id": {"catalog_id": policy.catalog_id + "_OTHER"},
        "other-catalog-version": {"catalog_version": policy.catalog_version + 1},
        "signature": {},
    }
    invalid = signed(policy.model_copy(update=updates[fault]), ALLOCATION_POLICY, "bank")
    if fault == "signature":
        invalid = invalid.model_copy(update={"sig": "0" * 128})
    state = state.model_copy(update={"allocation_policies": {invalid.id: invalid}})
    assert risk_retake_errors("C_DEMO", state) == ["ALLOC-POLICY"]


@pytest.mark.rule("RISK-RETAKE-LIMIT")
@pytest.mark.parametrize("with_policy", [False, True])
def test_legacy_and_policy_free_banks_preserve_hard_caps(with_policy):
    state = make_wealth_state() if with_policy else make_state()
    if not with_policy:
        assert state.allocation_policies == {}
    assert risk_retake_errors("C_DEMO", state) == []
    original = state.risk_assessments["RISK_DEMO"]
    second = signed(original.model_copy(update={"id": "RT4_RETAKE_SECOND"}), RISK, "risk")
    capped = state.model_copy(
        update={"risk_assessments": {**state.risk_assessments, second.id: second}}
    )
    assert risk_retake_errors("C_DEMO", capped) == ["RISK-RETAKE-LIMIT"]
