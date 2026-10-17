"""Golden security failures and successful twins exercise the real bank kernel."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import CONTROL, INPUT, MFA
from corridor.kernel import check
from corridor.kernel.binding import intent_key
from corridor.schemas.bank import (
    AuthorizationRevocation,
    BankAction,
    BusinessEvent,
    InputTerm,
    ReadTerm,
    StateTerm,
    UserInput,
)
from corridor.schemas.domain import MerchantOrder
from corridor.schemas.models import Accept, Escalate, Reject
from corridor.stores.bank import add_seconds
from tests.bank_cases import query_case, recertify, signed, spa_case, transfer_case, with_mfa


def rejected(result, rule: str) -> None:
    assert isinstance(result, Reject), result
    assert rule in result.rule_ids


def test_legal_yellow_transfer_and_green_query_are_deterministic() -> None:
    for case in (transfer_case(), query_case()):
        result = check(*case, phase="propose")
        assert isinstance(result, Accept), result
        assert jcs_bytes(result) == jcs_bytes(check(*case, phase="propose"))
    assert check(*transfer_case(), phase="propose").tier == "yellow"
    assert check(*query_case(), phase="dispatch").tier == "green"


@pytest.mark.rule("CERT-HASH")
def test_action_or_dependency_omission_is_rejected() -> None:
    action, cert, state = transfer_case()
    rejected(
        check(action, cert.model_copy(update={"action_hash": "0" * 64}), state, phase="propose"),
        "CERT-HASH",
    )
    rejected(
        check(action, cert.model_copy(update={"dependency_hashes": {}}), state, phase="propose"),
        "CERT-HASH",
    )


@pytest.mark.rule("AUTH-SIG")
def test_tampered_device_input_and_authority_are_rejected() -> None:
    action, cert, state = transfer_case()
    source = state.user_inputs[action.args.amount_ref]
    corrupted = source.model_copy(update={"sig": "0" * 128})
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, source.id: corrupted}})
    rejected(check(*recertify(action, cert, state), phase="propose"), "AUTH-SIG")


@pytest.mark.rule("AUTH-PRINCIPAL")
def test_wrong_active_session_cannot_reuse_authority() -> None:
    action, cert, state = transfer_case()
    action = action.model_copy(update={"device_session_id": "STALE_SESSION"})
    rejected(check(*recertify(action, cert, state), phase="propose"), "AUTH-PRINCIPAL")


@pytest.mark.rule("AUTH-SCOPE")
def test_expired_or_revoked_authority_is_not_executable() -> None:
    action, cert, state = transfer_case()
    auth = state.authorizations[cert.authorization_ref]
    expired = signed(auth.model_copy(update={"expires_at": state.now}), CONTROL)
    invalid = state.model_copy(
        update={"authorizations": {**state.authorizations, auth.id: expired}}
    )
    rejected(check(*recertify(action, cert, invalid), phase="propose"), "AUTH-SCOPE")
    revocation = signed(
        AuthorizationRevocation(
            id="REVOKE",
            principal=action.principal,
            authorization_ref=auth.id,
            revoked_at=state.now,
            sig="0" * 128,
        ),
        CONTROL,
    )
    invalid = state.model_copy(
        update={"authorizations": {**state.authorizations, revocation.id: revocation}}
    )
    rejected(check(*recertify(action, cert, invalid), phase="propose"), "AUTH-SCOPE")


@pytest.mark.rule("IDEM-KEY")
def test_intent_key_cannot_be_minted_by_changing_action_intent() -> None:
    action, cert, state = transfer_case()
    action = action.model_copy(update={"intent_id": "FRESH_UNAUTHORIZED_INTENT"})
    rejected(check(*recertify(action, cert, state), phase="propose"), "IDEM-KEY")


@pytest.mark.rule("AUTH-CONSUMED")
@pytest.mark.parametrize("event_status", ["reserved", "settled", "unknown"])
@pytest.mark.parametrize("reference_source", ["cert", "authorization_ref"])
def test_operation_authority_is_single_use(event_status: str, reference_source: str) -> None:
    action, cert, state = transfer_case()
    reference = (
        {"cert": cert.model_dump(mode="json")}
        if reference_source == "cert"
        else {"authorization_ref": cert.authorization_ref}
    )
    event = BusinessEvent.model_validate({
        "id": "FIRST_AUTH_USE",
        "intent_key": H("prior-key"),
        "event": event_status,
        "kind": action.kind,
        "principal": action.principal,
        "object_delta": reference,
        "debit": {"account_ref": "A_CURRENT", "amount": "200/1"},
        "ts": state.now,
    })
    state = state.model_copy(update={"ledger": [event]})
    replay = action.model_copy(update={"node_id": "NEW_NODE", "plan_id": "NEW_PLAN"})
    rejected(check(*recertify(replay, cert, state), phase="dispatch"), "AUTH-CONSUMED")


def test_failed_authority_use_releases_the_bound_for_a_new_approval() -> None:
    action, cert, state = transfer_case()
    reserved = BusinessEvent.model_validate({
        "id": "RESERVED",
        "intent_key": intent_key(action, state),
        "event": "reserved",
        "kind": action.kind,
        "principal": action.principal,
        "object_delta": {"cert": cert.model_dump(mode="json")},
        "debit": {"account_ref": "A_CURRENT", "amount": "200/1"},
        "ts": state.now,
    })
    failed = reserved.model_copy(update={"id": "FAILED", "event": "failed"})
    state = state.model_copy(update={"ledger": [reserved, failed]})
    verdict = check(*recertify(action, cert, state), phase="dispatch")
    assert isinstance(verdict, Accept), verdict
    assert verdict.required_factors == ["device"]


@pytest.mark.rule("AUTH-SCOPE")
def test_authority_amount_bound_includes_previous_nonfailed_debits() -> None:
    action, cert, state = transfer_case()
    event = BusinessEvent.model_validate({
        "id": "PARTIAL_USE",
        "intent_key": H("old-planner-key"),
        "event": "settled",
        "kind": action.kind,
        "principal": action.principal,
        "object_delta": {"authorization_ref": cert.authorization_ref},
        "debit": {"account_ref": "A_CURRENT", "amount": "1/1"},
        "ts": state.now,
    })
    state = state.model_copy(update={"ledger": [event]})
    rejected(check(*recertify(action, cert, state), phase="propose"), "AUTH-SCOPE")


def test_immediate_intent_key_ignores_unsigned_planner_identifiers() -> None:
    action, _, state = transfer_case()
    replay = action.model_copy(
        update={
            "action_id": "NEW_ACTION",
            "node_id": "NEW_NODE",
            "plan_id": "NEW_PLAN",
            "plan_hash": H("new-plan"),
        }
    )
    expected = H({
        "principal": action.principal,
        "intent_id": action.intent_id,
        "kind": action.kind,
    })
    assert intent_key(action, state) == intent_key(replay, state) == expected


@pytest.mark.rule("PROV-MISSING")
def test_every_executable_argument_requires_a_derivation() -> None:
    action, cert, state = transfer_case()
    terms = dict(cert.derivations)
    del terms["args.amount_ref"]
    cert = cert.model_copy(update={"derivations": terms})
    rejected(check(action, cert, state, phase="propose"), "PROV-MISSING")


@pytest.mark.rule("PROV-LITERAL")
@pytest.mark.rule("SCHEMA-INVALID")
def test_literal_term_and_bypassed_model_validation_are_rejected() -> None:
    action, cert, state = transfer_case()
    body = cert.model_dump(mode="python")
    body["derivations"]["args.amount_ref"] = {"t": "literal", "value": "200/1"}
    rejected(check(action, body, state, phase="propose"), "PROV-LITERAL")
    bad = action.model_copy(update={"kind": "unknown"})
    rejected(check(bad, cert, state, phase="propose"), "SCHEMA-INVALID")


@pytest.mark.rule("SCHEMA-TIME")
def test_invalid_times_do_not_escape_kernel() -> None:
    action, cert, state = transfer_case()
    raw = state.model_dump(mode="python")
    raw["now"] = "2026-10-16T10:00:00+08:00"
    rejected(check(action, cert, raw, phase="propose"), "SCHEMA-TIME")


@pytest.mark.rule("SCHEMA-UNIT")
def test_fractional_cent_input_fails_at_kernel_boundary() -> None:
    action, cert, state = transfer_case()
    raw = state.model_dump(mode="python")
    raw["user_inputs"][action.args.amount_ref]["value"]["amount"] = "1/1000"
    rejected(check(action, cert, raw, phase="propose"), "SCHEMA-UNIT")


@pytest.mark.rule("PROV-FIELD")
def test_state_field_cannot_replace_reference_identity() -> None:
    action, cert, state = transfer_case()
    cert = cert.model_copy(
        update={
            "derivations": {
                **cert.derivations,
                "args.source_ref": StateTerm(
                    collection="accounts", object_ref="A_CURRENT", field="owner", version=1
                ),
            }
        }
    )
    rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-FIELD")


@pytest.mark.rule("PROV-MISMATCH")
def test_equal_amounts_do_not_allow_swapping_input_identity() -> None:
    action, cert, state = transfer_case()
    original = state.user_inputs[action.args.amount_ref]
    other = signed(original.model_copy(update={"id": "OTHER_INPUT"}), INPUT)
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, other.id: other}})
    cert = cert.model_copy(
        update={
            "derivations": {
                **cert.derivations,
                "args.amount_ref": InputTerm(input_ref=other.id, slot="amount"),
            }
        }
    )
    rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-MISMATCH")


@pytest.mark.rule("PROV-STALE")
def test_superseded_input_and_old_object_version_are_rejected() -> None:
    action, cert, state = transfer_case()
    original = state.user_inputs[action.args.amount_ref]
    replacement = signed(
        original.model_copy(update={"id": "NEW_INPUT", "supersedes": original.id}), INPUT
    )
    state = state.model_copy(
        update={"user_inputs": {**state.user_inputs, replacement.id: replacement}}
    )
    rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-STALE")


@pytest.mark.rule("PROV-COHERENCE")
def test_input_from_other_intent_cannot_be_reauthorized_by_reference() -> None:
    action, cert, state = transfer_case()
    original = state.user_inputs[action.args.amount_ref]
    other = signed(original.model_copy(update={"scope_id": "OTHER_INTENT"}), INPUT)
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, other.id: other}})
    rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-COHERENCE")


@pytest.mark.rule("PROV-AMBIGUOUS")
@pytest.mark.parametrize("collision", ["name_token", "phone_token", "aliases"])
def test_same_name_requires_explicit_signed_choice(collision: str) -> None:
    action, cert, state = transfer_case(contact_ref="CONTACT_LIN_A")
    primary = state.contacts["CONTACT_LIN_A"]
    sibling = state.contacts["CONTACT_LIN_B"].model_copy(
        update={
            "name_token": "OTHER_NAME",
            "phone_token": "OTHER_PHONE",
            "aliases": [],
            collision: getattr(primary, collision) if collision != "aliases" else ["shared-alias"],
        }
    )
    if collision == "aliases":
        primary = primary.model_copy(update={"aliases": ["shared-alias"]})
    state = state.model_copy(
        update={
            "contacts": {
                **state.contacts,
                primary.id: primary,
                sibling.id: sibling,
            }
        }
    )
    rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-AMBIGUOUS")
    amount = state.user_inputs[action.args.amount_ref]
    selected = signed(
        UserInput(
            id="CONTACT_CHOICE",
            principal=action.principal,
            batch_id=amount.batch_id,
            slot="contact_ref",
            value="CONTACT_LIN_A",
            submitted_at=state.now,
            scope_id=action.intent_id,
            sig="0" * 128,
        ),
        INPUT,
    )
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(update={"input_hashes": [*auth.input_hashes, H(selected)]}), CONTROL
    )
    state = state.model_copy(
        update={
            "authorizations": {**state.authorizations, auth.id: auth},
            "user_inputs": {**state.user_inputs, selected.id: selected},
        }
    )
    assert isinstance(check(*recertify(action, cert, state), phase="propose"), Accept)


@pytest.mark.rule("BAL-AVAILABLE")
def test_reserved_unknown_funds_are_not_available_twice() -> None:
    action, cert, state = transfer_case(Fraction(200))
    event = BusinessEvent.model_validate({
        "id": "EVENT",
        "intent_key": H("existing"),
        "event": "unknown",
        "kind": "transfer",
        "principal": action.principal,
        "debit": {"account_ref": "A_CURRENT", "amount": "9900/1"},
        "ts": state.now,
    })
    state = state.model_copy(update={"ledger": [event]})
    rejected(check(*recertify(action, cert, state), phase="propose"), "BAL-AVAILABLE")


@pytest.mark.rule("DOMAIN-STATE")
def test_locked_account_cannot_fund_an_external_transfer() -> None:
    action, cert, state = transfer_case(source_ref="A_LOCKED")
    rejected(check(action, cert, state, phase="propose"), "DOMAIN-STATE")


@pytest.mark.rule("TIER-MFA-REQUIRED")
def test_new_payee_and_daily_threshold_require_mfa() -> None:
    result = check(*transfer_case(contact_ref="CONTACT_NEW"), phase="propose")
    assert isinstance(result, Escalate)
    assert "TIER-MFA-REQUIRED" in result.rule_ids
    assert isinstance(check(*transfer_case(Fraction(1000)), phase="propose"), Accept)
    assert isinstance(check(*transfer_case(Fraction(100001, 100)), phase="propose"), Escalate)
    assert isinstance(check(*with_mfa(*transfer_case(Fraction(1001))), phase="dispatch"), Accept)


@pytest.mark.rule("MFA-INVALID")
def test_wrong_scope_or_expired_grant_is_not_a_red_override() -> None:
    action, cert, state = with_mfa(*transfer_case(Fraction(1001)))
    grant = state.security.mfa_grants[cert.mfa_grant_refs[0]]
    changed = signed(grant.model_copy(update={"scope_hash": "0" * 64}), MFA, "mfa")
    state = state.model_copy(
        update={
            "security": state.security.model_copy(
                update={"mfa_grants": {changed.grant_id: changed}}
            )
        }
    )
    rejected(check(action, cert, state, phase="dispatch"), "MFA-INVALID")


def test_consumption_is_gateway_owned_and_mfa_does_not_change_dependencies() -> None:
    original = transfer_case(Fraction(1001))
    action, cert, state = with_mfa(*original)
    assert original[1].dependency_hashes == cert.dependency_hashes
    state = state.model_copy(
        update={
            "security": state.security.model_copy(
                update={
                    "consumed_grant_ids": cert.mfa_grant_refs,
                }
            )
        }
    )
    assert isinstance(check(action, cert, state, phase="dispatch"), Accept)


@pytest.mark.rule("TIER-BLACK-KIND")
def test_black_kind_is_not_overridden_by_mfa() -> None:
    action, cert, state = transfer_case()
    raw = action.model_dump(mode="python")
    raw.update(kind="request_secret", args={})
    rejected(check(raw, cert, state, phase="propose"), "TIER-BLACK-KIND")


@pytest.mark.rule("BIC-PREFERENCE")
def test_investment_without_signed_preference_never_accepts_as_noop() -> None:
    action, cert, state = transfer_case()
    raw = action.model_dump(mode="python")
    raw.update(
        kind="purchase_product",
        args={
            "source_ref": "A_CURRENT",
            "preference_ref": "PREF",
            "product_ref": "P_A",
            "amount_ref": action.args.amount_ref,
        },
    )
    rejected(check(raw, cert, state, phase="propose"), "BIC-PREFERENCE")


@pytest.mark.rule("TOOL-UNAVAILABLE")
def test_policy_disabled_tool_is_not_executable() -> None:
    action, cert, state = transfer_case()
    state = state.model_copy(
        update={
            "policy": state.policy.model_copy(
                update={
                    "tool_whitelist": [
                        kind for kind in state.policy.tool_whitelist if kind != action.kind
                    ],
                }
            )
        }
    )
    rejected(check(*recertify(action, cert, state), phase="propose"), "TOOL-UNAVAILABLE")


def test_time_decorations_do_not_cause_spurious_cert_drift() -> None:
    action, cert, state = transfer_case()
    state = state.model_copy(update={"now": add_seconds(state.now, 30)})
    assert isinstance(check(action, cert, state, phase="dispatch"), Accept)


def test_cumulative_boundary_counts_existing_settled_amount() -> None:
    for amount, expected_type in [(Fraction(400), Accept), (Fraction(40001, 100), Escalate)]:
        action, cert, state = transfer_case(amount)
        event = BusinessEvent.model_validate({
            "id": "PREVIOUS",
            "intent_key": H("previous"),
            "event": "settled",
            "kind": "transfer",
            "principal": action.principal,
            "debit": {"account_ref": "A_CURRENT", "amount": "600/1"},
            "ts": state.now,
        })
        state = state.model_copy(update={"ledger": [event]})
        assert isinstance(check(*recertify(action, cert, state), phase="propose"), expected_type)


def test_subscription_query_uses_yellow_operation_authority() -> None:
    action, cert, state = transfer_case()
    amount = state.user_inputs[action.args.amount_ref]
    period = signed(
        UserInput(
            id="PERIOD_INPUT",
            principal=action.principal,
            batch_id=amount.batch_id,
            slot="period",
            value="2026-10",
            submitted_at=state.now,
            scope_id=action.intent_id,
            sig="0" * 128,
        ),
        INPUT,
    )
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(
            update={
                "allowed_kind": "subscription_query",
                "object_refs": ["A_CURRENT"],
                "input_hashes": [H(period)],
                "amount_bound": None,
            }
        ),
        CONTROL,
    )
    state = state.model_copy(
        update={
            "authorizations": {**state.authorizations, auth.id: auth},
            "user_inputs": {**state.user_inputs, period.id: period},
        }
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "subscription_query",
        "args": {"account_ref": "A_CURRENT", "period": "2026-10"},
    })
    cert = cert.model_copy(
        update={
            "derivations": {
                "args.account_ref": StateTerm(
                    collection="accounts", object_ref="A_CURRENT", field="id", version=1
                ),
                "args.period": InputTerm(input_ref=period.id, slot="period"),
            }
        }
    )
    assert check(*recertify(action, cert, state), phase="propose").tier == "yellow"
    assert isinstance(check(*recertify(action, cert, state), phase="propose"), Accept)
    _, query_cert, query_state = query_case()
    state = state.model_copy(
        update={"authorizations": {**state.authorizations, **query_state.authorizations}}
    )
    cert = cert.model_copy(update={"authorization_ref": query_cert.authorization_ref})
    rejected(check(*recertify(action, cert, state), phase="propose"), "AUTH-SCOPE")


@pytest.mark.rule("DOMAIN-AA")
def test_aa_cannot_emit_zero_cent_participants() -> None:
    action, cert, state = transfer_case(Fraction(1, 100))
    raw = action.model_dump(mode="python")
    raw.update(
        kind="aa_request",
        args={
            "source_bill_ref": "BILL",
            "total_ref": action.args.amount_ref,
            "participant_refs": ["CONTACT_CHEN", "CONTACT_NEW"],
        },
    )
    rejected(check(raw, cert, state, phase="propose"), "DOMAIN-AA")


@pytest.mark.rule("DOMAIN-COMPENSATION")
def test_paid_order_cannot_be_cancelled_as_if_payment_rolled_back() -> None:
    action, cert, state = transfer_case()
    order = MerchantOrder.model_validate({
        "id": "ORDER_PAID",
        "owner": action.principal,
        "merchant_ref": "FLOWERS",
        "offer_ref": "OFFER_FLOWERS",
        "amount": "300/1",
        "status": "paid",
    })
    authority = state.authorizations[cert.authorization_ref]
    authority = signed(
        authority.model_copy(
            update={
                "allowed_kind": "cancel_order",
                "object_refs": [order.id],
                "input_hashes": [],
                "amount_bound": None,
            }
        ),
        CONTROL,
    )
    state = state.model_copy(
        update={
            "orders": {order.id: order},
            "authorizations": {**state.authorizations, authority.id: authority},
            "user_inputs": {},
        }
    )
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": "cancel_order",
        "args": {"order_ref": order.id},
    })
    cert = cert.model_copy(
        update={
            "derivations": {
                "args.order_ref": StateTerm(
                    collection="orders", object_ref=order.id, field="id", version=1
                ),
            }
        }
    )
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject)
    assert set(result.rule_ids) == {"DOMAIN-STATE", "DOMAIN-COMPENSATION"}


def test_future_ledger_event_cannot_spend_future_credit() -> None:
    action, cert, state = transfer_case()
    event = BusinessEvent.model_validate({
        "id": "FUTURE",
        "intent_key": H("future"),
        "event": "settled",
        "kind": "unlock_funds",
        "principal": action.principal,
        "credit": {"account_ref": "A_CURRENT", "amount": "600/1"},
        "ts": add_seconds(state.now, 1),
    })
    state = state.model_copy(update={"ledger": [event]})
    rejected(check(*recertify(action, cert, state), phase="propose"), "SCHEMA-TIME")


@pytest.mark.rule("DOMAIN-SPA-TIER")
def test_yellow_spa_run_crossing_daily_limit_requires_fresh_mfa() -> None:
    action, cert, state = spa_case(execution=True)
    assert isinstance(check(action, cert, state, phase="dispatch"), Accept)
    prior = BusinessEvent.model_validate({
        "id": "PRIOR_PAYMENT",
        "intent_key": H("prior"),
        "event": "settled",
        "kind": "transfer",
        "principal": action.principal,
        "debit": {"account_ref": "A_CURRENT", "amount": "900/1"},
        "ts": state.now,
    })
    state = state.model_copy(update={"ledger": [*state.ledger, prior]})
    action, cert, state = recertify(action, cert, state)
    result = check(action, cert, state, phase="dispatch")
    assert isinstance(result, Escalate)
    assert result.rule_ids == ["DOMAIN-SPA-TIER"]
    assert isinstance(check(*with_mfa(action, cert, state), phase="dispatch"), Accept)


def test_red_spa_run_uses_consumed_creation_evidence_without_live_grant() -> None:
    action, cert, state = spa_case(Fraction(3000), execution=True)
    result = check(action, cert, state, phase="dispatch")
    assert isinstance(result, Accept), result
    assert cert.mfa_grant_refs == []


@pytest.mark.rule("DOMAIN-SPA")
def test_spa_creation_cannot_substitute_operation_authority() -> None:
    action, cert, state = spa_case()
    assert isinstance(check(action, cert, state, phase="propose"), Accept)
    auth = state.authorizations["AUTH_SPA_TEST"]
    auth = signed(
        auth.model_copy(
            update={
                "allowed_kind": "schedule_transfer",
                "object_refs": [*auth.object_refs, "SPA_TEST"],
            }
        ),
        CONTROL,
    )
    state = state.model_copy(update={"authorizations": {**state.authorizations, auth.id: auth}})
    cert = cert.model_copy(update={"authorization_ref": auth.id})
    rejected(check(*recertify(action, cert, state), phase="propose"), "DOMAIN-SPA")


def test_scheduled_action_id_cannot_reduce_other_intents_daily_total() -> None:
    _, _, scheduled = spa_case(execution=True)
    action, cert, state = transfer_case(state=scheduled)
    action = action.model_copy(update={"action_id": "SPA_RUN"})
    rejected(check(*recertify(action, cert, state), phase="propose"), "IDEM-KEY")


@pytest.mark.parametrize("period", ["2026-99", "2026-02-31", "0000", "2026-2", "2026-13-01"])
def test_read_period_requires_a_valid_calendar_date(period: str) -> None:
    action, cert, state = query_case()
    action = action.model_copy(update={"args": action.args.model_copy(update={"period": period})})
    cert = cert.model_copy(
        update={
            "derivations": {
                **cert.derivations,
                "args.period": ReadTerm(
                    session_authorization_ref=cert.authorization_ref,
                    query_field="period",
                    value=period,
                ),
            }
        }
    )
    rejected(check(*recertify(action, cert, state), phase="propose"), "PROV-FIELD")
