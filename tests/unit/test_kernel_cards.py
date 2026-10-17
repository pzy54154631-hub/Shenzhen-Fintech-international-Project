"""Card operations retain provenance, state transitions and MFA obligations."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT
from corridor.kernel import check
from corridor.kernel.binding import binding
from corridor.schemas.bank import BankAction, BusinessEvent, InputTerm, StateTerm, UserInput
from corridor.schemas.domain import Card
from corridor.schemas.models import Accept, Escalate, Reject
from tests.bank_cases import recertify, signed, transfer_case, with_mfa


def card_case(kind, *, status="active", limit="1000/1", restrictions=(), change=None):
    action, cert, state = transfer_case()
    card = Card.model_validate({
        "id": "CARD_TEST",
        "owner": action.principal,
        "account_ref": "A_CURRENT",
        "status": status,
        "limit": limit,
        "restrictions": list(restrictions),
        "card_token": "CARD_TOKEN_TEST",
    })
    state = state.model_copy(update={"cards": {card.id: card}, "user_inputs": {}})
    args = (
        {"account_ref": card.account_ref} if kind == "apply_virtual_card" else {"card_ref": card.id}
    )
    terms = {
        "args.account_ref" if kind == "apply_virtual_card" else "args.card_ref": StateTerm(
            collection="accounts" if kind == "apply_virtual_card" else "cards",
            object_ref=card.account_ref if kind == "apply_virtual_card" else card.id,
            field="id",
            version=1,
        )
    }
    input_hashes = []
    if change is not None:
        value = signed(
            UserInput(
                id="CARD_CHANGE",
                principal=action.principal,
                batch_id="CARD_BATCH",
                slot="card_change",
                value={"card_ref": card.id, "kind": kind, **change},
                submitted_at=state.now,
                scope_id=action.intent_id,
                sig="0" * 128,
            ),
            INPUT,
        )
        state = state.model_copy(update={"user_inputs": {value.id: value}})
        input_hashes.append(H(value))
        args["change_ref"] = value.id
        terms["args.change_ref"] = InputTerm(input_ref=value.id, slot="card_change")
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(
        auth.model_copy(
            update={
                "allowed_kind": kind,
                "object_refs": [card.account_ref] if kind == "apply_virtual_card" else [card.id],
                "amount_bound": None,
                "input_hashes": input_hashes,
            }
        ),
        CONTROL,
    )
    state = state.model_copy(update={"authorizations": {auth.id: auth}})
    action = BankAction.model_validate({
        **action.model_dump(mode="python"),
        "kind": kind,
        "args": args,
    })
    cert = cert.model_copy(update={"derivations": terms})
    return recertify(action, cert, state)


@pytest.mark.parametrize(
    ("kind", "status", "restrictions", "change", "tier", "after_status"),
    [
        ("apply_virtual_card", "active", (), None, "yellow", "active"),
        ("freeze_card", "active", (), {"status": "frozen"}, "yellow", "frozen"),
        ("lower_card_limit", "active", (), {"limit": "500/1"}, "yellow", "active"),
        ("restrict_card", "active", (), {"restrictions": ["travel"]}, "yellow", "active"),
        ("report_card_lost", "active", ("travel",), None, "red", "lost"),
        ("report_card_lost", "frozen", ("travel",), None, "red", "lost"),
        ("restore_card", "lost", ("travel",), None, "red", "frozen"),
        ("unfreeze_card", "frozen", (), {"status": "active"}, "red", "active"),
        ("raise_card_limit", "active", (), {"limit": "2000/1"}, "red", "active"),
        ("relax_card_restriction", "active", ("travel",), {"restrictions": []}, "red", "active"),
    ],
)
def test_valid_card_kinds_have_exact_facts_and_require_original_factors(
    kind, status, restrictions, change, tier, after_status
):
    case = card_case(kind, status=status, restrictions=restrictions, change=change)
    result = check(*case, phase="propose")
    assert isinstance(result, Escalate if tier == "red" else Accept), result
    assert result.tier == tier
    if tier == "red":
        assert result.rule_ids == ["TIER-MFA-REQUIRED"]
        assert isinstance(check(*case, phase="dispatch"), Escalate)
        assert isinstance(check(*with_mfa(*case), phase="dispatch"), Accept)
    facts = result.verified_facts["card_core"]["card_change"]
    assert facts["account_ref"] == "A_CURRENT"
    assert facts["after"]["status"] == after_status
    assert facts["after"]["limit"] == (change.get("limit", "1000/1") if change else "1000/1")
    assert facts["after"]["restrictions"] == (
        change.get("restrictions", list(restrictions)) if change else list(restrictions)
    )


@pytest.mark.rule("DOMAIN-STATE")
@pytest.mark.parametrize(
    ("kind", "status", "change"),
    [
        ("freeze_card", "frozen", {"status": "frozen"}),
        ("freeze_card", "lost", {"status": "frozen"}),
        ("unfreeze_card", "active", {"status": "active"}),
        ("unfreeze_card", "lost", {"status": "active"}),
        ("report_card_lost", "lost", None),
        ("restore_card", "active", None),
        ("restore_card", "frozen", None),
        ("lower_card_limit", "active", {"limit": "1000/1"}),
        ("lower_card_limit", "active", {"limit": "1001/1"}),
        ("raise_card_limit", "active", {"limit": "1000/1"}),
        ("raise_card_limit", "active", {"limit": "999/1"}),
        ("lower_card_limit", "lost", {"limit": "500/1"}),
        ("restrict_card", "active", {"restrictions": ["travel"]}),
        ("restrict_card", "active", {"restrictions": ["retail"]}),
        ("relax_card_restriction", "active", {"restrictions": ["travel"]}),
        ("relax_card_restriction", "active", {"restrictions": ["retail", "travel"]}),
    ],
)
def test_invalid_transitions_and_noops_are_rejected(kind, status, change):
    result = check(
        *card_case(kind, status=status, restrictions=("travel",), change=change), phase="propose"
    )
    assert isinstance(result, Reject), result
    assert "DOMAIN-STATE" in result.rule_ids


@pytest.mark.rule("TIER-BLACK-KIND")
@pytest.mark.parametrize(
    "mutation", ["missing", "forged", "other_intent", "wrong_slot", "unauthorized"]
)
@pytest.mark.parametrize(
    ("kind", "status", "change"),
    [
        ("lower_card_limit", "active", {"limit": "500/1"}),
        ("raise_card_limit", "active", {"limit": "1500/1"}),
        ("freeze_card", "active", {"status": "frozen"}),
        ("unfreeze_card", "frozen", {"status": "active"}),
        ("restrict_card", "active", {"restrictions": ["retail", "travel"]}),
        ("relax_card_restriction", "active", {"restrictions": []}),
    ],
)
def test_agent_cannot_change_card_control_without_specific_signed_input(
    mutation, kind, status, change
):
    action, cert, state = card_case(kind, status=status, restrictions=("travel",), change=change)
    value = state.user_inputs["CARD_CHANGE"]
    if mutation == "missing":
        state = state.model_copy(update={"user_inputs": {}})
    else:
        changed = value.model_copy(
            update={
                "forged": {"sig": "0" * 128},
                "other_intent": {"scope_id": "OTHER_INTENT"},
                "wrong_slot": {"slot": "purpose"},
                "unauthorized": {"value": {**value.value, "limit": "400/1"}},
            }[mutation]
        )
        if mutation != "forged":
            changed = signed(changed, INPUT)
        state = state.model_copy(update={"user_inputs": {changed.id: changed}})
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject), result
    assert "TIER-BLACK-KIND" in result.rule_ids


@pytest.mark.parametrize("change", [{"card_ref": "ANOTHER_CARD"}, {"kind": "raise_card_limit"}])
def test_signed_card_input_cannot_be_redirected_to_different_kind_or_card(change):
    action, cert, state = card_case("lower_card_limit", change={"limit": "500/1"})
    value = state.user_inputs["CARD_CHANGE"]
    value = signed(value.model_copy(update={"value": {**value.value, **change}}), INPUT)
    auth = state.authorizations[cert.authorization_ref]
    auth = signed(auth.model_copy(update={"input_hashes": [H(value)]}), CONTROL)
    state = state.model_copy(
        update={"user_inputs": {value.id: value}, "authorizations": {auth.id: auth}}
    )
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject)
    assert "TIER-BLACK-KIND" in result.rule_ids
    assert "PROV-COHERENCE" in result.rule_ids


@pytest.mark.parametrize(
    "change", [{"limit": "0/1"}, {"limit": "-1/1"}, {"limit": "1/1000"}, {"limit": 500}]
)
def test_card_limit_must_be_positive_exact_signed_cents(change):
    result = check(*card_case("lower_card_limit", change=change), phase="propose")
    assert isinstance(result, Reject), result


def test_card_binding_detects_current_object_and_linked_account_drift():
    action, cert, state = card_case("freeze_card", change={"status": "frozen"})
    original = binding(action, cert, state)
    for collection, key, update in [
        ("cards", "CARD_TEST", {"limit": Fraction(900), "version": 2}),
        ("accounts", "A_CURRENT", {"status": "closed", "version": 2}),
    ]:
        objects = getattr(state, collection)
        changed = state.model_copy(
            update={collection: {**objects, key: objects[key].model_copy(update=update)}}
        )
        result = check(action, cert, changed, phase="dispatch")
        assert isinstance(result, Reject), result
        assert "CERT-HASH" in result.rule_ids
        assert binding(action, cert, changed).dependency_hash != original.dependency_hash
        assert (
            binding(action, cert, changed).card_core["business_context_hash"]
            != original.card_core["business_context_hash"]
        )


def test_card_account_ownership_and_current_status_are_rechecked():
    for field, value, expected in [
        ("owner", "OTHER", "AUTH-PRINCIPAL"),
        ("status", "closed", "DOMAIN-STATE"),
        ("kind", "locked", "DOMAIN-STATE"),
    ]:
        action, cert, state = card_case("freeze_card", change={"status": "frozen"})
        update = {field: value, **({"parent_ref": "A_PARENT"} if field == "kind" else {})}
        account = state.accounts["A_CURRENT"].model_copy(update=update)
        state = state.model_copy(update={"accounts": {**state.accounts, account.id: account}})
        result = check(*recertify(action, cert, state), phase="propose")
        assert isinstance(result, Reject), result
        assert expected in result.rule_ids


@pytest.mark.rule("TOOL-UNAVAILABLE")
def test_card_tool_still_rejects_when_not_in_trusted_policy_whitelist():
    action, cert, state = card_case("freeze_card", change={"status": "frozen"})
    policy = state.policy.model_copy(
        update={
            "tool_whitelist": [
                kind for kind in state.policy.tool_whitelist if kind != "freeze_card"
            ]
        }
    )
    state = state.model_copy(update={"policy": policy})
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject)
    assert "TOOL-UNAVAILABLE" in result.rule_ids


def test_application_rejects_nonpositive_trusted_default_limit():
    action, cert, state = card_case("apply_virtual_card")
    state = state.model_copy(
        update={"policy": state.policy.model_copy(update={"transfer_yellow_limit": Fraction(0)})}
    )
    result = check(*recertify(action, cert, state), phase="propose")
    assert isinstance(result, Reject)
    assert "SCHEMA-UNIT" in result.rule_ids


@pytest.mark.rule("IDEM-DUP")
@pytest.mark.parametrize("status", ["reserved", "settled", "unknown"])
def test_application_cannot_issue_second_card_for_same_intent_under_new_node(status):
    action, cert, state = card_case("apply_virtual_card")
    previous = action.model_copy(
        update={"action_id": "PREVIOUS_ACTION", "node_id": "PREVIOUS_NODE"}
    )
    event = BusinessEvent(
        id="PREVIOUS_EVENT",
        intent_key=H("previous_apply_key"),
        event=status,
        kind="apply_virtual_card",
        principal=action.principal,
        object_delta={"action": previous.model_dump(mode="json")},
        ts=state.now,
    )
    state = state.model_copy(update={"ledger": [event]})
    result = check(*recertify(action, cert, state), phase="dispatch")
    assert isinstance(result, Reject), result
    assert "IDEM-DUP" in result.rule_ids


def test_failed_application_is_retryable_and_other_intents_do_not_block_it():
    action, cert, state = card_case("apply_virtual_card")
    reserved = BusinessEvent(
        id="RESERVED_EVENT",
        intent_key=H("previous_apply_key"),
        event="reserved",
        kind="apply_virtual_card",
        principal=action.principal,
        object_delta={"action": action.model_dump(mode="json")},
        ts=state.now,
    )
    failed = reserved.model_copy(update={"id": "FAILED_EVENT", "event": "failed"})
    another = reserved.model_copy(
        update={
            "id": "OTHER_EVENT",
            "intent_key": H("other_apply_key"),
            "event": "settled",
            "object_delta": {
                "action": action.model_copy(update={"intent_id": "OTHER_INTENT"}).model_dump(
                    mode="json"
                )
            },
        }
    )
    state = state.model_copy(update={"ledger": [reserved, failed, another]})
    assert isinstance(check(*recertify(action, cert, state), phase="dispatch"), Accept)
