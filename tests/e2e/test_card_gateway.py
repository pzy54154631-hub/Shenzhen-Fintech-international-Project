"""Card authority, drift, duplicate issuance, and bank recovery use the real gateway."""

from fractions import Fraction

import pytest

from corridor.bench.bank_cases import BankCase, PreparedCase
from corridor.bench.card_runner import card_state, prepare_card
from corridor.bench.investment_runner import _with_mfa
from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.audit import AuditLog
from corridor.gateway.bank_adapter import card_authorize
from corridor.gateway.service import Gateway
from corridor.kernel.binding import dependency_hashes, intent_key
from corridor.schemas.bank import InputTerm
from corridor.sim.fixtures import make_state
from corridor.sim.keys import signing_key
from corridor.stores.bank import BankStore, add_seconds, latest_events


def _case(name, *, state=None):
    return BankCase(state or card_state(), task_id="B13-GATEWAY", subcase_id=name)


def _token(case, prepared, sequence=0):
    return case.device.approve(
        prepared.action,
        prepared.cert,
        prepared.proposal.card,
        now=case.state.now,
        sequence=sequence,
    )


def _reopen(case, path):
    audit_path = path / "audit.jsonl"
    if not audit_path.exists():
        audit_path.write_bytes(
            b"".join(jcs_bytes(row) + b"\n" for row in case.gateway.audit.records())
        )
    return Gateway(
        BankStore(case.state, path=path / "state.jsonl"),
        case.gateway.bank,
        audit=AuditLog(audit_path),
        mfa=case.gateway.mfa,
        analysis_key=signing_key("gateway"),
        risk_key=signing_key("risk"),
        evidence_dir=path / "decisions",
    )


@pytest.mark.rule("APR-DRIFT")
def test_another_control_change_invalidates_an_existing_card_approval():
    case = _case("approval-drift")
    limit = prepare_card(case, "lower_card_limit", change={"limit": "500/1"})
    token = _token(case, limit)
    restrict = prepare_card(case, "restrict_card", change={"restrictions": ["online"]}, step=1)
    assert case.dispatch(restrict).status == "settled"
    result = case.gateway.dispatch(limit.action, limit.cert, token)
    assert result.status == "rejected" and "APR-DRIFT" in result.rule_ids
    assert case.state.cards["CARD_DEMO"].limit == 1000
    assert case.state.cards["CARD_DEMO"].restrictions == ["online"]
    assert case.gateway.bank.execute_count == 1


def test_signed_change_reference_cannot_be_swapped_after_approval():
    case = _case("payload-swap")
    first = prepare_card(case, "lower_card_limit", change={"limit": "500/1"})
    token = _token(case, first)
    second = prepare_card(case, "lower_card_limit", change={"limit": "100/1"}, step=1)
    action = first.action.model_copy(
        update={
            "args": first.action.args.model_copy(
                update={"change_ref": second.action.args.change_ref}
            )
        }
    )
    cert = first.cert.model_copy(
        update={
            "action_hash": H(action),
            "derivations": {
                **first.cert.derivations,
                "args.change_ref": InputTerm(
                    input_ref=second.action.args.change_ref, slot="card_change"
                ),
            },
        }
    )
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(action, cert, case.state)}
    )
    result = case.gateway.dispatch(action, cert, token)
    assert result.status == "rejected"
    assert result.rule_ids == ["PLAN-SCOPE"]
    assert case.state.cards["CARD_DEMO"].limit == 1000
    assert case.gateway.bank.execute_count == 0


@pytest.mark.parametrize("fault", ["response_loss", "bad_signature"])
@pytest.mark.parametrize("kind", ["apply_virtual_card", "freeze_card"])
def test_unknown_card_response_recovers_exactly_once(fault, kind):
    case = _case(
        f"recover-{kind}-{fault}", state=make_state() if kind == "apply_virtual_card" else None
    )
    prepared = prepare_card(
        case, kind, change={"status": "frozen"} if kind == "freeze_card" else None
    )
    token = _token(case, prepared)
    key = intent_key(prepared.action, case.state)
    before = H(case.state.cards)
    case.gateway.bank.faults[key] = fault
    result = case.gateway.dispatch(prepared.action, prepared.cert, token)
    assert result.status == "unknown" and H(case.state.cards) == before
    assert key in case.state.security.unknown_intent_ids
    assert latest_events(case.state)[key].event == "unknown"
    assert case.gateway.dispatch(prepared.action, prepared.cert, token).status == "rejected"
    recovered = case.gateway.reconcile(key)
    assert recovered.status == "settled"
    assert len(case.state.cards) == 1
    assert case.gateway.bank.final_state()["cards"] == {
        ref: card.model_dump(mode="json") for ref, card in case.state.cards.items()
    }
    assert key not in case.state.security.unknown_intent_ids
    assert latest_events(case.state)[key].event == "settled"
    assert case.gateway.reconcile(key).rule_ids == ["IDEM-DUP"]
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.audit.verify()


def test_unknown_issuance_recovers_after_journal_restart(tmp_path):
    case = _case("restart", state=make_state())
    case.gateway = _reopen(case, tmp_path)
    prepared = prepare_card(case, "apply_virtual_card")
    key = intent_key(prepared.action, case.state)
    case.gateway.bank.faults[key] = "response_loss"
    assert case.dispatch(prepared).status == "unknown"
    assert not case.state.cards
    case.gateway = _reopen(case, tmp_path)
    recovered = case.gateway.reconcile(key)
    assert recovered.status == "settled"
    assert len(case.state.cards) == 1
    assert case.gateway.bank.execute_count == 1
    assert (tmp_path / "decisions" / f"{key}.json").exists()
    assert case.gateway.audit.verify()


@pytest.mark.parametrize("kind", ["apply_virtual_card", "freeze_card"])
def test_card_decision_write_failure_remains_unknown_until_recovery(kind, monkeypatch):
    case = _case(
        f"write-failure-{kind}", state=make_state() if kind == "apply_virtual_card" else None
    )
    prepared = prepare_card(
        case, kind, change={"status": "frozen"} if kind == "freeze_card" else None
    )
    key = intent_key(prepared.action, case.state)
    before = H(case.state.cards)
    original = case.gateway._decision

    def unavailable(*args, **kwargs):
        raise OSError("AUD-WRITE")

    monkeypatch.setattr(case.gateway, "_decision", unavailable)
    assert case.dispatch(prepared).status == "unknown"
    assert H(case.state.cards) == before
    assert case.gateway.reconcile(key).status == "unknown"
    assert key in case.state.security.unknown_intent_ids
    monkeypatch.setattr(case.gateway, "_decision", original)
    assert case.gateway.reconcile(key).status == "settled"
    assert len(case.state.cards) == 1
    assert H(case.state.cards) != before
    assert case.gateway.bank.execute_count == 1
    assert case.gateway.audit.verify()


def test_lost_restore_and_unfreeze_require_separate_mfa_and_preserve_controls():
    case = _case("lost-lifecycle", state=card_state(limit="200/1", restrictions=["online"]))
    grants = []
    for step, (kind, change, status) in enumerate([
        ("report_card_lost", None, "lost"),
        ("restore_card", None, "frozen"),
        ("unfreeze_card", {"status": "active"}, "active"),
    ]):
        if step:
            # Separate user visits preserve the existing six-requests-per-ten-minutes limit.
            case.gateway.advance_clock(add_seconds(case.state.now, 601))
        prepared = prepare_card(case, kind, change=change, step=step)
        assert prepared.proposal.verdict.tier == "red"
        assert prepared.proposal.verdict.outcome == "Escalate"
        before = H(case.state.cards)
        denied = case.gateway.dispatch(prepared.action, prepared.cert, _token(case, prepared))
        assert denied.status == "rejected" and "TIER-MFA-REQUIRED" in denied.rule_ids
        assert H(case.state.cards) == before and case.gateway.bank.execute_count == step
        prepared = _with_mfa(case, prepared)
        grants.extend(prepared.cert.mfa_grant_refs)
        result = case.gateway.dispatch(prepared.action, prepared.cert, _token(case, prepared, 1))
        assert result.status == "settled", result
        card = case.state.cards["CARD_DEMO"]
        assert card.status == status and card.limit == 200 and card.restrictions == ["online"]
        assert card_authorize(case.gateway.bank, card.id, Fraction(200), "dining") is (
            status == "active"
        )
        assert not card_authorize(case.gateway.bank, card.id, Fraction(20001, 100), "dining")
        assert not card_authorize(case.gateway.bank, card.id, Fraction(1), "online")
    assert len(set(grants)) == 3
    assert set(grants) <= set(case.state.security.consumed_grant_ids)
    assert case.gateway.bank.execute_count == 3
    assert case.gateway.audit.verify()


@pytest.mark.parametrize(
    "mutations", [{"action_id"}, {"node_id", "plan_id"}, {"action_id", "node_id", "plan_id"}]
)
def test_same_signed_issuance_intent_cannot_issue_again_with_new_ids(mutations):
    case = _case("issuance-intent", state=make_state())
    first = prepare_card(case, "apply_virtual_card")
    assert case.dispatch(first).status == "settled"
    node = first.plan.nodes[0]
    changes = {name: f"SECOND_{name.upper()}" for name in mutations}
    node = node.model_copy(update={"node_id": changes.get("node_id", node.node_id)})
    plan = first.plan.model_copy(
        update={"plan_id": changes.get("plan_id", first.plan.plan_id), "nodes": [node]}
    )
    if "plan_id" in mutations:
        registered = case.gateway.submit_plan(plan)
        assert registered.status == "registered", registered
    action = first.action.model_copy(update={**changes, "plan_hash": H(plan)})
    cert = first.cert.model_copy(update={"action_hash": H(action)})
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(action, cert, case.state)}
    )
    proposal = case.gateway.propose(action, cert)
    assert proposal.verdict.outcome == "Reject"
    assert "IDEM-DUP" in proposal.verdict.rule_ids
    token = _token(case, PreparedCase(action, cert, plan, proposal), sequence=1)
    result = case.gateway.dispatch(action, cert, token)
    assert result.status == "rejected" and "IDEM-DUP" in result.rule_ids
    assert len(case.state.cards) == 1
    assert case.gateway.bank.execute_count == 1


@pytest.mark.rule("PLAN-SCOPE")
def test_a_device_cannot_control_another_owners_card():
    state = card_state()
    foreign = state.cards["CARD_DEMO"].model_copy(update={"owner": "C_OTHER"})
    case = _case("foreign-owner", state=state.model_copy(update={"cards": {foreign.id: foreign}}))
    with pytest.raises(ValueError, match="PLAN-SCOPE") as error:
        prepare_card(case, "freeze_card", change={"status": "frozen"})
    assert "PLAN-SCOPE" in str(error.value)
    assert case.state.cards[foreign.id].status == "active"
    assert case.gateway.bank.execute_count == 0


@pytest.mark.parametrize("consume_first", [False, True])
def test_mfa_grant_cannot_be_reused_for_another_card_operation(consume_first):
    case = _case(f"mfa-replay-{consume_first}")
    first = prepare_card(case, "raise_card_limit", change={"limit": "1500/1"})
    first = _with_mfa(case, first)
    assert first.proposal.verdict.outcome == "Accept"
    if consume_first:
        assert case.dispatch(first).status == "settled"
    second = prepare_card(case, "report_card_lost", step=1)
    cert = second.cert.model_copy(update={"mfa_grant_refs": first.cert.mfa_grant_refs})
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(second.action, cert, case.state)}
    )
    proposal = case.gateway.propose(second.action, cert)
    assert proposal.verdict.outcome in {"Reject", "Escalate"}
    result = case.gateway.dispatch(
        second.action,
        cert,
        _token(case, PreparedCase(second.action, cert, second.plan, proposal), 1),
    )
    assert result.status == "rejected"
    assert result.rule_ids == (["MFA-REUSE"] if consume_first else ["MFA-INVALID"])
    assert case.state.cards["CARD_DEMO"].status == "active"
    assert case.state.cards["CARD_DEMO"].limit == (
        Fraction(1500) if consume_first else Fraction(1000)
    )
    assert case.gateway.bank.execute_count == int(consume_first)
