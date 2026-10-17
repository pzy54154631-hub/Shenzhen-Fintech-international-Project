"""B6 reports pass the real authorization, analysis receipt and fact gates."""

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, sign, verify
from corridor.gateway.facts import render_narrative
from corridor.gateway.privacy import PIIVault
from corridor.gateway.runtime import create_gateway
from corridor.kernel import check
from corridor.kernel.binding import dependency_hashes
from corridor.schemas.bank import (
    BankAction,
    BankCertificate,
    InputTerm,
    Plan,
    PlanNode,
    ReadTerm,
    StateTerm,
)
from corridor.schemas.narrative import FactRef, Narrative
from corridor.sim.device import Device
from corridor.sim.keys import signing_key, stable_id
from corridor.stores.bank import BankStore, add_seconds
from tests.billing_cases import (
    ACCOUNT,
    MONTH_SOURCES,
    anomaly_state,
    report_state,
    subscription_state,
)


def analysis_case(state=None, *, kind="bill_report", period="2026-09", analysis_spec=None):
    """Prepare one real gateway action with no implicit approval or backend bypass."""
    state = state or report_state()
    device = Device()
    gateway = create_gateway(
        BankStore(state), bank_key=signing_key("bank"), gateway_key=signing_key("gateway")
    )
    session_id = stable_id(f"B6-{kind}-{period}", 0, "session")
    session = device.login(session_id=session_id, expires_at=add_seconds(state.now, 3600))
    assert gateway.login(session).status == "accepted"
    intent = stable_id(f"B6-{kind}-{period}", 0, "intent")
    args = {"account_ref": ACCOUNT, "period": period}
    terms = {
        "account_ref": StateTerm(collection="accounts", object_ref=ACCOUNT, field="id", version=1)
    }
    goal_inputs = []
    if kind in {"subscription_query", "subscription_reminders"}:
        period_input = device.confirm_input(
            intent_id=intent, slot="period", value=period, now=state.now
        )
        assert gateway.submit_input(period_input).status == "accepted"
        authorization = device.authorize({
            "id": stable_id(intent, 0, "authority"),
            "intent_id": intent,
            "allowed_kind": kind,
            "object_refs": [ACCOUNT],
            "expires_at": add_seconds(state.now, 3600),
            "input_hashes": [H(period_input)],
        })
        assert gateway.submit_authorization(authorization).status == "accepted"
        authority_ref = authorization.id
        terms["period"] = InputTerm(input_ref=period_input.id, slot="period")
        goal_inputs = [period_input.id]
    else:
        authority_ref = session.id
        args["analysis_spec"] = analysis_spec or (
            "anomaly_v1" if kind == "anomaly_query" else "bill_summary_v1"
        )
        for field in ("period", "analysis_spec"):
            terms[field] = ReadTerm(
                session_authorization_ref=session.id, query_field=field, value=args[field]
            )
    node = PlanNode(node_id=stable_id(intent, 0, "node"), tool=kind, args=terms)
    plan = Plan(
        plan_id=stable_id(intent, 0, "plan"),
        revision=1,
        principal=device.principal,
        device_session_id=session_id,
        intent_id=intent,
        goal_input_refs=goal_inputs,
        nodes=[node],
        ownership_epoch=0,
    )
    assert gateway.submit_plan(plan).status == "registered"
    action = BankAction(
        action_id=stable_id(intent, 0, "action"),
        intent_id=intent,
        principal=device.principal,
        device_session_id=session_id,
        plan_id=plan.plan_id,
        plan_hash=H(plan),
        node_id=node.node_id,
        kind=kind,
        args=args,
    )
    cert = BankCertificate(
        action_hash=H(action),
        authorization_ref=authority_ref,
        derivations={f"args.{field}": term for field, term in terms.items()},
        dependency_hashes={},
    )
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(action, cert, gateway.store.snapshot())}
    )
    return gateway, device, action, cert


@pytest.mark.parametrize("kind", ["bill_analyze", "bill_report"])
@pytest.mark.parametrize(
    ("period", "gross", "net", "dining"),
    [("2026-09", "1800/1", "1700/1", "300/1"), ("2026", "1875/1", "1775/1", "375/1")],
)
def test_real_green_reports_have_exact_signed_facts_and_no_financial_effect(
    kind, period, gross, net, dining
):
    gateway, _, action, cert = analysis_case(kind=kind, period=period)
    before = H(gateway.bank.final_state())
    proposal = gateway.propose(action, cert)
    assert proposal.verdict.outcome == "Accept"
    assert proposal.verdict.tier == "green"
    result = gateway.query(action, cert)
    assert result.status == "settled" and result.rule_ids == []
    receipt = result.analysis_receipt
    assert receipt is not None and result.receipt is None
    assert receipt.function_id == "bill_summary_v1" and receipt.trust == "builtin"
    assert receipt.parameters["principal"] == action.principal
    assert receipt.parameters["account_ref"] == ACCOUNT
    assert receipt.parameters["action_hash"] == H(action)
    assert verify(gateway.store.snapshot().roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
    expected = {
        "gross_spend": gross,
        "refunds": "100/1",
        "net_spend": net,
        "category_totals.dining": dining,
        "category_totals.transport": "100/1",
        "category_totals.shopping": "1300/1",
    }
    for field, value in expected.items():
        assert receipt.results[field].value == value
        assert receipt.results[field].unit == "CNY"
        if period == "2026-09":
            assert tuple(receipt.results[field].source_tx_ids) == MONTH_SOURCES[field]
    narrative = Narrative(
        fact_refs=[
            FactRef(receipt_ref=receipt.id, field=field, expected=value)
            for field, value in expected.items()
        ]
    )
    rendered = render_narrative(narrative, gateway.store.snapshot(), action.principal, PIIVault())
    assert rendered.status == "rendered" and rendered.rule_ids == []
    assert {fact.field: fact.exact_value for fact in rendered.facts} == expected
    assert "Transfer settled" not in rendered.text
    assert gateway.bank.execute_count == 0 and H(gateway.bank.final_state()) == before
    assert gateway.verify_log()


@pytest.mark.rule("RCPT-MISMATCH")
def test_tampered_report_number_rejects_entire_narrative():
    gateway, _, action, cert = analysis_case()
    receipt = gateway.query(action, cert).analysis_receipt
    assert receipt is not None
    result = render_narrative(
        Narrative(
            fact_refs=[
                FactRef(receipt_ref=receipt.id, field="gross_spend", expected="1800/1"),
                FactRef(receipt_ref=receipt.id, field="net_spend", expected="1701/1"),
            ]
        ),
        gateway.store.snapshot(),
        action.principal,
        PIIVault(),
    )
    assert result.status == "rejected" and "RCPT-MISMATCH" in result.rule_ids
    assert result.facts == [] and "1701" not in result.text


@pytest.mark.parametrize("mutation", ["signature", "principal", "account", "dataset", "action"])
def test_forged_or_rebound_analysis_receipt_never_renders(mutation):
    gateway, _, action, cert = analysis_case()
    receipt = gateway.query(action, cert).analysis_receipt
    assert receipt is not None
    state = gateway.store.snapshot()
    if mutation == "signature":
        forged = receipt.model_copy(update={"sig": "0" * 128})
    elif mutation == "dataset":
        forged = receipt.model_copy(update={"dataset_hash": H({"unrelated": "dataset"})})
    else:
        key = {"principal": "principal", "account": "account_ref", "action": "action_hash"}[
            mutation
        ]
        value = H({"unrelated": "action"}) if mutation == "action" else "OTHER"
        forged = receipt.model_copy(update={"parameters": {**receipt.parameters, key: value}})
    if mutation != "signature":
        forged = forged.model_copy(update={"sig": sign(signing_key("gateway"), RECEIPT, forged)})
    state = state.model_copy(update={"receipts": {**state.receipts, receipt.id: forged}})
    result = render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field="net_spend")]),
        state,
        action.principal,
        PIIVault(),
    )
    assert result.status == "rejected" and result.facts == []
    assert result.rule_ids
    assert "Transfer settled" not in result.text


@pytest.mark.parametrize(
    "foreign_context", ["principal", "missing_receipt", "missing_event", "source_owner"]
)
def test_analysis_receipt_requires_registered_state_and_original_principal(foreign_context):
    gateway, _, action, cert = analysis_case()
    receipt = gateway.query(action, cert).analysis_receipt
    assert receipt is not None
    state = gateway.store.snapshot()
    principal = action.principal
    if foreign_context == "principal":
        principal = "OTHER"
    elif foreign_context == "missing_receipt":
        state = state.model_copy(update={"receipts": {}})
    elif foreign_context == "missing_event":
        state = state.model_copy(update={"ledger": []})
    else:
        changed = state.transactions["TX_DINING"].model_copy(update={"owner": "OTHER"})
        state = state.model_copy(
            update={"transactions": {**state.transactions, changed.id: changed}}
        )
    result = render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field="net_spend")]),
        state,
        principal,
        PIIVault(),
    )
    assert result.status == "rejected" and result.facts == []


@pytest.mark.parametrize("field", ["status", "balance_after"])
def test_analysis_receipt_cannot_invent_completion_or_account_balance(field):
    gateway, _, action, cert = analysis_case()
    receipt = gateway.query(action, cert).analysis_receipt
    assert receipt is not None
    result = render_narrative(
        Narrative(fact_refs=[FactRef(receipt_ref=receipt.id, field=field)]),
        gateway.store.snapshot(),
        action.principal,
        PIIVault(),
    )
    assert result.status == "rejected" and result.rule_ids == ["RCPT-MISMATCH"]
    assert result.facts == [] and "Transfer settled" not in result.text


@pytest.mark.rule("PROV-FIELD")
@pytest.mark.parametrize("analysis_spec", ["arbitrary_function", "anomaly_v1"])
def test_unknown_or_wrong_builtin_analysis_spec_is_rejected(analysis_spec):
    gateway, _, action, cert = analysis_case()
    term = cert.derivations["args.analysis_spec"].model_copy(update={"value": analysis_spec})
    terms = {**cert.derivations, "args.analysis_spec": term}
    bad_plan = Plan(
        plan_id=stable_id(action.intent_id, 1, "invalid-plan"),
        revision=1,
        principal=action.principal,
        device_session_id=action.device_session_id,
        intent_id=action.intent_id,
        goal_input_refs=[],
        nodes=[
            PlanNode(
                node_id=action.node_id,
                tool=action.kind,
                args={field.removeprefix("args."): value for field, value in terms.items()},
            )
        ],
        ownership_epoch=0,
    )
    assert gateway.submit_plan(bad_plan).rule_ids == ["PLAN-SCOPE"]
    action = action.model_copy(
        update={"args": action.args.model_copy(update={"analysis_spec": analysis_spec})}
    )
    cert = cert.model_copy(update={"action_hash": H(action), "derivations": terms})
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(action, cert, gateway.store.snapshot())}
    )
    verdict = check(action, cert, gateway.store.snapshot(), phase="propose")
    assert verdict.outcome == "Reject" and "PROV-FIELD" in verdict.rule_ids
    result = gateway.query(action, cert)
    assert result.status == "rejected" and "PLAN-SCOPE" in result.rule_ids
    assert result.analysis_receipt is None and result.receipt is None
    assert gateway.bank.execute_count == 0
    assert not gateway.store.snapshot().receipts
    assert gateway.verify_log()


@pytest.mark.parametrize("kind", ["subscription_query", "subscription_reminders"])
def test_yellow_subscription_results_require_separate_explicit_approval(kind):
    gateway, device, action, cert = analysis_case(subscription_state(), kind=kind, period="2026")
    before = H(gateway.bank.final_state())
    proposal = gateway.propose(action, cert)
    assert proposal.verdict.outcome == "Accept" and proposal.verdict.tier == "yellow"
    assert not gateway.store.snapshot().receipts
    assert "candidate_merchants" not in str(proposal.card)
    green_bypass = gateway.query(action, cert)
    assert green_bypass.rule_ids == ["READ-ROLE"] and green_bypass.analysis_receipt is None
    unapproved = gateway.dispatch(action, cert)
    assert unapproved.rule_ids == ["APR-REQUIRED"] and unapproved.analysis_receipt is None
    assert not gateway.store.snapshot().receipts
    token = device.approve(action, cert, proposal.card, now=gateway.store.snapshot().now)
    result = gateway.dispatch(action, cert, token)
    assert result.status == "settled" and result.analysis_receipt is not None
    receipt = result.analysis_receipt
    assert receipt.results["candidate_merchants"].value == ["SUB_A", "SUB_B"]
    assert receipt.results["cancellable_authorizations"].value == ["S1"]
    assert receipt.results["reminder_authorizations"].value == ["S1"]
    assert receipt.results["next_due.S1"].value == "2026-10-19T02:00:00Z"
    assert verify(gateway.store.snapshot().roots.gateway_pubkey, RECEIPT, receipt, receipt.sig)
    assert gateway.dispatch(action, cert, token).rule_ids == ["APR-REUSE"]
    assert gateway.store.snapshot().subscriptions["S1"].status == "active"
    assert gateway.bank.execute_count == 0 and H(gateway.bank.final_state()) == before
    assert gateway.verify_log()


@pytest.mark.parametrize("benign", [False, True])
def test_anomaly_receipt_and_benign_twin_have_exact_ids_without_freezing(benign):
    gateway, _, action, cert = analysis_case(anomaly_state(benign=benign), kind="anomaly_query")
    before = H(gateway.bank.final_state())
    result = gateway.query(action, cert)
    assert result.status == "settled" and result.analysis_receipt is not None
    receipt = result.analysis_receipt
    assert receipt.function_id == "anomaly_v1"
    assert receipt.results["anomaly_tx_ids"].value == (
        [] if benign else ["TX_DUPLICATE_A", "TX_DUPLICATE_B", "TX_LARGE"]
    )
    if not benign:
        assert receipt.results["anomalies.TX_DUPLICATE_A"].value == ["duplicate_candidate"]
        assert receipt.results["anomalies.TX_DUPLICATE_B"].value == ["duplicate_candidate"]
        assert receipt.results["anomalies.TX_LARGE"].value == ["large_expense"]
    assert gateway.bank.execute_count == 0 and H(gateway.bank.final_state()) == before
    assert not gateway.store.snapshot().security.locked_at
    assert gateway.verify_log()
