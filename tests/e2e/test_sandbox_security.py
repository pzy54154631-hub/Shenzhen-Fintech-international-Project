"""Adversarial review of sandbox ownership, privacy, snapshots and fact authority."""

from fractions import Fraction
from hashlib import sha256
from unittest.mock import patch

import pytest

from corridor.bench.planning_runner import prepare_transfer
from corridor.bench.sandbox_runner import INTEGER_OVERFLOW, prepare_sandbox, sandbox_case
from corridor.crypto.jcs import H, jcs_bytes
from corridor.crypto.sign import CONTROL, RECEIPT, sign
from corridor.kernel.binding import dependency_hashes
from corridor.kernel.check import check
from corridor.schemas.bank import ReadTerm, ReceiptTerm
from corridor.schemas.narrative import Narrative
from corridor.sim.billing import transaction
from corridor.sim.device import Device
from corridor.sim.keys import public_key, signing_key, stable_id
from corridor.stores.bank import add_seconds

PROGRAM = "result = {'total': sum_money(dataset), 'rows': count(dataset)}"


@pytest.mark.rule("SBX-SYNTAX")
@pytest.mark.parametrize(
    "failure", [MemoryError, RecursionError, SyntaxError, ValueError, RuntimeError, OverflowError]
)
def test_program_parser_exceptions_are_controlled_and_hash_only(failure):
    case = sandbox_case(f"parser_{failure.__name__}")
    before = case.state.model_dump(mode="json")
    with patch("corridor.gateway.sandbox.ast.parse", side_effect=failure("private parser detail")):
        with pytest.raises(ValueError, match="^SBX-SYNTAX$"):
            case.gateway.register_program(case.device.principal, PROGRAM)
    assert case.state.model_dump(mode="json") == before
    assert case.gateway.audit.records()[-1]["payload"] == {
        "program_hash": sha256(PROGRAM.encode("utf-8")).hexdigest(),
        "status": "rejected",
        "reason": "SBX-SYNTAX",
    }
    result = case.dispatch(prepare_sandbox(case, PROGRAM))
    assert result.status == "settled"
    assert case.gateway.bank.execute_count == 0


def test_exploratory_labels_are_positional_in_all_fact_fields_and_nested_values():
    case = sandbox_case("nested_labels")
    labels = ["transfer_completed_successfully", "guaranteed_return", "pay_all_funds"]
    program = (
        "result = {'z': count(dataset), 'transfer_completed_successfully': "
        "{'guaranteed_return': [{'pay_all_funds': 2}]}}"
    )
    result = case.dispatch(prepare_sandbox(case, program))
    assert result.status == "settled"
    receipt = result.analysis_receipt
    rendered = case.gateway.render_narrative(
        Narrative(
            fact_refs=[
                {"receipt_ref": receipt.id, "field": "z"},
                {"receipt_ref": receipt.id, "field": labels[0]},
            ]
        ),
        case.device.principal,
    )
    assert rendered.status == "rendered"
    assert [fact.field for fact in rendered.facts] == ["r2", "r1"]
    assert rendered.facts[1].exact_value == {"r1": [{"r1": "2/1"}]}
    assert all(label not in str(rendered.facts) for label in labels)
    assert rendered.note.startswith("Assistant note (unverified): ")
    assert all(label in rendered.note for label in labels)
    trusted_text, note = rendered.text.split("\nAssistant note (unverified): ", maxsplit=1)
    assert all(label not in trusted_text for label in labels)
    assert all(label in note for label in labels)


def _prepare_handles(case, args, *, step=0):
    return case.prepare(
        "sandbox_analyze",
        args,
        {
            key: ReadTerm(
                session_authorization_ref=case.session_authorization.id,
                query_field=key,
                value=value,
            )
            for key, value in args.items()
        },
        step=step,
    )


def _other_owner(case):
    customer = case.state.customers[case.device.principal].model_copy(
        update={
            "id": "C_OTHER",
            "principal": "C_OTHER",
            "device_pubkey": public_key("other-device"),
            "account_refs": ["A_OTHER"],
            "risk_profile_ref": None,
        }
    )
    account = case.state.accounts["A_CURRENT"].model_copy(
        update={"id": "A_OTHER", "owner": "C_OTHER"}
    )
    case.gateway.store.update(
        customers={**case.state.customers, customer.id: customer},
        accounts={**case.state.accounts, account.id: account},
    )
    device = Device("C_OTHER", key_label="other-device")
    login = device.login(session_id="OTHER_SESSION", expires_at=add_seconds(case.state.now, 3600))
    login = login.model_copy(update={"read_kinds": [*login.read_kinds, "sandbox_analyze"]})
    login = login.model_copy(update={"sig": sign(signing_key("other-device"), CONTROL, login)})
    assert case.gateway.login(login).status == "accepted"


@pytest.mark.parametrize("field", ["dataset_ref", "program_ref"])
@pytest.mark.parametrize("foreign", [False, True])
def test_unknown_and_cross_owner_handles_fail_before_worker(field, foreign):
    case = sandbox_case(f"handles_{field}_{foreign}")
    args = {
        "dataset_ref": case.gateway.register_dataset(case.device.principal, "A_CURRENT", "2026-09"),
        "program_ref": case.gateway.register_program(case.device.principal, PROGRAM),
    }
    if foreign:
        _other_owner(case)
        args[field] = (
            case.gateway.register_dataset("C_OTHER", "A_OTHER", "2026-09")
            if field == "dataset_ref"
            else case.gateway.register_program("C_OTHER", PROGRAM)
        )
    else:
        args[field] = ("DSET_" if field == "dataset_ref" else "PROG_") + "a" * 64
    with patch("corridor.gateway.sandbox_monitor.run_sandbox") as worker:
        with pytest.raises(ValueError, match="PLAN-SCOPE"):
            _prepare_handles(case, args)
        worker.assert_not_called()
    assert case.gateway.bank.execute_count == 0
    assert case.state.receipts == {}


def test_authenticated_owner_cannot_register_another_owners_account():
    case = sandbox_case("foreign_account")
    _other_owner(case)
    with pytest.raises(ValueError, match="READ-ROLE"):
        case.gateway.register_dataset(case.device.principal, "A_OTHER", "2026-09")
    assert case.gateway.bank.execute_count == 0


@pytest.mark.parametrize("encoding", ["unicode", "adjacent", "hex_integer"])
def test_decoded_private_constants_are_rejected_with_hash_only_audit(encoding):
    case = sandbox_case(f"private_{encoding}")
    private = "13812345678"
    if encoding == "unicode":
        value = "'" + "".join(f"\\u{ord(char):04x}" for char in private) + "'"
    elif encoding == "adjacent":
        value = "'13812' '345678'"
    else:
        value = hex(int(private))
    program = "result = {'x': " + value + "}"
    assert private not in program
    with pytest.raises(ValueError, match="PII-CTX"):
        case.gateway.register_program(case.device.principal, program)
    records = case.gateway.audit.records()
    assert private.encode() not in jcs_bytes(records)
    assert program.encode() not in jcs_bytes(records)
    rejected = records[-1]
    assert rejected["event"] == "sandbox_rejected"
    assert rejected["payload"] == {
        "program_hash": sha256(program.encode()).hexdigest(),
        "status": "rejected",
        "reason": "PII-CTX",
    }


def test_computed_private_output_is_rejected_before_receipt_or_raw_audit():
    case = sandbox_case("computed_private")
    # Named operands keep source literals separate under the all-alphanumeric PII scan.
    program = "result = {'x': 138123 * {'scale': 100000}['scale'] + 45678}"
    case.gateway.vault.ensure_safe(program)
    result = case.dispatch(prepare_sandbox(case, program))
    assert result.status == "rejected"
    assert "PII-OUT" in result.rule_ids
    assert result.analysis_receipt is None and case.state.receipts == {}
    assert b"13812345678" not in jcs_bytes(case.gateway.audit.records())
    assert case.gateway.bank.execute_count == 0


def test_computed_integer_overflow_reaches_worker_limit():
    case = sandbox_case("computed_overflow")
    case.gateway.vault.ensure_safe(INTEGER_OVERFLOW)
    result = case.dispatch(prepare_sandbox(case, INTEGER_OVERFLOW))
    assert result.status == "rejected"
    assert "SBX-LIMIT" in result.rule_ids
    assert result.analysis_receipt is None and case.state.receipts == {}
    assert any(
        record["event"] == "sandbox_run" and record["payload"]["reason"] == "worker_limit"
        for record in case.gateway.audit.records()
    )
    assert case.gateway.bank.execute_count == 0


def test_dataset_handle_retains_snapshot_when_transactions_change():
    case = sandbox_case("immutable_snapshot")
    old_ref = case.gateway.register_dataset(case.device.principal, "A_CURRENT", "2026-09")
    source_ref = case.gateway.register_program(case.device.principal, PROGRAM)
    added = transaction("LATER", Fraction(1000), "2026-09-10T02:00:00Z")
    case.gateway.store.update(transactions={**case.state.transactions, added.id: added})
    new_ref = case.gateway.register_dataset(case.device.principal, "A_CURRENT", "2026-09")
    assert old_ref != new_ref
    receipts = []
    for step, ref in enumerate((old_ref, new_ref)):
        prepared = _prepare_handles(
            case, {"dataset_ref": ref, "program_ref": source_ref}, step=step
        )
        result = case.dispatch(prepared)
        assert result.status == "settled", result
        receipts.append(result.analysis_receipt)
    assert receipts[0].results["total"].value == "353/2"
    assert receipts[0].results["rows"].value == "8/1"
    assert receipts[1].results["total"].value == "2353/2"
    assert receipts[1].results["rows"].value == "9/1"
    assert receipts[0].dataset_hash != receipts[1].dataset_hash
    assert case.gateway.bank.execute_count == 0


@pytest.fixture
def analyzed_case():
    case = sandbox_case("facts")
    result = case.dispatch(prepare_sandbox(case, PROGRAM))
    assert result.status == "settled", result
    return case, result.analysis_receipt


def _render(case, receipt, *, principal=None, expected="353/2"):
    return case.gateway.render_narrative(
        Narrative(fact_refs=[{"receipt_ref": receipt.id, "field": "total", "expected": expected}]),
        principal or case.device.principal,
    )


def test_exploratory_fact_mismatch_is_rejected_and_correct_twin_renders(analyzed_case):
    case, receipt = analyzed_case
    wrong = _render(case, receipt, expected="354/2")
    assert wrong.status == "rejected" and "RCPT-MISMATCH" in wrong.rule_ids
    assert wrong.facts == []
    correct = _render(case, receipt)
    assert correct.status == "rendered"
    assert correct.facts[0].exact_value == "353/2"
    assert "Exploratory analysis" in correct.text and "cannot authorize a payment" in correct.text
    assert case.gateway.bank.execute_count == 0


@pytest.mark.parametrize(
    "mutation",
    [
        "unsigned_result",
        "resigned_result",
        "resigned_action",
        "builtin_trust",
        "unregistered_signed",
    ],
)
def test_forged_analysis_receipt_cannot_replace_registered_fact(analyzed_case, mutation):
    case, receipt = analyzed_case
    if mutation in {"unsigned_result", "resigned_result"}:
        item = receipt.results["total"].model_copy(update={"value": "1/1"})
        forged = receipt.model_copy(update={"results": {**receipt.results, "total": item}})
    elif mutation == "resigned_action":
        forged = receipt.model_copy(
            update={"parameters": {**receipt.parameters, "action_hash": H({"other": "action"})}}
        )
    elif mutation == "builtin_trust":
        forged = receipt.model_copy(update={"trust": "builtin"})
    else:
        forged = receipt.model_copy(update={"receipt_id": receipt.id + "_FORGED"})
    if mutation != "unsigned_result":
        forged = forged.model_copy(update={"sig": sign(signing_key("gateway"), RECEIPT, forged)})
    case.gateway.store.update(receipts={**case.state.receipts, forged.id: forged})
    rendered = _render(case, forged, expected=forged.results["total"].value)
    assert rendered.status == "rejected" and "RCPT-MISMATCH" in rendered.rule_ids
    assert rendered.facts == []
    assert case.gateway.bank.execute_count == 0


def test_other_principal_cannot_render_owned_analysis(analyzed_case):
    case, receipt = analyzed_case
    _other_owner(case)
    rendered = _render(case, receipt, principal="C_OTHER")
    assert rendered.status == "rejected" and "RCPT-MISMATCH" in rendered.rule_ids
    assert rendered.facts == []


def test_exploratory_result_has_no_transfer_authority():
    case = sandbox_case("amount_authority")
    result = case.dispatch(prepare_sandbox(case, "result = {'weekday': sum_money(dataset)}"))
    assert result.status == "settled"
    assert result.analysis_receipt.results["weekday"].value == "353/2"
    valid = prepare_transfer(case, "200/1", step=2)
    source = ReceiptTerm(receipt_ref=result.analysis_receipt.id, field="weekday")
    node = valid.plan.nodes[0].model_copy(
        update={"args": {**valid.plan.nodes[0].args, "amount_ref": source}}
    )
    attempted = valid.plan.model_copy(
        update={"plan_id": stable_id(case.identity, 3, "exploratory_plan"), "nodes": [node]}
    )
    registration = case.gateway.submit_plan(attempted)
    assert registration.status == "rejected" and "PLAN-SCOPE" in registration.rule_ids
    action = valid.action.model_copy(
        update={"args": valid.action.args.model_copy(update={"amount_ref": source.receipt_ref})}
    )
    cert = valid.cert.model_copy(
        update={
            "action_hash": H(action),
            "derivations": {**valid.cert.derivations, "args.amount_ref": source},
        }
    )
    cert = cert.model_copy(
        update={"dependency_hashes": dependency_hashes(action, cert, case.state)}
    )
    verdict = check(action, cert, case.state, phase="dispatch")
    assert verdict.outcome == "Reject" and "PROV-FIELD" in verdict.rule_ids
    assert case.gateway.bank.final_state()["balances"]["A_CURRENT"] == "10000/1"
    assert case.gateway.bank.execute_count == 0
