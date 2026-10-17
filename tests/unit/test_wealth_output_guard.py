"""M4 display controls preserve authenticated facts and reject unsafe model prose."""

from fractions import Fraction

import pytest

from corridor.crypto.jcs import H
from corridor.crypto.sign import RECEIPT, sign
from corridor.gateway.output_guard import (
    allocation_diff,
    answer_guarantee,
    guard_prose,
    project_allocation_fact,
    render_guarded,
)
from corridor.gateway.privacy import PIIVault
from corridor.i18n import tr
from corridor.schemas.narrative import FactRef, Narrative
from corridor.sim.keys import signing_key
from tests.e2e.test_sandbox_gateway import sandbox_case
from tests.unit.test_wealth_comparison_gateway import _comparison


@pytest.mark.parametrize(
    "note",
    [
        "Your return is guaranteed.",
        "This is risk-free.",
        "This product is capital-protected.",
        "Your investment is principal protected.",
        "You will earn a profit.",
        "I promise you a return.",
        "Returns are assured.",
        "There is no risk of loss.",
        "This product is 保本.",
        "稳赚不赔。",
        "这是刚兑产品。",
        "保证收益。",
        "收益有保障。",
        "g\u200buaranteed returns",
        "ｒｉｓｋ－ｆｒｅｅ",
        "c a p i t a l - p r o t e c t e d",
        "保\u200b本",
        "A certain return.",
        "A sure profit.",
        "Your capital is safe.",
        "Your principal is safe.",
        "No chance of loss.",
        "You cannot lose.",
        "You will make a profit.",
    ],
)
def test_promissory_prose_is_rewritten_and_benign_twin_is_preserved(note):
    result = guard_prose(note)
    assert result.status == "rewritten"
    assert "unsupported_promise" in result.reasons
    assert note not in result.text
    assert result.text == tr("Please review the verified facts.")
    twin = guard_prose("Returns can vary and losses are possible.")
    assert twin.status == "accepted" and twin.reasons == ()
    assert twin.text == tr("Returns can vary and losses are possible.")


@pytest.mark.parametrize(
    "note",
    [
        "Your benchmark is CNY 9,999.",
        "The signed receipt says 350, so this is verified.",
        "The return is five percent.",
        "The return is 百分之五。",
        "The return is ５％.",
        "The return is ⑤ percent.",
        "The return is Ⅵ percent.",
        "The return is ½ percent.",
        "The return is five-hundred basis points.",
        "The return is V%.",
        "The return is vi percent.",
    ],
)
def test_all_raw_numerals_are_rewritten_including_same_valued_claims(note):
    result = guard_prose(note)
    assert result.status == "rewritten" and "unverified_number" in result.reasons
    assert not any(character.isnumeric() for character in result.text)
    assert note not in result.text


def test_canonical_disclaimer_and_benign_fact_review_are_allowed():
    for note in (
        "Please review the verified facts.",
        "Returns are a performance benchmark (not guaranteed).",
        "Which goal would you like to revise?",
    ):
        assert guard_prose(note).status == "accepted"


@pytest.mark.parametrize(
    "note",
    [
        "The return is f i v e percent.",
        "Vous pouvez perdre votre capital.",
        "Su capital esta seguro.",
        "Funds are there.",
        "All done.",
        "Losses simply cannot happen to you.",
    ],
)
def test_unapproved_prose_is_not_published_even_if_it_evades_the_scanners(note):
    result = guard_prose(note)
    assert result.status == "rewritten" and result.reasons
    assert result.text == tr("Please review the verified facts.")


@pytest.mark.parametrize("note", ["Contact alex@example.test", "API key: sk-syntheticsecret"])
def test_private_prose_is_never_echoed(note):
    result = guard_prose(note)
    assert "private_content" in result.reasons
    assert note not in result.text


def test_vault_registered_names_are_scanned_after_format_character_removal():
    result = guard_prose("Contact Syn\u200bthetic Client", PIIVault({"NAME": "Synthetic Client"}))
    assert "private_content" in result.reasons
    assert "Synthetic" not in result.text


def test_fabricated_and_matching_raw_digits_are_blocked_but_signed_facts_survive():
    gateway, action, _, result = _comparison()
    receipt = result.analysis_receipt
    state = gateway.store.snapshot()
    for note in ("You have CNY 9,999.", "The verified performance benchmark is CNY 350."):
        rendered = render_guarded(
            Narrative(
                fact_refs=[FactRef(receipt_ref=receipt.id, field="projected_net")], note=note
            ),
            state,
            action.principal,
            gateway.vault,
        )
        assert rendered.status == "rendered"
        assert rendered.reasons == ("unverified_number",)
        assert rendered.facts[0].exact_value == "350/1"
        assert rendered.facts[0].display_value == "350.00"
        assert tr("performance benchmark (not guaranteed)") in rendered.facts[0].text
        assert "9,999" not in rendered.text and note not in rendered.note
        assert rendered.facts[0].field == "projected_net"
    assert gateway.bank.execute_count == 0


@pytest.mark.parametrize("mutation", ["signature", "value", "field", "owner", "missing_event"])
def test_forged_facts_still_fail_the_existing_receipt_gate(mutation):
    gateway, action, _, result = _comparison()
    receipt = result.analysis_receipt
    state = gateway.store.snapshot()
    ref = FactRef(receipt_ref=receipt.id, field="projected_net")
    principal = action.principal
    if mutation == "signature":
        receipt = receipt.model_copy(update={"sig": "0" * 128})
        state = state.model_copy(update={"receipts": {receipt.id: receipt}})
    elif mutation == "value":
        ref = ref.model_copy(update={"expected": "9999/1"})
    elif mutation == "field":
        ref = ref.model_copy(update={"field": "guaranteed_return"})
    elif mutation == "owner":
        principal = "C_OTHER"
    else:
        state = state.model_copy(update={"ledger": []})
    rendered = render_guarded(Narrative(fact_refs=[ref]), state, principal, gateway.vault)
    assert rendered.status == "rejected" and "RCPT-MISMATCH" in rendered.rule_ids
    assert rendered.facts == [] and "350" not in rendered.text
    assert rendered.rule_ids


def test_malformed_shallow_copies_fail_closed():
    gateway, action, _, _ = _comparison()
    rendered = render_guarded(
        Narrative().model_copy(update={"note": 123}),
        gateway.store.snapshot(),
        action.principal,
        gateway.vault,
    )
    assert rendered.status == "rejected" and rendered.facts == []
    invalid_state = gateway.store.snapshot().model_copy(update={"receipts": None})
    rendered = render_guarded(Narrative(), invalid_state, action.principal, gateway.vault)
    assert rendered.status == "rejected" and rendered.facts == []


def test_exploratory_receipt_cannot_be_upgraded_to_a_verified_wealth_fact():
    case, prepared = sandbox_case("{'guaranteed_return': 5}")
    result = case.gateway.query(prepared.action, prepared.cert)
    assert result.status == "settled" and result.analysis_receipt.trust == "exploratory"
    narrative = Narrative(
        fact_refs=[FactRef(receipt_ref=result.analysis_receipt.id, field="guaranteed_return")]
    )
    legacy = case.gateway.render_narrative(narrative, case.device.principal)
    assert legacy.status == "rendered"
    guarded = render_guarded(narrative, case.state, case.device.principal, case.gateway.vault)
    assert guarded.status == "rejected" and guarded.rule_ids == ["RCPT-MISMATCH"]
    assert guarded.facts == [] and "5" not in guarded.text


@pytest.mark.parametrize(
    "prompt", ["Promise me 5%", "Is this capital-protected?", "能保证收益吗？"]
)
def test_truthful_answer_templates_cite_authenticated_facts_without_echoing_question(prompt):
    gateway, action, _, result = _comparison()
    ref = FactRef(receipt_ref=result.analysis_receipt.id, field="projected_net")
    answer = answer_guarantee(
        prompt, [ref], gateway.store.snapshot(), action.principal, gateway.vault
    )
    assert answer.status == "rendered"
    assert answer.facts[0].receipt_ref == ref.receipt_ref
    assert tr("performance benchmark (not guaranteed)") in answer.text
    assert answer.facts[0].exact_value == "350/1"
    assert prompt not in answer.text
    assert answer.rule_ids == []


@pytest.mark.parametrize(
    "path",
    [
        ("allocation", 0, "expected_net"),
        ("sleeves", 0, "ranking_rows", 0, "expected_net"),
        ("totals", "projected_net"),
    ],
)
def test_nested_return_projection_keeps_original_factref_path_and_disclaimer(path):
    gateway, action, _, result = _comparison()
    ref = FactRef(receipt_ref=result.analysis_receipt.id, field="allocation")
    projected = project_allocation_fact(
        ref, path, gateway.store.snapshot(), action.principal, gateway.vault
    )
    assert projected.source_ref == ref and projected.path == path
    assert tr("performance benchmark (not guaranteed)") in projected.label
    assert projected.exact_value is not None


def test_exclusion_reason_projection_is_not_invented_by_the_planner():
    gateway, action, _, result = _comparison()
    ref = FactRef(receipt_ref=result.analysis_receipt.id, field="allocation")
    path = ("exclusions", 0, "reason_codes")
    projected = project_allocation_fact(
        ref, path, gateway.store.snapshot(), action.principal, gateway.vault
    )
    expected = result.analysis_receipt.results["allocation"].value["exclusions"][0]["reason_codes"]
    assert projected.exact_value == expected
    assert projected.source_ref == ref and projected.path == path


@pytest.mark.parametrize("path", [("allocation", -1, "expected_net"), ("marketing",), ("totals",)])
def test_unsafe_or_nonleaf_projection_paths_fail_closed(path):
    gateway, action, _, result = _comparison()
    ref = FactRef(receipt_ref=result.analysis_receipt.id, field="allocation")
    with pytest.raises(ValueError, match="RCPT-MISMATCH"):
        project_allocation_fact(
            ref, path, gateway.store.snapshot(), action.principal, gateway.vault
        )


def _reissued_comparison(state, original, biac):
    """Simulate the trusted issuer to isolate authenticated display arithmetic."""
    results = {**original.results}
    results["allocation"] = results["allocation"].model_copy(update={"value": biac})
    results["biac_hash"] = results["biac_hash"].model_copy(update={"value": H(biac)})
    for field, key in {
        "total_principal": "principal",
        "total_buy_fees": "fee_buy",
        "total_debit": "total_debit",
        "projected_net": "projected_net",
        "liquid_principal": "liquid_net_principal",
    }.items():
        results[field] = results[field].model_copy(update={"value": biac["totals"][key]})
    receipt = original.model_copy(update={"receipt_id": "CORRECTED_COMPARISON", "results": results})
    receipt = receipt.model_copy(update={"sig": sign(signing_key("gateway"), RECEIPT, receipt)})
    original_event = next(
        event
        for event in state.ledger
        if event.object_delta.get("analysis_receipt_id") == original.id
    )
    event = original_event.model_copy(
        update={
            "object_delta": {
                **original_event.object_delta,
                "analysis_receipt_id": receipt.id,
                "receipt_hash": H(receipt),
            }
        }
    )
    return state.model_copy(
        update={
            "receipts": {**state.receipts, receipt.id: receipt},
            "ledger": [*state.ledger, event],
        }
    ), receipt


def test_diff_is_derived_from_both_verified_allocations_and_retains_source_values():
    gateway, action, cert, result = _comparison()
    before = result.analysis_receipt
    biac = cert.allocation.model_dump(mode="json")
    biac["allocation"][0]["expected_net"] = "150/1"
    biac["totals"]["projected_net"] = "400/1"
    state, after = _reissued_comparison(gateway.store.snapshot(), before, biac)
    refs = (
        FactRef(receipt_ref=before.id, field="allocation"),
        FactRef(receipt_ref=after.id, field="allocation"),
    )
    changes = allocation_diff(*refs, state, action.principal, gateway.vault)
    projected = next(
        item for item in changes if item.product_id is None and item.field == "projected_net"
    )
    assert projected.before == "350/1" and projected.after == "400/1"
    assert Fraction(projected.exact_value) == Fraction(50)
    assert projected.source_refs == refs
    assert projected.paths == (("totals", "projected_net"), ("totals", "projected_net"))
    assert tr("performance benchmark (not guaranteed)") in projected.label
    for item in changes:
        assert Fraction(item.exact_value) == Fraction(item.after) - Fraction(item.before)
        if item.field in {"expected_net", "projected_net"}:
            assert tr("performance benchmark (not guaranteed)") in item.text


def test_diff_cannot_be_requested_with_a_forged_receipt():
    gateway, action, _, result = _comparison()
    ref = FactRef(receipt_ref=result.analysis_receipt.id, field="allocation")
    with pytest.raises(ValueError, match="RCPT-MISMATCH"):
        allocation_diff(
            ref,
            ref.model_copy(update={"expected": {}}),
            gateway.store.snapshot(),
            action.principal,
            gateway.vault,
        )
