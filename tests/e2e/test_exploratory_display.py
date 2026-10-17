"""Exploratory evidence never inherits a bank-verified presentation."""

from contextlib import contextmanager

from corridor.bench.sandbox_runner import prepare_sandbox, sandbox_case
from corridor.schemas.narrative import Narrative
from corridor.ui import components


class DisplayRecorder:
    def __init__(self):
        self.events = []
        self.context = []

    def __getattr__(self, name):
        def record(value, **kwargs):
            self.events.append((name, value, tuple(self.context)))

        return record

    @contextmanager
    def expander(self, title, **kwargs):
        self.context.append(title)
        try:
            yield
        finally:
            self.context.pop()


def test_exploratory_receipt_labels_only_appear_in_unverified_display(monkeypatch):
    case = sandbox_case("ui_labels")
    labels = ("transfer_completed_successfully", "guaranteed_return")
    execution = case.dispatch(
        prepare_sandbox(
            case,
            "result = {'transfer_completed_successfully': {'guaranteed_return': 2}}",
        )
    )
    assert execution.status == "settled"
    receipt = execution.analysis_receipt
    facts = case.gateway.render_narrative(
        Narrative(fact_refs=[{"receipt_ref": receipt.id, "field": labels[0]}]),
        case.device.principal,
    )
    assert facts.status == "rendered"
    display = DisplayRecorder()
    monkeypatch.setattr(components, "st", display)
    components.render_result({
        "status": execution.status,
        "analysis_receipt": receipt.model_dump(mode="json"),
        "facts": facts.model_dump(mode="json"),
        "message": "transfer_completed_successfully",
    })
    assert not any(name == "success" for name, _, _ in display.events)
    assert any("Exploratory analysis r1" in str(value) for _, value, _ in display.events)
    assert any(value == receipt.model_dump(mode="json") for _, value, _ in display.events)
    for _, value, contexts in display.events:
        if any(label in str(value) for label in labels):
            assert any("unverified" in title.lower() for title in contexts), (value, contexts)
    assert all("bank receipt verified" not in str(value) for _, value, _ in display.events)


def test_bank_receipt_keeps_verified_presentation(monkeypatch):
    display = DisplayRecorder()
    monkeypatch.setattr(components, "st", display)
    receipt = {"id": "BANK_RECEIPT", "status": "settled", "kind": "transfer"}
    components.render_result({"status": "settled", "receipt": receipt})
    assert ("success", "Executed · bank receipt verified", ()) in display.events
    assert ("json", receipt, ("Technical evidence",)) in display.events
