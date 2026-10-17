"Explicit English transfer fields backed by the existing device approval workflow."

import streamlit as st

from corridor.crypto.jcs import H
from corridor.gateway.handles import available_handles
from corridor.schemas.bank import InputTerm, StateTerm
from corridor.schemas.money import fraction_string, parse_fraction
from corridor.ui.components import render_card, render_result
from corridor.ui.messages import tr


def _choices(controller):
    views = available_handles(controller.state, controller.device.principal, controller.session)
    accounts = [
        item.id for item in views if item.kind == "account" and item.account_kind == "current"
    ]
    contacts = [item.id for item in views if item.kind == "contact" and item.verified]
    return accounts, contacts


def preview_structured_transfer(controller, source, contact, amount, request_id):
    "Retain an unsigned canonical card; the later approval gesture signs its inputs."
    controller._require_login()
    accounts, contacts = _choices(controller)
    if source not in accounts or contact not in contacts:
        raise ValueError(tr("Choose an owned current account and a verified recipient."))
    if not isinstance(amount, str):
        raise ValueError(tr("Enter the amount as exact CNY text."))
    value = parse_fraction(amount.strip())
    if value <= 0 or (value * 100).denominator != 1:
        raise ValueError(tr("Enter a positive CNY amount in whole cents."))
    exact = fraction_string(value)
    controller._claim_request(
        request_id, {"kind": "transfer", "source": source, "contact": contact, "amount": exact}
    )

    def build(builder):
        accounts, contacts = _choices(builder)
        if source not in accounts or contact not in contacts:
            raise ValueError(tr("The selected account or recipient is no longer available."))
        signed = builder.device.confirm_input(
            intent_id=builder.intent(),
            slot="amount",
            value={"amount": exact, "ccy": "CNY"},
            now=builder.state.now,
        )
        selection = builder.device.confirm_input(
            intent_id=builder.intent(),
            slot="contact_ref",
            value=contact,
            now=builder.state.now,
        )
        authorization = builder.operation(
            "transfer", [source, contact], [signed, selection], amount_bound=exact
        )
        return builder.prepare(
            "transfer",
            {"source_ref": source, "contact_ref": contact, "amount_ref": signed.id},
            {
                "source_ref": StateTerm(
                    collection="accounts",
                    object_ref=source,
                    field="id",
                    version=builder.state.accounts[source].version,
                ),
                "contact_ref": StateTerm(
                    collection="contacts",
                    object_ref=contact,
                    field="id",
                    version=builder.state.contacts[contact].version,
                ),
                "amount_ref": InputTerm(input_ref=signed.id, slot="amount"),
            },
            inputs=[signed, selection],
            authorization=authorization,
        )

    return controller._preview_operation(build, request_id=request_id)


def render_structured_transfer(controller):
    st.subheader(tr("Transfer with explicit device fields"))
    st.caption(
        tr("Select a verified recipient and enter the exact amount. Previewing signs nothing.")
    )
    try:
        accounts, contacts = _choices(controller)
    except (ValueError, RuntimeError, KeyError):
        st.warning(
            tr("Your session or account changed. Sign in again before preparing a transfer.")
        )
        return
    with st.form("structured_transfer_form"):
        source = st.selectbox(
            tr("Source account"),
            [None, *accounts],
            format_func=lambda value: tr("Choose an account") if value is None else value,
            key="structured_source",
        )
        contact = st.selectbox(
            tr("Verified recipient"),
            [None, *contacts],
            format_func=lambda value: tr("Choose a recipient") if value is None else value,
            key="structured_contact",
        )
        amount = st.text_input(tr("Transfer amount (CNY)"), key="structured_amount")
        submitted = st.form_submit_button(tr("Preview transfer"), key="structured_preview")
    if submitted:
        fingerprint = H({"source": source, "contact": contact, "amount": amount})
        previous = st.session_state.get("structured_transfer_request")
        if previous is None or previous["fingerprint"] != fingerprint:
            previous = {"fingerprint": fingerprint, "id": controller._id("structured-transfer")}
            st.session_state["structured_transfer_request"] = previous
        try:
            pending = preview_structured_transfer(
                controller, source, contact, amount, previous["id"]
            )
        except (ValueError, RuntimeError, KeyError):
            st.warning(
                tr(
                    "No transfer was prepared. Select an account, recipient and positi"
                    "ve whole-cent amount."
                )
            )
            st.session_state.pop("structured_transfer_pending", None)
            st.session_state.pop("structured_transfer_result", None)
        else:
            st.session_state["structured_transfer_pending"] = pending
            st.session_state.pop("structured_transfer_result", None)
    pending = st.session_state.get("structured_transfer_pending")
    if pending is None:
        return
    identifier = pending["pending_id"]
    if identifier not in controller._pending:
        st.info(tr("This transfer draft was withdrawn. Prepare a new draft to continue."))
        return
    result = controller._results.get(identifier, st.session_state.get("structured_transfer_result"))
    render_card(pending["card"], canonical=True)
    if identifier not in controller._results:
        if st.button(tr("Confirm transfer on device"), key="structured_approve", type="primary"):
            try:
                result = controller.approve_pending(identifier)
            except (ValueError, RuntimeError, KeyError):
                st.warning(
                    tr(
                        "The transfer result could not be confirmed. Check Evidence & Audi"
                        "t before retrying."
                    )
                )
                return
            st.session_state["structured_transfer_result"] = result
            if result.get("replacement"):
                st.session_state["structured_transfer_pending"] = result["replacement"]
                st.rerun()
        if pending["card"].get("tier") == "red":
            st.caption(
                tr(
                    "Confirm this intent, then open Device for independent simulated M"
                    "FA and approval."
                )
            )
    render_result(result)
    if identifier in controller._results and st.button(
        tr("Prepare another transfer"), key="structured_new"
    ):
        for key in (
            "structured_transfer_pending",
            "structured_transfer_result",
            "structured_transfer_request",
        ):
            st.session_state.pop(key, None)
        st.rerun()
