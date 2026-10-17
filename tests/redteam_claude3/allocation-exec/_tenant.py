"""A second, independent synthetic customer sharing the same gateway and bank."""

from fractions import Fraction

from corridor.crypto.sign import CATALOG, RISK
from corridor.gateway.allocations import draft_allocation, register_allocation
from corridor.sim.keys import public_key
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.sim.wealth_device import WealthDevice
from corridor.stores.bank import add_seconds
from tests.bank_cases import signed

OTHER = "C_OTHER"
OTHER_SESSION = "SESSION_OTHER"
OTHER_ACCOUNT = "A_OTHER"
OTHER_INTENT = "WEALTH_OTHER"


def two_tenant_state():
    state = make_wealth_state()
    products = [
        product.model_copy(update={"eligible_customers": [*product.eligible_customers, OTHER]})
        for product in state.catalog.products
    ]
    catalog = signed(state.catalog.model_copy(update={"products": products}), CATALOG, "bank")
    risk = state.risk_assessments["RISK_DEMO"]
    other_risk = signed(risk.model_copy(update={"id": "RISK_OTHER", "owner": OTHER}), RISK, "risk")
    me = next(iter(state.customers.values()))
    customer = me.model_copy(
        update={
            "id": OTHER,
            "principal": OTHER,
            "display_alias": "Other synthetic customer",
            "device_pubkey": public_key("device-other"),
            "risk_profile_ref": other_risk.id,
            "account_refs": [OTHER_ACCOUNT],
        }
    )
    account = state.accounts["A_CURRENT"].model_copy(
        update={"id": OTHER_ACCOUNT, "owner": OTHER, "opening_balance": Fraction(12000)}
    )
    return state.model_copy(
        update={
            "catalog": catalog,
            "customers": {**state.customers, OTHER: customer},
            "accounts": {**state.accounts, OTHER_ACCOUNT: account},
            "risk_assessments": {**state.risk_assessments, other_risk.id: other_risk},
        }
    )


class OtherTenant:
    """Customer B uses only public gateway entry points with B's own device."""

    def __init__(self, gateway, intents=(OTHER_INTENT,)):
        self.gateway = gateway
        self.device = WealthDevice(OTHER, key_label="device-other")
        now = gateway.store.snapshot().now
        login = self.device.login(session_id=OTHER_SESSION, expires_at=add_seconds(now, 3600))
        assert gateway.login(login).status == "accepted"
        request = allocation_request(source_account_ref=OTHER_ACCOUNT)
        self.requests = {}
        for intent in intents:
            value = self.device.confirm_input(
                intent_id=intent,
                slot="allocation",
                value=request.model_dump(mode="json"),
                now=now,
                step=7,
            )
            assert gateway.submit_input(value).status == "accepted"
            self.requests[intent] = value

    def register(self, intent=OTHER_INTENT):
        draft = draft_allocation(self.gateway, OTHER, intent, self.requests[intent].id)
        signing = self.device.sign_allocation(
            draft,
            [item.item_ref for item in draft.parent.items],
            now=self.gateway.store.snapshot().now,
        )
        result = register_allocation(
            self.gateway,
            draft,
            selection=signing.selection,
            inputs=signing.inputs,
            authorizations=signing.authorizations,
        )
        assert result.status == "ready", result
        return draft
