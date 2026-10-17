"""Red-team helpers for the BIAC selector (signed state built only with sim keys)."""

from fractions import Fraction

from corridor.crypto.sign import ALLOCATION_POLICY, CATALOG
from corridor.kernel.allocation import evaluate_allocation
from corridor.sim.device import Device
from corridor.sim.wealth import allocation_request, make_wealth_state
from tests.bank_cases import signed

PRINCIPAL = "C_DEMO"
INTENT = "RT3_BIAC"


def sign_request(request=None, state=None, *, step=1, supersedes=None, intent=INTENT):
    state = state or make_wealth_state()
    request = request or allocation_request()
    value = Device().confirm_input(
        intent_id=intent,
        slot="allocation",
        value=request.model_dump(mode="json"),
        now=state.now,
        step=step,
        supersedes=supersedes,
    )
    state = state.model_copy(update={"user_inputs": {**state.user_inputs, value.id: value}})
    return value.id, state


def evaluate(ref, state, intent=INTENT, **kw):
    return evaluate_allocation(PRINCIPAL, intent, ref, state, **kw)


def with_products(state, changes=None, *, only=None, extra=()):
    values = [
        p.model_copy(update=(changes or {}).get(p.id, {}))
        for p in state.catalog.products
        if only is None or p.id in only
    ]
    values.extend(extra)
    catalog = signed(state.catalog.model_copy(update={"products": values}), CATALOG, "bank")
    return state.model_copy(update={"catalog": catalog})


def with_profile(state, level="C2", *, weights=None, bands=None, groups=None):
    value = next(iter(state.allocation_policies.values()))
    profile = value.profiles[level]
    update = {}
    if weights is not None:
        update["model_weights"] = {k: Fraction(v) for k, v in weights.items()}
    if bands is not None:
        update["bands"] = [
            band.model_copy(
                update={
                    "lower": Fraction(bands.get(band.sleeve, (band.lower, band.upper))[0]),
                    "upper": Fraction(bands.get(band.sleeve, (band.lower, band.upper))[1]),
                }
            )
            for band in profile.bands
        ]
    if groups is not None:
        update["group_bounds"] = groups
    value = signed(
        value.model_copy(
            update={"profiles": {**value.profiles, level: profile.model_copy(update=update)}}
        ),
        ALLOCATION_POLICY,
        "bank",
    )
    return state.model_copy(update={"allocation_policies": {value.id: value}})


def weights(r1, r2, r3=0, r4=0, r5=0):
    return {
        "R1": Fraction(r1),
        "R2": Fraction(r2),
        "R3": Fraction(r3),
        "R4": Fraction(r4),
        "R5": Fraction(r5),
    }


def vector(cert):
    return {item.product_id: item.principal for item in cert.allocation}
