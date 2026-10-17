"""Red-team round 3: explicit-adjustment binding to its model default (DESIGN-WEALTH §6).

Spec: "用户调整会产生新的已签输入并替代旧输入 ... 它不再授予旧默认配置执行权" and
"同一上下文指 base_context_hash 相同，不要求两个完整 request_hash 相同".
"""

import importlib.util as _iu
from pathlib import Path as _P

from corridor.crypto.jcs import H
from corridor.sim.wealth import allocation_request

_spec = _iu.spec_from_file_location("rt3_biac", _P(__file__).with_name("_biac.py"))
B = _iu.module_from_spec(_spec)
_spec.loader.exec_module(B)


def _explicit(default, **changes):
    return allocation_request(
        selection_mode="explicit_weights",
        target_weights=B.weights("3/5", "2/5"),
        model_biac_hash=H(default),
        reason_code="user_adjustment",
        **changes,
    )


def test_explicit_adjustment_must_replace_its_model_default():
    """The trusted device supersedes its default as required by DESIGN-WEALTH section 6.

    RT3-BIAC-01 was rejected because its device fixture omitted signed supersession.
    Keep the original non-coexistence assertion as a control for the valid device flow.
    """
    ref, state = B.sign_request()
    default = B.evaluate(ref, state).certificate
    assert default is not None
    new_ref, state = B.sign_request(_explicit(default), state, step=2, supersedes=ref)
    adjusted = B.evaluate(new_ref, state)
    old = B.evaluate(ref, state)
    assert adjusted.certificate is not None, adjusted.errors
    assert old.errors == ("BIC-PREFERENCE",)
    both_executable = adjusted.certificate is not None and old.certificate is not None
    assert not both_executable, (
        "explicit adjustment accepted while its model default stays current; "
        f"adjusted={B.vector(adjusted.certificate)} default={B.vector(old.certificate)}"
    )


def test_explicit_adjustment_same_base_context_regardless_of_allowed_types_order():
    """Model lookup compares allowed_types as an ordered list, base_context_hash sorts it.

    The default and adjustment have the identical common economic context (the spec's
    sole sameness criterion), yet the signed adjustment is refused with ALLOC-SELECT
    because the device serialised the type set in a different order.
    """
    ref, state = B.sign_request(allocation_request(allowed_types=["deposit", "wealth"]))
    default = B.evaluate(ref, state).certificate
    assert default is not None
    new_ref, state = B.sign_request(
        _explicit(default, allowed_types=["wealth", "deposit"]), state, step=2, supersedes=ref
    )
    evaluation = B.evaluate(new_ref, state)
    assert evaluation.errors == (), evaluation.errors
    assert evaluation.certificate.base_context_hash == default.base_context_hash
    assert evaluation.certificate.model_biac_hash == H(default)
