"""Explicit simulated device gestures for a complete allocation overview."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from corridor.crypto.jcs import H
from corridor.crypto.sign import CONTROL, INPUT, sign
from corridor.schemas.allocation import AllocationPlan
from corridor.schemas.bank import (
    InputTerm,
    OperationAuthorization,
    Plan,
    SessionAuthorization,
    StateTerm,
    UserInput,
)
from corridor.schemas.money import fraction_string
from corridor.sim.device import Device
from corridor.sim.keys import stable_id
from corridor.stores.bank import add_seconds

if TYPE_CHECKING:
    from corridor.gateway.allocations import AllocationDraft


@dataclass(frozen=True)
class AllocationSigning:
    selection: UserInput | None
    inputs: tuple[UserInput, ...]
    authorizations: tuple[OperationAuthorization, ...]


class WealthDevice(Device):
    def login(self, *, session_id: str, expires_at: str) -> SessionAuthorization:
        authorization = super().login(session_id=session_id, expires_at=expires_at)
        authorization = authorization.model_copy(
            update={"read_kinds": [*authorization.read_kinds, "allocation_compare"]}
        )
        return authorization.model_copy(update={"sig": sign(self._key, CONTROL, authorization)})

    def sign_allocation(
        self, draft: "AllocationDraft", selected_items: list[str], *, now: str
    ) -> AllocationSigning:
        """Sign only an explicit selection of every displayed positive item.

        This is an input/authority gesture. It does not create an approval token
        or satisfy any child's independent MFA requirement.
        """
        parent = AllocationPlan.model_validate(draft.parent.model_dump(mode="python"))
        expected = sorted(item.item_ref for item in parent.items)
        if sorted(selected_items) != expected:
            return AllocationSigning(None, (), ())
        body = parent.model_dump(mode="json")
        body.pop("plan_hash")
        if (
            parent.principal != self.principal
            or H(body) != parent.plan_hash
            or H(draft.biac) != parent.biac_hash
            or parent.selection_input_ref is None
            or len(draft.children) != len(parent.items)
            or any(
                H(child) != item.child_plan_hash
                for child, item in zip(draft.children, parent.items, strict=True)
            )
        ):
            raise ValueError("Displayed allocation does not match its immutable parent")
        if [(item.product_ref, item.principal, item.fee_buy) for item in parent.items] != [
            (row.product_id, row.principal, row.fee_buy) for row in draft.biac.allocation
        ]:
            raise ValueError("Displayed allocation amounts differ from the certificate")
        for item, raw_child in zip(parent.items, draft.children, strict=True):
            child = Plan.model_validate(raw_child.model_dump(mode="python"))
            expected_intent = stable_id(
                parent.parent_intent_id, 0, f"allocation-child-{item.product_ref}"
            )
            expected_item = stable_id(
                parent.parent_intent_id, 0, f"allocation-item-{item.product_ref}"
            )
            if (
                item.child_intent_id != expected_intent
                or item.item_ref != expected_item
                or child.intent_id != expected_intent
                or child.principal != self.principal
                or child.plan_id != item.child_plan_id
                or child.ownership_epoch != 0
                or child.goal_input_refs != item.input_refs
                or len(item.input_refs) != 2
                or len(child.nodes) != 1
                or child.nodes[0].node_id != item.child_node_id
                or child.nodes[0].tool != "purchase_product"
                or child.nodes[0].depends_on
            ):
                raise ValueError("Displayed allocation child scope is not device-derived")
            args = child.nodes[0].args
            source, product = args.get("source_ref"), args.get("product_ref")
            if (
                set(args)
                != {
                    "source_ref",
                    "product_ref",
                    "amount_ref",
                    "allocation_ref",
                    "allocation_item_ref",
                }
                or not isinstance(source, StateTerm)
                or source.collection != "accounts"
                or source.object_ref != draft.biac.source_account_ref
                or source.field != "id"
                or not isinstance(product, StateTerm)
                or product.collection != "catalog"
                or product.object_ref != item.product_ref
                or product.field != "id"
                or args.get("amount_ref") != InputTerm(input_ref=item.input_refs[0], slot="amount")
                or any(
                    args.get(field)
                    != InputTerm(input_ref=item.input_refs[1], slot="allocation_binding")
                    for field in ("allocation_ref", "allocation_item_ref")
                )
            ):
                raise ValueError("Displayed allocation child provenance does not match its item")
        selection = UserInput.model_validate({
            "id": parent.selection_input_ref,
            "principal": self.principal,
            "batch_id": stable_id(parent.parent_intent_id, 0, "batch"),
            "slot": "allocation_selection",
            "scope_id": parent.parent_intent_id,
            "submitted_at": now,
            "value": {
                "parent_id": parent.id,
                "plan_hash": parent.plan_hash,
                "biac_hash": parent.biac_hash,
                "request_ref": parent.request_ref,
                "selected_items": expected,
            },
            "sig": "0" * 128,
        })
        selection = selection.model_copy(update={"sig": sign(self._key, INPUT, selection)})
        inputs: list[UserInput] = []
        authorizations: list[OperationAuthorization] = []
        for item in parent.items:
            batch = stable_id(item.child_intent_id, 0, "batch")
            amount = UserInput.model_validate({
                "id": item.input_refs[0],
                "principal": self.principal,
                "batch_id": batch,
                "slot": "amount",
                "scope_id": item.child_intent_id,
                "submitted_at": now,
                "value": {"amount": fraction_string(item.principal), "ccy": "CNY"},
                "sig": "0" * 128,
            })
            amount = amount.model_copy(update={"sig": sign(self._key, INPUT, amount)})
            binding = UserInput.model_validate({
                "id": item.input_refs[1],
                "principal": self.principal,
                "batch_id": batch,
                "slot": "allocation_binding",
                "scope_id": item.child_intent_id,
                "submitted_at": now,
                "value": {
                    "allocation_ref": parent.id,
                    "allocation_item_ref": item.item_ref,
                    "parent_intent_id": parent.parent_intent_id,
                    "request_hash": draft.biac.request_hash,
                    "biac_hash": parent.biac_hash,
                    "product_ref": item.product_ref,
                    "principal": fraction_string(item.principal),
                    "fee_buy": fraction_string(item.fee_buy),
                    "parent_plan_hash": parent.plan_hash,
                },
                "sig": "0" * 128,
            })
            binding = binding.model_copy(update={"sig": sign(self._key, INPUT, binding)})
            authorization = self.authorize({
                "id": item.authorization_ref,
                "intent_id": item.child_intent_id,
                "allowed_kind": "purchase_product",
                "object_refs": sorted({draft.biac.source_account_ref, item.product_ref, parent.id}),
                "amount_bound": fraction_string(item.principal + item.fee_buy),
                "expires_at": add_seconds(now, 300),
                "input_hashes": sorted([H(amount), H(binding)]),
            })
            inputs.extend([amount, binding])
            authorizations.append(authorization)
        return AllocationSigning(selection, tuple(inputs), tuple(authorizations))
