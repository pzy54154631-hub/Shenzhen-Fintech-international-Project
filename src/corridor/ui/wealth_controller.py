"""Wealth UI adapter: only explicit device gestures create signatures."""

from dataclasses import asdict, replace

from corridor.agent.llm import LLMClient, LLMOutputError, ReplayCorrupt, ReplayMiss
from corridor.agent.wealth_dialogue import GOAL_FIELDS, GoalSlot, WealthCandidate, WealthDialogue
from corridor.crypto.jcs import H
from corridor.gateway.allocations import (
    draft_allocation,
    register_allocation,
)
from corridor.kernel.check import check
from corridor.kernel.rules import RULES
from corridor.schemas.bank import BankAction, BankCertificate, InputTerm
from corridor.schemas.money import fraction_string
from corridor.sim.wealth import allocation_request, make_wealth_state
from corridor.sim.wealth_device import WealthDevice
from corridor.stores.bank import available
from corridor.ui.controller import DemoController, _Builder


class WealthController(DemoController):
    def __init__(self, *, evidence_dir=None, initial_state=None):
        state = initial_state or make_wealth_state()
        if initial_state is None:
            customer = state.customers["C_DEMO"].model_copy(update={"risk_profile_ref": None})
            state = state.model_copy(
                update={
                    "customers": {**state.customers, customer.id: customer},
                    "risk_assessments": {},
                }
            )
        super().__init__(evidence_dir=evidence_dir, initial_state=state, device=WealthDevice())
        self.client = LLMClient(
            mode="scripted",
            api="responses",
            model="gpt-6.1-sol",
            reasoning_effort="low",
            env_file=None,
            context_guard=self.gateway.vault.ensure_safe,
        )
        self.wealth_chat = None
        self.candidate = None
        self.comparison = None
        self.signed_goals = None
        self.draft = None
        self.parent_id = None
        self.leg = None
        self.guided = False
        self._confirmed_hash = None
        self.last_result = None
        self.history = []
        self.leg_results = {}
        self.dialogue_result = None
        self.suitability_details = None
        self._goal_results = {}
        self.proposal_source = "scripted"

    @property
    def planner_source(self):
        return f"live: {self.client.model}" if self.client.mode == "live" else "scripted"

    def at_transaction_boundary(self):
        snapshot = self.execution_snapshot()
        signed_ref = self.wealth_chat.signed_request_ref if self.wealth_chat else None
        if signed_ref:
            if not snapshot:
                return False
            parent = self.state.allocation_plans[snapshot["allocation_ref"]]
            if parent.request_ref != signed_ref:
                return False
        if snapshot:
            return (
                snapshot["status"] in {"completed", "cancelled", "failed", "partially_executed"}
                and self.leg is None
            )
        return self.comparison is None and self.draft is None and self.leg is None

    def set_client(self, client):
        if client is self.client:
            return
        if not self.at_transaction_boundary():
            raise ValueError("Planner cannot change during a transaction")
        self.client = client
        if self.wealth_chat is not None:
            self.wealth_chat.client = client
            self.wealth_chat.require_live = client.mode == "live"
            self.wealth_chat.max_model_attempts = 1 if client.mode == "live" else 3
            self.wealth_chat.mode = "assistant"
            self.wealth_chat._source = "not_run" if client.mode == "live" else "scripted"
        self.guided = False

    def start_session(self):
        previous_session = self.session
        result = super().start_session()
        if self.session != previous_session:
            self.withdraw_proposal()
        if self.wealth_chat is None or self.wealth_chat.session_id != self.session:
            self.wealth_chat = WealthDialogue(
                self.gateway,
                self.client,
                principal=self.device.principal,
                session_id=self.session,
                task_id="UI-WEALTH",
                source_account_ref="A_CURRENT",
                allowed_types=["wealth"],
                evaluation=True,
                require_live=self.client.mode == "live",
                max_model_attempts=1 if self.client.mode == "live" else 3,
            )
            self.dialogue_result = None
            self.suitability_details = None
            self._goal_results = {}
        return result

    def risk_profile(self):
        customer = self.state.customers[self.device.principal]
        risk = self.state.risk_assessments.get(customer.risk_profile_ref or "")
        return risk.model_dump(mode="json") if risk else None

    def submit_risk_answers(self, answers):
        self._require_login()
        builder = _Builder(self, self._id("questionnaire"))
        signed = self.device.confirm_input(
            intent_id=builder.intent(),
            slot="answers",
            value=answers,
            now=self.state.now,
        )
        result = self.gateway.submit_input(signed)
        if result.status != "accepted":
            return self._result(result)
        prepared = builder.prepare(
            "risk_assess",
            {"answers_input_ref": signed.id},
            {"answers_input_ref": InputTerm(input_ref=signed.id, slot="answers")},
            inputs=[signed],
        )
        result = self.gateway.query(prepared.action, prepared.cert)
        if result.status == "settled":
            self.withdraw_proposal()
            receipt = result.analysis_receipt
            if receipt:
                self.suitability_details = {
                    "raw_level": receipt.results["level"].value,
                    "effective_level": receipt.results["effective_level"].value,
                    "clarification": receipt.results["suitability_clarification"].value,
                }
        return self._result(result)

    def comparison_is_current(self):
        if self.comparison is None:
            return False
        return (
            check(self.comparison.action, self.comparison.cert, self.state, phase="propose").outcome
            == "Accept"
        )

    def receive_goal(self, text, *, request_id):
        self._require_login()
        digest = self.gateway.utterance_digest(text, None)
        if request_id in self._goal_results:
            old_digest, result = self._goal_results[request_id]
            if old_digest != digest:
                raise ValueError("Request ID cannot replace an existing utterance")
            return result.copy()
        try:
            turn = self.wealth_chat.turn(text, request_id=request_id)
        except (ReplayMiss, ReplayCorrupt):
            self.withdraw_proposal()
            raise
        if turn.mode == "guided" and not self.guided:
            notice = self.withdraw_proposal()
            phase = "terminal" if self.execution_snapshot() else "collecting"
            self.wealth_chat.phase = phase
            turn = replace(
                turn,
                phase=phase,
                proposal_withdrawn=True,
                message="Guided mode (assistant unavailable). " + notice,
                device_action="lookup" if self.wealth_chat.reconciliation_ref else None,
            )
        signal = turn.suitability_signal
        if (
            signal
            and signal.get("effective_level_cap") is not None
            and self.comparison is not None
            and not self.comparison_is_current()
        ):
            self.withdraw_proposal()
        result = self._dialogue_view(turn)
        self._goal_results[request_id] = (digest, result.copy())
        return result

    def _dialogue_view(self, turn):
        self.guided = turn.mode == "guided"
        self.candidate = WealthCandidate(
            self.wealth_chat.intent_id, turn.pending_slots, turn.question
        )
        if (
            self.wealth_chat.comparison is not None
            and self.wealth_chat.comparison is not self.comparison
        ):
            self.proposal_source = (
                f"live: {self.client.model}"
                if turn.evidence_source == "live"
                else turn.evidence_source
            )
        self.comparison = self.wealth_chat.comparison
        if turn.proposal_withdrawn or self.comparison is None:
            self.draft = None
            self.leg = None
            self._confirmed_hash = None
            if self.parent_id and self.wealth_chat.execution_ref != self.parent_id:
                if self.parent_id not in self.history:
                    self.history.append(self.parent_id)
                self.parent_id = self.wealth_chat.reconciliation_ref
        result = asdict(turn)
        result["facts"] = [fact.model_dump(mode="json") for fact in turn.facts]
        result["projected_facts"] = [asdict(fact) for fact in turn.projected_facts]
        signal = result.get("suitability_signal")
        if signal and signal.get("effective_level_cap") is not None:
            self.suitability_details = {
                "effective_level": signal["effective_level_cap"],
                "clarification": signal["message"],
            }
        if self.comparison and self.comparison.result.analysis_receipt:
            self.suitability_details = self.comparison.result.analysis_receipt.parameters.get(
                "suitability", self.suitability_details
            )
        result.update(
            status="collecting" if turn.phase in {"collecting", "adjusting"} else turn.phase,
            source=turn.evidence_source,
            guided=self.guided,
            planner_source=(
                f"live: {self.client.model}" if turn.evidence_source == "live" else "scripted"
            ),
        )
        self.dialogue_result = result
        return result.copy()

    def withdraw_proposal(self):
        pending = None
        if self.parent_id:
            result = self.gateway.stop_allocation(self.parent_id)
            if result.status == "unknown":
                pending = self.parent_id
                if self.wealth_chat:
                    self.wealth_chat.reconciliation_ref = pending
            if self.parent_id not in self.history:
                self.history.append(self.parent_id)
        self.comparison = None
        self.draft = None
        self.parent_id = pending
        self.leg = None
        self._confirmed_hash = None
        if self.wealth_chat is not None:
            self.wealth_chat.comparison = None
        return self._withdrawal_notice()

    def _withdrawal_notice(self):
        snapshot = self.execution_snapshot()
        if snapshot:
            status = snapshot["status"]
            if status == "partially_executed":
                return (
                    "Partially executed. Settled holdings remain; remaining work and approvals "
                    "are withdrawn. Nothing is reversed automatically."
                )
            if status == "unknown":
                return "Outcome pending reconciliation - do not retry. Remaining work is stopped."
            if status == "completed":
                return "Execution complete. Settled holdings and verified receipts remain."
            return "Remaining execution stopped. Review the retained plan and leg receipts."
        return "The proposal and pending approvals are withdrawn. Confirm fresh goals on Device."

    def stop(self, plan_id=None):
        # Withdraw all cards before any best-effort dialogue or model work.
        notice = self.withdraw_proposal()
        result = super().stop(plan_id)
        if self.wealth_chat is not None:
            try:
                self._dialogue_view(
                    self.wealth_chat.turn("Stop", request_id=self._id("wealth-stop"))
                )
            except (
                ReplayMiss,
                ReplayCorrupt,
                ValueError,
                RuntimeError,
                TimeoutError,
                ConnectionError,
            ):
                pass
        self.candidate = None
        snapshot = self.execution_snapshot()
        return {
            **result,
            "status": snapshot["status"] if snapshot else result["status"],
            "message": notice,
            "execution": snapshot,
        }

    def approval_window(self):
        return self.gateway.approval_budget(self.device.principal)

    def prepare_allocation(self):
        self._require_login()
        if self.comparison is None or self.signed_goals is None:
            raise ValueError("A current comparison is required")
        if self.draft is None:
            self.draft = draft_allocation(
                self.gateway,
                self.device.principal,
                self.signed_goals.scope_id,
                self.signed_goals.id,
            )
        return self.draft.overview

    def start_allocation(self, selected_items):
        self._require_login()
        self.prepare_allocation()
        expected = [item.item_ref for item in self.draft.parent.items]
        if sorted(selected_items) != sorted(expected):
            return {
                "status": "draft",
                "message": "Select every leg to start the complete allocation.",
            }
        if self.parent_id:
            return {"status": self.execution_snapshot()["status"]}
        window = self.approval_window()
        if len(expected) > window["remaining"]:
            return {
                "status": "approval_budget",
                "needed": len(expected),
                **window,
                "message": (
                    "Not enough approvals remain in the current window. No purchases submitted."
                ),
            }
        signed = self.device.sign_allocation(self.draft, selected_items, now=self.state.now)
        result = register_allocation(
            self.gateway,
            self.draft,
            selection=signed.selection,
            inputs=signed.inputs,
            authorizations=signed.authorizations,
        )
        if result.status != "ready":
            return self._result(result)
        self.parent_id = self.draft.parent.id
        self._dialogue_view(self.wealth_chat.attach_execution(self.parent_id))
        return self.prepare_leg()

    def prepare_leg(self):
        if self.leg:
            return {"status": "waiting_mfa" if not self.leg.get("verified") else "waiting_approval"}
        result = self.gateway.advance_allocation(self.parent_id)
        if result.status in {"waiting_mfa", "waiting_approval"}:
            action = BankAction.model_validate(result.details["action"])
            cert = BankCertificate.model_validate(result.details["cert"])
            self.leg = {
                "action": action,
                "cert": cert,
                "card": result.details["card"],
                "verified": False,
            }
        return self._result(result)

    def prepare_leg_mfa(self, action_id):
        """Return the simulated device factor only to the explicit UI panel."""
        self._require_login()
        if self.leg is None or self.leg["action"].action_id != action_id:
            return None
        leg = self.leg
        if leg["verified"]:
            return None
        if not leg.get("mfa_challenge"):
            challenge = self.gateway.request_mfa(
                leg["action"], leg["cert"], request_id=self._id("wealth-mfa")
            )
            if challenge is None:
                return None
            leg["mfa_challenge"] = challenge
        return self.gateway.mfa.test_code(leg["mfa_challenge"])

    def verify_leg(self, action_id, code=None):
        self._require_login()
        if self.leg is None or self.leg["action"].action_id != action_id:
            return {"status": "rejected", "rule_ids": ["APR-VOID"]}
        leg = self.leg
        if leg["verified"]:
            return {"status": "mfa_verified"}
        if self.prepare_leg_mfa(action_id) is None:
            return {"status": "rejected", "rule_ids": ["MFA-INVALID"]}
        challenge = leg["mfa_challenge"]
        grant = (
            self.device.complete_mfa(self.gateway.mfa, challenge, now=self.state.now)
            if code is None
            else self.gateway.mfa.verify(challenge, code, now=self.state.now)
        )
        if grant is None or self.gateway.submit_mfa(grant).status != "accepted":
            return {"status": "rejected", "rule_ids": ["MFA-INVALID"]}
        leg["cert"] = leg["cert"].model_copy(update={"mfa_grant_refs": [grant.grant_id]})
        leg["verified"] = True
        return {"status": "mfa_verified"}

    def approve_leg(self, action_id):
        self._require_login()
        if action_id in self.leg_results:
            return self.leg_results[action_id].copy()
        if self.leg is None or self.leg["action"].action_id != action_id:
            return {"status": "rejected", "rule_ids": ["APR-VOID"]}
        leg = self.leg
        if not leg["verified"]:
            return {"status": "waiting_mfa", "rule_ids": ["TIER-MFA-REQUIRED"]}
        token = self.device.approve(
            leg["action"],
            leg["cert"],
            leg["card"],
            now=self.state.now,
            sequence=len(self.leg_results),
        )
        result = self._result(self.gateway.dispatch(leg["action"], leg["cert"], token))
        self.leg_results[action_id] = result
        self.leg = None
        if result["status"] == "settled" and self.execution_snapshot()["status"] != "completed":
            self.prepare_leg()
        self._dialogue_view(self.wealth_chat.execution_status())
        return result.copy()

    def execution_snapshot(self, parent_id=None):
        parent_id = parent_id or self.parent_id
        if parent_id is None and self.comparison is None and self.history:
            parent_id = self.history[-1]
        if not parent_id:
            return None
        result = self.gateway.allocation_snapshot(parent_id)
        parent = self.state.allocation_plans[parent_id]
        request = self.state.user_inputs[parent.request_ref].value
        result["available_balance"] = fraction_string(
            available(self.state, request["source_account_ref"])
        )
        result["account_ref"] = request["source_account_ref"]
        return result

    def lookup_pending(self, parent_id=None):
        snapshot = self.execution_snapshot(parent_id)
        results = []
        for item in snapshot["items"]:
            if item["status"] in {"unknown", "reserved"}:
                results.append(self._result(self.gateway.reconcile(item["decision_key"])))
        if self.wealth_chat.reconciliation_ref:
            self._dialogue_view(self.wealth_chat.refresh_reconciliation())
        elif self.wealth_chat.execution_ref:
            self._dialogue_view(self.wealth_chat.execution_status())
        return {"status": "lookup_complete", "results": results}

    def keep_or_handoff(self, *, handoff=False):
        if self.parent_id is None:
            return {"status": "no_active_plan"}
        result = self.gateway.stop_allocation(self.parent_id, handoff=handoff)
        self.leg = None
        self._dialogue_view(self.wealth_chat.execution_status())
        return self._result(result)

    def confirm_goals(self, fields):
        self._require_login()
        if self.candidate is None:
            return {"status": "clarify", "rule_ids": ["AUTH-SCOPE"]}
        digest = H(fields)
        if digest == self._confirmed_hash and self.comparison_is_current():
            return self.last_result.copy()
        if self.wealth_chat.signed_request_ref:
            self.receive_goal("Change my goals", request_id=self._id("goal-edit"))
        self.comparison = None
        try:
            request = allocation_request(**fields)
        except ValueError:
            return {"status": "rejected", "rule_ids": ["BIC-PREFERENCE"]}
        profile = self.risk_profile()
        if profile is None or profile["expires_at"] <= self.state.now:
            return {"status": "rejected", "rule_ids": ["BIC-RISK"]}
        self.wealth_chat.slots = {
            name: GoalSlot(request.model_dump(mode="json")[name], "heard, not signed")
            for name in GOAL_FIELDS
        }
        request = self.wealth_chat.goal_sheet()
        signed = self.device.confirm_input(
            intent_id=self.wealth_chat.intent_id,
            slot="allocation",
            value=request.model_dump(mode="json"),
            now=self.state.now,
        )
        self.signed_goals = signed
        try:
            self._dialogue_view(self.wealth_chat.confirm_goals(signed))
            result = self.receive_goal("Propose allocation", request_id=self._id("wealth-proposal"))
        except (ReplayMiss, ReplayCorrupt):
            raise
        except LLMOutputError:
            return {
                "status": "rejected",
                "message": (
                    "Live AI failed. No scripted fallback ran. Check access, budget and retry."
                ),
            }
        except (ValueError, RuntimeError, TimeoutError) as error:
            rule = str(error) if str(error) in RULES else "ALLOC-SELECT"
            return {
                "status": "rejected",
                "rule_ids": [rule],
                "message": "No allocation was constructed. Review your goals and policy.",
            }
        if self.comparison is None:
            return {**result, "status": "rejected"}
        self._confirmed_hash = digest
        self.proposal_source = self.planner_source
        self.last_result = {
            **result,
            "status": "comparison_only",
            "biac": self.comparison.cert.allocation.model_dump(mode="json"),
        }
        return self.last_result.copy()
