
"""
TrustGate-MCP - Step 30
Hybrid GenAI + Deterministic Security Gateway

Integrates:
- Step 21: ReferenceGateway
- Step 29: TrustGateAIGuard

The hybrid gateway:
1. Resolves the model-visible document reference.
2. Checks deterministic authorization before execution.
3. Requests an internal GenAI security assessment.
4. Combines both decisions.
5. Executes storage only if both layers ALLOW.

No real MCP storage operation is executed by the
standalone tests at the bottom of this file.
"""

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Optional

from step21_reference_gateway import ReferenceGateway
from trustgate_ai_guard import TrustGateAIGuard


@dataclass
class HybridResult:
    decision: str
    reason: str
    executed: bool
    deterministic_decision: str
    ai_decision: str
    ai_assessment: Optional[dict]

    def as_dict(self):
        return {
            "decision": self.decision,
            "reason": self.reason,
            "executed": self.executed,
            "deterministic_decision": (
                self.deterministic_decision
            ),
            "ai_decision": self.ai_decision,
            "ai_assessment": self.ai_assessment,
        }


class HybridTrustGate:
    """
    Wraps a real ReferenceGateway.

    This class must be the only storage entry point
    exposed to the protected agent during hybrid mode.
    """

    def __init__(
        self,
        gateway: ReferenceGateway,
        guard: Optional[TrustGateAIGuard] = None,
    ):
        self.gateway = gateway
        self.guard = (
            guard if guard is not None
            else TrustGateAIGuard()
        )

    @staticmethod
    def _classification_from_taint(taint_record):
        """
        Return a conservative classification hint.

        This value is explanatory input to the AI,
        not a replacement for the gateway's own
        authorization decision.
        """
        if taint_record is None:
            return "unknown"

        return str(taint_record)

    def _trusted_classification(self, handle):
        """
        The model does not supply classification.

        We derive a hint from the trusted gateway's
        taint record, if one is available.
        """
        try:
            taint_id = self.gateway.handle_to_taint.get(
                handle
            )

            if taint_id is None:
                return "unknown"

            taint_state = self.gateway.taint

            # Do not assume a particular internal
            # TaintState storage representation.
            return (
                "gateway-tracked taint record: "
                + str(taint_id)
            )

        except Exception:
            return "unknown"

    @staticmethod
    def combine_decisions(
        deterministic_decision,
        ai_decision,
    ):
        """
        BLOCK takes priority over REVIEW.
        Only ALLOW + ALLOW permits execution.
        """

        if deterministic_decision == "BLOCK":
            return "BLOCK"

        if deterministic_decision not in (
            "ALLOW",
            "BLOCK",
            "CONFIRM",
        ):
            return "REVIEW"

        if deterministic_decision == "CONFIRM":
            return "REVIEW"

        if ai_decision == "BLOCK":
            return "BLOCK"

        if ai_decision == "REVIEW":
            return "REVIEW"

        if (
            deterministic_decision == "ALLOW"
            and ai_decision == "ALLOW"
        ):
            return "ALLOW"

        return "REVIEW"

    async def store_ref(
        self,
        document_ref: str,
        workspace: str,
        user_request: str,
        tool_output: str,
    ) -> HybridResult:
        """
        The protected agent proposes a storage action.

        user_request:
            Original trusted user request.

        tool_output:
            Raw MCP output that influenced the agent.

        These values must come from the trusted
        orchestration layer, not agent-generated
        tool-call arguments.
        """

        # -------------------------------------------------
        # 1. Resolve the gateway-owned reference
        # -------------------------------------------------

        handle = self.gateway._resolve_reference(
            document_ref
        )

        if handle is None:
            return HybridResult(
                decision="REVIEW",
                reason=(
                    "Unknown or foreign document reference"
                ),
                executed=False,
                deterministic_decision="CONFIRM",
                ai_decision="NOT_RUN",
                ai_assessment=None,
            )

        # -------------------------------------------------
        # 2. Check deterministic policy
        # -------------------------------------------------

        policy_result = (
            self.gateway.evaluate_storage(
                handle,
                workspace,
            )
        )

        deterministic_decision = (
            policy_result.decision
        )

        if deterministic_decision != "ALLOW":

            final_decision = self.combine_decisions(
                deterministic_decision,
                "NOT_RUN",
            )

            return HybridResult(
                decision=final_decision,
                reason=(
                    "Deterministic gateway rejected "
                    "or held the action: "
                    + policy_result.reason
                ),
                executed=False,
                deterministic_decision=(
                    deterministic_decision
                ),
                ai_decision="NOT_RUN",
                ai_assessment=None,
            )

        # -------------------------------------------------
        # 3. Get document content from trusted gateway
        # -------------------------------------------------

        document_content = self.gateway.documents.get(
            handle
        )

        if document_content is None:
            return HybridResult(
                decision="REVIEW",
                reason="Document content unavailable",
                executed=False,
                deterministic_decision="ALLOW",
                ai_decision="NOT_RUN",
                ai_assessment=None,
            )

        classification = (
            self._trusted_classification(handle)
        )

        # -------------------------------------------------
        # 4. Ask the internal GenAI security guard
        # -------------------------------------------------

        assessment = await self.guard.assess(
            user_request=user_request,
            tool_output=tool_output,
            proposed_tool="store_document_ref",
            proposed_arguments={
                "document_ref": document_ref,
                "workspace": workspace,
            },
            classification=classification,
        )

        ai_decision = assessment.recommended_action

        # -------------------------------------------------
        # 5. Combine decisions
        # -------------------------------------------------

        final_decision = self.combine_decisions(
            deterministic_decision,
            ai_decision,
        )

        if final_decision != "ALLOW":
            return HybridResult(
                decision=final_decision,
                reason=(
                    "GenAI security assessment: "
                    + assessment.explanation
                ),
                executed=False,
                deterministic_decision=(
                    deterministic_decision
                ),
                ai_decision=ai_decision,
                ai_assessment=assessment.as_dict(),
            )

        # -------------------------------------------------
        # 6. Execute only after both checks ALLOW
        # -------------------------------------------------

        execution_result = (
            await self.gateway.store_ref(
                document_ref,
                workspace,
            )
        )

        actual_executed = bool(
            execution_result.executed
        )

        actual_decision = (
            execution_result.decision
        )

        if actual_executed:
            final_decision = "ALLOW"
        elif actual_decision == "BLOCK":
            final_decision = "BLOCK"
        else:
            final_decision = "REVIEW"

        return HybridResult(
            decision=final_decision,
            reason=(
                "Hybrid authorization completed. "
                + execution_result.reason
            ),
            executed=actual_executed,
            deterministic_decision=(
                deterministic_decision
            ),
            ai_decision=ai_decision,
            ai_assessment=assessment.as_dict(),
        )


# ============================================================
# Standalone integration tests
# ============================================================

@dataclass
class FakePolicyResult:
    decision: str
    reason: str


@dataclass
class FakeExecutionResult:
    decision: str
    reason: str
    executed: bool


class FakeGateway:
    """
    Simulates the ReferenceGateway interface.

    This verifies hybrid control flow without
    connecting to an MCP server.
    """

    def __init__(self, deterministic_decision):
        self.deterministic_decision = (
            deterministic_decision
        )

        self.documents = {
            "internal_handle_1": (
                "Example public maintenance notice."
            )
        }

        self.handle_to_taint = {}
        self.taint = None

        self.execution_count = 0

    def _resolve_reference(self, document_ref):
        if document_ref == "valid_ref":
            return "internal_handle_1"
        return None

    def evaluate_storage(self, handle, workspace):
        return FakePolicyResult(
            self.deterministic_decision,
            "Simulated deterministic policy",
        )

    async def store_ref(self, document_ref, workspace):
        self.execution_count += 1

        return FakeExecutionResult(
            "ALLOW",
            "Simulated storage execution",
            True,
        )


class FakeGuard:

    def __init__(self, decision):
        self.decision = decision
        self.calls = 0

    async def assess(self, **kwargs):
        self.calls += 1

        from trustgate_ai_guard import (
            GuardAssessment,
        )

        return GuardAssessment(
            attack_detected=(
                self.decision == "BLOCK"
            ),
            attack_type=(
                "workflow_hijacking"
                if self.decision == "BLOCK"
                else "none"
            ),
            risk_level=(
                "high"
                if self.decision == "BLOCK"
                else "low"
            ),
            intent_aligned=(
                self.decision == "ALLOW"
            ),
            recommended_action=self.decision,
            explanation=(
                "Simulated internal GenAI assessment"
            ),
        )


async def run_test(
    name,
    policy_decision,
    ai_decision,
    expected,
    should_execute,
):
    gateway = FakeGateway(policy_decision)
    guard = FakeGuard(ai_decision)

    hybrid = HybridTrustGate(
        gateway=gateway,
        guard=guard,
    )

    result = await hybrid.store_ref(
        document_ref="valid_ref",
        workspace="external",
        user_request=(
            "Export the public notice."
        ),
        tool_output=(
            "Example public maintenance notice."
        ),
    )

    correct = (
        result.decision == expected
        and result.executed == should_execute
        and gateway.execution_count
        == int(should_execute)
    )

    print(
        f"[{'PASS' if correct else 'FAIL'}] "
        f"{name}"
    )
    print(
        f"  Policy={result.deterministic_decision}"
        f", AI={result.ai_decision}"
        f", Final={result.decision}"
        f", Executed={result.executed}"
    )

    return correct


async def main():

    print("\n=== STEP 30 HYBRID GATEWAY TESTS ===")

    tests = [
        (
            "Both layers allow",
            "ALLOW", "ALLOW", "ALLOW", True
        ),
        (
            "AI blocks policy-allowed action",
            "ALLOW", "BLOCK", "BLOCK", False
        ),
        (
            "AI requests review",
            "ALLOW", "REVIEW", "REVIEW", False
        ),
        (
            "Policy blocks AI-allowed action",
            "BLOCK", "ALLOW", "BLOCK", False
        ),
        (
            "Policy requires confirmation",
            "CONFIRM", "ALLOW", "REVIEW", False
        ),
        (
            "Both layers block",
            "BLOCK", "BLOCK", "BLOCK", False
        ),
    ]

    passed = 0

    for test in tests:
        if await run_test(*test):
            passed += 1

    print("\n=== STEP 30 RESULTS ===")
    print(f"Passed: {passed}")
    print(f"Failed: {len(tests) - passed}")
    print(f"Total: {len(tests)}")


if __name__ == "__main__":
    asyncio.run(main())
