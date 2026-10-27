
from dataclasses import dataclass
from typing import Literal

from tracker import ActivityTracker


Decision = Literal["ALLOW", "CONFIRM", "BLOCK"]


@dataclass
class GuardResult:
    decision: Decision
    reason: str


class TrustGateGuard:
    def __init__(self, tracker: ActivityTracker):
        self.tracker = tracker

    def evaluate(
        self,
        tool_name: str,
        arguments: dict,
        data_id: str | None = None
    ) -> GuardResult:

        intent = self.tracker.user_intent

        if tool_name in intent.forbidden_actions:
            return GuardResult(
                "BLOCK",
                "Tool is explicitly forbidden."
            )

        if tool_name not in intent.allowed_actions:
            return GuardResult(
                "CONFIRM",
                "Tool is not in the authorized list."
            )

        if tool_name == "store_document":

            workspace = arguments.get("workspace")

            if not isinstance(workspace, str):
                return GuardResult(
                    "CONFIRM",
                    "Storage destination is invalid."
                )

            if data_id is None:
                return GuardResult(
                    "CONFIRM",
                    "Document provenance is unknown."
                )

            metadata = self.tracker.data_registry.get(
                data_id
            )

            if metadata is None:
                return GuardResult(
                    "CONFIRM",
                    "Data ID is not registered."
                )

            classification = metadata["classification"]

            # Confirm the source was actually executed.
            source_tool = metadata["source_tool"]

            source_verified = any(
                event["tool"] == source_tool
                and event["success"]
                for event in self.tracker.tool_history
            )

            if not source_verified:
                return GuardResult(
                    "CONFIRM",
                    "Source tool execution is not verified."
                )

            if (
                classification == "confidential"
                and workspace != "local"
            ):
                lineage = self.tracker.get_lineage(
                    data_id
                )

                return GuardResult(
                    "BLOCK",
                    "Confidential data cannot leave "
                    "the local workspace. "
                    f"Lineage: {lineage}"
                )

        return GuardResult(
            "ALLOW",
            "Tool call is consistent with current policy."
        )
