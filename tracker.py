
import json
from datetime import datetime, timezone
from pathlib import Path

from intent import UserIntent


class ActivityTracker:
    def __init__(self, user_intent: UserIntent):
        self.user_intent = user_intent

        # Store tool execution history.
        self.tool_history = []

        # Track sensitive data that has been accessed.
        self.sensitive_data_accessed = set()

        # Store registered data and provenance relationships.
        self.data_registry = {}

        # Log tool activity without recording argument values.
        self.log_file = (
            Path(__file__).resolve().parent
            / "activity_log.jsonl"
        )

    def register_data(
        self,
        data_id: str,
        source_tool: str,
        classification: str,
        parents=None
    ):
        """
        Register a data object and its provenance.

        If any parent is confidential, the child
        automatically inherits the confidential classification.

        Only trusted application code should register provenance.
        """

        parents = list(parents or [])

        if data_id in self.data_registry:
            raise ValueError(
                f"Data ID already registered: {data_id}"
            )

        if classification not in ("public", "confidential"):
            raise ValueError(
                f"Invalid classification: {classification}"
            )

        # Ensure every parent has already been registered.
        for parent_id in parents:
            if parent_id not in self.data_registry:
                raise ValueError(
                    f"Unknown parent data ID: {parent_id}"
                )

        # Confidentiality inheritance.
        for parent_id in parents:
            parent_classification = (
                self.data_registry[parent_id]["classification"]
            )

            if parent_classification == "confidential":
                classification = "confidential"
                break

        # Register the data object.
        self.data_registry[data_id] = {
            "source_tool": source_tool,
            "classification": classification,
            "parents": parents
        }

        print(
            f"[TRACKER] Registered {data_id} "
            f"as {classification} | parents={parents}"
        )

    def get_classification(self, data_id):
        """
        Return the effective classification of a data object.
        """
        record = self.data_registry.get(data_id)

        if record is None:
            return None

        return record["classification"]

    def get_lineage(self, data_id):
        """
        Return the data object and all its ancestors.

        Example:
            report_001
                |
            summary_001
                |
            formatted_001

        get_lineage("formatted_001") returns:
            ["formatted_001", "report_001", "summary_001"]
        """

        if data_id not in self.data_registry:
            return []

        visited = set()
        pending = [data_id]

        while pending:
            current = pending.pop()

            if current in visited:
                continue

            visited.add(current)

            parents = self.data_registry[
                current
            ]["parents"]

            pending.extend(parents)

        return sorted(visited)

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        success: bool,
        sensitive_data=None,
        decision=None
    ):
        """
        Record an MCP tool execution.

        Argument values are intentionally excluded from logs
        to avoid exposing confidential information.
        """

        event = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "tool": tool_name,
            "argument_names": list(arguments.keys()),
            "success": success,
            "sensitive_data": sensitive_data,
            "decision": decision
        }

        self.tool_history.append(event)

        if sensitive_data is not None and success:
            self.sensitive_data_accessed.add(
                sensitive_data
            )

        # Append event to JSONL log.
        with self.log_file.open(
            "a",
            encoding="utf-8"
        ) as file:
            file.write(
                json.dumps(event) + "\n"
            )

        print(
            f"[TRACKER] {tool_name} | "
            f"Decision: {decision} | "
            f"Success: {success}"
        )

    def show_history(self):
        """
        Display the tool execution history.
        """

        print("\n========== TOOL HISTORY ==========")

        for index, event in enumerate(
            self.tool_history,
            start=1
        ):
            print(
                f"{index}. {event['tool']} | "
                f"Decision: {event['decision']} | "
                f"Success: {event['success']}"
            )

    def show_intent(self):
        """
        Display the user's original intent and restrictions.
        """

        print("\n========== USER INTENT ==========")

        print("Goal:", self.user_intent.goal)

        print(
            "Allowed tools:",
            self.user_intent.allowed_actions
        )

        print(
            "Forbidden actions:",
            self.user_intent.forbidden_actions
        )

        print(
            "Restrictions:",
            self.user_intent.restrictions
        )

    def show_data_registry(self):
        """
        Display all registered data objects and their lineage.
        """

        print("\n========== DATA PROVENANCE ==========")

        for data_id, metadata in (
            self.data_registry.items()
        ):
            print(
                f"{data_id}: "
                f"source={metadata['source_tool']} | "
                f"classification={metadata['classification']} | "
                f"parents={metadata['parents']}"
            )
