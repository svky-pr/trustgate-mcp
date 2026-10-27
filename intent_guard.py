
from dataclasses import dataclass, field


@dataclass(frozen=True)
class IntentPolicy:
    allowed_actions: frozenset
    storage_workspaces: frozenset = field(
        default_factory=frozenset
    )
    allow_confidential_external: bool = False


@dataclass
class IntentDecision:
    decision: str
    reason: str
    violation: str = "none"


class IntentGuard:
    def __init__(self, user_intent):
        # Supports both the new IntentPolicy and
        # the original get_demo_intent() object.
        if isinstance(user_intent, IntentPolicy):
            self.policy = user_intent
            self.forbidden_actions = set()
        else:
            self.policy = IntentPolicy(
                allowed_actions=frozenset(
                    user_intent.allowed_actions
                ),
                storage_workspaces=frozenset(
                    {"local"}
                ),
            )
            self.forbidden_actions = set(
                user_intent.forbidden_actions
            )

    def evaluate(
        self,
        tool_name,
        arguments,
        classification="unknown",
    ):
        if not isinstance(arguments, dict):
            return IntentDecision(
                "BLOCK",
                "Invalid arguments.",
                "invalid_arguments",
            )

        if tool_name in self.forbidden_actions:
            return IntentDecision(
                "BLOCK",
                "Action explicitly forbidden.",
                "forbidden_action",
            )

        if tool_name not in self.policy.allowed_actions:
            return IntentDecision(
                "BLOCK",
                "Action not authorized by user intent.",
                "unauthorized_action",
            )

        if tool_name != "store_document":
            return IntentDecision(
                "ALLOW",
                "Action authorized.",
            )

        workspace = arguments.get("workspace")

        if (
            not isinstance(workspace, str)
            or workspace not in self.policy.storage_workspaces
        ):
            return IntentDecision(
                "BLOCK",
                "Storage destination not authorized.",
                "destination_violation",
            )

        # Local storage is permitted by this policy.
        # Other guards may still require provenance.
        if workspace == "local":
            return IntentDecision(
                "ALLOW",
                "Local storage authorized.",
            )

        # Confidential data requires a separate,
        # explicit external-transfer authorization.
        if classification == "confidential":
            if not self.policy.allow_confidential_external:
                return IntentDecision(
                    "BLOCK",
                    "Confidential external transfer not authorized.",
                    "classification_violation",
                )

            return IntentDecision(
                "ALLOW",
                "Confidential external transfer authorized.",
            )

        if classification == "public":
            return IntentDecision(
                "ALLOW",
                "Verified public external transfer authorized.",
            )

        # Unknown classification must not be treated
        # as public merely because the LLM says so.
        return IntentDecision(
            "CONFIRM",
            "External transfer requires verified provenance.",
            "unknown_classification",
        )
