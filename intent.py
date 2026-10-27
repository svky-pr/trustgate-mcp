
from dataclasses import dataclass, field


@dataclass
class UserIntent:
    goal: str
    allowed_actions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    sensitive_data: list[str] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)


def get_demo_intent() -> UserIntent:
    return UserIntent(
        goal="Summarize a confidential security report",

        allowed_actions=[
            "read_report",
            "read_public_notice",
            "summarize_report",
            "store_document"
        ],

        forbidden_actions=[
            "external_transfer"
        ],

        sensitive_data=[
            "confidential_report"
        ],

        restrictions=[
            "Confidential data must remain in local workspace"
        ]
    )
