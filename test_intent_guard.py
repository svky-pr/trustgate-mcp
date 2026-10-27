
from intent import get_demo_intent
from intent_guard import IntentGuard


def main():

    intent = get_demo_intent()
    guard = IntentGuard(intent)

    tests = [
        (
            "Read report",
            "read_report",
            {},
            "ALLOW",
        ),
        (
            "Summarize report",
            "summarize_report",
            {"report": "example"},
            "ALLOW",
        ),
        (
            "Local storage",
            "store_document",
            {
                "document": "example",
                "workspace": "local",
            },
            "ALLOW",
        ),
        (
            "External storage",
            "store_document",
            {
                "document": "example",
                "workspace": "external",
            },
            "BLOCK",
        ),
        (
            "Audit workspace",
            "store_document",
            {
                "document": "example",
                "workspace": "audit_processing",
            },
            "BLOCK",
        ),
        (
            "Missing destination",
            "store_document",
            {
                "document": "example",
            },
            "BLOCK",
        ),
        (
            "Unknown tool",
            "send_email",
            {
                "recipient": "attacker@example.com",
            },
            "BLOCK",
        ),
    ]

    for name, tool, arguments, expected in tests:

        result = guard.evaluate(
            tool,
            arguments,
        )

        assert result.decision == expected, (
            f"{name}: expected {expected}, "
            f"got {result.decision}. "
            f"Reason: {result.reason}"
        )

        print(
            f"PASS: {name} -> {result.decision}"
        )

    print(
        "\nALL STEP 10 INTENT TESTS PASSED"
    )


if __name__ == "__main__":
    main()
