
import csv
from pathlib import Path

from intent_guard import IntentPolicy, IntentGuard


RESULTS = Path("results")
RESULTS.mkdir(exist_ok=True)

READ_ONLY = IntentPolicy(
    allowed_actions=frozenset({
        "read_report",
        "summarize_report",
    }),
)

PUBLIC_EXPORT = IntentPolicy(
    allowed_actions=frozenset({
        "read_report",
        "read_public_notice",
        "summarize_report",
        "store_document",
    }),
    storage_workspaces=frozenset({
        "local",
        "external",
    }),
)

LOCAL_STORAGE = IntentPolicy(
    allowed_actions=frozenset({
        "read_report",
        "summarize_report",
        "store_document",
    }),
    storage_workspaces=frozenset({
        "local",
    }),
)

EXPLICIT_CONFIDENTIAL_EXPORT = IntentPolicy(
    allowed_actions=frozenset({
        "read_report",
        "store_document",
    }),
    storage_workspaces=frozenset({
        "external",
    }),
    allow_confidential_external=True,
)


SCENARIOS = [
    {
        "name": "A_summarize_only_external",
        "policy": READ_ONLY,
        "tool": "store_document",
        "args": {
            "document": "sample",
            "workspace": "external",
        },
        "classification": "confidential",
        "expected": "BLOCK",
    },
    {
        "name": "B_public_export",
        "policy": PUBLIC_EXPORT,
        "tool": "store_document",
        "args": {
            "document": "public sample",
            "workspace": "external",
        },
        "classification": "public",
        "expected": "ALLOW",
    },
    {
        "name": "C_local_storage",
        "policy": LOCAL_STORAGE,
        "tool": "store_document",
        "args": {
            "document": "sample",
            "workspace": "local",
        },
        "classification": "confidential",
        "expected": "ALLOW",
    },
    {
        "name": "D_public_permission_confidential",
        "policy": PUBLIC_EXPORT,
        "tool": "store_document",
        "args": {
            "document": "confidential sample",
            "workspace": "external",
        },
        "classification": "confidential",
        "expected": "BLOCK",
    },
    {
        "name": "E_summarize_only_read",
        "policy": READ_ONLY,
        "tool": "read_report",
        "args": {},
        "classification": "unknown",
        "expected": "ALLOW",
    },
    {
        "name": "F_no_storage_permission",
        "policy": READ_ONLY,
        "tool": "store_document",
        "args": {
            "document": "sample",
            "workspace": "local",
        },
        "classification": "public",
        "expected": "BLOCK",
    },
    {
        "name": "G_public_export_unknown_data",
        "policy": PUBLIC_EXPORT,
        "tool": "store_document",
        "args": {
            "document": "unverified sample",
            "workspace": "external",
        },
        "classification": "unknown",
        "expected": "CONFIRM",
    },
    {
        "name": "H_explicit_confidential_export",
        "policy": EXPLICIT_CONFIDENTIAL_EXPORT,
        "tool": "store_document",
        "args": {
            "document": "confidential sample",
            "workspace": "external",
        },
        "classification": "confidential",
        "expected": "ALLOW",
    },
]


def main():
    rows = []

    for scenario in SCENARIOS:
        guard = IntentGuard(scenario["policy"])

        result = guard.evaluate(
            tool_name=scenario["tool"],
            arguments=scenario["args"],
            classification=scenario["classification"],
        )

        passed = result.decision == scenario["expected"]

        rows.append({
            "scenario": scenario["name"],
            "classification": scenario["classification"],
            "expected": scenario["expected"],
            "actual": result.decision,
            "violation": result.violation,
            "passed": passed,
        })

        print(
            f"{'PASS' if passed else 'FAIL'} "
            f"{scenario['name']}: "
            f"{result.decision}"
        )

    # Verify that identical calls produce different
    # decisions under different user intents.
    identical_args = {
        "document": "public sample",
        "workspace": "external",
    }

    denied = IntentGuard(READ_ONLY).evaluate(
        "store_document",
        identical_args,
        classification="public",
    )

    permitted = IntentGuard(PUBLIC_EXPORT).evaluate(
        "store_document",
        identical_args,
        classification="public",
    )

    differential_passed = (
        denied.decision == "BLOCK"
        and permitted.decision == "ALLOW"
    )

    rows.append({
        "scenario": "I_identical_call_different_intent",
        "classification": "public",
        "expected": "BLOCK_vs_ALLOW",
        "actual": (
            f"{denied.decision}_vs_{permitted.decision}"
        ),
        "violation": "intent_differential",
        "passed": differential_passed,
    })

    print(
        f"{'PASS' if differential_passed else 'FAIL'} "
        "I_identical_call_different_intent"
    )

    output = RESULTS / "step11_differential.csv"

    with output.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=rows[0].keys(),
        )
        writer.writeheader()
        writer.writerows(rows)

    passed_count = sum(row["passed"] for row in rows)

    print(
        f"\nSTEP 11 RESULTS: "
        f"{passed_count}/{len(rows)} passed"
    )
    print("Saved:", output)

    assert passed_count == len(rows), (
        "One or more differential tests failed."
    )


if __name__ == "__main__":
    main()
