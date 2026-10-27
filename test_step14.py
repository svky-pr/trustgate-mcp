
"""Step 14 deterministic provenance and authorization tests."""

import csv
from pathlib import Path

from step14_provenance import TrustedProvenance
from intent_guard import IntentGuard, IntentPolicy


RESULTS = Path("results")
RESULTS.mkdir(exist_ok=True)


def policy(actions, workspaces=(), confidential=False):
    return IntentPolicy(
        allowed_actions=frozenset(actions),
        storage_workspaces=frozenset(workspaces),
        allow_confidential_external=confidential,
    )


READ_ONLY = policy(
    ("read_report", "read_public_notice", "summarize_report")
)

PUBLIC_EXPORT = policy(
    ("read_report", "read_public_notice", "store_document"),
    ("external",),
)

LOCAL_STORAGE = policy(
    ("read_report", "store_document"),
    ("local",),
)

CONFIDENTIAL_EXPORT = policy(
    ("read_report", "store_document"),
    ("external",),
    True,
)


def evaluate(policy_obj, content, workspace, registry):
    classification, verified = registry.classify_exact(
        content
    )

    args = {
        "document": content,
        "workspace": workspace,
    }

    intent = IntentGuard(policy_obj).evaluate(
        "store_document",
        args,
        classification=classification,
    )

    # Authorization is distinct from provenance verification.
    authorized = intent.decision == "ALLOW"

    decision = intent.decision

    if (
        workspace != "local"
        and not verified
        and decision == "ALLOW"
    ):
        decision = "CONFIRM"

    executed = decision == "ALLOW"

    return {
        "classification": classification,
        "verified": verified,
        "authorized": authorized,
        "decision": decision,
        "executed": executed,
        "intent_violation": intent.violation,
    }


def main():
    registry = TrustedProvenance()

    public_text = "Public maintenance announcement."
    confidential_text = "Confidential security assessment."

    public_id = registry.register_source(
        public_text,
        "public",
        "read_public_notice",
    )

    confidential_id = registry.register_source(
        confidential_text,
        "confidential",
        "read_report",
    )

    # Trusted transformation: classification is inherited.
    summary_text = "Summary of confidential assessment."

    summary_id = registry.register_transformation(
        summary_text,
        [confidential_id],
        "summarize_report",
    )

    assert (
        registry.resolve_handle(summary_id).classification
        == "confidential"
    )

    assert registry.lineage(summary_id) == [
        confidential_id
    ]

    cases = [
        (
            "public_export_allowed",
            PUBLIC_EXPORT,
            public_text,
            "external",
            "ALLOW",
        ),
        (
            "same_public_export_readonly",
            READ_ONLY,
            public_text,
            "external",
            "BLOCK",
        ),
        (
            "confidential_export_blocked",
            PUBLIC_EXPORT,
            confidential_text,
            "external",
            "BLOCK",
        ),
        (
            "confidential_summary_blocked",
            PUBLIC_EXPORT,
            summary_text,
            "external",
            "BLOCK",
        ),
        (
            "local_confidential_allowed",
            LOCAL_STORAGE,
            confidential_text,
            "local",
            "ALLOW",
        ),
        (
            "explicit_confidential_allowed",
            CONFIDENTIAL_EXPORT,
            confidential_text,
            "external",
            "ALLOW",
        ),
        (
            "unverified_external_confirm",
            PUBLIC_EXPORT,
            "LLM-rewritten public notice.",
            "external",
            "CONFIRM",
        ),
    ]

    rows = []

    for name, selected_policy, content, workspace, expected in cases:
        result = evaluate(
            selected_policy,
            content,
            workspace,
            registry,
        )

        passed = result["decision"] == expected

        row = {
            "scenario": name,
            "expected": expected,
            **result,
            "passed": passed,
        }

        rows.append(row)

        print(
            f"{'PASS' if passed else 'FAIL'} "
            f"{name}: "
            f"expected={expected}, "
            f"actual={result['decision']}"
        )

    # Same content and destination, different user intent.
    assert rows[0]["decision"] == "ALLOW"
    assert rows[1]["decision"] == "BLOCK"

    # Confidential classification survives trusted summarization.
    assert rows[3]["classification"] == "confidential"
    assert rows[3]["verified"]

    # Unknown provenance is not mislabeled as an authorization violation.
    assert rows[6]["intent_violation"] == "unknown_classification"
    assert not rows[6]["executed"]

    output = RESULTS / "step14_results.csv"

    with output.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=rows[0].keys(),
        )
        writer.writeheader()
        writer.writerows(rows)

    passed_count = sum(row["passed"] for row in rows)

    print(
        f"\nSTEP 14: {passed_count}/{len(rows)} passed"
    )
    print(f"Results saved to {output}")

    assert passed_count == len(rows)


if __name__ == "__main__":
    main()

"""Step 14 deterministic provenance and authorization tests."""

import csv
from pathlib import Path

from step14_provenance import TrustedProvenance
from intent_guard import IntentGuard, IntentPolicy


RESULTS = Path("results")
RESULTS.mkdir(exist_ok=True)


def policy(actions, workspaces=(), confidential=False):
    return IntentPolicy(
        allowed_actions=frozenset(actions),
        storage_workspaces=frozenset(workspaces),
        allow_confidential_external=confidential,
    )


READ_ONLY = policy(
    ("read_report", "read_public_notice", "summarize_report")
)

PUBLIC_EXPORT = policy(
    ("read_report", "read_public_notice", "store_document"),
    ("external",),
)

LOCAL_STORAGE = policy(
    ("read_report", "store_document"),
    ("local",),
)

CONFIDENTIAL_EXPORT = policy(
    ("read_report", "store_document"),
    ("external",),
    True,
)


def evaluate(policy_obj, content, workspace, registry):
    classification, verified = registry.classify_exact(
        content
    )

    args = {
        "document": content,
        "workspace": workspace,
    }

    intent = IntentGuard(policy_obj).evaluate(
        "store_document",
        args,
        classification=classification,
    )

    # Authorization is distinct from provenance verification.
    authorized = intent.decision == "ALLOW"

    decision = intent.decision

    if (
        workspace != "local"
        and not verified
        and decision == "ALLOW"
    ):
        decision = "CONFIRM"

    executed = decision == "ALLOW"

    return {
        "classification": classification,
        "verified": verified,
        "authorized": authorized,
        "decision": decision,
        "executed": executed,
        "intent_violation": intent.violation,
    }


def main():
    registry = TrustedProvenance()

    public_text = "Public maintenance announcement."
    confidential_text = "Confidential security assessment."

    public_id = registry.register_source(
        public_text,
        "public",
        "read_public_notice",
    )

    confidential_id = registry.register_source(
        confidential_text,
        "confidential",
        "read_report",
    )

    # Trusted transformation: classification is inherited.
    summary_text = "Summary of confidential assessment."

    summary_id = registry.register_transformation(
        summary_text,
        [confidential_id],
        "summarize_report",
    )

    assert (
        registry.resolve_handle(summary_id).classification
        == "confidential"
    )

    assert registry.lineage(summary_id) == [
        confidential_id
    ]

    cases = [
        (
            "public_export_allowed",
            PUBLIC_EXPORT,
            public_text,
            "external",
            "ALLOW",
        ),
        (
            "same_public_export_readonly",
            READ_ONLY,
            public_text,
            "external",
            "BLOCK",
        ),
        (
            "confidential_export_blocked",
            PUBLIC_EXPORT,
            confidential_text,
            "external",
            "BLOCK",
        ),
        (
            "confidential_summary_blocked",
            PUBLIC_EXPORT,
            summary_text,
            "external",
            "BLOCK",
        ),
        (
            "local_confidential_allowed",
            LOCAL_STORAGE,
            confidential_text,
            "local",
            "ALLOW",
        ),
        (
            "explicit_confidential_allowed",
            CONFIDENTIAL_EXPORT,
            confidential_text,
            "external",
            "ALLOW",
        ),
        (
            "unverified_external_confirm",
            PUBLIC_EXPORT,
            "LLM-rewritten public notice.",
            "external",
            "CONFIRM",
        ),
    ]

    rows = []

    for name, selected_policy, content, workspace, expected in cases:
        result = evaluate(
            selected_policy,
            content,
            workspace,
            registry,
        )

        passed = result["decision"] == expected

        row = {
            "scenario": name,
            "expected": expected,
            **result,
            "passed": passed,
        }

        rows.append(row)

        print(
            f"{'PASS' if passed else 'FAIL'} "
            f"{name}: "
            f"expected={expected}, "
            f"actual={result['decision']}"
        )

    # Same content and destination, different user intent.
    assert rows[0]["decision"] == "ALLOW"
    assert rows[1]["decision"] == "BLOCK"

    # Confidential classification survives trusted summarization.
    assert rows[3]["classification"] == "confidential"
    assert rows[3]["verified"]

    # Unknown provenance is not mislabeled as an authorization violation.
    assert rows[6]["intent_violation"] == "unknown_classification"
    assert not rows[6]["executed"]

    output = RESULTS / "step14_results.csv"

    with output.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=rows[0].keys(),
        )
        writer.writeheader()
        writer.writerows(rows)

    passed_count = sum(row["passed"] for row in rows)

    print(
        f"\nSTEP 14: {passed_count}/{len(rows)} passed"
    )
    print(f"Results saved to {output}")

    assert passed_count == len(rows)


if __name__ == "__main__":
    main()