
from intent import get_demo_intent
from tracker import ActivityTracker
from guard import TrustGateGuard


def run_test(
    guard,
    name,
    data_id,
    workspace,
    expected
):
    result = guard.evaluate(
        tool_name="store_document",
        arguments={
            "document": "Synthetic test content",
            "workspace": workspace
        },
        data_id=data_id
    )

    print(f"\nTEST: {name}")
    print("Data ID:", data_id)
    print("Workspace:", workspace)
    print("Decision:", result.decision)
    print("Reason:", result.reason)

    assert result.decision == expected, (
        f"Expected {expected}, "
        f"got {result.decision}"
    )

    print("PASS")


def main():

    intent = get_demo_intent()
    tracker = ActivityTracker(intent)
    guard = TrustGateGuard(tracker)

    # Simulate a verified confidential report read.
    tracker.log_tool_call(
        tool_name="read_report",
        arguments={},
        success=True,
        decision="ALLOW"
    )

    tracker.register_data(
        data_id="report_001",
        source_tool="read_report",
        classification="confidential"
    )

    # Simulate a verified summary derived from the report.
    tracker.log_tool_call(
        tool_name="summarize_report",
        arguments={"report": "Synthetic test content"},
        success=True,
        decision="ALLOW"
    )

    tracker.register_data(
        data_id="summary_001",
        source_tool="summarize_report",
        classification="public",
        parents=["report_001"]
    )

    # A second transformation inherits the same restriction.
    tracker.log_tool_call(
        tool_name="format_document",
        arguments={},
        success=True,
        decision="ALLOW"
    )

    tracker.register_data(
        data_id="formatted_001",
        source_tool="format_document",
        classification="public",
        parents=["summary_001"]
    )

    # Simulate a public document with no confidential parent.
    tracker.log_tool_call(
        tool_name="read_public_notice",
        arguments={},
        success=True,
        decision="ALLOW"
    )

    tracker.register_data(
        data_id="notice_001",
        source_tool="read_public_notice",
        classification="public"
    )

    print("\n========== DATA REGISTRY ==========")
    tracker.show_data_registry()

    assert (
        tracker.get_classification("summary_001")
        == "confidential"
    )

    assert (
        tracker.get_classification("formatted_001")
        == "confidential"
    )

    run_test(
        guard,
        "Original confidential report stored locally",
        "report_001",
        "local",
        "ALLOW"
    )

    run_test(
        guard,
        "Original confidential report stored externally",
        "report_001",
        "external",
        "BLOCK"
    )

    run_test(
        guard,
        "Derived summary stored in audit workspace",
        "summary_001",
        "audit",
        "BLOCK"
    )

    run_test(
        guard,
        "Second-generation document stored externally",
        "formatted_001",
        "external_audit_workspace",
        "BLOCK"
    )

    run_test(
        guard,
        "Derived summary stored locally",
        "summary_001",
        "local",
        "ALLOW"
    )

    run_test(
        guard,
        "Public notice stored externally",
        "notice_001",
        "external",
        "ALLOW"
    )

    run_test(
        guard,
        "Unknown document provenance",
        None,
        "external",
        "CONFIRM"
    )

    print("\n" + "=" * 50)
    print("ALL 7 PROVENANCE TESTS PASSED")
    print("=" * 50)


if __name__ == "__main__":
    main()
