
from intent import get_demo_intent
from tracker import ActivityTracker
from guard import TrustGateGuard
from provenance import ProvenanceMiddleware


def main():
    tracker = ActivityTracker(get_demo_intent())
    guard = TrustGateGuard(tracker)
    middleware = ProvenanceMiddleware(tracker)

    report = "Synthetic confidential security report."
    summary = "Synthetic summary of confidential findings."

    tracker.log_tool_call(
        "read_report", {}, True, decision="ALLOW"
    )

    report_id = middleware.observe_result(
        "read_report", {}, report
    )

    tracker.log_tool_call(
        "summarize_report",
        {"report": report},
        True,
        decision="ALLOW"
    )

    summary_id = middleware.observe_result(
        "summarize_report",
        {"report": report},
        summary
    )

    assert report_id is not None
    assert summary_id is not None

    assert (
        tracker.get_classification(summary_id)
        == "confidential"
    )

    assert report_id in tracker.get_lineage(summary_id)

    def check(document, workspace, expected):
        data_id = middleware.resolve(document)

        result = guard.evaluate(
            "store_document",
            {
                "document": document,
                "workspace": workspace
            },
            data_id=data_id
        )

        print(
            f"{workspace}: {result.decision} "
            f"| {result.reason}"
        )

        assert result.decision == expected

    check(summary, "local", "ALLOW")
    check(summary, "audit", "BLOCK")
    check(summary, "external_audit_workspace", "BLOCK")

    # Unknown transformed content is withheld.
    check(summary + " Modified", "external", "CONFIRM")

    print("\nALL STEP 9B MIDDLEWARE TESTS PASSED")


if __name__ == "__main__":
    main()
