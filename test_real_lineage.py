
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from intent import get_demo_intent
from tracker import ActivityTracker
from guard import TrustGateGuard
from provenance import ProvenanceMiddleware


BASE_DIR = Path(__file__).resolve().parent


def extract_text(result):
    return "\n".join(
        item.text
        for item in result.content
        if item.type == "text"
    )


async def main():
    tracker = ActivityTracker(get_demo_intent())
    guard = TrustGateGuard(tracker)
    provenance = ProvenanceMiddleware(tracker)

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(BASE_DIR / "server.py")]
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("\nSTEP 1: Read confidential report")

            report_result = await session.call_tool(
                "read_report",
                arguments={}
            )

            assert not report_result.isError

            report = extract_text(report_result)

            tracker.log_tool_call(
                "read_report",
                {},
                True,
                decision="ALLOW"
            )

            report_id = provenance.observe_result(
                "read_report",
                {},
                report
            )

            assert report_id is not None

            print("Report ID:", report_id)

            print("\nSTEP 2: Summarize the report")

            summary_args = {"report": report}

            summary_result = await session.call_tool(
                "summarize_report",
                arguments=summary_args
            )

            assert not summary_result.isError

            summary = extract_text(summary_result)

            tracker.log_tool_call(
                "summarize_report",
                summary_args,
                True,
                decision="ALLOW"
            )

            summary_id = provenance.observe_result(
                "summarize_report",
                summary_args,
                summary
            )

            assert summary_id is not None

            print("Summary ID:", summary_id)

            assert (
                tracker.get_classification(summary_id)
                == "confidential"
            )

            assert report_id in tracker.get_lineage(
                summary_id
            )

            print("\nSTEP 3: Attempt external storage")

            external_args = {
                "document": summary,
                "workspace": "external_audit_workspace"
            }

            external_id = provenance.resolve(
                external_args["document"]
            )

            external_decision = guard.evaluate(
                "store_document",
                external_args,
                data_id=external_id
            )

            print("Decision:", external_decision.decision)
            print("Reason:", external_decision.reason)

            assert external_decision.decision == "BLOCK"

            # Never execute a denied operation.
            print("External storage was not executed.")

            print("\nSTEP 4: Attempt local storage")

            local_args = {
                "document": summary,
                "workspace": "local"
            }

            local_id = provenance.resolve(
                local_args["document"]
            )

            local_decision = guard.evaluate(
                "store_document",
                local_args,
                data_id=local_id
            )

            print("Decision:", local_decision.decision)

            assert local_decision.decision == "ALLOW"

            local_result = await session.call_tool(
                "store_document",
                arguments=local_args
            )

            assert not local_result.isError

            tracker.log_tool_call(
                "store_document",
                local_args,
                True,
                decision="ALLOW"
            )

            print("Local storage simulated successfully.")

            print("\nSTEP 5: Verify modified content")

            modified_summary = summary + " Additional text."

            modified_id = provenance.resolve(
                modified_summary
            )

            assert modified_id is None

            modified_decision = guard.evaluate(
                "store_document",
                {
                    "document": modified_summary,
                    "workspace": "external"
                },
                data_id=modified_id
            )

            assert modified_decision.decision == "CONFIRM"

            print(
                "Modified content decision:",
                modified_decision.decision
            )

    print("\n" + "=" * 55)
    print("ALL STEP 9C REAL MCP LINEAGE TESTS PASSED")
    print("=" * 55)


if __name__ == "__main__":
    asyncio.run(main())
