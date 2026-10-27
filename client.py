
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from intent import get_demo_intent
from tracker import ActivityTracker
from guard import TrustGateGuard


async def main():

    intent = get_demo_intent()
    tracker = ActivityTracker(intent)
    guard = TrustGateGuard(tracker)

    tracker.show_intent()

    server_path = Path(__file__).resolve().parent / "server.py"

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_path)]
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:

            await session.initialize()
            print("\nConnected to MCP Server!")

            tools = await session.list_tools()
            print("\nAvailable tools:")

            for tool in tools.tools:
                print("-", tool.name)

            async def guarded_call(
                tool_name: str,
                arguments: dict,
                data_id: str | None = None
            ):
                decision = guard.evaluate(
                    tool_name,
                    arguments,
                    data_id
                )

                print(f"\n[GUARD] Tool: {tool_name}")
                print("Decision:", decision.decision)
                print("Reason:", decision.reason)

                if decision.decision != "ALLOW":
                    tracker.log_tool_call(
                        tool_name=tool_name,
                        arguments=arguments,
                        success=False,
                        decision=decision.decision
                    )
                    return None

                try:
                    result = await session.call_tool(
                        tool_name,
                        arguments=arguments
                    )

                    success = not result.isError

                except Exception as error:
                    print("[CLIENT] Error:", error)
                    result = None
                    success = False

                tracker.log_tool_call(
                    tool_name=tool_name,
                    arguments=arguments,
                    success=success,
                    decision=decision.decision
                )

                return result

            # STEP A: Read confidential report
            print("\n--- READ CONFIDENTIAL REPORT ---")

            report_result = await guarded_call(
                "read_report",
                {}
            )

            if report_result is None or report_result.isError:
                print("Report reading failed.")
                return

            report_text = "\n".join(
                item.text
                for item in report_result.content
                if item.type == "text"
            )

            tracker.register_data(
                data_id="report_001",
                source_tool="read_report",
                classification="confidential"
            )

            # STEP B: Authorized local storage
            print("\n--- STORE REPORT LOCALLY ---")

            await guarded_call(
                "store_document",
                {
                    "document": report_text,
                    "workspace": "local"
                },
                data_id="report_001"
            )

            # STEP C: Unauthorized external storage
            print("\n--- ATTEMPT EXTERNAL STORAGE ---")

            await guarded_call(
                "store_document",
                {
                    "document": report_text,
                    "workspace": "external"
                },
                data_id="report_001"
            )

            tracker.show_history()
            tracker.show_data_registry()


if __name__ == "__main__":
    asyncio.run(main())
