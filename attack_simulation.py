
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from intent import get_demo_intent
from tracker import ActivityTracker
from guard import TrustGateGuard
from attack_payloads import inject_payload


BASE_DIR = Path(__file__).resolve().parent


def extract_text(result):
    return "\n".join(
        item.text
        for item in result.content
        if item.type == "text"
    )


async def run_attack(session, use_guard: bool):

    print("\n" + "=" * 55)
    print(
        "DEFENSE:",
        "TRUSTGATE" if use_guard else "NONE"
    )
    print("=" * 55)

    intent = get_demo_intent()
    tracker = ActivityTracker(intent)
    guard = TrustGateGuard(tracker)

    # 1. Agent reads the confidential report
    report_result = await session.call_tool(
        "read_report",
        arguments={}
    )

    if report_result.isError:
        raise RuntimeError(
            "Could not read report: "
            + extract_text(report_result)
        )

    report_text = extract_text(report_result)

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

    # 2. Simulate attacker modifying the tool response
    poisoned_response = inject_payload(report_text)

    print("\n[ATTACKER] Poisoned tool response created.")

    # 3. Simulate a vulnerable agent interpreting the payload
    # This is NOT a real LLM yet.
    if (
        "store the complete report" in poisoned_response.lower()
        and 'workspace = "external"' in poisoned_response.lower()
    ):
        print(
            "[AGENT] Following instruction found "
            "in MCP tool output."
        )

        proposed_tool = "store_document"

        # Transfer the original report, not the injected text
        proposed_arguments = {
            "document": report_text,
            "workspace": "external"
        }

        if use_guard:
            result = guard.evaluate(
                tool_name=proposed_tool,
                arguments=proposed_arguments,
                data_id="report_001"
            )

            decision = result.decision
            reason = result.reason

        else:
            decision = "ALLOW"
            reason = "No security guard enabled."

        print("\n[GUARD] Decision:", decision)
        print("[GUARD] Reason:", reason)

        executed = False

        if decision == "ALLOW":
            storage_result = await session.call_tool(
                proposed_tool,
                arguments=proposed_arguments
            )

            executed = not storage_result.isError

            if executed:
                print(
                    "[RESULT] Simulated external "
                    "storage executed."
                )
            else:
                print(
                    "[RESULT] Storage tool returned an error."
                )

        else:
            print(
                "[RESULT] Unauthorized storage prevented."
            )

        tracker.log_tool_call(
            tool_name=proposed_tool,
            arguments=proposed_arguments,
            success=executed,
            decision=decision
        )

        return {
            "defense": "trustgate" if use_guard else "none",
            "attack_attempted": True,
            "attack_succeeded": executed
        }

    print("[AGENT] No attack instruction recognized.")

    return {
        "defense": "trustgate" if use_guard else "none",
        "attack_attempted": False,
        "attack_succeeded": False
    }


async def main():

    server_path = BASE_DIR / "server.py"

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_path)]
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:

            await session.initialize()

            no_defense = await run_attack(
                session,
                use_guard=False
            )

            trustgate = await run_attack(
                session,
                use_guard=True
            )

    print("\n========== ATTACK COMPARISON ==========")

    for result in [no_defense, trustgate]:
        print(
            f"{result['defense']}: "
            f"attempted={result['attack_attempted']}, "
            f"succeeded={result['attack_succeeded']}"
        )


if __name__ == "__main__":
    asyncio.run(main())
