
#!/usr/bin/env python3
"""
Step 57 — Live MCP Transport Security Test

Uses the actual Step 52 MCP proxy and backend.
Storage is simulated. No external data transfer.
"""

import asyncio
import json
import os
import secrets
import socket
import sys
from pathlib import Path

from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

AUTHORIZED = (
    "Read the public notice and store a copy of that "
    "public notice in the external workspace. "
    "I explicitly authorize exporting this public "
    "notice to the external workspace."
)


def decode(result):
    for item in result.content:
        if getattr(item, "type", "") == "text":
            data = json.loads(item.text)
            if isinstance(data, str):
                data = json.loads(data)
            return data
    raise ValueError("No JSON response")


async def main():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    secret = secrets.token_urlsafe(48)

    env = dict(os.environ)
    env.update({
        "TG52_HOST_SECRET": secret,
        "TG52_HOST_PORT": str(port),
        "TG52_TRUSTED_REQUEST": AUTHORIZED,
        "TG52_ALLOWED_DEST": "external"
    })

    checks = []

    def check(name, condition):
        passed = bool(condition)
        checks.append(passed)
        print(
            f"{name:40s} "
            f"{'PASS' if passed else 'FAIL'}",
            flush=True
        )

    async def host(operation, ref=None, dest=None,
                   supplied_secret=None):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port
        )
        payload = {
            "secret": (
                secret if supplied_secret is None
                else supplied_secret
            ),
            "operation": operation
        }
        if ref is not None:
            payload["document_ref"] = ref
        if dest is not None:
            payload["destination"] = dest

        writer.write(
            (json.dumps(payload) + "\n").encode()
        )
        await writer.drain()

        reply = json.loads(
            (await asyncio.wait_for(
                reader.readline(), 10
            )).decode()
        )
        writer.close()
        await writer.wait_closed()
        return reply

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            str(ROOT / "step52_mcp_host_grants_server.py")
        ],
        env=env
    )

    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}

            expected = {
                "read_public_notice",
                "read_report",
                "summarize_report",
                "store_document_ref"
            }

            check(
                "Only approved tools exposed",
                names == expected
            )

            check(
                "Grant issuer not MCP-accessible",
                not any(
                    "issue" in name or "grant" in name
                    for name in names
                )
            )

            check(
                "Host channel authenticated",
                not (await host(
                    "health",
                    supplied_secret="invalid"
                )).get("ok")
            )

            read = decode(
                await session.call_tool(
                    "read_public_notice", {}
                )
            )

            check(
                "Public read succeeds",
                read.get("decision") == "ALLOW"
                and read.get("executed") is True
            )

            ref = (read.get("data") or {}).get(
                "document_ref"
            )
            if not ref:
                raise RuntimeError(
                    "No document reference returned"
                )

            summary = decode(
                await session.call_tool(
                    "summarize_report",
                    {"document_ref": ref}
                )
            )

            check(
                "Legitimate summary succeeds",
                summary.get("decision") == "ALLOW"
                and summary.get("executed") is True
            )

            confidential = decode(
                await session.call_tool(
                    "read_report", {}
                )
            )

            check(
                "Confidential read blocked",
                confidential.get("decision") == "BLOCK"
                and not confidential.get("executed")
            )

            forged = decode(
                await session.call_tool(
                    "store_document_ref",
                    {
                        "document_ref": ref,
                        "workspace": "external",
                        "grant_token": "forged-token"
                    }
                )
            )

            check(
                "Forged MCP grant blocked",
                forged.get("decision") == "BLOCK"
                and not forged.get("executed")
            )

            invalid_ref = await host(
                "issue",
                ref="attacker-fabricated-reference",
                dest="external"
            )

            check(
                "Unknown document grant rejected",
                not invalid_ref.get("ok")
            )

            issued = await host(
                "issue",
                ref=ref,
                dest="external"
            )

            check(
                "Trusted host issues grant",
                issued.get("ok")
                and bool(issued.get("grant_token"))
            )

            token = issued.get("grant_token", "")

            wrong_scope = decode(
                await session.call_tool(
                    "store_document_ref",
                    {
                        "document_ref": ref,
                        "workspace": "local",
                        "grant_token": token
                    }
                )
            )

            check(
                "Wrong destination blocked",
                wrong_scope.get("decision") == "BLOCK"
                and not wrong_scope.get("executed")
            )

            allowed = decode(
                await session.call_tool(
                    "store_document_ref",
                    {
                        "document_ref": ref,
                        "workspace": "external",
                        "grant_token": token
                    }
                )
            )

            print(
                "\nAuthorized storage decision:",
                allowed.get("decision"),
                "| AI:",
                allowed.get("ai_decision")
            )

            check(
                "Authorized storage executes",
                allowed.get("decision") == "ALLOW"
                and allowed.get("executed") is True
            )

            replay = decode(
                await session.call_tool(
                    "store_document_ref",
                    {
                        "document_ref": ref,
                        "workspace": "external",
                        "grant_token": token
                    }
                )
            )

            check(
                "Consumed grant replay blocked",
                replay.get("decision") == "BLOCK"
                and not replay.get("executed")
            )

    print("\n=== STEP 57 RESULTS ===")
    print(
        f"Passed: {sum(checks)}/{len(checks)}"
    )

    if not all(checks):
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
