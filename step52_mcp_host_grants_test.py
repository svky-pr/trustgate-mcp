
#!/usr/bin/env python3
"""Step 52 end-to-end MCP and host-grant integration test.

Runs 14 security checks and reads the GenAI diagnostic file.
Storage is simulated, not real exfiltration.
"""

import asyncio
import json
import os
import secrets
import socket
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parent

DEBUG_FILE = ROOT / "step52_guard_debug.json"


def decode(result):

    for item in result.content:

        if getattr(item, "type", "") == "text":
            return json.loads(item.text)

    raise ValueError(
        "MCP response missing JSON text"
    )


async def main():

    # Remove stale diagnostic output.
    if DEBUG_FILE.exists():
        DEBUG_FILE.unlink()

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    secret = secrets.token_urlsafe(48)

    trusted_request = (
        "Read the public notice and store a copy "
        "of that public notice in the external workspace. "
        "I explicitly authorize exporting this public "
        "notice to the external workspace."
    )

    env = dict(os.environ)

    env.update({
        "TG52_HOST_SECRET": secret,
        "TG52_HOST_PORT": str(port),
        "TG52_TRUSTED_REQUEST": trusted_request,
        "TG52_ALLOWED_DEST": "external"
    })

    print(
        "\n=== TRUSTED USER REQUEST ===",
        flush=True
    )

    print(trusted_request, flush=True)

    print(
        "============================\n",
        flush=True
    )

    checks = []

    def check(name, ok):

        checks.append(
            (name, bool(ok))
        )

        print(
            f'{name:37s} {"PASS" if ok else "FAIL"}',
            flush=True
        )

    async def host(
        operation,
        *,
        document_ref=None,
        destination=None,
        secret_override=None
    ):

        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port
        )

        payload = {
            "secret": (
                secret
                if secret_override is None
                else secret_override
            ),
            "operation": operation
        }

        if document_ref is not None:
            payload["document_ref"] = document_ref

        if destination is not None:
            payload["destination"] = destination

        writer.write(
            (
                json.dumps(payload) + "\n"
            ).encode("utf-8")
        )

        await writer.drain()

        raw = await asyncio.wait_for(
            reader.readline(),
            timeout=10
        )

        reply = json.loads(
            raw.decode("utf-8")
        )

        writer.close()
        await writer.wait_closed()

        return reply

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            str(
                ROOT / "step52_mcp_host_grants_server.py"
            )
        ],
        env=env
    )

    async with stdio_client(params) as (r, w):

        async with ClientSession(r, w) as client:

            await client.initialize()

            names = {
                tool.name
                for tool in (
                    await client.list_tools()
                ).tools
            }

            expected = {
                "read_public_notice",
                "read_report",
                "summarize_report",
                "store_document_ref"
            }

            check(
                "only four mediated MCP tools",
                names == expected
            )

            check(
                "grant issuer not an MCP tool",
                not any(
                    "issue" in n or "grant" in n
                    for n in names
                )
            )

            check(
                "private host channel ready",
                (
                    await host("health")
                ).get("ok") is True
            )

            check(
                "host authentication rejects forgery",
                (
                    await host(
                        "health",
                        secret_override="invalid"
                    )
                ).get("ok") is False
            )

            read = decode(
                await client.call_tool(
                    "read_public_notice",
                    {}
                )
            )

            check(
                "public read allowed",
                read["decision"] == "ALLOW"
            )

            ref = (
                read.get("data", {})
                .get("document_ref")
            )

            check(
                "document reference returned",
                isinstance(ref, str)
                and bool(ref)
            )

            forged = await host(
                "issue",
                document_ref="not-a-real-ref",
                destination="external"
            )

            check(
                "host refuses unknown document",
                not forged.get("ok")
            )

            wrong = await host(
                "issue",
                document_ref=ref,
                destination="local"
            )

            check(
                "host refuses unapproved destination",
                not wrong.get("ok")
            )

            blocked = decode(
                await client.call_tool(
                    "store_document_ref",
                    {
                        "document_ref": ref,
                        "workspace": "external",
                        "grant_token": "forged"
                    }
                )
            )

            check(
                "agent forged grant blocked",
                blocked["decision"] == "BLOCK"
                and not blocked["executed"]
            )

            issued = await host(
                "issue",
                document_ref=ref,
                destination="external"
            )

            check(
                "trusted host issues scoped grant",
                bool(issued.get("ok"))
                and bool(issued.get("grant_token"))
            )

            token = issued.get(
                "grant_token", ""
            )

            mismatch = decode(
                await client.call_tool(
                    "store_document_ref",
                    {
                        "document_ref": ref,
                        "workspace": "local",
                        "grant_token": token
                    }
                )
            )

            check(
                "wrong destination blocked",
                mismatch["decision"] == "BLOCK"
            )

            allowed = decode(
                await client.call_tool(
                    "store_document_ref",
                    {
                        "document_ref": ref,
                        "workspace": "external",
                        "grant_token": token
                    }
                )
            )

            print(
                "\n=== AUTHORIZED STORAGE DEBUG ===",
                flush=True
            )

            print(
                json.dumps(allowed, indent=2),
                flush=True
            )

            check(
                "authorized MCP storage executed",
                allowed["decision"] == "ALLOW"
                and allowed["executed"]
            )

            replay = decode(
                await client.call_tool(
                    "store_document_ref",
                    {
                        "document_ref": ref,
                        "workspace": "external",
                        "grant_token": token
                    }
                )
            )

            check(
                "replay blocked",
                replay["decision"] == "BLOCK"
                and not replay["executed"]
            )

            private = decode(
                await client.call_tool(
                    "read_report",
                    {}
                )
            )

            check(
                "confidential read blocked",
                private["decision"] == "BLOCK"
            )

    print(
        "\n=== STEP 52 RESULTS ===",
        flush=True
    )

    passed = sum(
        ok for _, ok in checks
    )

    print(
        f"Checks: {passed}/{len(checks)} passed",
        flush=True
    )

    print(
        "Storage is simulated. Host authentication "
        "is prototype-only.",
        flush=True
    )

    print(
        "GenAI REVIEW remains BLOCK.",
        flush=True
    )

    print(
        "\n=== GENAI DIAGNOSTIC FILE ===",
        flush=True
    )

    if DEBUG_FILE.exists():

        diagnostic = json.loads(
            DEBUG_FILE.read_text(
                encoding="utf-8"
            )
        )

        print(
            json.dumps(
                diagnostic,
                indent=2
            ),
            flush=True
        )

    else:
        print(
            "No diagnostic file was generated. "
            "The guard may not have been invoked.",
            flush=True
        )

    if not all(ok for _, ok in checks):
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
