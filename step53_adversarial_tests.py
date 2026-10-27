
#!/usr/bin/env python3
"""
TrustGate-MCP Step 53
Adversarial Security Regression Suite

Uses the real Step 52 MCP server.
No real data export occurs.

Requires:
    step52_mcp_host_grants_server.py
    server.py
    Step 21-50 dependencies
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

TRUSTED_REQUEST = (
    "Read the public notice and store a copy of "
    "that public notice in the external workspace. "
    "I explicitly authorize exporting this public "
    "notice to the external workspace."
)

results = []


def check(name, passed, details=""):
    passed = bool(passed)

    results.append({
        "test": name,
        "passed": passed,
        "details": details
    })

    status = "PASS" if passed else "FAIL"

    print(f"{name:43s} {status}", flush=True)


def decode(result):
    for item in result.content:
        if getattr(item, "type", "") == "text":
            return json.loads(item.text)

    raise RuntimeError("Missing JSON response")


def blocked(result):
    return (
        result.get("decision") == "BLOCK"
        and result.get("executed") is False
    )


async def main():

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    secret = secrets.token_urlsafe(48)

    env = dict(os.environ)

    env.update({
        "TG52_HOST_SECRET": secret,
        "TG52_HOST_PORT": str(port),
        "TG52_TRUSTED_REQUEST": TRUSTED_REQUEST,
        "TG52_ALLOWED_DEST": "external"
    })

    async def host(
        operation,
        document_ref=None,
        destination=None,
        supplied_secret=None
    ):

        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port
        )

        payload = {
            "secret": (
                secret
                if supplied_secret is None
                else supplied_secret
            ),
            "operation": operation
        }

        if document_ref is not None:
            payload["document_ref"] = document_ref

        if destination is not None:
            payload["destination"] = destination

        writer.write(
            (json.dumps(payload) + "\n").encode()
        )

        await writer.drain()

        data = await asyncio.wait_for(
            reader.readline(),
            timeout=10
        )

        writer.close()
        await writer.wait_closed()

        return json.loads(data.decode())

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

            async def call(name, arguments):
                return decode(
                    await client.call_tool(
                        name,
                        arguments
                    )
                )

            print("\n=== STEP 53 SECURITY TESTS ===\n")

            tools = {
                t.name
                for t in (
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
                "T01: MCP tool allowlist",
                tools == expected
            )

            check(
                "T02: Grant issuer not exposed",
                not any(
                    "grant" in t or "issue" in t
                    for t in tools
                )
            )

            check(
                "T03: Host channel available",
                (await host("health")).get("ok")
                is True
            )

            check(
                "T04: Invalid host secret rejected",
                not (
                    await host(
                        "health",
                        supplied_secret="attacker-secret"
                    )
                ).get("ok")
            )

            check(
                "T05: Unknown host operation rejected",
                not (
                    await host("unknown_operation")
                ).get("ok")
            )

            public = await call(
                "read_public_notice",
                {}
            )

            ref = public.get(
                "data", {}
            ).get("document_ref")

            check(
                "T06: Public read succeeds",
                public.get("decision") == "ALLOW"
                and bool(ref)
            )

            confidential = await call(
                "read_report",
                {}
            )

            check(
                "T07: Confidential read blocked",
                blocked(confidential)
            )

            fake_grant = await host(
                "issue",
                document_ref="attacker-fake-reference",
                destination="external"
            )

            check(
                "T08: Unknown reference grant denied",
                not fake_grant.get("ok")
            )

            wrong_dest_grant = await host(
                "issue",
                document_ref=ref,
                destination="local"
            )

            check(
                "T09: Unapproved grant destination denied",
                not wrong_dest_grant.get("ok")
            )

            forged = await call(
                "store_document_ref",
                {
                    "document_ref": ref,
                    "workspace": "external",
                    "grant_token": "forged-token"
                }
            )

            check(
                "T10: Forged storage grant blocked",
                blocked(forged)
            )

            unknown_ref = await call(
                "store_document_ref",
                {
                    "document_ref": "attacker-fake-reference",
                    "workspace": "external",
                    "grant_token": "forged-token"
                }
            )

            check(
                "T11: Forged document reference blocked",
                blocked(unknown_ref)
            )

            no_grant = await call(
                "store_document_ref",
                {
                    "document_ref": ref,
                    "workspace": "external",
                    "grant_token": ""
                }
            )

            check(
                "T12: Missing grant blocked",
                blocked(no_grant)
            )

            issued = await host(
                "issue",
                document_ref=ref,
                destination="external"
            )

            token = issued.get(
                "grant_token", ""
            )

            check(
                "T13: Trusted grant issued",
                issued.get("ok")
                and bool(token)
            )

            wrong_workspace = await call(
                "store_document_ref",
                {
                    "document_ref": ref,
                    "workspace": "local",
                    "grant_token": token
                }
            )

            check(
                "T14: Destination substitution blocked",
                blocked(wrong_workspace)
            )

            other_ref = await call(
                "read_public_notice",
                {}
            )

            ref2 = other_ref.get(
                "data", {}
            ).get("document_ref")

            check(
                "T15: Second document reference available",
                bool(ref2)
            )

            ref_substitution = await call(
                "store_document_ref",
                {
                    "document_ref": ref2,
                    "workspace": "external",
                    "grant_token": token
                }
            )

            check(
                "T16: Grant reference substitution blocked",
                blocked(ref_substitution)
            )

            # Legitimate operation uses the original
            # grant and original document reference.
            legitimate = await call(
                "store_document_ref",
                {
                    "document_ref": ref,
                    "workspace": "external",
                    "grant_token": token
                }
            )

            print("\n=== LEGITIMATE EXPORT DECISION ===")
            print(
                json.dumps(
                    legitimate,
                    indent=2
                )
            )

            check(
                "T17: Authorized public export succeeds",
                legitimate.get("decision") == "ALLOW"
                and legitimate.get("executed") is True,
                legitimate.get("reason", "")
            )

            replay = await call(
                "store_document_ref",
                {
                    "document_ref": ref,
                    "workspace": "external",
                    "grant_token": token
                }
            )

            check(
                "T18: Used grant replay blocked",
                blocked(replay)
            )

            check(
                "T19: AI decision recorded",
                legitimate.get("ai_decision")
                in {"ALLOW", "BLOCK", "REVIEW"}
            )

    print("\n=== STEP 53 RESULTS ===")

    passed = sum(
        item["passed"]
        for item in results
    )

    total = len(results)

    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}")

    output = ROOT / "step53_results.json"

    output.write_text(
        json.dumps(
            {
                "passed": passed,
                "total": total,
                "results": results
            },
            indent=2
        ),
        encoding="utf-8"
    )

    print(f"Results saved: {output.name}")

    print(
        "\nNote: These are security regression tests. "
        "They do not yet inject malicious text into "
        "the public notice or test all prompt-injection variants."
    )

    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
