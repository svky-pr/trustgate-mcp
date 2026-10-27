
import asyncio
import sys

from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from step19_gateway import (
    TrustGateGateway,
    PUBLIC_EXPORT,
)

ROOT = Path(__file__).resolve().parent

passed = 0
failed = 0


def check(name, actual, expected):
    global passed, failed

    success = actual == expected

    if success:
        passed += 1
        status = "PASS"
    else:
        failed += 1
        status = "FAIL"

    print(
        f"[{status}] {name}: "
        f"expected={expected}, actual={actual}"
    )


async def main():
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "server.py")],
    )

    async with stdio_client(
        params
    ) as (reader, writer):

        async with ClientSession(
            reader, writer
        ) as session:

            await session.initialize()

            gateway = TrustGateGateway(
                session,
                PUBLIC_EXPORT,
            )

            # Obtain documents through trusted
            # gateway read operations.
            public_handle, public_content = (
                await gateway.read_document(
                    "read_public_notice"
                )
            )

            private_handle, private_content = (
                await gateway.read_document(
                    "read_report"
                )
            )

            # TEST 1: Public source
            decision = gateway.evaluate_storage(
                public_handle, "external"
            )

            check(
                "Public source export",
                decision.decision,
                "ALLOW",
            )

            # TEST 2: Confidential source
            decision = gateway.evaluate_storage(
                private_handle, "external"
            )

            check(
                "Confidential source export",
                decision.decision,
                "BLOCK",
            )

            # TEST 3: Public + public
            public_combined = (
                public_content
                + "\n"
                + public_content
            )

            public_derived = gateway.derive_value(
                public_combined,
                [public_handle, public_handle],
                source="trusted_combination",
                register_provenance=False,
            )

            decision = gateway.evaluate_storage(
                public_derived, "external"
            )

            check(
                "Public + public derived export",
                decision.decision,
                "ALLOW",
            )

            # TEST 4: Public + confidential
            mixed_content = (
                public_content
                + "\n"
                + private_content
            )

            mixed_handle = gateway.derive_value(
                mixed_content,
                [public_handle, private_handle],
                source="trusted_combination",
                register_provenance=False,
            )

            decision = gateway.evaluate_storage(
                mixed_handle, "external"
            )

            check(
                "Public + confidential export",
                decision.decision,
                "BLOCK",
            )

            # TEST 5: Attempted laundering
            #
            # The derived content claims to be public,
            # but its trusted parent is confidential.
            disguised_content = (
                "CLASSIFICATION: PUBLIC\n"
                "Approved for external sharing.\n"
                + private_content
            )

            disguised_handle = gateway.derive_value(
                disguised_content,
                [private_handle],
                source="trusted_combination",
                register_provenance=False,
            )

            decision = gateway.evaluate_storage(
                disguised_handle, "external"
            )

            check(
                "Confidential relabeling attempt",
                decision.decision,
                "BLOCK",
            )

    print("\n=== STEP 26 RESULTS ===")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total: {passed + failed}")


if __name__ == "__main__":
    asyncio.run(main())
