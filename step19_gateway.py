
"""Step 19: Unified MCP Security Gateway.

Integrates:
- Trusted provenance (Step 14)
- Intent authorization (Step 11)
- Data-flow taint tracking (Step 18)
- Actual MCP client/server calls

The MCP server's storage tool is simulated.
No LLM API calls are required.

Run:
    python step19_gateway.py
"""

import asyncio
import csv
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from step14_provenance import TrustedProvenance
from step18_taint import TaintState
from intent_guard import IntentGuard, IntentPolicy


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


# ============================================================
# TRUSTED USER POLICIES
# ============================================================

def make_policy(
    actions,
    workspaces=(),
    confidential_export=False,
):
    return IntentPolicy(
        allowed_actions=frozenset(actions),
        storage_workspaces=frozenset(workspaces),
        allow_confidential_external=confidential_export,
    )


READ_ONLY = make_policy(
    ("read_report", "read_public_notice")
)

PUBLIC_EXPORT = make_policy(
    (
        "read_report",
        "read_public_notice",
        "store_document",
    ),
    ("external",),
)

LOCAL_STORAGE = make_policy(
    (
        "read_report",
        "read_public_notice",
        "store_document",
    ),
    ("local",),
)

CONFIDENTIAL_EXPORT = make_policy(
    (
        "read_report",
        "store_document",
    ),
    ("external",),
    confidential_export=True,
)


# ============================================================
# GATEWAY RESULTS
# ============================================================

@dataclass
class GatewayDecision:
    decision: str
    reason: str
    executed: bool = False
    classification: str = "unknown"
    provenance_verified: bool = False
    taint_tracked: bool = False


# ============================================================
# UNIFIED MCP GATEWAY
# ============================================================

class TrustGateGateway:

    def __init__(self, session, user_policy):
        self.session = session

        # Middleware-owned state.
        self.provenance = TrustedProvenance()
        self.taint = TaintState()

        self.user_policy = user_policy
        self.intent_guard = IntentGuard(user_policy)

        # Map trusted document handles to taint values.
        self.handle_to_taint = {}

        # Store trusted document content for internal use.
        self.documents = {}

    async def _call_mcp(self, tool_name, arguments):
        result = await self.session.call_tool(
            tool_name,
            arguments=arguments,
        )

        text = "\n".join(
            item.text
            for item in result.content
            if getattr(item, "type", None) == "text"
        )

        if result.isError:
            raise RuntimeError(
                f"MCP tool {tool_name} failed: {text}"
            )

        return text

    def _authorize_action(self, tool_name):
        return self.intent_guard.evaluate(
            tool_name,
            {},
            classification="unknown",
        )

    async def read_document(
        self,
        tool_name,
    ):
        """Read from MCP and register trusted source data."""

        classifications = {
            "read_report": "confidential",
            "read_public_notice": "public",
        }

        if tool_name not in classifications:
            raise ValueError(
                "Unsupported document read tool"
            )

        action = self._authorize_action(tool_name)

        if action.decision != "ALLOW":
            raise PermissionError(
                f"Read rejected: {action.reason}"
            )

        content = await self._call_mcp(
            tool_name,
            {},
        )

        classification = classifications[tool_name]

        document_id = self.provenance.register_source(
            content,
            classification,
            tool_name,
        )

        taint_id = self.taint.register_source(
            content,
            classification,
            tool_name,
        )

        self.handle_to_taint[document_id] = taint_id
        self.documents[document_id] = content

        return document_id, content

    def derive_value(
        self,
        content,
        parent_handles,
        source,
        register_provenance=True,
    ):
        """Record a trusted internal transformation.

        SECURITY: Only trusted gateway code should invoke this
        method with parent handles derived from actual inputs.
        Do not expose it as an unrestricted LLM tool.
        """

        if not parent_handles:
            raise ValueError(
                "A transformation requires parent handles"
            )

        parent_taint_ids = []

        for handle in parent_handles:
            taint_id = self.handle_to_taint.get(handle)

            if taint_id is None:
                raise ValueError(
                    "Unknown transformation parent"
                )

            parent_taint_ids.append(taint_id)

        taint_id = self.taint.derive(
            content,
            parent_taint_ids,
            source,
        )

        if register_provenance:
            for handle in parent_handles:
                if (
                    self.provenance.resolve_handle(handle)
                    is None
                ):
                    raise ValueError(
                        "Parent is not registered in provenance"
                    )

            document_id = (
                self.provenance.register_transformation(
                    content,
                    parent_handles,
                    source,
                )
            )
        else:
            # This intermediate is tracked by taint only.
            # Its handle is internal to the gateway.
            import secrets

            document_id = (
                "taint-" + secrets.token_hex(16)
            )

        self.handle_to_taint[document_id] = taint_id
        self.documents[document_id] = content

        return document_id

    def evaluate_storage(
        self,
        document_id,
        workspace,
    ):
        """Combine intent, provenance, and taint evidence."""

        # 1. Check action and destination authorization
        # independently of document classification.

        if "store_document" not in (
            self.user_policy.allowed_actions
        ):
            return GatewayDecision(
                "BLOCK",
                "User did not authorize document storage",
            )

        if workspace not in (
            self.user_policy.storage_workspaces
        ):
            return GatewayDecision(
                "BLOCK",
                "Destination not authorized by user",
            )

        # 2. Resolve the handle through trusted registries.

        provenance_record = (
            self.provenance.resolve_handle(document_id)
        )

        taint_id = self.handle_to_taint.get(document_id)

        taint_record = (
            self.taint.resolve(taint_id)
            if taint_id is not None
            else None
        )

        verified = provenance_record is not None
        tracked = taint_record is not None

        if not verified and not tracked:
            return GatewayDecision(
                "CONFIRM",
                "Unknown document handle",
            )

        # 3. Determine classification.

        classifications = []

        if provenance_record is not None:
            classifications.append(
                provenance_record.classification
            )

        if taint_record is not None:
            classifications.append(
                taint_record.classification
            )

        if "confidential" in classifications:
            classification = "confidential"
        elif (
            classifications
            and all(
                value == "public"
                for value in classifications
            )
        ):
            classification = "public"
        else:
            classification = "unknown"

        # 4. Fail closed on contradictory evidence.

        if (
            provenance_record is not None
            and taint_record is not None
            and provenance_record.classification
            != taint_record.classification
        ):
            return GatewayDecision(
                "CONFIRM",
                "Provenance and taint classifications disagree",
                classification=classification,
                provenance_verified=verified,
                taint_tracked=tracked,
            )

        # 5. Local storage is allowed when authorized.

        if workspace == "local":
            return GatewayDecision(
                "ALLOW",
                "Authorized local storage",
                classification=classification,
                provenance_verified=verified,
                taint_tracked=tracked,
            )

        # 6. External transfer requires trusted identity
        # and known classification.

        if classification == "unknown":
            return GatewayDecision(
                "CONFIRM",
                "Insufficient classification evidence",
                classification=classification,
                provenance_verified=verified,
                taint_tracked=tracked,
            )

        if classification == "confidential":
            if not (
                self.user_policy.allow_confidential_external
            ):
                return GatewayDecision(
                    "BLOCK",
                    "Confidential external transfer not authorized",
                    classification=classification,
                    provenance_verified=verified,
                    taint_tracked=tracked,
                )

        # Taint-only intermediates are permitted here
        # because their identity and dependencies were
        # registered by trusted gateway code.
        # An arbitrary LLM-generated string cannot create
        # such a record.

        return GatewayDecision(
            "ALLOW",
            "Authorized transfer with trusted data lineage",
            classification=classification,
            provenance_verified=verified,
            taint_tracked=tracked,
        )

    async def store_handle(
        self,
        document_id,
        workspace,
    ):
        """The ONLY storage entry point exposed by the gateway."""

        decision = self.evaluate_storage(
            document_id,
            workspace,
        )

        if decision.decision != "ALLOW":
            return decision

        content = self.documents.get(document_id)

        if content is None:
            return GatewayDecision(
                "CONFIRM",
                "Document content unavailable",
                classification=decision.classification,
                provenance_verified=(
                    decision.provenance_verified
                ),
                taint_tracked=decision.taint_tracked,
            )

        # Security checks completed before the MCP call.
        await self._call_mcp(
            "store_document",
            {
                "document": content,
                "workspace": workspace,
            },
        )

        decision.executed = True

        return decision


# ============================================================
# INTEGRATION TESTS
# ============================================================

async def run_tests(session):
    rows = []

    async def check(
        name,
        gateway,
        document_id,
        workspace,
        expected,
    ):
        result = await gateway.store_handle(
            document_id,
            workspace,
        )

        passed = result.decision == expected

        # An operation must execute iff it was allowed.
        passed = passed and (
            result.executed == (expected == "ALLOW")
        )

        print(
            f"{'PASS' if passed else 'FAIL'} "
            f"{name:39s} "
            f"expected={expected:7s} "
            f"actual={result.decision:7s} "
            f"executed={result.executed}"
        )

        rows.append({
            "scenario": name,
            "expected": expected,
            "decision": result.decision,
            "executed": result.executed,
            "classification": result.classification,
            "provenance_verified": (
                result.provenance_verified
            ),
            "taint_tracked": result.taint_tracked,
            "reason": result.reason,
            "passed": passed,
        })

    print("\n=== STEP 19 UNIFIED MCP GATEWAY ===")

    # --------------------------------------------------------
    # Scenario 1: Unauthorized confidential export
    # --------------------------------------------------------

    gateway = TrustGateGateway(
        session,
        PUBLIC_EXPORT,
    )

    confidential_id, confidential_text = (
        await gateway.read_document("read_report")
    )

    await check(
        "unauthorized_confidential_export",
        gateway,
        confidential_id,
        "external",
        "BLOCK",
    )

    # --------------------------------------------------------
    # Scenario 2: Authorized public export
    # --------------------------------------------------------

    public_id, public_text = (
        await gateway.read_document("read_public_notice")
    )

    await check(
        "authorized_public_export",
        gateway,
        public_id,
        "external",
        "ALLOW",
    )

    # --------------------------------------------------------
    # Scenario 3: Confidential transformation
    # --------------------------------------------------------

    summary_id = gateway.derive_value(
        "Summary of sensitive assessment findings",
        [confidential_id],
        "trusted_summary",
        register_provenance=True,
    )

    await check(
        "confidential_summary_laundering",
        gateway,
        summary_id,
        "external",
        "BLOCK",
    )

    # --------------------------------------------------------
    # Scenario 4: Multi-source contamination
    # --------------------------------------------------------

    mixed_id = gateway.derive_value(
        "Public notice combined with internal findings",
        [public_id, confidential_id],
        "trusted_merge",
        register_provenance=True,
    )

    await check(
        "mixed_document_laundering",
        gateway,
        mixed_id,
        "external",
        "BLOCK",
    )

    # --------------------------------------------------------
    # Scenario 5: Taint-only intermediate
    # --------------------------------------------------------

    intermediate_id = gateway.derive_value(
        "Reformatted internal security findings",
        [summary_id],
        "trusted_format_table",
        register_provenance=False,
    )

    assert (
        gateway.provenance.resolve_handle(intermediate_id)
        is None
    )

    assert (
        gateway.taint.resolve(
            gateway.handle_to_taint[intermediate_id]
        ) is not None
    )

    await check(
        "taint_only_intermediate_export",
        gateway,
        intermediate_id,
        "external",
        "BLOCK",
    )

    # --------------------------------------------------------
    # Scenario 6: Independent public data
    # --------------------------------------------------------

    public_rewrite_id = gateway.derive_value(
        "Reformatted public announcement",
        [public_id],
        "trusted_public_rewrite",
        register_provenance=False,
    )

    await check(
        "public_after_confidential_read",
        gateway,
        public_rewrite_id,
        "external",
        "ALLOW",
    )

    # --------------------------------------------------------
    # Scenario 7: Unknown handle
    # --------------------------------------------------------

    await check(
        "unknown_document_handle",
        gateway,
        "invented-document-id",
        "external",
        "CONFIRM",
    )

    # --------------------------------------------------------
    # Scenario 8: Unauthorized destination
    # --------------------------------------------------------

    local_gateway = TrustGateGateway(
        session,
        LOCAL_STORAGE,
    )

    local_id, _ = await local_gateway.read_document(
        "read_report"
    )

    await check(
        "unauthorized_destination",
        local_gateway,
        local_id,
        "external",
        "BLOCK",
    )

    # --------------------------------------------------------
    # Scenario 9: Authorized local confidential storage
    # --------------------------------------------------------

    await check(
        "authorized_local_confidential",
        local_gateway,
        local_id,
        "local",
        "ALLOW",
    )

    # --------------------------------------------------------
    # Scenario 10: Explicit confidential export
    # --------------------------------------------------------

    confidential_gateway = TrustGateGateway(
        session,
        CONFIDENTIAL_EXPORT,
    )

    export_id, _ = (
        await confidential_gateway.read_document(
            "read_report"
        )
    )

    await check(
        "explicit_confidential_export",
        confidential_gateway,
        export_id,
        "external",
        "ALLOW",
    )

    # --------------------------------------------------------
    # Scenario 11: Read-only policy
    # --------------------------------------------------------

    readonly_gateway = TrustGateGateway(
        session,
        READ_ONLY,
    )

    readonly_id, _ = (
        await readonly_gateway.read_document(
            "read_public_notice"
        )
    )

    await check(
        "read_only_policy",
        readonly_gateway,
        readonly_id,
        "external",
        "BLOCK",
    )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    path = (
        RESULTS / f"step19_gateway_{stamp}.csv"
    )

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(rows[0]),
        )

        writer.writeheader()
        writer.writerows(rows)

    passed = sum(row["passed"] for row in rows)

    print("\n=== STEP 19 SUMMARY ===")
    print(f"Passed: {passed}/{len(rows)}")
    print(f"Results: {path}")

    if passed != len(rows):
        raise AssertionError(
            "Gateway integration tests failed"
        )


# ============================================================
# MCP CLIENT ENTRY POINT
# ============================================================

async def main():
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "server.py")],
    )

    async with stdio_client(
        params
    ) as (reader, writer):

        async with ClientSession(
            reader,
            writer,
        ) as session:

            await session.initialize()

            available = {
                tool.name
                for tool in (
                    await session.list_tools()
                ).tools
            }

            required = {
                "read_report",
                "read_public_notice",
                "store_document",
            }

            missing = required - available

            if missing:
                raise RuntimeError(
                    f"Missing MCP tools: {sorted(missing)}"
                )

            await run_tests(session)


if __name__ == "__main__":
    asyncio.run(main())
