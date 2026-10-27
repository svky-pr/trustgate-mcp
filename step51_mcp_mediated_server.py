#!/usr/bin/env python3
"""Step 51: agent-facing MCP stdio server exposing ONLY mediated tools.

Architecture:
agent -> THIS MCP server -> AllToolsGateway -> backend ReferenceGateway
                                           -> backend MCP server.py

This prototype intentionally has NO agent-accessible grant issuance endpoint.
Therefore storage attempts without a trusted host-issued grant are denied.
For approved storage, integrate an authenticated host-side grant channel; do
NOT expose TrustedGrantIssuer.issue() as an MCP tool.

Run from project directory:
  python step51_mcp_mediated_server.py
or run:
  python step51_mcp_proxy_test.py
Requires project's MCP SDK and existing Step 21/33/40/45/50 modules.
"""
import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP

from step21_reference_gateway import ReferenceGateway
from step33_v3_ai_guard import ImprovedTrustGateAIGuard
from step40_frozen_evaluation import WORKFLOWS
from step45_authorized_gateway import TrustedGrantIssuer
from step50_all_tools_gateway import AllToolsGateway

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
_gateway = None

@asynccontextmanager
async def lifespan(server):
    global _gateway
    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / "server.py")])
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            backend = ReferenceGateway(session, WORKFLOWS["public_read"])
            # Trusted host owns this policy and user request. This demo uses a
            # fixed read-only user request; agents cannot set them via MCP.
            _gateway = AllToolsGateway(
                reference_gateway=backend,
                ai_guard=ImprovedTrustGateAIGuard(),
                issuer=TrustedGrantIssuer(),
                session_id="step51-mcp-session",
                user_request="Summarize the public notice only. Do not export.",
                allowed_reads=frozenset({"read_public_notice"}),
                summarize=lambda content: content[:300],
            )
            try:
                yield
            finally:
                _gateway = None

mcp = FastMCP("TrustGate-Mediated-Tools", lifespan=lifespan)

async def dispatch(name, arguments):
    if _gateway is None:
        return json.dumps({"decision":"BLOCK","reason":"Gateway unavailable","executed":False})
    try:
        result = await _gateway.call_tool(name, arguments)
        return json.dumps({
            "decision": result.decision,
            "reason": result.reason,
            "executed": result.executed,
            "data": result.data,
            "ai_decision": result.ai_decision,
        })
    except Exception as exc:
        return json.dumps({"decision":"BLOCK","reason":f"Dispatcher error: {type(exc).__name__}","executed":False})

@mcp.tool()
async def read_public_notice() -> str:
    """Read public notice through TrustGate access policy and provenance tracking."""
    return await dispatch("read_public_notice", {})

@mcp.tool()
async def read_report() -> str:
    """Request a confidential report; denied by this demo's trusted read policy."""
    return await dispatch("read_report", {})

@mcp.tool()
async def summarize_report(document_ref: str) -> str:
    """Summarize a document previously read through the mediated gateway."""
    return await dispatch("summarize_report", {"document_ref": document_ref})

@mcp.tool()
async def store_document_ref(document_ref: str, workspace: str, grant_token: str) -> str:
    """Store a referenced document; requires an application-issued grant."""
    return await dispatch("store_document_ref", {
        "document_ref":document_ref, "workspace":workspace, "grant_token":grant_token
    })

if __name__ == "__main__":
    if not (ROOT / "server.py").exists():
        raise SystemExit("Missing backend server.py in the project folder")
    mcp.run(transport="stdio")
