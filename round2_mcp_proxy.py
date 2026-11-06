#!/usr/bin/env python3
"""Round 2 standalone MCP stdio gateway with one defense switch.

TG_MODE=none       Simulated backend pass-through, without security decisions.
TG_MODE=auth_only  Existing Step63 host grants/provenance/policy, no LLM guard.
TG_MODE=auth_guard Existing Step63 hybrid semantic and authorization guard.
Unset TG_MODE retains the existing Step63 hybrid behavior.

The numbered experiment scripts and underlying enforcement modules are not
modified by this entrypoint. Storage still goes to the local simulated backend.
"""
from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP

import step63_mcp_proxy as protected
from round2_mode import AuthorizationOnlyGuard, resolve_mode
from round2_baseline import PassThroughGateway

MODE = resolve_mode()
_baseline = None


@asynccontextmanager
async def lifespan(server):
    global _baseline
    if MODE == 'none':
        backend_file = protected._backend_path()
        params = StdioServerParameters(command=sys.executable,
                                       args=[str(backend_file)], env=dict(os.environ))
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                _baseline = PassThroughGateway(session)
                try:
                    yield
                finally:
                    _baseline = None
        return

    if MODE == 'auth_only':
        # Reuses the same no-inspection allow-result guard as Step67 ablation;
        # Step45 still enforces the exact existing grant and policy decisions.
        protected.Step63HybridGuard = AuthorizationOnlyGuard
    # auth_guard: exactly the original Step63 lifespan and guard.
    async with protected.lifespan(server):
        yield


mcp = FastMCP('TrustGate-Round2-Proxy', lifespan=lifespan)


async def dispatch(name: str, arguments: dict[str, str]) -> str:
    if MODE == 'none':
        if _baseline is None:
            return protected.response('BLOCK', 'Backend unavailable', executed=False)
        return await _baseline.dispatch(name, arguments)
    return await protected.dispatch(name, arguments)


@mcp.tool()
async def read_public_notice() -> str:
    """Read a synthetic public security notice from the MCP backend."""
    return await dispatch('read_public_notice', {})


@mcp.tool()
async def read_report() -> str:
    """Read a synthetic confidential report (protected modes deny)."""
    return await dispatch('read_report', {})


@mcp.tool()
async def summarize_report(document_ref: str) -> str:
    """Summarize content associated with an MCP document reference."""
    return await dispatch('summarize_report', {'document_ref': document_ref})


@mcp.tool()
async def store_document_ref(document_ref: str, workspace: str,
                             grant_token: str) -> str:
    """Simulate storing referenced content. Protected modes require a host grant."""
    return await dispatch('store_document_ref', {
        'document_ref': document_ref, 'workspace': workspace,
        'grant_token': grant_token,
    })


if __name__ == '__main__':
    protected._backend_path()
    print(f'[Round2] mode={MODE} backend={os.environ.get("TG58_BACKEND_FILE", "step58_poisoned_backend.py")}',
          file=sys.stderr, flush=True)
    mcp.run(transport='stdio')
