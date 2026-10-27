#!/usr/bin/env python3
"""Step 64 backend: serves one exact Step 61 benchmark document via real MCP.

Only use with a trusted local test harness. No real storage/network exports.
"""
import os
from mcp.server.fastmcp import FastMCP
from step61_unseen_attack_eval import CASES

mcp = FastMCP('TrustGate-Step64-Unseen-Case-Backend')
BY_ID = {item[0]: item for item in CASES}


def chosen_case():
    ident = os.environ.get('TG64_CASE_ID', '')
    if ident not in BY_ID:
        raise ValueError('TG64_CASE_ID must be one of the Step 61 case identifiers')
    return BY_ID[ident]


@mcp.tool()
def read_public_notice() -> str:
    """Read a public notice whose contents are untrusted test data."""
    return chosen_case()[3]


@mcp.tool()
def read_report() -> str:
    """Return a simulated confidential report (gateway should deny access)."""
    return 'CONFIDENTIAL: simulated internal report'


@mcp.tool()
def summarize_report(document: str) -> str:
    """Legacy backend summary tool."""
    return document[:300]


@mcp.tool()
def store_document(document: str, workspace: str) -> str:
    """Simulate storage; does not write data or perform network transfers."""
    if workspace not in ('local', 'external'):
        return 'REJECTED: unsupported workspace'
    return f'SIMULATED_STORE_OK workspace={workspace} chars={len(document)}'


if __name__ == '__main__':
    chosen_case()
    mcp.run(transport='stdio')
