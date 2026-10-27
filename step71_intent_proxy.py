#!/usr/bin/env python3
"""Step71: host-scoped pre-execution intent checks in the real Step63 MCP proxy.

This wrapper preserves Step63's grants, provenance and hybrid content inspection.
Host policy comes ONLY from process environment, never tool output or agent args.
The backend is still a simulation. The agent must access only this proxy.
"""
from __future__ import annotations
import json
import os
import sys
from dataclasses import dataclass

import step63_mcp_proxy as proxy


@dataclass(frozen=True)
class HostIntent:
    tools: frozenset[str]
    destinations: frozenset[str]
    export_authorized: bool


def trusted_intent() -> HostIntent:
    request = os.environ.get('TG52_TRUSTED_REQUEST', '')
    dest = os.environ.get('TG52_ALLOWED_DEST', '')
    export = bool(proxy._explicit_export_authorization(request, dest))
    tools = frozenset({'read_public_notice', 'summarize_report'} |
                      ({'store_document_ref'} if export else set()))
    return HostIntent(tools, frozenset({dest}) if export else frozenset(), export)


INTENT = trusted_intent()
SCHEMAS = {
    'read_public_notice': frozenset(),
    'summarize_report': frozenset({'document_ref'}),
    'store_document_ref': frozenset({'document_ref', 'workspace', 'grant_token'}),
}
# References observed through the mediated read tool, not guessed from agent text.
SEEN_REFS: set[str] = set()
ORIGINAL_DISPATCH = proxy.dispatch


def block(reason: str) -> str:
    return proxy.response('BLOCK', 'Step71 pre-execution: ' + reason,
                          executed=False, data=None, ai_decision='NOT_EVALUATED')


async def guarded_dispatch(name, args):
    if name not in INTENT.tools:
        return block('Tool not authorized by trusted host intent')
    expected = SCHEMAS.get(name)
    if expected is None or not isinstance(args, dict) or set(args) != expected:
        return block('Unknown tool or unexpected argument schema')
    if any(not isinstance(v, str) or not v.strip() for v in args.values()):
        return block('Invalid argument value')
    if name in ('summarize_report', 'store_document_ref'):
        if args['document_ref'] not in SEEN_REFS:
            return block('Reference not observed through this proxy session')
    if name == 'store_document_ref':
        if not INTENT.export_authorized:
            return block('Export not authorized')
        if args['workspace'] not in INTENT.destinations:
            return block('Destination outside trusted scope')
        # Step63 still checks the scoped, single-use grant, provenance,
        # deterministic policy and GenAI content guard before storage.
    result = await ORIGINAL_DISPATCH(name, args)
    if name == 'read_public_notice':
        try:
            parsed = json.loads(result)
            data = parsed.get('data') or {}
            ref = data.get('document_ref')
            if parsed.get('executed') is True and isinstance(ref, str) and ref:
                SEEN_REFS.add(ref)
        except (ValueError, TypeError, AttributeError):
            pass
    return result


proxy.dispatch = guarded_dispatch

if __name__ == '__main__':
    print('[Step71] intent guard active; export_authorized=',
          INTENT.export_authorized, file=sys.stderr, flush=True)
    proxy.mcp.run(transport='stdio')
