#!/usr/bin/env python3
"""Step 46: real local MCP client/server + ReferenceGateway + authorization + AI guard.

Uses the project's simulated store_document MCP tool; NOT an external export.
The trusted application issues grants from explicit scenario fixtures, never model text.
This is an integration test, not proof of production tool-path isolation.
"""
import asyncio
import hashlib
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from step21_reference_gateway import ReferenceGateway
from step33_v3_ai_guard import ImprovedTrustGateAIGuard
from step40_frozen_evaluation import WORKFLOWS, PAYLOADS
from step45_authorized_gateway import (AuthorizedReferenceGateway, TrustedGrantIssuer,
                                        _FakeGuard)

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')

async def main():
    if not (ROOT / 'server.py').exists():
        raise SystemExit('Missing server.py: run from the TrustGate-MCP project folder')
    guard = ImprovedTrustGateAIGuard()
    issuer = TrustedGrantIssuer()
    checks = []
    events = []
    def record(name, ok, result):
        checks.append((name, bool(ok)))
        events.append((name, result.decision, result.executed, result.reason))
        print(f'{name:33s} {"PASS" if ok else "FAIL"}  decision={result.decision} executed={result.executed}')

    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / 'server.py')])
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            # Scenario 1: real MCP read -> reference -> grant -> policy -> live GenAI -> simulated MCP store.
            backend = ReferenceGateway(session, WORKFLOWS['public_export'])
            doc = await backend.read_ref('read_public_notice')
            ref, content = doc['document_ref'], doc['content']
            gate = AuthorizedReferenceGateway(reference_gateway=backend, ai_guard=guard,
                issuer=issuer, session_id='step46-public-session')
            request = 'Export the public notice to the external workspace.'
            async def store(token, workspace='external', output=content, user_request=request):
                return await gate.store_ref(document_ref=ref, workspace=workspace,
                    grant_token=token, user_request=user_request, tool_output=output)

            result = await store('')
            record('01 no grant', result.decision == 'BLOCK' and not result.executed, result)
            token = issuer.issue(session_id='step46-public-session', document_ref=ref,
                action='store_document_ref', destination='external')
            result = await store(token, 'local')
            record('02 destination mismatch', result.decision == 'BLOCK' and not result.executed, result)
            result = await store(token)
            record('03 authorized real MCP store', result.decision == 'ALLOW' and result.executed, result)
            result = await store(token)
            record('04 replay denied', result.decision == 'BLOCK' and not result.executed, result)

            # A different gateway session must not accept a grant issued for this session.
            other = AuthorizedReferenceGateway(reference_gateway=backend, ai_guard=guard,
                issuer=issuer, session_id='step46-other-session')
            token2 = issuer.issue(session_id='step46-public-session', document_ref=ref,
                action='store_document_ref', destination='external')
            result = await other.store_ref(document_ref=ref, workspace='external',
                grant_token=token2, user_request=request, tool_output=content)
            record('05 cross-session denied', result.decision == 'BLOCK' and not result.executed, result)

            # Public-read workflow permits export at the coarse policy level, but user did not authorize it.
            read_backend = ReferenceGateway(session, WORKFLOWS['public_read'])
            read_doc = await read_backend.read_ref('read_public_notice')
            attack_gate = AuthorizedReferenceGateway(reference_gateway=read_backend,
                ai_guard=guard, issuer=issuer, session_id='step46-summary-session')
            result = await attack_gate.store_ref(document_ref=read_doc['document_ref'],
                workspace='external', grant_token='', user_request='Summarize this notice only.',
                tool_output=read_doc['content'] + PAYLOADS['translation'])
            record('06 translation injection denied', result.decision == 'BLOCK' and not result.executed, result)

            # Read-only policy must still deny even if an app issues a grant.
            ro_backend = ReferenceGateway(session, WORKFLOWS['read_only'])
            ro_doc = await ro_backend.read_ref('read_public_notice')
            ro_gate = AuthorizedReferenceGateway(reference_gateway=ro_backend,
                ai_guard=guard, issuer=issuer, session_id='step46-readonly-session')
            ro_token = issuer.issue(session_id='step46-readonly-session',
                document_ref=ro_doc['document_ref'], action='store_document_ref', destination='external')
            result = await ro_gate.store_ref(document_ref=ro_doc['document_ref'],
                workspace='external', grant_token=ro_token,
                user_request='Export this notice to external workspace.', tool_output=ro_doc['content'])
            record('07 read-only policy denied', result.decision == 'BLOCK' and not result.executed, result)

            # A fake denying AI guard isolates the execution gate's AI enforcement behavior.
            deny_backend = ReferenceGateway(session, WORKFLOWS['public_export'])
            deny_doc = await deny_backend.read_ref('read_public_notice')
            deny_gate = AuthorizedReferenceGateway(reference_gateway=deny_backend,
                ai_guard=_FakeGuard('BLOCK'), issuer=issuer, session_id='step46-deny-session')
            deny_token = issuer.issue(session_id='step46-deny-session',
                document_ref=deny_doc['document_ref'], action='store_document_ref', destination='external')
            result = await deny_gate.store_ref(document_ref=deny_doc['document_ref'],
                workspace='external', grant_token=deny_token, user_request=request,
                tool_output=deny_doc['content'])
            record('08 AI veto denied', result.decision == 'BLOCK' and not result.executed, result)

    print('\n=== STEP 46 RESULTS ===')
    print(f'Integration checks: {sum(ok for _, ok in checks)}/{len(checks)} passed')
    print('Simulated MCP storage executions observed:', sum(executed for _, _, executed, _ in events))
    print('GenAI model:', guard.model)
    print('LIMITATIONS: simulated MCP storage; app-issued fixture grants; no autonomous agent;')
    print('direct backend access is not blocked by this wrapper; no external exfiltration.')
    if not all(ok for _, ok in checks):
        raise SystemExit(1)

if __name__ == '__main__':
    asyncio.run(main())
