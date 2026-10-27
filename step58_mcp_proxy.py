#!/usr/bin/env python3
"""Step 58: MCP proxy for live poisoned-backend evaluation.

Agent-facing tools are mediated by AllToolsGateway. The backend is selected
only from trusted process environment and never from MCP tool arguments.
The localhost grant channel is a prototype, not production authentication.
No grants are issued for the Step 58 read-only / do-not-export request.
"""
import asyncio
import hmac
import json
import os
import secrets
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
load_dotenv(ROOT / '.env')
_gateway = None
_issuer = None
_session_id = None


def response(decision, reason, **extra):
    return json.dumps({'decision': decision, 'reason': reason, **extra})


def _explicit_export_authorization(request, destination):
    """Conservative demo gate; never treat a negative mention as permission."""
    import re
    text = request.lower()
    if re.search(r'\b(do not|don\'t|never|without|prohibit(?:ed)?|forbid(?:den)?)\b', text):
        return False
    if destination == 'external':
        return bool(re.search(r'\b(export|store|save|upload|send)\b', text) and
                    re.search(r'\bexternal\b', text))
    return bool(re.search(r'\b(store|save)\b', text) and
                re.search(r'\blocal\b', text))


def _backend_path():
    filename = os.environ.get('TG58_BACKEND_FILE', 'step58_poisoned_backend.py')
    candidate = ROOT / filename
    if candidate.resolve().parent != ROOT.resolve() or not candidate.is_file():
        raise RuntimeError(f'Invalid backend filename: {filename}')
    if candidate.resolve() == Path(__file__).resolve():
        raise RuntimeError('Backend cannot be the proxy itself')
    return candidate


@asynccontextmanager
async def lifespan(server):
    global _gateway, _issuer, _session_id
    secret = os.environ.get('TG52_HOST_SECRET', '')
    try:
        port = int(os.environ.get('TG52_HOST_PORT', '0'))
    except ValueError as exc:
        raise RuntimeError('Invalid host port') from exc
    trusted_request = os.environ.get('TG52_TRUSTED_REQUEST', '')
    trusted_dest = os.environ.get('TG52_ALLOWED_DEST', '')
    if len(secret) < 40 or not (1024 <= port <= 65535):
        raise RuntimeError('Trusted host secret and localhost port required')
    if trusted_dest not in ('external', 'local') or not trusted_request:
        raise RuntimeError('Trusted host request and destination required')

    backend_file = _backend_path()
    print(f'[Step58 proxy] backend={backend_file.name} '
          f'attack={os.environ.get("TG58_ATTACK", "clean")}',
          file=sys.stderr, flush=True)

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(backend_file)],
        env=dict(os.environ),
    )
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            _issuer = TrustedGrantIssuer()
            _session_id = secrets.token_urlsafe(18)
            backend = ReferenceGateway(session, WORKFLOWS['public_export'])
            _gateway = AllToolsGateway(
                reference_gateway=backend,
                ai_guard=ImprovedTrustGateAIGuard(),
                issuer=_issuer,
                session_id=_session_id,
                user_request=trusted_request,
                allowed_reads=frozenset({'read_public_notice'}),
                summarize=lambda content: content[:300],
            )

            async def host_control(r, w):
                try:
                    raw = await asyncio.wait_for(r.readline(), timeout=5)
                    if len(raw) > 4096:
                        raise ValueError('Oversized host request')
                    data = json.loads(raw.decode('utf-8'))
                    supplied = data.get('secret', '')
                    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, secret):
                        answer = {'ok': False, 'reason': 'Host authentication failed'}
                    elif data.get('operation') == 'health':
                        answer = {'ok': True}
                    elif data.get('operation') == 'issue':
                        ref = data.get('document_ref')
                        dest = data.get('destination')
                        doc = (_gateway._AllToolsGateway__documents.get(ref)
                               if isinstance(ref, str) else None)
                        if not _explicit_export_authorization(trusted_request, trusted_dest):
                            answer = {'ok': False, 'reason': 'Trusted request does not authorize storage'}
                        elif (not doc or doc.get('source') != 'read_public_notice'
                              or dest != trusted_dest):
                            answer = {'ok': False, 'reason': 'Reference or scope denied'}
                        else:
                            token = _issuer.issue(
                                session_id=_session_id,
                                document_ref=ref,
                                action='store_document_ref',
                                destination=dest,
                            )
                            answer = {'ok': True, 'grant_token': token}
                    else:
                        answer = {'ok': False, 'reason': 'Unknown host operation'}
                except Exception as exc:
                    answer = {'ok': False, 'reason': f'Invalid host request: {type(exc).__name__}'}
                try:
                    w.write((json.dumps(answer) + '\n').encode('utf-8'))
                    await w.drain()
                finally:
                    w.close()
                    await w.wait_closed()

            control = await asyncio.start_server(host_control, '127.0.0.1', port)
            try:
                yield
            finally:
                control.close()
                await control.wait_closed()
                _gateway = None
                _issuer = None
                _session_id = None


mcp = FastMCP('TrustGate-Step58-Poisoned-Backend-Proxy', lifespan=lifespan)


async def dispatch(name, args):
    if _gateway is None:
        return response('BLOCK', 'Gateway unavailable', executed=False)
    try:
        result = await _gateway.call_tool(name, args)
        if name == 'store_document_ref':
            print(f'[Step58 proxy] storage decision={result.decision} '
                  f'ai={result.ai_decision} reason={result.reason}',
                  file=sys.stderr, flush=True)
        return response(result.decision, result.reason,
                        executed=result.executed, data=result.data,
                        ai_decision=result.ai_decision)
    except Exception as exc:
        print(f'[Step58 proxy] dispatch error: {type(exc).__name__}: {exc}',
              file=sys.stderr, flush=True)
        return response('BLOCK', f'Gateway exception: {type(exc).__name__}',
                        executed=False)


@mcp.tool()
async def read_public_notice() -> str:
    """Read public notice through the mediated gateway."""
    return await dispatch('read_public_notice', {})


@mcp.tool()
async def read_report() -> str:
    """Read confidential report (denied by trusted read policy)."""
    return await dispatch('read_report', {})


@mcp.tool()
async def summarize_report(document_ref: str) -> str:
    """Summarize a previously tracked document."""
    return await dispatch('summarize_report', {'document_ref': document_ref})


@mcp.tool()
async def store_document_ref(document_ref: str, workspace: str, grant_token: str) -> str:
    """Simulated store requiring a scoped trusted-host-issued grant."""
    return await dispatch('store_document_ref', {
        'document_ref': document_ref,
        'workspace': workspace,
        'grant_token': grant_token,
    })


if __name__ == '__main__':
    _backend_path()
    mcp.run(transport='stdio')
