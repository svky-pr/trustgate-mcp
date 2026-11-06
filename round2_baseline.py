#!/usr/bin/env python3
"""Round 2 baseline: MCP protocol adapter with no gateway security checks.

Designed for the *simulated* local Step58 backend only. Its document-ref lookup
is necessary to translate the client API into backend store_document(content).
It does not enforce authorization, provenance policy, DLP or LLM guard checks.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import sys
from typing import Any


def response(decision: str, reason: str, **extra: Any) -> str:
    return json.dumps({'decision': decision, 'reason': reason, **extra})


class PassThroughGateway:
    def __init__(self, session: Any):
        self.session = session
        self.documents: dict[str, str] = {}
        self.lock = asyncio.Lock()

    async def _backend(self, name: str, arguments: dict[str, str]):
        result = await self.session.call_tool(name, arguments=arguments)
        text = '\n'.join(item.text for item in result.content
                         if getattr(item, 'type', None) == 'text')
        if result.isError:
            raise RuntimeError(f'Backend MCP error: {text[:200]}')
        return text

    async def dispatch(self, name: str, args: dict[str, Any]) -> str:
        try:
            if name in ('read_public_notice', 'read_report'):
                content = await self._backend(name, {})
                async with self.lock:
                    ref = 'doc_' + secrets.token_hex(16)
                    self.documents[ref] = content
                return response('ALLOW', 'Baseline backend read', executed=True,
                                data={'document_ref': ref, 'content': content},
                                ai_decision='NOT_EVALUATED')

            if name == 'summarize_report':
                content = self.documents.get(args.get('document_ref'))
                if content is None:
                    return response('BLOCK', 'Unknown reference in baseline adapter',
                                    executed=False)
                return response('ALLOW', 'Baseline local summarization',
                                executed=True, data={'summary': content[:300]},
                                ai_decision='NOT_EVALUATED')

            if name == 'store_document_ref':
                content = self.documents.get(args.get('document_ref'))
                if content is None:
                    return response('BLOCK', 'Unknown reference in baseline adapter',
                                    executed=False)
                # Baseline: no grant, provenance-policy, DLP or LLM enforcement.
                result = await self._backend('store_document', {
                    'document': content, 'workspace': args.get('workspace', '')})
                stored = result.startswith('SIMULATED_STORE_OK')
                return response('ALLOW' if stored else 'BLOCK',
                                'Baseline simulated backend store' if stored else result,
                                executed=stored, data=None,
                                ai_decision='NOT_EVALUATED')
            return response('BLOCK', 'Unknown backend tool', executed=False)
        except Exception as exc:
            print(f'[Round2 baseline] {name}: {type(exc).__name__}: {exc}',
                  file=sys.stderr, flush=True)
            return response('BLOCK', f'Backend error: {type(exc).__name__}',
                            executed=False)
