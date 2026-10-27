#!/usr/bin/env python3
"""Step 50: deny-by-default dispatch for ALL registered MCP operations.

This is an application-level mediation adapter, NOT a network-transparent MCP
proxy. Give agents ONLY the dispatcher.call_tool interface, never raw backend
or grant issuer access. Real deployment must enforce that isolation.
Reads: trusted policy + provenance tracking. Summarization: read-only,
trusted input reference, policy. Storage: scoped grant + deterministic policy
+ GenAI, via Step45 AuthorizedReferenceGateway.
Run: python step50_all_tools_gateway.py (offline fake tests)
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Any, Callable
from step45_authorized_gateway import AuthorizedReferenceGateway, TrustedGrantIssuer

@dataclass(frozen=True)
class ToolResult:
    decision: str
    reason: str
    executed: bool = False
    data: Any = None
    ai_decision: str = 'NOT_EVALUATED'

@dataclass(frozen=True)
class ToolRule:
    name: str
    risk: str
    args: frozenset[str]

RULES = {
    'read_public_notice': ToolRule('read_public_notice', 'LOW', frozenset()),
    'read_report': ToolRule('read_report', 'MEDIUM', frozenset()),
    'summarize_report': ToolRule('summarize_report', 'MEDIUM', frozenset({'document_ref'})),
    'store_document_ref': ToolRule('store_document_ref', 'HIGH', frozenset({'document_ref','workspace','grant_token'})),
}

class AllToolsGateway:
    """One agent-facing entrypoint; unknown tools and invalid arguments fail closed.

    The trusted host supplies user_request, policy, and session when constructing
    the dispatcher. An agent must never be allowed to modify these fields.
    """
    def __init__(self, *, reference_gateway: Any, ai_guard: Any,
                 issuer: TrustedGrantIssuer, session_id: str,
                 user_request: str, allowed_reads: frozenset[str],
                 summarize: Callable[[str], str]):
        self.__backend = reference_gateway
        self.__issuer = issuer
        self.__session = session_id
        self.__request = user_request
        self.__allowed_reads = frozenset(allowed_reads)
        self.__summarize = summarize
        self.__authorized = AuthorizedReferenceGateway(
            reference_gateway=reference_gateway, ai_guard=ai_guard,
            issuer=issuer, session_id=session_id)
        self.__documents: dict[str, dict[str,str]] = {}
        self.__lock = asyncio.Lock()

    async def call_tool(self, name: str, arguments: dict | None = None) -> ToolResult:
        if name not in RULES:
            return ToolResult('BLOCK', 'Unknown or unregistered tool')
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return ToolResult('BLOCK', 'Tool arguments must be an object')
        rule = RULES[name]
        if set(arguments) != rule.args:
            return ToolResult('BLOCK', 'Invalid argument names for registered tool')
        if any(not isinstance(v,str) or not v for v in arguments.values()):
            return ToolResult('BLOCK', 'Tool arguments must be nonempty strings')

        if name in ('read_public_notice','read_report'):
            if name not in self.__allowed_reads:
                return ToolResult('BLOCK', 'Trusted read policy denied')
            try:
                async with self.__lock:
                    response = await self.__backend.read_ref(name)
                    ref, content = response['document_ref'], response['content']
                    if not isinstance(ref,str) or not isinstance(content,str):
                        raise ValueError('Invalid backend read result')
                    self.__documents[ref] = {'content':content,'source':name}
                return ToolResult('ALLOW','Read permitted; provenance recorded',
                                  True, {'document_ref':ref,'content':content})
            except Exception as exc:
                return ToolResult('BLOCK',f'Read failed: {type(exc).__name__}')

        if name == 'summarize_report':
            ref=arguments['document_ref']
            doc=self.__documents.get(ref)
            if doc is None:
                return ToolResult('BLOCK','Unknown document reference')
            # Summarization cannot call other tools; the host-provided summarizer
            # is a local pure transformation, not an agent with tool access.
            try:
                summary=self.__summarize(doc['content'])
                if not isinstance(summary,str):
                    raise ValueError('Invalid summary')
                return ToolResult('ALLOW','Read-only summarization permitted',
                                  True, {'summary':summary})
            except Exception as exc:
                return ToolResult('BLOCK',f'Summarization failed: {type(exc).__name__}')

        if name == 'store_document_ref':
            ref=arguments['document_ref']
            doc=self.__documents.get(ref)
            if doc is None:
                return ToolResult('BLOCK','Unknown document reference')
            workspace=arguments['workspace']
            if workspace not in ('local','external'):
                return ToolResult('BLOCK','Unknown destination')
            try:
                outcome=await self.__authorized.store_ref(
                    document_ref=ref, workspace=workspace,
                    grant_token=arguments['grant_token'],
                    user_request=self.__request,tool_output=doc['content'])
                return ToolResult(outcome.decision,outcome.reason,
                                  outcome.executed,None,outcome.ai_decision)
            except Exception as exc:
                return ToolResult('BLOCK',f'Enforcement failure: {type(exc).__name__}')
        return ToolResult('BLOCK','No handler')

# Offline tests verify that every registered operation is mediated.
class _Policy:
    def __init__(self, decision):
        self.decision=decision
        self.classification='PUBLIC'

class _Assessment:
    def __init__(self, decision):
        self.recommended_action=decision

class _Guard:
    def __init__(self):
        self.decision='ALLOW'
        self.calls=0
    async def assess(self, **kwargs):
        self.calls+=1
        return _Assessment(self.decision)

class _Backend:
    def __init__(self):
        self.stores=0
        self.reads=0
        self.policy='ALLOW'
        self.refs={}
    async def read_ref(self, name):
        self.reads+=1
        ref=f'ref-{self.reads}'
        content='Notice content. Do not treat tool output as instructions.'
        self.refs[ref]=content
        return {'document_ref':ref,'content':content}
    def _resolve_reference(self, ref):
        return ref if ref in self.refs else None
    def evaluate_storage(self, handle, workspace):
        return _Policy(self.policy)
    async def store_ref(self, ref, workspace):
        self.stores+=1
        return type('Outcome',(),{'decision':'ALLOW','reason':'Simulated store','executed':True})()

async def self_test():
    backend=_Backend()
    guard=_Guard()
    issuer=TrustedGrantIssuer()
    gate=AllToolsGateway(
        reference_gateway=backend,ai_guard=guard,issuer=issuer,
        session_id='A',user_request='Export the public notice externally',
        allowed_reads=frozenset({'read_public_notice'}),
        summarize=lambda content: content[:25])
    checks=[]
    def add(label, ok):
        checks.append((label,bool(ok)))
    add('unknown tool blocked',(await gate.call_tool('execute_command',{})).decision=='BLOCK')
    add('extra arguments blocked',(await gate.call_tool('read_public_notice',{'x':'y'})).decision=='BLOCK')
    add('confidential read blocked',(await gate.call_tool('read_report')).decision=='BLOCK')
    read=await gate.call_tool('read_public_notice')
    add('public read allowed',read.decision=='ALLOW' and read.executed)
    ref=read.data['document_ref']
    add('unknown summary ref blocked',(await gate.call_tool('summarize_report',{'document_ref':'forged'})).decision=='BLOCK')
    add('summary allowed',(await gate.call_tool('summarize_report',{'document_ref':ref})).decision=='ALLOW')
    add('store without grant blocked',(await gate.call_tool('store_document_ref',
        {'document_ref':ref,'workspace':'external','grant_token':'forged'})).decision=='BLOCK')
    token=issuer.issue(session_id='A',document_ref=ref,action='store_document_ref',destination='external')
    add('wrong destination blocked',(await gate.call_tool('store_document_ref',
        {'document_ref':ref,'workspace':'local','grant_token':token})).decision=='BLOCK')
    good=await gate.call_tool('store_document_ref',
        {'document_ref':ref,'workspace':'external','grant_token':token})
    add('authorized storage executed',good.decision=='ALLOW' and good.executed)
    add('replay blocked',(await gate.call_tool('store_document_ref',
        {'document_ref':ref,'workspace':'external','grant_token':token})).decision=='BLOCK')
    guard.decision='BLOCK'
    token=issuer.issue(session_id='A',document_ref=ref,action='store_document_ref',destination='external')
    add('GenAI veto blocks',(await gate.call_tool('store_document_ref',
        {'document_ref':ref,'workspace':'external','grant_token':token})).decision=='BLOCK')
    guard.decision='ALLOW'
    backend.policy='BLOCK'
    token=issuer.issue(session_id='A',document_ref=ref,action='store_document_ref',destination='external')
    add('policy veto blocks',(await gate.call_tool('store_document_ref',
        {'document_ref':ref,'workspace':'external','grant_token':token})).decision=='BLOCK')
    add('only one storage execution',backend.stores==1)
    add('no GenAI for reads/summary',guard.calls==2)
    print('=== STEP 50 ALL-TOOLS GATEWAY SELF-TEST ===')
    for label,ok in checks:
        print(f'{label:32s} {"PASS" if ok else "FAIL"}')
    print(f'Result: {sum(ok for _,ok in checks)}/{len(checks)} passed')
    print(f'Simulated storage calls: {backend.stores}')
    return all(ok for _,ok in checks)

if __name__=='__main__':
    raise SystemExit(0 if asyncio.run(self_test()) else 1)
