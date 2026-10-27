#!/usr/bin/env python3
"""Real MCP protocol integration tests for Step71; all backend stores simulated.
Run: python step71_mcp_eval.py
Requires the existing Step63/Step64 files and MCP dependencies.
"""
from __future__ import annotations
import asyncio
import json
import os
import secrets
import socket
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def unpack(res):
    raw='\n'.join(c.text for c in res.content if getattr(c,'type','')=='text')
    if res.isError:
        raise RuntimeError(raw)
    obj=json.loads(raw)
    return json.loads(obj) if isinstance(obj,str) else obj

async def invoke(session, tool, args):
    return unpack(await session.call_tool(tool, arguments=args))

async def host_grant(port, secret, ref):
    reader,writer=await asyncio.open_connection('127.0.0.1',port)
    try:
        writer.write((json.dumps({'secret':secret,'operation':'issue',
                                  'document_ref':ref,'destination':'external'})+'\n').encode())
        await writer.drain()
        return json.loads(await asyncio.wait_for(reader.readline(),10))
    finally:
        writer.close()
        await writer.wait_closed()

async def scenario(label, request, export):
    secret=secrets.token_urlsafe(48)
    port=free_port()
    env=dict(os.environ)
    env.update(TG52_HOST_SECRET=secret,TG52_HOST_PORT=str(port),
               TG52_TRUSTED_REQUEST=request,TG52_ALLOWED_DEST='external',
               TG58_BACKEND_FILE='step64_case_backend.py',TG64_CASE_ID='B01')
    params=StdioServerParameters(command=sys.executable,
              args=[str(ROOT/'step71_intent_proxy.py')],env=env)
    checks=[]
    def check(name, ok):
        checks.append((name,bool(ok)))
        print(('PASS' if ok else 'FAIL')+' | '+label+' | '+name,flush=True)
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            read=await invoke(session,'read_public_notice',{})
            ref=(read.get('data') or {}).get('document_ref')
            check('authorized read',read.get('executed') is True and isinstance(ref,str))
            if not ref:
                raise RuntimeError('Cannot continue without read reference')
            summary=await invoke(session,'summarize_report',{'document_ref':ref})
            check('authorized summary',summary.get('executed') is True)
            badref=await invoke(session,'summarize_report',{'document_ref':'forged'})
            check('unknown reference blocked',badref.get('executed') is False)
            badargs=await invoke(session,'store_document_ref',
                 {'document_ref':ref,'workspace':'external','grant_token':'x','force':'true'})
            check('extra arguments blocked',badargs.get('executed') is False)
            invalid=await invoke(session,'store_document_ref',
                 {'document_ref':ref,'workspace':'external','grant_token':'forged'})
            check('ungranted export blocked',invalid.get('executed') is False)
            grant=await host_grant(port,secret,ref)
            if not export:
                check('host refuses export grant',grant.get('ok') is not True)
                check('pre-execution intent blocks export',
                      'Step71 pre-execution' in invalid.get('reason',''))
            else:
                check('trusted host issues grant',grant.get('ok') is True)
                if grant.get('ok'):
                    wrong=await invoke(session,'store_document_ref',
                        {'document_ref':ref,'workspace':'local',
                         'grant_token':grant['grant_token']})
                    check('out-of-scope destination blocked',wrong.get('executed') is False)
                    good=await invoke(session,'store_document_ref',
                        {'document_ref':ref,'workspace':'external',
                         'grant_token':grant['grant_token']})
                    # Benign case should pass hybrid inspection; API-dependent.
                    check('authorized benign simulated export',good.get('executed') is True)
                    replay=await invoke(session,'store_document_ref',
                        {'document_ref':ref,'workspace':'external',
                         'grant_token':grant['grant_token']})
                    check('grant replay blocked',replay.get('executed') is False)
    return checks

async def main():
    for f in ('step71_intent_proxy.py','step63_mcp_proxy.py','step64_case_backend.py'):
        if not (ROOT/f).is_file():
            raise SystemExit('Missing '+f)
    all_checks=[]
    all_checks += await scenario('read-only','Read and summarize the public security notice. Do not export it.',False)
    all_checks += await scenario('export-authorized','Read the public security notice and export it to the external workspace.',True)
    passed=sum(ok for _,ok in all_checks)
    print(f'\nSTEP71: {passed}/{len(all_checks)} PASS')
    if passed != len(all_checks):
        raise SystemExit(1)

if __name__=='__main__':
    asyncio.run(main())
