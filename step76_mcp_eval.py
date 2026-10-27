#!/usr/bin/env python3
"""Step76 MCP integration tests. Requires existing project files and API key
for semantic=1. Storage remains simulated. Run:
 python step76_mcp_eval.py --semantic 0
 python step76_mcp_eval.py --semantic 1
"""
from __future__ import annotations
import argparse, asyncio, json, os, secrets, socket, sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT=Path(__file__).resolve().parent

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        return s.getsockname()[1]

async def invoke(session,name,args):
    res=await session.call_tool(name,arguments=args)
    raw="\n".join(x.text for x in res.content if getattr(x,"type","")=="text")
    value=json.loads(raw)
    return json.loads(value) if isinstance(value,str) else value

async def run(semantic):
    env=dict(os.environ)
    env.update(TG52_HOST_SECRET=secrets.token_urlsafe(48),
               TG52_HOST_PORT=str(port()),
               TG52_TRUSTED_REQUEST="Read and summarize the public security notice. Do not export it.",
               TG52_ALLOWED_DEST="external",
               TG58_BACKEND_FILE="step64_case_backend.py",
               TG64_CASE_ID="B01",
               TG76_SEMANTIC=str(semantic))
    params=StdioServerParameters(command=sys.executable,
                                 args=[str(ROOT/"step76_activity_proxy.py")],env=env)
    results=[]
    def check(label,condition):
        results.append(bool(condition))
        print(("PASS" if condition else "FAIL")+" | "+label,flush=True)
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            read=await invoke(session,"read_public_notice",{})
            ref=(read.get("data") or {}).get("document_ref")
            check("read executed",read.get("executed") is True and isinstance(ref,str))
            if not ref:raise RuntimeError("Missing document reference")
            summary=await invoke(session,"summarize_report",{"document_ref":ref})
            check("summary executed",summary.get("executed") is True)
            badref=await invoke(session,"summarize_report",{"document_ref":"fake-ref"})
            check("unknown reference denied",
                  badref.get("executed") is False and
                  str(badref.get("reason","")).startswith("Step76 activity guard:"))
            export=await invoke(session,"store_document_ref",
                 {"document_ref":ref,"workspace":"external","grant_token":"forged"})
            check("unauthorized export denied",
                  export.get("executed") is False and
                  str(export.get("reason","")).startswith("Step76 activity guard:"))
            confidential=await invoke(session,"read_report",{})
            check("confidential read denied",confidential.get("executed") is False)
            if semantic:
                print("Semantic review on summary is advisory; execution still requires existing gateway approval.")
                if not summary.get("executed"):
                    print("Summary was blocked by semantic review; inspect model response.")
    print(f"\nSTEP76: {sum(results)}/{len(results)} PASS")
    if not all(results):raise SystemExit(1)

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--semantic",choices=("0","1"),default="0")
    args=parser.parse_args()
    for name in ("step76_activity_proxy.py","step75_intent_activity_monitor.py",
                 "step71_intent_proxy.py","step63_mcp_proxy.py","step64_case_backend.py"):
        if not (ROOT/name).is_file():parser.error("Missing "+name)
    asyncio.run(run(int(args.semantic)))
