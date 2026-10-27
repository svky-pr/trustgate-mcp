#!/usr/bin/env python3
"""Step 51 real MCP protocol smoke test of the agent-facing mediated server.

No external export. Storage is deliberately denied without host-issued grant.
"""
import asyncio
import json
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent

def decode(result):
    texts=[c.text for c in result.content if getattr(c, "type", "")=="text"]
    if not texts:
        raise RuntimeError("No text in MCP tool result")
    return json.loads(texts[0])

async def main():
    checks=[]
    def check(name, ok):
        checks.append((name,bool(ok)))
        print(f"{name:36s} {'PASS' if ok else 'FAIL'}")
    params=StdioServerParameters(command=sys.executable,args=[str(ROOT/"step51_mcp_mediated_server.py")])
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            listed=await session.list_tools()
            names={t.name for t in listed.tools}
            expected={"read_public_notice","read_report","summarize_report","store_document_ref"}
            check("exact mediated tool exposure",names==expected)
            check("no grant issuance tool",not any("grant" in n or "issue" in n for n in names))
            read=decode(await session.call_tool("read_public_notice",{}))
            check("MCP public read mediated",read["decision"]=="ALLOW" and read["executed"])
            ref=read.get("data",{}).get("document_ref")
            check("opaque document reference",isinstance(ref,str) and bool(ref))
            private=decode(await session.call_tool("read_report",{}))
            check("MCP private read blocked",private["decision"]=="BLOCK")
            summary=decode(await session.call_tool("summarize_report",{"document_ref":ref}))
            check("MCP summary mediated",summary["decision"]=="ALLOW")
            forged=decode(await session.call_tool("summarize_report",{"document_ref":"forged"}))
            check("forged reference blocked",forged["decision"]=="BLOCK")
            denied=decode(await session.call_tool("store_document_ref",{
                "document_ref":ref,"workspace":"external","grant_token":"forged"
            }))
            check("MCP storage without grant blocked",denied["decision"]=="BLOCK" and not denied["executed"])
    print("\n=== STEP 51 MCP PROXY RESULTS ===")
    print(f"Checks: {sum(ok for _,ok in checks)}/{len(checks)} passed")
    print("LIMITATION: mediated tools exposed by this server; client-side access to raw backend")
    print("must be removed by deployment configuration. No host grant channel in this demo.")
    if not all(ok for _,ok in checks):
        raise SystemExit(1)

if __name__=="__main__":
    asyncio.run(main())
