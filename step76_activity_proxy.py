#!/usr/bin/env python3
"""Step76: integrate Step75 activity-aware GenAI review into the real Step63 MCP proxy.

Trusted host policy is derived from Step71. Existing Step63 grant/provenance/
content controls remain authoritative. No real export: Step64 backend simulates.
Environment:
 TG76_SEMANTIC=1 (default): review authorized summary/store calls with GenAI
 TG76_SEMANTIC=0: deterministic activity tracking only (ablation)
 TG76_MODEL=gpt-4.1-mini
"""
from __future__ import annotations
import json
import os
import sys

import step71_intent_proxy as step71
from step75_intent_activity_monitor import (
    HostPolicy, ProposedCall, SessionMonitor, decide, READ, SUMMARY, STORE
)

proxy = step71.proxy
intent = step71.INTENT
monitor = SessionMonitor(
    host_policy=HostPolicy(intent.tools, intent.destinations, intent.export_authorized),
    trusted_user_request=os.environ.get("TG52_TRUSTED_REQUEST", ""),
)
ORIGINAL_DISPATCH = proxy.dispatch  # Step71 guarded_dispatch, installed on import


def denied(reason: str, semantic=None) -> str:
    return proxy.response(
        "BLOCK", "Step76 activity guard: " + reason,
        executed=False, data=None, ai_decision="NOT_EVALUATED",
        semantic_review=semantic,
    )


async def activity_dispatch(name, args):
    # Exact call is captured before any MCP backend operation.
    call = ProposedCall(name, args)
    # Synchronize observed refs with Step71's mediated read tracking.
    monitor.observed_refs.update(step71.SEEN_REFS)
    use_llm = (os.getenv("TG76_SEMANTIC", "1") == "1"
               and name in (SUMMARY, STORE))
    verdict = await decide(monitor, call, use_llm=use_llm)
    if verdict["action"] != "PASS_TO_EXISTING_GATEWAY":
        monitor.record(call, "BLOCKED", verdict["reason"])
        return denied(verdict["reason"], verdict.get("semantic"))

    # Preserve the existing Step71 -> Step63 -> grant/provenance/content path.
    raw = await ORIGINAL_DISPATCH(name, args)
    try:
        result = json.loads(raw)
        if isinstance(result, str):
            result = json.loads(result)
        if not isinstance(result, dict):
            raise ValueError("Gateway returned non-object JSON")
        executed = result.get("executed") is True
        observed_ref = None
        if name == READ and executed:
            data = result.get("data") or {}
            if isinstance(data, dict):
                observed_ref = data.get("document_ref")
        monitor.record(call, "EXECUTED" if executed else "BLOCKED",
                       str(result.get("reason", ""))[:300],
                       observed_ref=observed_ref)
        return raw
    except (ValueError, TypeError, AttributeError):
        monitor.record(call, "BLOCKED", "Unparseable gateway response")
        return denied("Unparseable gateway response")


proxy.dispatch = activity_dispatch

if __name__ == "__main__":
    print("[Step76] activity monitor enabled; semantic=" +
          os.getenv("TG76_SEMANTIC", "1"), file=sys.stderr, flush=True)
    proxy.mcp.run(transport="stdio")
