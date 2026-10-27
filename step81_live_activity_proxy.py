#!/usr/bin/env python3
"""Step81: real MCP dispatch telemetry + advisory workflow-risk alerts.

Wraps Step76 -> Step71 -> Step63 without replacing authorization, grants,
provenance, or content inspection. Every tool attempt is logged after its
actual mediated outcome. Log path is HOST controlled, never MCP controlled.
The activity detector is advisory; it does not grant or block tool calls.

Environment: TG81_AUDIT_FILE (absolute path), TG76_SEMANTIC (default 0 here).
Do not expose the audit file to the MCP agent.
"""
from __future__ import annotations
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Step76 installs its dispatch wrapper when imported.
os.environ.setdefault('TG76_SEMANTIC', '0')
import step76_activity_proxy as step76
from step80_hybrid_workflow_engine import history_signal

proxy = step76.proxy
ORIGINAL_DISPATCH = proxy.dispatch
AUDIT_FILE = os.environ.get('TG81_AUDIT_FILE', '')


def _log(entry: dict) -> None:
    if not AUDIT_FILE:
        return
    path = Path(AUDIT_FILE)
    if not path.is_absolute():
        raise ValueError('TG81_AUDIT_FILE must be an absolute host path')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as out:
        out.write(json.dumps(entry, ensure_ascii=False) + '\n')


async def audited_dispatch(name, args):
    try:
        raw = await ORIGINAL_DISPATCH(name, args)
    except Exception as exc:
        # Do not hide a genuine backend error or record it as execution.
        _log({'time': datetime.now(timezone.utc).isoformat(),
              'tool': name, 'outcome': 'ERROR', 'error_type': type(exc).__name__})
        raise
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        if not isinstance(parsed, dict):
            raise ValueError('not object')
        executed = parsed.get('executed') is True
        outcome = 'EXECUTED' if executed else 'BLOCKED'
        reason = str(parsed.get('reason', ''))[:200]
    except (ValueError, TypeError):
        outcome, reason = 'ERROR', 'Unparseable gateway result'
    # Step76 recorded the same actual call in its SessionMonitor.
    # The detector reads that history; it never trusts tool output as policy.
    risk = history_signal(step76.monitor.history)
    _log({'time': datetime.now(timezone.utc).isoformat(),
          'tool': name, 'outcome': outcome,
          'reason': reason, 'session_alert': risk['alert'],
          'session_risk': risk['risk'],
          'security_event_count': len(risk['events']),
          'security_events': risk['events'][-5:]})
    return raw


proxy.dispatch = audited_dispatch

if __name__ == '__main__':
    print('[Step81] MCP activity auditing active; telemetry is advisory',
          file=sys.stderr, flush=True)
    proxy.mcp.run(transport='stdio')
