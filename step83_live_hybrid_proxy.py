#!/usr/bin/env python3
"""Step83: live MCP proxy with post-call deterministic alerts and optional
nonblocking GenAI session review. Existing Step76->71->63 gateway authorizes.

Host-controlled env:
 TG83_AUDIT_FILE absolute JSONL path; TG83_REVIEW_FILE absolute JSONL path
 TG83_GENAI=1 to schedule an advisory review after summarize_report calls
 TG83_MODEL=gpt-4.1-mini; TG76_SEMANTIC=0 avoids separate Step76 LLM latency

Never expose audit/review files to an agent. Storage remains simulated.
"""
from __future__ import annotations
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault('TG76_SEMANTIC','0')
import step76_activity_proxy as step76
from step82_contextual_risk import classify, genai_review

proxy=step76.proxy
ORIGINAL_DISPATCH=proxy.dispatch
AUDIT=os.environ.get('TG83_AUDIT_FILE','')
REVIEWS=os.environ.get('TG83_REVIEW_FILE','')
GENAI=os.environ.get('TG83_GENAI','0')=='1'
MODEL=os.environ.get('TG83_MODEL','gpt-4.1-mini')
EVENTS=[]
PENDING=set()


def _append(path_text, item):
    if not path_text:
        return
    path=Path(path_text)
    if not path.is_absolute():
        raise ValueError('Audit/review file must be an absolute host-controlled path')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a',encoding='utf-8') as out:
        out.write(json.dumps(item,ensure_ascii=False)+'\n')


async def _semantic_snapshot(snapshot, call_index):
    rules=classify(snapshot)
    try:
        review=await genai_review(snapshot,rules,MODEL)
        result={'review_status':'OK','genai_risk':review['workflow_risk'],
                'genai_evidence_indices':review['evidence_indices'],
                'genai_reason':review['reason'],
                'hybrid_alert':rules['alert'] or review['workflow_risk'] in ('MEDIUM','HIGH')}
    except Exception as exc:
        result={'review_status':'ERROR','error_type':type(exc).__name__,
                'hybrid_alert':rules['alert']}
    _append(REVIEWS,{'time':datetime.now(timezone.utc).isoformat(),
                     'after_call_index':call_index,'rules_alert':rules['alert'],**result})


async def hybrid_dispatch(name,args):
    index=len(EVENTS)
    try:
        raw=await ORIGINAL_DISPATCH(name,args)
    except Exception as exc:
        record={'tool':name,'outcome':'ERROR','error_type':type(exc).__name__}
        EVENTS.append(record)
        _append(AUDIT,{'time':datetime.now(timezone.utc).isoformat(),
                       'call_index':index,**record,'rules':classify(EVENTS)})
        raise
    try:
        data=json.loads(raw)
        if isinstance(data,str): data=json.loads(data)
        if not isinstance(data,dict): raise ValueError('nonobject gateway result')
        outcome='EXECUTED' if data.get('executed') is True else 'BLOCKED'
    except (ValueError,TypeError):
        outcome='ERROR'
    # Record trusted mediation outcome, never user-controlled arguments or document text.
    record={'tool':name,'outcome':outcome}
    EVENTS.append(record)
    rules=classify(EVENTS)
    _append(AUDIT,{'time':datetime.now(timezone.utc).isoformat(),
                   'call_index':index,**record,'rules_alert':rules['alert'],
                   'rules_risk':rules['risk'],'security_event_count':len(rules['events'])})
    # A separate asyncio task performs GenAI review after the tool response is ready.
    # It cannot change the gateway decision. The host must keep the process alive
    # until the review log arrives; otherwise outstanding tasks may be cancelled.
    if GENAI and name=='summarize_report':
        task=asyncio.create_task(_semantic_snapshot(list(EVENTS),index))
        PENDING.add(task)
        task.add_done_callback(PENDING.discard)
    return raw

proxy.dispatch=hybrid_dispatch

if __name__=='__main__':
    print('[Step83] hybrid audit enabled; GenAI advisory='+str(GENAI),
          file=sys.stderr,flush=True)
    proxy.mcp.run(transport='stdio')
