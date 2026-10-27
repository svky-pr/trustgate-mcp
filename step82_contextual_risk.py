#!/usr/bin/env python3
"""Step82: context-aware MCP session alert classifier and optional GenAI review.

Reads HOST-side Step81 audit JSONL. Does not change tool authorization.
Deterministic signals use trusted tool/outcome metadata; reason text is only
context, never an authorization source. GenAI is advisory and optional.
"""
from __future__ import annotations
import argparse, asyncio, json, os, re, time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

SENSITIVE_TOOLS={'read_report':'restricted_read',
                 'store_document_ref':'export_attempt'}
LOW_RISK_TOOLS={'read_public_notice','summarize_report'}
OPERATIONAL=re.compile(r'timeout|rate.limit|503|temporar|backend.unavailable|quota',re.I)

@dataclass
class Event:
    index:int
    tool:str
    outcome:str
    category:str
    severity:str
    evidence:str

def classify(records:list[dict[str,Any]])->dict[str,Any]:
    events=[]
    for i,r in enumerate(records):
        tool=str(r.get('tool',''))
        outcome=str(r.get('outcome','')).upper()
        reason=str(r.get('reason',''))[:160]
        if outcome not in ('BLOCKED','DENIED','EXECUTED','ERROR'):
            continue
        if tool in SENSITIVE_TOOLS and outcome in ('BLOCKED','DENIED'):
            events.append(Event(i,tool,outcome,SENSITIVE_TOOLS[tool],'MEDIUM',
                                'blocked_sensitive_operation'))
        elif tool in SENSITIVE_TOOLS and outcome=='EXECUTED':
            # Execution of a restricted read or authorized export is not by
            # itself malicious. Record it, but don't flag it as an attack.
            events.append(Event(i,tool,outcome,'sensitive_operation_executed','INFO',
                                'authorization_must_be_verified_separately'))
        elif tool in LOW_RISK_TOOLS and outcome in ('BLOCKED','DENIED','ERROR'):
            events.append(Event(i,tool,outcome,'ordinary_tool_failure','INFO',
                                'failure_not_automatically_suspicious'))
        elif tool not in LOW_RISK_TOOLS and tool not in SENSITIVE_TOOLS:
            if outcome in ('BLOCKED','DENIED'):
                events.append(Event(i,tool,outcome,'unknown_tool_denied','MEDIUM',
                                    'unrecognized_tool_attempt'))
            elif outcome=='EXECUTED':
                events.append(Event(i,tool,outcome,'unknown_tool_executed','HIGH',
                                    'unexpected_tool_execution_requires_review'))
    medium=sum(e.severity=='MEDIUM' for e in events)
    high=sum(e.severity=='HIGH' for e in events)
    return {'alert':bool(medium or high),
            'risk':'HIGH' if high else 'MEDIUM' if medium else 'LOW',
            'events':[asdict(e) for e in events],
            'security_attempts':medium,
            'unexpected_executions':high}

async def genai_review(records:list[dict[str,Any]], deterministic:dict[str,Any],
                       model:str='gpt-4.1-mini')->dict[str,Any]:
    """Optional advisory-only review; sends redacted event metadata, no document content."""
    from openai import AsyncOpenAI
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent/'.env')
    # Do not forward raw reasons, arguments, references, grants, or document content.
    redacted=[{'index':i,'tool':str(r.get('tool',''))[:70],
               'outcome':str(r.get('outcome',''))[:24],
               'category':next((e['category'] for e in deterministic['events']
                                if e['index']==i),'normal_operation')}
              for i,r in enumerate(records)]
    instructions=(
      'You are an advisory MCP workflow analyst. Judge whether a sequence shows '
      'suspicious intent. A denied restricted read or export is security relevant, '
      'but an invalid summary reference, timeout, or retry may be benign. '
      'A successfully executed sensitive operation may be authorized; do not '
      'assume it was malicious. Return ONLY JSON with keys '
      'workflow_risk (LOW, MEDIUM, HIGH), evidence_indices (array of integer '
      'indices from supplied events), and reason (brief). '
      'This assessment never changes authorization.')
    response=await AsyncOpenAI().chat.completions.create(
        model=model,temperature=0,response_format={'type':'json_object'},
        messages=[{'role':'system','content':instructions},
                  {'role':'user','content':json.dumps({'events':redacted,
                    'deterministic_risk':deterministic['risk']})}])
    result=json.loads(response.choices[0].message.content or '{}')
    if result.get('workflow_risk') not in ('LOW','MEDIUM','HIGH'):
        raise ValueError('invalid workflow_risk')
    evidence=result.get('evidence_indices',[])
    if not isinstance(evidence,list) or any(type(i) is not int or i<0 or i>=len(records)
                                             for i in evidence):
        # A model citation error is a review error, not a detection.
        raise ValueError('invalid evidence indices')
    return {'workflow_risk':result['workflow_risk'],
            'evidence_indices':evidence,
            'reason':str(result.get('reason',''))[:400]}

async def assess(records:list[dict[str,Any]],use_llm:bool=False,
                 model:str='gpt-4.1-mini')->dict[str,Any]:
    rules=classify(records)
    review=None;error='';elapsed=0.
    if use_llm:
        start=time.perf_counter()
        try: review=await genai_review(records,rules,model)
        except Exception as exc: error=f'{type(exc).__name__}: {exc}'[:220]
        elapsed=round((time.perf_counter()-start)*1000,1)
    return {'rules':rules,'genai':review,'genai_error':error,
            'genai_ms':elapsed,
            'hybrid_alert':rules['alert'] or bool(review and review['workflow_risk'] in ('MEDIUM','HIGH')),
            'advisory_only':True}

def self_test():
    examples=[
      ('blocked confidential read', [{'tool':'read_report','outcome':'BLOCKED'}],True),
      ('blocked export', [{'tool':'store_document_ref','outcome':'BLOCKED'}],True),
      ('bad summary ref', [{'tool':'summarize_report','outcome':'BLOCKED'}],False),
      ('summary timeout', [{'tool':'summarize_report','outcome':'ERROR','reason':'timeout'}],False),
      ('authorized export', [{'tool':'store_document_ref','outcome':'EXECUTED'}],False),
      ('ordinary read', [{'tool':'read_public_notice','outcome':'EXECUTED'}],False),
      ('unknown blocked tool', [{'tool':'send_to_webhook','outcome':'BLOCKED'}],True),
    ]
    passed=0
    for name,history,expected in examples:
        ok=classify(history)['alert']==expected
        passed+=ok;print(('PASS' if ok else 'FAIL')+' | '+name)
    print(f'STEP82 SELF-TEST: {passed}/{len(examples)} PASS')
    if passed!=len(examples):raise SystemExit(1)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--self-test',action='store_true')
    ap.add_argument('--audit',type=Path)
    ap.add_argument('--llm',action='store_true')
    ap.add_argument('--model',default='gpt-4.1-mini')
    args=ap.parse_args()
    if args.self_test:return self_test()
    if not args.audit:ap.error('Specify --audit or --self-test')
    records=[json.loads(line) for line in args.audit.read_text(encoding='utf-8').splitlines() if line.strip()]
    print(json.dumps(asyncio.run(assess(records,args.llm,args.model)),indent=2))

if __name__=='__main__':main()
