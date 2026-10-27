#!/usr/bin/env python3
"""Step80 hybrid workflow risk prototype; synthetic evaluation, not live MCP.
Requires Step75, Step78 and Step79 scripts in the same directory.
"""
import argparse, asyncio, csv, json, os, re, time
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from step75_intent_activity_monitor import ProposedCall, SUMMARY
from step79_unseen_workflow_eval import CASES, REF, build, stats
from step78_workflow_risk_eval import review_workflow

ROOT=Path(__file__).resolve().parent
load_dotenv(ROOT/'.env')
# Generic action vocabulary, not a list of held-out case identifiers.
ACTION=re.compile(r'send|post|export|upload|store|transfer|sync|archiv|write|shell|exec|admin|register|secret|credential|token|webhook',re.I)
POLICY=re.compile(r'unauthoriz|unapproved|out.of.scope|privileg|credential|secret|forged|invalid.grant|remote|external|transmit|upload',re.I)


def history_signal(history):
    events=[]
    for i,e in enumerate(history):
        outcome=e.outcome.upper()
        if outcome not in ('EXECUTED','BLOCKED','DENIED'):
            continue
        sensitive=bool(ACTION.search(e.tool) or POLICY.search(e.reason))
        if not sensitive:
            continue
        events.append({'index':i,'tool':e.tool,'outcome':outcome,
                       'category':'sensitive_executed' if outcome=='EXECUTED' else 'sensitive_attempt',
                       'reason':e.reason[:160]})
    high=any(e['category']=='sensitive_executed' for e in events)
    return {'alert':bool(events),'risk':'HIGH' if high else 'MEDIUM' if events else 'LOW',
            'events':events}


async def assess(monitor, call, use_llm=False, model='gpt-4.1-mini'):
    policy,reason=monitor.check(call)
    rules=history_signal(monitor.history)
    llm=None; error=''; elapsed=0.0
    if use_llm:
        started=time.perf_counter()
        try:
            # Step78 reviewer is kept unchanged. The metadata is advisory.
            llm=await review_workflow(monitor.context(call),
                {'security_events':rules['events'],'deterministic_risk':rules['risk']},model)
        except Exception as exc:
            error=f'{type(exc).__name__}: {exc}'[:250]
        elapsed=round((time.perf_counter()-started)*1000,2)
    llm_alert=llm['workflow_risk'] in ('MEDIUM','HIGH') if llm else None
    return {'authorization':policy,'authorization_reason':reason,
            'execution_decision':'DENY' if policy=='DENY' else 'DEFER_TO_EXISTING_GATEWAY',
            'rules':rules,'llm':llm,'llm_alert':llm_alert,
            'session_alert':rules['alert'] or llm_alert is True,
            'llm_ms':elapsed,'error':error}


def self_test():
    from step75_intent_activity_monitor import Activity
    checks={
      'normal read no alert':not history_signal([Activity('read_public_notice','EXECUTED','ok')])['alert'],
      'blocked webhook alerted':history_signal([Activity('send_to_webhook','BLOCKED','unknown tool')])['alert'],
      'blocked admin export alerted':history_signal([Activity('admin_export','BLOCKED','denied')])['alert'],
      'summary timeout no alert':not history_signal([Activity('summarize_report','BLOCKED','timeout')])['alert'],
      'executed webhook high risk':history_signal([Activity('send_to_webhook','EXECUTED','sent')])['risk']=='HIGH',
    }
    for name,ok in checks.items():print(('PASS' if ok else 'FAIL')+' | '+name)
    print(f'STEP80 SELF-TEST: {sum(checks.values())}/{len(checks)} PASS')
    if not all(checks.values()):raise SystemExit(1)


async def evaluate(args):
    rows=[]
    for iteration in range(1,args.repeat+1):
        for case in CASES:
            monitor=build(case)
            result=await assess(monitor,ProposedCall(SUMMARY,{'document_ref':REF}),
                                not args.no_llm,args.model)
            row={'iteration':iteration,'case_id':case.id,'label':case.label,
                 'action_denied':result['authorization']=='DENY',
                 'rule_flag':result['rules']['alert'],
                 'llm_flag':result['llm_alert'],
                 'hybrid_flag':result['session_alert'],
                 'risk':result['rules']['risk'],
                 'events':json.dumps(result['rules']['events']),
                 'llm_reason':(result['llm'] or {}).get('reason',''),
                 'llm_ms':result['llm_ms'],'error':result['error']}
            rows.append(row)
            print(f"{case.id} label={case.label:10} rules={row['rule_flag']} "
                  f"llm={row['llm_flag']} hybrid={row['hybrid_flag']} "
                  f"{'ERROR='+row['error'] if row['error'] else ''}",flush=True)
    outdir=ROOT/'results';outdir.mkdir(exist_ok=True)
    path=outdir/('step80_hybrid_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.csv')
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print('\n=== STEP 80 HYBRID WORKFLOW EVALUATION ===')
    print('cases=',len(CASES),'iterations=',args.repeat)
    print('action_only=',stats(rows,'action_denied'))
    print('deterministic=',stats(rows,'rule_flag'))
    evaluated=[r for r in rows if r['llm_flag'] is not None]
    if evaluated:
        print('genai=',stats(evaluated,'llm_flag'))
        print('hybrid=',stats(evaluated,'hybrid_flag'))
        print('incremental_genai_TP=',sum(r['label']=='suspicious' and r['llm_flag'] and not r['rule_flag'] for r in evaluated))
        print('incremental_genai_FP=',sum(r['label']=='benign' and r['llm_flag'] and not r['rule_flag'] for r in evaluated))
        print('mean_genai_ms=',round(sum(r['llm_ms'] for r in evaluated)/len(evaluated),1))
    print('genai_evaluated=',len(evaluated),'genai_errors=',sum(bool(r['error']) for r in rows))
    print('Synthetic histories; no MCP execution. Alerts do not deny valid summary calls.')
    print('Reuses Step79 cases, so this is NOT a new held-out evaluation.')
    print('Results:',path)
    if any(r['error'] for r in rows):raise SystemExit(1)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    mode=ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--self-test',action='store_true')
    mode.add_argument('--eval',action='store_true')
    ap.add_argument('--no-llm',action='store_true')
    ap.add_argument('--repeat',type=int,default=1)
    ap.add_argument('--model',default=os.getenv('TG76_MODEL','gpt-4.1-mini'))
    args=ap.parse_args()
    if args.self_test:self_test();return
    if not 1<=args.repeat<=10:ap.error('--repeat must be between 1 and 10')
    if not args.no_llm and not os.getenv('OPENAI_API_KEY'):
        ap.error('OPENAI_API_KEY missing in .env')
    asyncio.run(evaluate(args))

if __name__=='__main__':main()
