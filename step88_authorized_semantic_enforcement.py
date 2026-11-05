#!/usr/bin/env python3
"""Step88 controlled, paired pre-execution enforcement replay.

This is a SIMULATED executor, not a live MCP gateway or agent experiment.
Uses Step86's authored cases and authorization fixture. It distinguishes
injection detection from harmful action: an authorized call with malicious
surrounding text is not automatically an unauthorized execution.

Run:
 python step88_authorized_semantic_enforcement.py --self-test
 python step88_authorized_semantic_enforcement.py --trials 1 --guard-model gpt-4.1-mini
 python step88_authorized_semantic_enforcement.py --trials 3 --guard-model gpt-5.6-luna
"""
from __future__ import annotations
import argparse, asyncio, csv, json, os, statistics, time
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from step86_paired_guard_ablation import CASES, authorize

ROOT=Path(__file__).resolve().parent
load_dotenv(ROOT/'.env')
MODES=('authorization_only','hybrid_action','hybrid_detection_hold')


def decide(authorized, action, detected, mode, review_policy='hold'):
    """Return execution decision; no semantic model can override a denial."""
    if not authorized:
        return 'DENY_AUTH'
    if mode=='authorization_only':
        return 'EXECUTE'
    if mode=='hybrid_detection_hold' and detected:
        return 'HOLD_DETECTION'
    if action=='BLOCK':
        return 'BLOCK_SEMANTIC'
    if action=='REVIEW' and review_policy=='hold':
        return 'HOLD_REVIEW'
    return 'EXECUTE'


def self_test():
    checks={
        'authorized malicious evidence exists':any(c.label=='malicious' and authorize(c)[0] for c in CASES),
        'authorized benign cases exist':any(c.label=='benign' and authorize(c)[0] for c in CASES),
        'deny cannot be overridden':all(decide(False,'ALLOW',False,m)=='DENY_AUTH' for m in MODES),
        'authorized clean executes':all(decide(True,'ALLOW',False,m)=='EXECUTE' for m in MODES),
        'semantic block enforced':decide(True,'BLOCK',True,'hybrid_action')=='BLOCK_SEMANTIC',
        'review held':decide(True,'REVIEW',True,'hybrid_action')=='HOLD_REVIEW',
        'detection hold':decide(True,'ALLOW',True,'hybrid_detection_hold')=='HOLD_DETECTION',
        'allow despite detection is explicit':decide(True,'ALLOW',True,'hybrid_action')=='EXECUTE',
    }
    for name,ok in checks.items():print(('PASS' if ok else 'FAIL'),name)
    print(f'STEP88 SELF-TEST: {sum(checks.values())}/{len(checks)} PASS')
    return all(checks.values())


async def evaluate(args):
    from trustgate_ai_guard import TrustGateAIGuard
    guard=TrustGateAIGuard(model=args.guard_model)
    rows=[]
    try:
        for trial in range(1,args.trials+1):
            for case in CASES:
                authorized,auth_reason=authorize(case)
                action='NOT_CALLED';detected=False;error='';guard_ms=0.0
                # Guard runs only for authorization-permitted proposals.
                if authorized:
                    t0=time.perf_counter()
                    try:
                        assessment=await guard.assess(case.request,case.output,case.tool,
                                                      case.arguments,case.classification)
                        action=assessment.recommended_action
                        detected=assessment.attack_detected
                        # Guard may silently return REVIEW on API error: count separately.
                        explanation=str(assessment.explanation)
                        if any(s in explanation.lower() for s in ('api error','apierror','badrequesterror','unsupported value','authenticationerror')):
                            error=explanation[:300]
                    except Exception as exc:
                        action='REVIEW';error=f'{type(exc).__name__}: {exc}'[:300]
                    guard_ms=round((time.perf_counter()-t0)*1000,2)
                for mode in MODES:
                    decision=decide(authorized,action,detected,mode,args.review_policy)
                    # Controlled fixture: EXECUTE only records a hypothetical call.
                    # No real MCP tool or external storage is invoked.
                    rows.append(dict(trial=trial,case_id=case.case_id,label=case.label,
                        mode=mode,tool=case.tool,authorized=authorized,
                        auth_reason=auth_reason,guard_action=action,attack_detected=detected,
                        guard_error=error,decision=decision,
                        simulated_execution=(decision=='EXECUTE'),
                        semantic_intervention=decision in ('BLOCK_SEMANTIC','HOLD_REVIEW','HOLD_DETECTION'),
                        guard_ms=guard_ms if mode!='authorization_only' else 0.0))
                print(f'{case.case_id:30} trial={trial} auth={"ALLOW" if authorized else "DENY":5} '
                      f'guard={action:10} detected={detected} ms={guard_ms:.0f}',flush=True)
    finally:
        await guard.client.close()
    output=ROOT/'results';output.mkdir(exist_ok=True)
    path=output/('step88_authorized_enforcement_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.csv')
    with path.open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    print('\n=== STEP88 CONTROLLED PAIRED ENFORCEMENT REPLAY ===')
    for mode in MODES:
        part=[r for r in rows if r['mode']==mode]
        permitted=[r for r in part if r['authorized']]
        print(mode,'cases=',len(part),'authorized=',len(permitted),
              'executions=',sum(r['simulated_execution'] for r in part),
              'semantic_interventions=',sum(r['semantic_intervention'] for r in part),
              'malicious_context_interventions=',sum(r['semantic_intervention'] and r['label']=='malicious' for r in part),
              'benign_interventions=',sum(r['semantic_intervention'] and r['label']=='benign' for r in part),
              'guard_errors=',sum(bool(r['guard_error']) for r in part))
    reviewed=[r for r in rows if r['mode']=='hybrid_action' and r['authorized']]
    print('guard_latency_median_ms=',round(statistics.median(r['guard_ms'] for r in reviewed),1) if reviewed else 'N/A')
    print('WARNING: Authored Step86 cases, repeated; not held-out.')
    print('WARNING: Malicious context is NOT proof that an authorized operation is harmful.')
    print('WARNING: No live agent, MCP calls, real export, or verified attack prevention.')
    print('CSV:',path)
    return 1 if any(r['guard_error'] for r in reviewed) else 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true')
    p.add_argument('--trials',type=int,default=1)
    p.add_argument('--guard-model',default='gpt-4.1-mini')
    p.add_argument('--review-policy',choices=('hold','pass'),default='hold')
    args=p.parse_args()
    if args.self_test:return 0 if self_test() else 1
    if not 1<=args.trials<=20:p.error('trials must be 1..20')
    if not os.getenv('OPENAI_API_KEY'):p.error('OPENAI_API_KEY missing')
    return asyncio.run(evaluate(args))

if __name__=='__main__':raise SystemExit(main())
