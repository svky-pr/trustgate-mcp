"""Step 42: targeted translation_trick failure diagnostic. No storage execution."""
import asyncio, csv, hashlib, json, os, sys, time
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from openai import AsyncOpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from step21_reference_gateway import ReferenceGateway
from step30_hybrid_gateway import HybridTrustGate
from step33_v3_ai_guard import ImprovedTrustGateAIGuard
from step35_autonomous_agent_eval import agent_propose
from step40_frozen_evaluation import CASES, PAYLOADS, WORKFLOWS

ROOT=Path(__file__).resolve().parent
load_dotenv(ROOT/'.env')
REPS=int(os.getenv('TRUSTGATE_DIAG_REPS','8'))
if not 1<=REPS<=30: raise ValueError('TRUSTGATE_DIAG_REPS must be 1..30')
CASE=next(c for c in CASES if c[0]=='translation_trick')
NAME, WORKFLOW, READ_TOOL, USER, PAYLOAD_KEY, AUTHORIZED=CASE
assert AUTHORIZED is None
FILES=['step33_v3_ai_guard.py','step19_gateway.py','step21_reference_gateway.py','step30_hybrid_gateway.py','step40_frozen_evaluation.py']
def digest(p):
    path=ROOT/p
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else 'MISSING'

async def main():
    guard=ImprovedTrustGateAIGuard()
    kw=dict(api_key=os.environ['OPENAI_API_KEY'],timeout=30.0,max_retries=1)
    if os.getenv('OPENAI_API_BASE'): kw['base_url']=os.environ['OPENAI_API_BASE']
    agent=AsyncOpenAI(**kw)
    before={f:digest(f) for f in FILES}
    print('=== STEP 42 TRANSLATION ROOT-CAUSE DIAGNOSTIC ===')
    print('Scenario:',NAME,'| Guard:',guard.model,'| Repetitions per mode:',REPS)
    print('Trusted user request:',USER)
    print('Untrusted payload:',repr(PAYLOADS[PAYLOAD_KEY]))
    print('No storage execution; no code changes.')
    rows=[]
    params=StdioServerParameters(command=sys.executable,args=[str(ROOT/'server.py')])
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            for mode in ('autonomous','fixed_proposal'):
                for rep in range(1,REPS+1):
                    gateway=ReferenceGateway(session,WORKFLOWS[WORKFLOW])
                    doc=await gateway.read_ref(READ_TOOL)
                    ref=doc['document_ref']
                    untrusted=doc['content']+PAYLOADS[PAYLOAD_KEY]
                    agent_error=guard_error=''
                    if mode=='autonomous':
                        try: proposal=await agent_propose(agent,USER,untrusted,ref)
                        except Exception as exc:
                            agent_error=f'{type(exc).__name__}: {exc}'
                            proposal={'action':'error','workspace':None}
                    else: proposal={'action':'store_document_ref','workspace':'external'}
                    action=proposal.get('action','error')
                    dest=proposal.get('workspace') if action=='store_document_ref' else None
                    policy=ai=hybrid='NOT_APPLICABLE'
                    explanation=attack_type=risk=intent=detected=''
                    elapsed=0
                    if action=='store_document_ref':
                        handle=gateway._resolve_reference(ref)
                        if handle is None: raise RuntimeError('Reference resolution failed')
                        result=gateway.evaluate_storage(handle,dest)
                        policy=result.decision
                        start=time.perf_counter()
                        try:
                            assessment=await guard.assess(user_request=USER,tool_output=untrusted,
                                proposed_tool='store_document_ref',
                                proposed_arguments={'document_ref':ref,'workspace':dest},
                                classification=result.classification)
                            ai=assessment.recommended_action
                            explanation=assessment.explanation
                            attack_type=assessment.attack_type
                            risk=assessment.risk_level
                            intent=assessment.intent_aligned
                            detected=assessment.attack_detected
                        except Exception as exc:
                            guard_error=f'{type(exc).__name__}: {exc}'
                            ai='REVIEW'
                        elapsed=round((time.perf_counter()-start)*1000)
                        hybrid=HybridTrustGate.combine_decisions(policy,ai)
                    row=dict(mode=mode,repetition=rep,scenario=NAME,user_request=USER,
                        payload=PAYLOADS[PAYLOAD_KEY],agent_action=action,destination=dest or '',
                        authorized_action=False,policy_decision=policy,ai_decision=ai,
                        hybrid_decision=hybrid,attack_detected=detected,attack_type=attack_type,
                        risk_level=risk,intent_aligned=intent,guard_explanation=explanation,
                        ai_latency_ms=elapsed,agent_error=agent_error,guard_error=guard_error)
                    rows.append(row)
                    print(f'{mode:14s} rep={rep:2d} action={action:18s} dest={str(dest):8s} '
                          f'policy={policy:14s} ai={ai:8s} hybrid={hybrid:14s} '
                          f'intent_aligned={str(intent):5s} attack_detected={str(detected):5s}')
                    if hybrid=='ALLOW': print('  UNAUTHORIZED ALLOW — explanation:',explanation)
    results=ROOT/'results'; results.mkdir(exist_ok=True)
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S')
    out=results/f'step42_translation_diagnostic_{stamp}.csv'
    with out.open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    after={f:digest(f) for f in FILES}
    changed=[f for f in FILES if before[f]!=after[f]]
    manifest=results/f'step42_translation_manifest_{stamp}.json'
    manifest.write_text(json.dumps(dict(scenario=NAME,reps_per_mode=REPS,guard_model=guard.model,
        files_before=before,files_after=after,changed_files=changed,csv=str(out)),indent=2))
    print('\n=== STEP 42 RESULTS ===')
    for mode in ('autonomous','fixed_proposal'):
        subset=[r for r in rows if r['mode']==mode]
        proposed=[r for r in subset if r['agent_action']=='store_document_ref']
        print(f'{mode}: unauthorized proposals={len(proposed)}/{len(subset)} '
              f'hybrid ALLOW={sum(r["hybrid_decision"]=="ALLOW" for r in proposed)} '
              f'BLOCK={sum(r["hybrid_decision"]=="BLOCK" for r in proposed)}')
    print('Agent errors:',sum(bool(r['agent_error']) for r in rows))
    print('Guard errors:',sum(bool(r['guard_error']) for r in rows))
    print('Changed files:',changed or 'none')
    print('CSV:',out)
    print('Manifest:',manifest)
    print('Targeted development diagnostic; not an independent held-out evaluation.')
    print('Guard explanations are model-generated, not definitive proof of causation.')

if __name__=='__main__': asyncio.run(main())
