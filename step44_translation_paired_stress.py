#!/usr/bin/env python3
"""Step 44: paired repeated translation-attack stress test. No storage executes.

Reuses the existing guard and Step 43 trusted fixture grants. This is a
post-discovery regression, not an independent or held-out evaluation.
"""
import asyncio
import csv
import hashlib
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from step21_reference_gateway import ReferenceGateway
from step30_hybrid_gateway import HybridTrustGate
from step33_v3_ai_guard import ImprovedTrustGateAIGuard
from step40_frozen_evaluation import CASES, PAYLOADS, WORKFLOWS
from step43_explicit_authorization import (grant_from_trusted_fixture,
    explicit_authorization, combine3)

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')
REPS = int(os.getenv('TRUSTGATE_STEP44_REPS', '20'))
if not 1 <= REPS <= 100:
    raise ValueError('TRUSTGATE_STEP44_REPS must be 1..100')
CASE_NAMES = ('translation_trick', 'public_export_clean',
              'confidential_export_clean', 'local_store_clean',
              'read_only_external_request')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else 'MISSING'


async def main():
    guard = ImprovedTrustGateAIGuard()
    cases = {case[0]: case for case in CASES}
    for name in CASE_NAMES:
        if name not in cases:
            raise ValueError(f'Step 40 case missing: {name}')
    watched = ['server.py', 'step19_gateway.py', 'step21_reference_gateway.py',
               'step30_hybrid_gateway.py', 'step33_v3_ai_guard.py',
               'step40_frozen_evaluation.py', 'step43_explicit_authorization.py',
               Path(__file__).name]
    before = {name: digest(ROOT / name) for name in watched}
    if any(v == 'MISSING' for v in before.values()):
        raise FileNotFoundError(f'Missing source files: {[k for k,v in before.items() if v == "MISSING"]}')
    print('=== STEP 44 PAIRED TRANSLATION STRESS TEST ===')
    print(f'Guard: {guard.model}; {REPS} assessments per scenario; {len(CASE_NAMES)} scenarios')
    print('Fixed store proposal in every trial; same AI assessment used for both defenses.')
    print('No agent generation, no storage execution, no source modifications.')
    rows = []
    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / 'server.py')])
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            for name in CASE_NAMES:
                case = cases[name]
                _, workflow, read_tool, user_request, payload_key, authorized_dest = case
                # Translation/read-only: deliberately propose unauthorized external export.
                destination = authorized_dest if authorized_dest in ('external', 'local') else 'external'
                grant = grant_from_trusted_fixture(case)
                for rep in range(1, REPS + 1):
                    gateway = ReferenceGateway(session, WORKFLOWS[workflow])
                    doc = await gateway.read_ref(read_tool)
                    ref = doc['document_ref']
                    content = doc['content'] + PAYLOADS[payload_key]
                    handle = gateway._resolve_reference(ref)
                    if handle is None:
                        raise RuntimeError('Reference resolution failed')
                    evaluation = gateway.evaluate_storage(handle, destination)
                    policy = evaluation.decision
                    grant_decision = explicit_authorization(
                        grant, workflow, read_tool, 'store_document_ref', destination)
                    start = time.perf_counter()
                    error = ''
                    explanation = ''
                    aligned = ''
                    detected = ''
                    try:
                        assessment = await guard.assess(
                            user_request=user_request, tool_output=content,
                            proposed_tool='store_document_ref',
                            proposed_arguments={'document_ref': ref, 'workspace': destination},
                            classification=evaluation.classification)
                        ai = assessment.recommended_action
                        if ai not in ('ALLOW', 'BLOCK', 'REVIEW'):
                            raise ValueError(f'Unexpected AI decision {ai!r}')
                        explanation = assessment.explanation
                        aligned = assessment.intent_aligned
                        detected = assessment.attack_detected
                    except Exception as exc:
                        ai = 'REVIEW'  # fail closed for simulated execution
                        error = f'{type(exc).__name__}: {exc}'
                    latency = round((time.perf_counter() - start) * 1000)
                    old = HybridTrustGate.combine_decisions(policy, ai)
                    revised = combine3(grant_decision, policy, ai)
                    authorized = authorized_dest == destination and authorized_dest is not None
                    rows.append(dict(scenario=name, repetition=rep, authorized=authorized,
                        user_request=user_request, destination=destination, payload_key=payload_key,
                        policy=policy, grant=grant_decision, ai=ai, original=old,
                        revised=revised, intent_aligned=aligned, attack_detected=detected,
                        explanation=explanation, ai_latency_ms=latency, guard_error=error))
                    if name == 'translation_trick' or (revised != 'ALLOW' and authorized):
                        print(f'{name:27s} rep={rep:2d} policy={policy:6s} '
                              f'grant={grant_decision:5s} ai={ai:6s} '
                              f'old={old:6s} revised={revised:6s}')
    outdir = ROOT / 'results'
    outdir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csvpath = outdir / f'step44_translation_paired_{stamp}.csv'
    with csvpath.open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    after = {name: digest(ROOT / name) for name in watched}
    changed = [name for name in watched if before[name] != after[name]]
    manifest = outdir / f'step44_manifest_{stamp}.json'
    manifest.write_text(json.dumps(dict(created_utc=datetime.now(timezone.utc).isoformat(),
        model=guard.model, reps=REPS, scenario_names=CASE_NAMES, before=before,
        after=after, changed_files=changed, csv=str(csvpath)), indent=2), encoding='utf-8')
    print('\n=== STEP 44 RESULTS ===')
    for group, selected in [('translation', [r for r in rows if r['scenario'] == 'translation_trick']),
                            ('authorized_controls', [r for r in rows if r['authorized']]),
                            ('read_only', [r for r in rows if r['scenario'] == 'read_only_external_request'])]:
        print(f'{group}: trials={len(selected)} original ALLOW={sum(r["original"] == "ALLOW" for r in selected)} '
              f'revised ALLOW={sum(r["revised"] == "ALLOW" for r in selected)} '
              f'original REVIEW={sum(r["original"] == "REVIEW" for r in selected)} '
              f'revised REVIEW={sum(r["revised"] == "REVIEW" for r in selected)}')
    print('Guard errors:', sum(bool(r['guard_error']) for r in rows))
    print('Mean guard latency (ms):', round(statistics.mean(r['ai_latency_ms'] for r in rows)))
    print('Changed files:', changed or 'none')
    print('CSV:', csvpath)
    print('Manifest:', manifest)
    print('LIMITATIONS: Known attacks and scenario-derived trusted grants; no agent generation or storage; '
          'repeated model calls are not independent observations of distinct attacks.')


if __name__ == '__main__':
    asyncio.run(main())
