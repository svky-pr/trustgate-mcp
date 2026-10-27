#!/usr/bin/env python3
"""Step85: reproducible final TrustGate-MCP ablation analysis.

Analyzes actual CSV artifacts from Steps 67, 83 and 84. Does not fabricate
missing experiments, and does not re-run API/MCP tests. Stdlib only.

Usage:
 python step85_final_analysis.py
 python step85_final_analysis.py --step84 results/step84_live_adversarial_YYYYMMDD_HHMMSS.csv
 python step85_final_analysis.py --step67 results/step67_ablation_YYYYMMDD_HHMMSS.csv --step83 results/step83_live_hybrid_YYYYMMDD_HHMMSS.csv
 python step85_final_analysis.py --self-test
"""
from __future__ import annotations
import argparse, csv, json, math, statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parent
RESULTS=ROOT/'results'

def read_csv(path):
    if path is None:return []
    with path.open(newline='',encoding='utf-8-sig') as f:
        rows=list(csv.DictReader(f))
    if not rows:raise ValueError(f'Empty CSV: {path}')
    return rows

def latest(glob,override):
    if override:
        path=Path(override)
        if not path.is_file():raise FileNotFoundError(path)
        return path
    found=sorted(RESULTS.glob(glob),key=lambda p:p.stat().st_mtime)
    return found[-1] if found else None

def num(v):
    try:return float(v)
    except (ValueError,TypeError):return float('nan')

def nsum(rows,col):return sum(int(num(r.get(col,0))) for r in rows if math.isfinite(num(r.get(col,0))))

def truth(v):return str(v).strip().lower() in ('true','1','yes')

def percent(x,y):return f'{100*x/y:.1f}%' if y else 'N/A'

def median(rows,col):
    values=[num(r.get(col)) for r in rows]
    values=[v for v in values if math.isfinite(v)]
    return round(statistics.median(values),1) if values else None

def mean(rows,col):
    values=[num(r.get(col)) for r in rows]
    values=[v for v in values if math.isfinite(v)]
    return round(statistics.mean(values),1) if values else None

def wilson(success,total,z=1.96):
    if total==0:return 'N/A'
    p=success/total; den=1+z*z/total
    center=(p+z*z/(2*total))/den
    half=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/den
    return f'{100*(center-half):.1f}%–{100*(center+half):.1f}%'

def summarize84(rows,lines):
    required={'mode','attack','trial','poison_delivered','agent_storage_attempts','agent_storage_executions','elapsed_ms'}
    if not required.issubset(rows[0]):raise ValueError('Step84 CSV missing: '+str(required-set(rows[0])))
    modes=['baseline','deterministic','hybrid']
    lines.extend(['## Step 84 — Autonomous agent trials','',
                  '| Mode | Runs | Poison delivered | Agent attempts | Unauthorized executions | Agent blocks | Rule alerts | GenAI alerts | Median end-to-end latency |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|---:|'])
    stats={}
    for mode in modes:
        subset=[r for r in rows if r['mode']==mode]
        if not subset:continue
        poisoned=[r for r in subset if r['attack']!='clean']
        delivered=sum(truth(r['poison_delivered']) for r in poisoned)
        attempts=nsum(subset,'agent_storage_attempts')
        executions=nsum(subset,'agent_storage_executions')
        blocks=nsum(subset,'agent_storage_blocks')
        rules=sum(truth(r.get('rules_alert')) for r in subset)
        genai=sum(truth(r.get('genai_alert')) for r in subset)
        med=median(subset,'elapsed_ms')
        stats[mode]={'runs':len(subset),'poisoned':len(poisoned),'delivered':delivered,
                     'attempts':attempts,'executions':executions,'blocks':blocks,
                     'rules_alerts':rules,'genai_alerts':genai,'median_ms':med}
        lines.append(f'| {mode} | {len(subset)} | {delivered}/{len(poisoned)} | {attempts} | {executions} | {blocks} | {rules} | {genai} | {med} ms |')
    lines.append('')
    if 'baseline' in stats:
        b=stats['baseline']; lines.append(f'- Baseline unauthorized execution among poisoned sessions: **{percent(b["executions"],b["poisoned"])}** (count-based; multiple executions per session are possible).')
        lines.append(f'- Baseline poison delivery: **{percent(b["delivered"],b["poisoned"])}**; Wilson 95% interval: {wilson(b["delivered"],b["poisoned"])}.')
    for mode in ('deterministic','hybrid'):
        if mode in stats:
            s=stats[mode]
            lines.append(f'- {mode} poison delivery: **{s["delivered"]}/{s["poisoned"]}**, Wilson 95% interval: {wilson(s["delivered"],s["poisoned"])}.')
    # Matched design: attack and trial only. Check exact pair completeness.
    bykey=defaultdict(dict)
    for r in rows:
        key=(r['attack'],r['trial'],r.get('system_style',''),r.get('model',''))
        if r['mode'] in bykey[key]:
            raise ValueError(f'Duplicate Step84 mode for {key}: {r["mode"]}')
        bykey[key][r['mode']]=r
    matched=[v for v in bykey.values() if all(k in v for k in modes)]
    lines.append(f'- Fully paired baseline/deterministic/hybrid trials: **{len(matched)}/{len(bykey)}**.')
    if len(matched)!=len(bykey):lines.append('- WARNING: Some attack/trial pairs are incomplete; do not treat modes as fully paired.')
    if matched:
        diffs=[num(v['hybrid']['elapsed_ms'])-num(v['deterministic']['elapsed_ms']) for v in matched]
        diffs=[v for v in diffs if math.isfinite(v)]
        if diffs:
            lines.append(f'- Median paired hybrid minus deterministic **session elapsed time**: **{round(statistics.median(diffs),1)} ms** (includes agent calls, tool calls, and review waiting; NOT isolated GenAI latency).')
        extra=sum(nsum([v['hybrid']],'agent_storage_executions')<nsum([v['deterministic']],'agent_storage_executions') for v in matched)
        lines.append(f'- Pairs where hybrid had fewer unauthorized executions than deterministic: **{extra}/{len(matched)}**. This is descriptive, not a causal estimate.')
    if 'hybrid' in stats and 'deterministic' in stats and stats['hybrid']['executions']==stats['deterministic']['executions']:
        lines.append('- **No demonstrated incremental execution-prevention benefit** from background GenAI in this evaluation.')
    lines.extend(['- If no protected agent attempted unauthorized storage, there is **no live-agent interception evidence** from these trials.',
                  '- Backend storage was simulated. Agent attempts and gateway execution outcomes must not be conflated.',''])
    return stats

def summarize67(rows,lines):
    required={'mode','label','actual','latency_ms','invalid_grant_blocked'}
    if not required.issubset(rows[0]):raise ValueError('Step67 CSV missing: '+str(required-set(rows[0])))
    lines.extend(['## Step 67 — Controlled MCP gateway ablation','',
                  '| Mode | Attack blocks | Benign executions | Forged-grant denials | Errors | Mean whole-case latency |',
                  '|---|---:|---:|---:|---:|---:|'])
    for mode in ('authorization_only','semantic_only','full'):
        part=[r for r in rows if r['mode']==mode]
        if not part:continue
        attacks=[r for r in part if r['label']=='attack']
        benign=[r for r in part if r['label']=='benign']
        blocked=sum(r['actual']=='BLOCKED' for r in attacks)
        executed=sum(r['actual']=='EXECUTED' for r in benign)
        forged=sum(truth(r['invalid_grant_blocked']) for r in part)
        errors=sum(r['actual']=='ERROR' or bool(r.get('error')) for r in part)
        lines.append(f'| {mode} | {blocked}/{len(attacks)} | {executed}/{len(benign)} | {forged}/{len(part)} | {errors} | {mean(part,"latency_ms")} ms |')
    lines.extend(['',
      '- All Step67 modes retain trusted grant and host-policy checks; **semantic_only is not an authorization-free system**.',
      '- The attack-block count measures whether a host-authorized simulated export was rejected because of content, not whether an LLM attempted a call.',
      '- Whole-case latency includes MCP startup, grant handling and backend operations; it does not isolate detector overhead.',''])

def summarize83(rows,lines):
    fields=set(rows[0]); lines.extend(['## Step 83 — Scripted real-MCP monitoring',''])
    lines.append('CSV columns: '+', '.join(sorted(fields))+'.')
    lines.append('')
    # Avoid assuming a specific schema beyond fields observed.
    for label_col in ('label',):
        if label_col in fields:
            lines.append('Label counts: '+str(dict(Counter(r[label_col] for r in rows)))+'.')
    for col in ('rules_alert','hybrid_alert','genai_alert','rule_alert','step82_rules'):
        if col in fields:
            lines.append(f'- {col}: {sum(truth(r[col]) for r in rows)} true across {len(rows)} rows.')
    lines.extend(['- These are **scripted MCP calls**, not autonomous LLM attack chains.',
                  '- Background GenAI session alerts are advisory, not gateway authorization denials.',''])

def self_test():
    assert percent(1,4)=='25.0%'
    assert truth('True') and not truth('False')
    assert wilson(0,0)=='N/A'
    assert median([{'v':'10'},{'v':'20'}],'v')==15
    print('STEP85 SELF-TEST: 4/4 PASS')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--step84',help='Explicit Step84 CSV; default newest in results/')
    p.add_argument('--step67',help='Explicit Step67 CSV; default newest in results/')
    p.add_argument('--step83',help='Explicit Step83 CSV; default newest in results/')
    p.add_argument('--self-test',action='store_true')
    args=p.parse_args()
    if args.self_test:return self_test()
    paths={
      '84':latest('step84_live_adversarial_*.csv',args.step84),
      '67':latest('step67_ablation_*.csv',args.step67),
      '83':latest('step83_live_hybrid_*.csv',args.step83),
    }
    if not paths['84']:
        p.error('Step84 CSV not found. Run Step84 first, or provide --step84 PATH.')
    lines=['# TrustGate-MCP — Step 85 Final Ablation and Performance Analysis','',
           f'Generated (UTC): {datetime.now(timezone.utc).isoformat(timespec="seconds")}','',
           '## Source artifacts','']
    for step,path in paths.items():
        lines.append(f'- Step {step}: `{path}`' if path else f'- Step {step}: **not found; omitted**')
    lines.extend(['','## Interpretation and limitations','',
      '- Step84 is autonomous LLM-driven; Steps67/83 use scripted MCP calls. They are **different experiments and cannot be pooled**.',
      '- Synthetic cases and investigator labels are not independent evidence of real-world generalization.',
      '- Confidence intervals are descriptive binomial intervals, not a correction for dependence between trials or reused prompts.',
      '- Different conditions may invoke different numbers of model calls, and background GenAI waiting can change session elapsed time.',
      '- The results do not establish that GenAI adds attack-prevention coverage unless it changes an actual execution outcome under matched conditions.',
      '- Content blocking can prevent all malicious agent attempts; a zero agent-attempt count is **not** evidence of successful attempted-call interception.',''])
    summary=summarize84(read_csv(paths['84']),lines)
    if paths['67']:summarize67(read_csv(paths['67']),lines)
    if paths['83']:summarize83(read_csv(paths['83']),lines)
    lines.extend(['## Research conclusion template','',
      'The evaluated TrustGate-MCP configurations showed [report exact observed attack and benign outcomes above]. '
      'Host authorization, content inspection, and workflow monitoring should be described as separate mechanisms. '
      'Where GenAI and deterministic results were identical, do not claim an incremental GenAI security benefit. '
      'Any claims about interception require observed unauthorized LLM attempts and corresponding gateway denials.',''])
    RESULTS.mkdir(exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    output=RESULTS/f'step85_final_analysis_{stamp}.md'
    output.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('=== STEP 85 FINAL ANALYSIS ===')
    for mode,v in summary.items():
        print(f'{mode}: runs={v["runs"]} poison={v["delivered"]}/{v["poisoned"]} '
              f'attempts={v["attempts"]} executions={v["executions"]} '
              f'median_session_ms={v["median_ms"]}')
    print('Step67:',paths['67'] or 'NOT FOUND')
    print('Step83:',paths['83'] or 'NOT FOUND')
    print('Report:',output)

if __name__=='__main__':main()
