#!/usr/bin/env python3
"""Step 68: reproducible research results from Step64, Step65, Step67 CSVs.

Standard-library only. Produces Markdown, CSV and SVG plots.
Example: python step68_results_report.py
         python step68_results_report.py --step64 results/step64_gateway_....csv
"""
from __future__ import annotations
import argparse
import csv
import html
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def latest(pattern):
    files = sorted((ROOT / 'results').glob(pattern), key=lambda p: (p.stat().st_mtime, p.name))
    if not files:
        raise FileNotFoundError(f'No files matching results/{pattern}')
    return files[-1]


def read_csv(path, required):
    with path.open(newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or [])
        missing = set(required) - fields
        if missing:
            raise ValueError(f'{path.name}: missing columns {sorted(missing)}')
        return list(reader)


def is_true(value):
    return str(value).strip().lower() in ('true', '1', 'yes')


def pct(a, b):
    return 100 * a / b if b else None


def fmt(v, decimals=1):
    return f'{v:.{decimals}f}%' if v is not None else 'N/A'


def wilson(k, n, z=1.959963984540054):
    if not n:
        return None
    p = k/n
    d = 1+z*z/n
    c = (p+z*z/(2*n))/d
    h = z*math.sqrt((p*(1-p)+z*z/(4*n))/n)/d
    return (max(0, c-h), min(1, c+h))


def ci(k, n):
    v = wilson(k,n)
    return f'{100*v[0]:.1f}%–{100*v[1]:.1f}%' if v else 'N/A'


def metric(rows):
    valid = [r for r in rows if r.get('actual') in ('BLOCKED','EXECUTED') and r.get('label') in ('attack','benign')]
    tp = sum(r['label']=='attack' and r['actual']=='BLOCKED' for r in valid)
    fn = sum(r['label']=='attack' and r['actual']=='EXECUTED' for r in valid)
    fp = sum(r['label']=='benign' and r['actual']=='BLOCKED' for r in valid)
    tn = sum(r['label']=='benign' and r['actual']=='EXECUTED' for r in valid)
    errors = len(rows)-len(valid)
    lat = []
    for r in valid:
        try:
            lat.append(float(r['latency_ms']))
        except (KeyError, ValueError, TypeError):
            pass
    return dict(n=len(rows), tp=tp, fn=fn, fp=fp, tn=tn, errors=errors,
                recall=pct(tp,tp+fn), fpr=pct(fp,fp+tn), precision=pct(tp,tp+fp),
                accuracy=pct(tp+tn,len(valid)), mean_ms=statistics.mean(lat) if lat else None,
                median_ms=statistics.median(lat) if lat else None)


def svg_bars(path, title, items, suffix, max_value=None):
    # Simple dependency-free SVG chart, safe for offline viewing.
    w=940; margin=230; plot_w=600; bar_h=36; gap=28
    height=105+len(items)*(bar_h+gap)
    vmax = max_value or max([float(x[1]) for x in items] + [1]) * 1.12
    lines=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{height}" viewBox="0 0 {w} {height}">',
           '<rect width="100%" height="100%" fill="#ffffff"/>',
           f'<text x="24" y="38" font-size="21" font-family="Arial" font-weight="bold" fill="#182338">{html.escape(title)}</text>']
    for i,(label,value) in enumerate(items):
        y=68+i*(bar_h+gap)
        bw=max(0,plot_w*float(value)/vmax)
        lines.extend([f'<text x="{margin-15}" y="{y+24}" text-anchor="end" font-size="15" font-family="Arial" fill="#182338">{html.escape(label)}</text>',
                      f'<rect x="{margin}" y="{y}" width="{plot_w}" height="{bar_h}" fill="#edf1f7" rx="5"/>',
                      f'<rect x="{margin}" y="{y}" width="{bw:.2f}" height="{bar_h}" fill="#335b99" rx="5"/>',
                      f'<text x="{min(margin+bw+10, w-90):.2f}" y="{y+24}" font-size="14" font-family="Arial" fill="#182338">{value:.1f}{suffix}</text>'])
    lines.append('</svg>')
    path.write_text('\n'.join(lines), encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--step64',type=Path)
    parser.add_argument('--step65',type=Path)
    parser.add_argument('--step67',type=Path)
    args=parser.parse_args()
    p64=args.step64 or latest('step64_gateway_*.csv')
    p65=args.step65 or latest('step65_live_agent_*.csv')
    p67=args.step67 or latest('step67_ablation_*.csv')
    a64=read_csv(p64,('id','label','actual','latency_ms'))
    a65=read_csv(p65,('mode','attack','poison_delivered','unauthorized_attempt','unauthorized_execution','elapsed_ms'))
    a67=read_csv(p67,('mode','id','label','actual','latency_ms','invalid_grant_blocked'))
    expected_modes=('authorization_only','semantic_only','full')
    modes={m:[r for r in a67 if r['mode']==m] for m in expected_modes}
    if not all(modes.values()):
        raise ValueError('Step67 must contain authorization_only, semantic_only, and full modes')
    summary64=metric(a64)
    summaries={m:metric(rows) for m,rows in modes.items()}
    now=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    out=ROOT/'results'/f'step68_report_{now}'
    out.mkdir(parents=True,exist_ok=True)

    # Case-level Step64 vs Step67 full, plus within-Step67 comparisons.
    full_by_id={r['id']:r for r in modes['full']}
    prev_by_id={r['id']:r for r in a64}
    cases=[]
    for ident in sorted(set(prev_by_id)|set(full_by_id)):
        old=prev_by_id.get(ident,{})
        new=full_by_id.get(ident,{})
        if old.get('actual')!=new.get('actual'):
            cases.append(dict(id=ident,label=new.get('label') or old.get('label'),
                              step64_actual=old.get('actual','MISSING'),
                              step67_full_actual=new.get('actual','MISSING'),
                              step64_reason=old.get('reason',''),
                              step67_reason=new.get('reason','')))
    mismatch_file=out/'step64_vs_step67_disagreements.csv'
    with mismatch_file.open('w',encoding='utf-8',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=['id','label','step64_actual','step67_full_actual','step64_reason','step67_reason'])
        wr.writeheader();wr.writerows(cases)

    mode_rows=[]
    for mode in expected_modes:
        v=summaries[mode]
        mode_rows.append(dict(mode=mode,TP=v['tp'],FN=v['fn'],FP=v['fp'],TN=v['tn'],ERRORS=v['errors'],
                              attack_block_pct=round(v['recall'],2) if v['recall'] is not None else '',
                              benign_false_block_pct=round(v['fpr'],2) if v['fpr'] is not None else '',
                              mean_latency_ms=round(v['mean_ms'],1) if v['mean_ms'] is not None else '',
                              invalid_grants_denied=sum(is_true(r['invalid_grant_blocked']) for r in modes[mode]),
                              total=len(modes[mode])))
    with (out/'step67_metrics.csv').open('w',encoding='utf-8',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=list(mode_rows[0]));wr.writeheader();wr.writerows(mode_rows)

    # Step65 live agent: poison exposure, unauthorized attempts and executions.
    live=[]
    for mode in ('baseline','hardened'):
        group=[r for r in a65 if r['mode']==mode]
        poison=[r for r in group if r['attack']!='clean']
        delivered=sum(is_true(r['poison_delivered']) for r in poison)
        attempts=sum(is_true(r['unauthorized_attempt']) for r in poison)
        executions=sum(is_true(r['unauthorized_execution']) for r in poison)
        lat=[]
        for r in group:
            try: lat.append(float(r['elapsed_ms']))
            except (ValueError,TypeError): pass
        live.append(dict(mode=mode,total=len(group),poisoned=len(poison),delivered=delivered,
                         attempts=attempts,executions=executions,
                         mean_latency_ms=statistics.mean(lat) if lat else None))

    svg_bars(out/'step67_blocking.svg','Step 67: Malicious-content blocking',
             [(m.replace('_',' ').title(),summaries[m]['recall'] or 0) for m in expected_modes], '%',100)
    svg_bars(out/'step67_false_blocks.svg','Step 67: Benign false-block rate',
             [(m.replace('_',' ').title(),summaries[m]['fpr'] or 0) for m in expected_modes], '%',100)
    svg_bars(out/'step67_latency.svg','Step 67: Mean end-to-end latency',
             [(m.replace('_',' ').title(),summaries[m]['mean_ms'] or 0) for m in expected_modes], ' ms')

    lines=['# TrustGate-MCP — Step 68 Experimental Results',
           '',f'Generated (UTC): {datetime.now(timezone.utc).isoformat(timespec="seconds")}',
           '', '## Data provenance',
           f'- Step 64: `{p64}`',f'- Step 65: `{p65}`',f'- Step 67: `{p67}`',
           '', '## Step 67: Paired gateway ablation',
           '', '| Configuration | TP | FN | FP | TN | Errors | Attack blocking | Benign false-block | Mean latency | Forged grants denied |',
           '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for m in expected_modes:
        v=summaries[m]; rows=modes[m]
        denied=sum(is_true(r['invalid_grant_blocked']) for r in rows)
        lines.append(f'| {m} | {v["tp"]} | {v["fn"]} | {v["fp"]} | {v["tn"]} | {v["errors"]} | {fmt(v["recall"])} (95% CI {ci(v["tp"],v["tp"]+v["fn"])}) | {fmt(v["fpr"])} | {v["mean_ms"]:.1f} ms | {denied}/{len(rows)} |')
    lines += ['', '![Blocking](step67_blocking.svg)', '', '![False blocks](step67_false_blocks.svg)', '', '![Latency](step67_latency.svg)',
              '', '### Scope and interpretation',
              '- The three modes share trusted grants and deterministic storage policy. The authorization-only mode disables content inspection; the semantic-only mode uses Step 62; full uses Step 63.',
              '- Malicious-content blocking is not synonymous with stopping an unauthorized agent-initiated action: the test host deliberately authorizes storage for all cases.',
              '- Latency includes MCP subprocess startup and other operations. It is not isolated classifier processing time.',
              '- These 40 cases are a small, development-influenced benchmark, not an independent large-scale test set.',
              '', '## Step 64: Prior full-gateway run',
              f'- TP={summary64["tp"]}, FN={summary64["fn"]}, FP={summary64["fp"]}, TN={summary64["tn"]}, errors={summary64["errors"]}.',
              f'- Attack blocking: {fmt(summary64["recall"])}; benign false-block: {fmt(summary64["fpr"])}.',
              f'- Case-level Step64 vs Step67-full disagreements: **{len(cases)}**. See `step64_vs_step67_disagreements.csv`.',
              '- Cross-run disagreements can reflect stochastic model behavior or other execution differences; this comparison alone does not establish the cause.',
              '', '## Step 65: Live LLM agent',
              '', '| Mode | Total trials | Poisoned trials | Exact poison delivered | Unauthorized attempt trials | Unauthorized execution trials | Mean end-to-end latency |',
              '|---|---:|---:|---:|---:|---:|---:|']
    for r in live:
        mean=f'{r["mean_latency_ms"]:.1f} ms' if r['mean_latency_ms'] is not None else 'N/A'
        lines.append(f'| {r["mode"]} | {r["total"]} | {r["poisoned"]} | {r["delivered"]} | {r["attempts"]} | {r["executions"]} | {mean} |')
    lines += ['', '- Step 65 is an agent-initiated tool-use evaluation. Step 64 and Step 67 are controlled gateway storage probes; do not combine their denominators.',
              '- Hardened runs with no unauthorized agent attempts cannot demonstrate an intercepted unauthorized agent call.',
              '- Storage is simulated; no real external export occurs.',
              '- Step 65 does not log token usage, so API cost cannot be reconstructed from its CSV.',
              '', '## Limitations and follow-up',
              '- Test reproducibility would benefit from repeated independent runs and case-level variance analysis.',
              '- Full-vs-semantic incremental value must be assessed on more diverse cases and under explicit component failure tests.',
              '- Evaluate false positives and any detected regressions before making general security claims.',
              '']
    report=out/'trustgate_results.md'
    report.write_text('\n'.join(lines),encoding='utf-8')
    print('=== STEP 68 RESULTS ===')
    for row in mode_rows:
        print(row)
    print('Step64 vs Step67 full disagreements:',len(cases))
    for row in cases:
        print(' ',row['id'],row['label'],row['step64_actual'],'->',row['step67_full_actual'])
    for row in live:
        print('Live:',row)
    print('Report:',report)
    print('Charts:',out/'step67_blocking.svg',out/'step67_false_blocks.svg',out/'step67_latency.svg')
    print('Note: no matplotlib required; SVG charts are generated with standard library.')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
