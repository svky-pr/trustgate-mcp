#!/usr/bin/env python3
"""Step 94: create reproducible figures and Markdown analysis from Step 93 JSON.

No API calls, no live agent/MCP. Requires matplotlib.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
LABELS = {90:'Step 90: injection-bearing content',91:'Step 91: unapproved content',92:'Step 92: approved-but-unsafe'}
DISPLAY = {'baseline':'Baseline','deterministic':'Metadata rules','metadata_only':'Metadata only',
           'hybrid_action':'Semantic block','hybrid_detection_hold':'Semantic hold',
           'integrity_only':'Integrity only','semantic_only':'Semantic only',
           'combined':'Integrity + semantic','dlp_only':'DLP only',
           'integrity_dlp':'Integrity + DLP','integrity_semantic':'Integrity + semantic',
           'all_controls':'All controls'}
ORDER = {90:['baseline','deterministic','hybrid_action','hybrid_detection_hold'],
         91:['baseline','metadata_only','integrity_only','semantic_only','combined'],
         92:['baseline','metadata_only','integrity_only','dlp_only','semantic_only',
             'integrity_dlp','integrity_semantic','all_controls']}

def load_report(path):
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj,dict) or not isinstance(obj.get('defenses'),list) or not isinstance(obj.get('offline_guard_assessments'),list):
        raise ValueError('Not a Step 93 report: missing defenses or offline_guard_assessments')
    if obj.get('failures'):
        raise ValueError('Step 93 report contains failures: '+str(obj['failures']))
    steps = {int(r['step']) for r in obj['defenses']}
    if not {90,91,92}.issubset(steps):
        raise ValueError('Report must contain Steps 90, 91, and 92')
    for r in obj['defenses']:
        for n,d in [('unsafe_allowed','unsafe_n'),('benign_blocked','benign_n')]:
            if not 0 <= int(r[n]) <= int(r[d]):
                raise ValueError('Invalid count in report: '+str(r))
    for r in obj['offline_guard_assessments']:
        if not 0 <= int(r['detected_unsafe']) <= int(r['unsafe_n']):
            raise ValueError('Invalid detection counts')
    return obj

def plot_all(obj, out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size':10,'figure.dpi':130,'savefig.dpi':200})
    guard = sorted(obj['offline_guard_assessments'],key=lambda r:r['step'])
    names = [f"Step {r['step']}" for r in guard]
    rates = [100*r['detected_unsafe']/r['unsafe_n'] for r in guard]
    fig,ax=plt.subplots(figsize=(8,4.5))
    bars=ax.bar(names,rates,color='#34679a',width=.55)
    ax.set_ylim(0,110);ax.set_ylabel('Detected labeled cases (%)')
    ax.set_title('Offline GenAI guard detection by experiment')
    for bar,r in zip(bars,guard):
        ax.text(bar.get_x()+bar.get_width()/2,bar.get_height()+2,
                f"{r['detected_unsafe']}/{r['unsafe_n']}",ha='center',fontsize=10)
    ax.text(.5,-.19,'Different authored datasets; repeated fixtures are not independent attacks.',
            transform=ax.transAxes,ha='center',fontsize=8)
    fig.tight_layout();fig.savefig(out/'fig1_guard_detection.png',bbox_inches='tight');plt.close(fig)

    for step in (90,91,92):
        rows={r['mode']:r for r in obj['defenses'] if int(r['step'])==step}
        modes=[m for m in ORDER[step] if m in rows]
        unsafe=[100*rows[m]['unsafe_allowed']/rows[m]['unsafe_n'] for m in modes]
        blocked=[100*rows[m]['benign_blocked']/rows[m]['benign_n'] for m in modes]
        fig,ax=plt.subplots(figsize=(max(9,len(modes)*1.3),5))
        x=list(range(len(modes)))
        ax.bar([v-.2 for v in x],unsafe,width=.38,label='Labeled unsafe allowed',color='#c45b50')
        ax.bar([v+.2 for v in x],blocked,width=.38,label='Benign blocked',color='#397b75')
        ax.set_xticks(x,[DISPLAY.get(m,m) for m in modes],rotation=24,ha='right')
        ax.set_ylabel('Rate (%)');ax.set_ylim(0,110)
        ax.set_title(LABELS[step]+' — simulated decisions')
        ax.legend(loc='upper right');ax.grid(axis='y',alpha=.2)
        fig.tight_layout();fig.savefig(out/f'fig{step}_defense_comparison.png',bbox_inches='tight');plt.close(fig)

    fig,ax=plt.subplots(figsize=(8,5))
    step=92
    for r in (row for row in obj['defenses'] if int(row['step'])==step):
        x=100*r['benign_blocked']/r['benign_n']
        y=100*r['unsafe_allowed']/r['unsafe_n']
        ax.scatter(x,y,s=85)
        ax.annotate(DISPLAY.get(r['mode'],r['mode']),(x,y),xytext=(6,4),textcoords='offset points',fontsize=8)
    ax.set_xlim(-3,105);ax.set_ylim(-3,105)
    ax.set_xlabel('Benign blocked (%) — lower is better')
    ax.set_ylabel('Unsafe allowed (%) — lower is better')
    ax.set_title('Step 92 security–usability trade-off (authored replay)')
    ax.grid(alpha=.2);fig.tight_layout()
    fig.savefig(out/'fig5_tradeoff.png',bbox_inches='tight');plt.close(fig)

def make_summary(obj,out,source):
    rows=obj['defenses'];guards=sorted(obj['offline_guard_assessments'],key=lambda r:r['step'])
    lines=['# TrustGate-MCP: Step 94 Results and Interpretation','',
      f'Source: `{source.name}`','',
      '**Scope:** Authored host-only replay; no live MCP execution, actual storage, or demonstrated compromise.','',
      '## Offline semantic screening','',
      '| Step | Detected labeled cases | Benign detections | Guard errors | Median latency |',
      '|---|---:|---:|---:|---:|']
    for g in guards:
        lines.append(f"| {g['step']} | {g['detected_unsafe']}/{g['unsafe_n']} | {g['false_positive_detections']}/{g['benign_n']} | {g['errors']} | {g['median_guard_ms']:.1f} ms |")
    lines += ['','The label meaning differs across experiments. Step 90 measures injection presence; Steps 91 and 92 use authored unsafe-content labels. These rates must not be pooled as a general attack-success or prevention rate.','',
              '## Simulated defense outcomes','',
              '| Step | Defense | Labeled unsafe allowed | Benign blocked |','|---|---|---:|---:|']
    for step in (90,91,92):
        by={r['mode']:r for r in rows if int(r['step'])==step}
        for m in ORDER[step]:
            if m not in by:continue
            r=by[m]
            lines.append(f"| {step} | {DISPLAY.get(m,m)} | {r['unsafe_allowed']}/{r['unsafe_n']} ({100*r['unsafe_allowed']/r['unsafe_n']:.1f}%) | {r['benign_blocked']}/{r['benign_n']} ({100*r['benign_blocked']/r['benign_n']:.1f}%) |")
    lines+=['','## Interpretation','',
        '- **Step 90:** Semantic intervention can flag or hold injection-bearing authored tool output. All simulated proposed exports were authorized, so this is not evidence of preventing unauthorized tool execution.',
        '- **Step 91:** Trusted SHA-256 approval checks reject unapproved malicious *and* unapproved benign modifications. The experiment does not show incremental protection from adding GenAI to integrity enforcement.',
        '- **Step 92:** All fixture hashes are intentionally approved. Integrity alone cannot identify semantically unsafe approved content. The combined controls can reduce labeled unsafe allowance relative to the tested DLP-only rules.',
        '- **Residual risk:** Approved factual reversal may remain undetected; the GenAI guard is not a replacement for source verification, data classification, or authorization.',
        '- **Inference limits:** Three repetitions per fixed authored fixture do not constitute independent attack samples; avoid broad statistical generalization or strong claims from Wilson intervals.',
        '- **Operational cost:** Guard median latency is per offline assessment, not measured end-to-end live-agent overhead.','',
        '## Figures','',
        '![Detection rates](fig1_guard_detection.png)','',
        '![Step 90 comparison](fig90_defense_comparison.png)','',
        '![Step 91 comparison](fig91_defense_comparison.png)','',
        '![Step 92 comparison](fig92_defense_comparison.png)','',
        '![Step 92 trade-off](fig5_tradeoff.png)','',
        '## Suggested conclusion','',
        'Within the tested authored replay scenarios, semantic screening provided complementary detection for certain instruction-bearing content that passed metadata and content-approval checks. However, deterministic integrity controls already rejected unapproved modifications, and the semantic guard missed some unsafe approved content. The results support defense-in-depth as a research direction, but do not establish real-world exploit prevention or generalization to unseen prompt injections.','']
    path=out/'step94_results_summary.md';path.write_text('\n'.join(lines),encoding='utf-8');return path

def self_test():
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as td:
        p=Path(td)/'test.json'
        sample={'defenses':[],'offline_guard_assessments':[],'failures':[]}
        for step in (90,91,92):
            sample['defenses'].append(dict(step=step,mode='baseline',unsafe_allowed=1,unsafe_n=1,benign_blocked=0,benign_n=1))
            sample['offline_guard_assessments'].append(dict(step=step,detected_unsafe=1,unsafe_n=1,false_positive_detections=0,benign_n=1,errors=0,median_guard_ms=100))
        p.write_text(json.dumps(sample),encoding='utf-8')
        assert len(load_report(p)['defenses'])==3
        summary=make_summary(sample,Path(td),p)
        assert summary.exists() and 'Step 92' in summary.read_text(encoding='utf-8')
        plot_all(sample,Path(td))
        assert (Path(td)/'fig92_defense_comparison.png').exists()
    print('STEP94 SELF-TEST: 3/3 PASS')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,help='Explicit Step 93 JSON path; defaults to latest in results')
    parser.add_argument('--self-test',action='store_true')
    args=parser.parse_args()
    if args.self_test:self_test();return
    results=ROOT/'results'
    if args.report:src=args.report
    else:
        candidates=sorted(results.glob('step93_report_*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
        if not candidates:parser.error('No Step 93 JSON found. Supply --report path.')
        src=candidates[0]
    obj=load_report(src)
    out=results/('step94_figures_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S'))
    out.mkdir(parents=True,exist_ok=False)
    plot_all(obj,out)
    summary=make_summary(obj,out,src)
    print('STEP94 COMPLETE')
    print('SOURCE:',src)
    print('OUTPUT:',out)
    print('SUMMARY:',summary)
    print('FIGURES: fig1_guard_detection.png, fig90_defense_comparison.png, fig91_defense_comparison.png, fig92_defense_comparison.png, fig5_tradeoff.png')
    print('NOTE: Host-only authored replay; figures are not proof of live exploit prevention.')

if __name__=='__main__':main()
