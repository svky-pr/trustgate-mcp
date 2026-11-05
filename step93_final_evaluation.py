#!/usr/bin/env python3
"""Step 93: run Steps 90-92 and summarize paired, authored replay results.

Runs each child script as a separate process, preserving its own CSV and logs.
No live agent/MCP/export. Never interpret authored labels as actual compromises.
"""
from __future__ import annotations
import argparse
import csv
import json
import math
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STEPS = {
    90: ('step90_semantic_incremental_replay.py', 'step90_*.csv', 'malicious_label', 'simulated_export_executed'),
    91: ('step91_content_integrity_semantic_eval.py', 'step91_*.csv', 'malicious_content_label', 'simulated_export'),
    92: ('step92_approved_unsafe_eval.py', 'step92_*.csv', 'unsafe_export_label', 'simulated_export'),
}

def boolean(value):
    if isinstance(value, bool): return value
    if str(value).lower() in ('true', '1'): return True
    if str(value).lower() in ('false', '0'): return False
    raise ValueError(f'Unexpected boolean value: {value!r}')

def wilson(k, n):
    if n == 0: return (None, None)
    z = 1.95996398454
    p = k / n
    d = 1 + z*z/n
    mid = (p + z*z/(2*n))/d
    rad = z*math.sqrt((p*(1-p) + z*z/(4*n))/n)/d
    return (round(max(0, mid-rad), 4), round(min(1, mid+rad), 4))

def summarize(step, path):
    label_col, export_col = STEPS[step][2:]
    with path.open(newline='', encoding='utf-8-sig') as handle:
        data = list(csv.DictReader(handle))
    if not data: raise ValueError(f'Empty CSV: {path}')
    required = {'trial', 'case', 'mode', label_col, export_col, 'guard_detected', 'guard_error', 'guard_ms'}
    missing = required - set(data[0]);
    if missing: raise ValueError(f'Missing columns in {path}: {sorted(missing)}')
    modes = defaultdict(list)
    per_case = defaultdict(list)
    for row in data:
        modes[row['mode']].append(row)
        per_case[(row['trial'], row['case'])].append(row)
    all_modes = set(modes)
    for key, group in per_case.items():
        if len(group) != len(all_modes) or {r['mode'] for r in group} != all_modes:
            raise ValueError(f'Incomplete paired scenario {key} in {path}')
        if len({r[label_col] for r in group}) != 1:
            raise ValueError(f'Inconsistent label for {key}')
    summary = []
    for mode, group in sorted(modes.items()):
        unsafe = [r for r in group if boolean(r[label_col])]
        benign = [r for r in group if not boolean(r[label_col])]
        unsafe_allowed = sum(boolean(r[export_col]) for r in unsafe)
        benign_blocked = sum(not boolean(r[export_col]) for r in benign)
        # Each defense receives the same offline guard assessment; report only
        # one unique set of guard calls, separately from enforcement outcomes.
        summary.append(dict(step=step, mode=mode, trials=len({r['trial'] for r in group}),
            cases=len({r['case'] for r in group}), unsafe_n=len(unsafe), unsafe_allowed=unsafe_allowed,
            unsafe_allowed_rate=round(unsafe_allowed/len(unsafe), 4) if unsafe else None,
            unsafe_allowed_ci95=wilson(unsafe_allowed, len(unsafe)),
            benign_n=len(benign), benign_blocked=benign_blocked,
            benign_blocked_rate=round(benign_blocked/len(benign), 4) if benign else None,
            benign_blocked_ci95=wilson(benign_blocked, len(benign))))
    unique = [group[0] for group in per_case.values()]
    guard_errors = sum(bool(r['guard_error']) for r in unique)
    detected_unsafe = sum(boolean(r['guard_detected']) and boolean(r[label_col]) for r in unique)
    false_positives = sum(boolean(r['guard_detected']) and not boolean(r[label_col]) for r in unique)
    import statistics
    guard = dict(step=step, assessments=len(unique), errors=guard_errors,
        detected_unsafe=detected_unsafe, unsafe_n=sum(boolean(r[label_col]) for r in unique),
        false_positive_detections=false_positives,
        benign_n=sum(not boolean(r[label_col]) for r in unique),
        median_guard_ms=round(statistics.median(float(r['guard_ms']) for r in unique), 1))
    return summary, guard

def self_test():
    assert boolean('True') and not boolean('False')
    assert wilson(0, 0) == (None, None)
    assert wilson(5, 5)[0] < 1
    assert wilson(0, 5)[1] > 0
    assert set(STEPS) == {90, 91, 92}
    print('STEP93 SELF-TEST: 5/5 PASS')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--steps', type=int, nargs='+', choices=sorted(STEPS), default=[90, 91, 92])
    parser.add_argument('--guard-model', default='gpt-4.1-mini')
    parser.add_argument('--summarize-only', action='store_true', help='Use newest existing CSV per step, without API calls')
    parser.add_argument('--stop-on-error', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test(); return 0
    if not 1 <= args.trials <= 20: parser.error('--trials must be 1..20')
    results = ROOT / 'results'; results.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    report = results / f'step93_report_{stamp}.json'
    summaries, guards, sources, failures = [], [], {}, []
    for step in args.steps:
        filename, pattern = STEPS[step][:2]
        script = ROOT / filename
        if not args.summarize_only:
            if not script.exists():
                failures.append(f'Step {step}: missing {filename}')
                if args.stop_on_error: break
                continue
            command = [sys.executable, str(script), '--trials', str(args.trials),
                       '--guard-model', args.guard_model, '--stop-on-error']
            print(f'\n=== Running Step {step} ({args.trials} trials) ===', flush=True)
            # Use start time and extract CSV path from the child's stdout to avoid
            # accidentally selecting an older file if a child fails.
            run = subprocess.run(command, cwd=str(ROOT), text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
            log = results / f'step93_child_{step}_{stamp}.log'
            log.write_text(run.stdout, encoding='utf-8')
            print(run.stdout[-3000:], flush=True)
            if run.returncode != 0:
                failures.append(f'Step {step}: process failed ({run.returncode}); see {log.name}')
                if args.stop_on_error: break
                continue
            match = re.findall(r'^CSV:\s*(.+\.csv)\s*$', run.stdout, flags=re.MULTILINE)
            if not match:
                failures.append(f'Step {step}: no CSV path in child output')
                if args.stop_on_error: break
                continue
            path = Path(match[-1].strip())
        else:
            candidates = sorted(results.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
            if not candidates:
                failures.append(f'Step {step}: no existing CSV matching {pattern}')
                if args.stop_on_error: break
                continue
            path = candidates[0]
        try:
            summary, guard = summarize(step, path)
            summaries.extend(summary); guards.append(guard); sources[str(step)] = str(path)
        except Exception as exc:
            failures.append(f'Step {step}: {exc}')
            if args.stop_on_error: break
    payload = dict(analysis='authored paired replay; no live agent, MCP, or storage',
        generated_utc=datetime.now(timezone.utc).isoformat(), source_csv=sources,
        defenses=summaries, offline_guard_assessments=guards, failures=failures,
        caveats=['Step 90 labels injection presence, not proven harmful exports.',
                 'Step 91 and 92 label authored content safety, not live compromise.',
                 'Wilson intervals describe trial variation, not generalization to unseen attacks.',
                 'The same offline guard output is reused across defense modes for paired comparison.',
                 'Steps 90-92 use different fixtures; do not pool their rates.'])
    report.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    print('\n=== STEP93 COMPARATIVE SUMMARY ===')
    for row in summaries:
        print(f"step={row['step']} {row['mode']:22} unsafe_allowed={row['unsafe_allowed']}/{row['unsafe_n']} "
              f"benign_blocked={row['benign_blocked']}/{row['benign_n']}")
    for row in guards:
        print(f"step={row['step']} guard_detected={row['detected_unsafe']}/{row['unsafe_n']} "
              f"guard_fp={row['false_positive_detections']}/{row['benign_n']} "
              f"errors={row['errors']} median_ms={row['median_guard_ms']}")
    for error in failures: print('ERROR:', error)
    print('REPORT:', report)
    print('NOTE: These are authored replays, not proof of actual exploit prevention.')
    return 1 if failures or any(g['errors'] for g in guards) else 0

if __name__ == '__main__':
    raise SystemExit(main())
