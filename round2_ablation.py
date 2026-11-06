#!/usr/bin/env python3
"""Paired Round 2 content-screening / benign-completion trial runner.

Runs identical host-approved export tasks per attack fixture against the three
TG_MODE settings. These are *not* unauthorized-export attack-success trials:
the trusted host explicitly approves each store, including hostile content.
A guard block is an intervention, NOT evidence of preventing actual compromise.

Example:
  python round2_ablation.py --payload-file round2_payloads_example.json --trials 2
Requires the MCP SDK; auth_guard also makes live OpenAI API calls.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from round2_benign_demo import run_case
from round2_mode import MODES
from round2_payloads import load_payload_file, is_benign_class

ROOT = Path(__file__).resolve().parent
BUILTIN = {
    'clean': 'benign', 'direct': 'direct_injection',
    'authority': 'authority_spoofing', 'workflow': 'workflow_hijacking',
    'metadata': 'metadata_injection', 'encoded': 'encoded_instruction',
}
FIELDS = ('trial', 'mode', 'payload_id', 'attack_class', 'labeled_attack',
          'read_executed', 'payload_delivered', 'invalid_grant_blocked', 'store_executed', 'store_decision', 'ai_decision',
          'replay_executed', 'store_latency_ms', 'session_latency_ms', 'error_type')


def cases(filename: str | None):
    items = [('clean', 'benign')]
    if filename:
        records = load_payload_file(filename, tuple(BUILTIN))
        items.extend((name, record['class']) for name, record in records.items())
    else:
        items.extend((name, family) for name, family in BUILTIN.items() if name != 'clean')
    return items


async def run(args):
    items = cases(args.payload_file)
    if args.max_cases:
        items = items[:args.max_cases]
    if len(items) == 1:
        print('No malicious payloads selected: using clean control only.', file=sys.stderr)
    rows = []
    for trial in range(1, args.trials + 1):
        for attack, family in items:
            for mode in args.modes:
                start = time.perf_counter()
                row = dict.fromkeys(FIELDS, '')
                row.update(trial=trial, mode=mode, payload_id=attack,
                           attack_class=family, labeled_attack=(not is_benign_class(family)))
                try:
                    outcome = await run_case(mode, attack, args.payload_file)
                    for key in ('read_executed', 'payload_delivered', 'invalid_grant_blocked', 'store_executed', 'store_decision',
                                'ai_decision', 'replay_executed', 'store_latency_ms'):
                        row[key] = outcome.get(key)
                except Exception as exc:
                    row['error_type'] = type(exc).__name__
                row['session_latency_ms'] = round((time.perf_counter() - start)*1000, 1)
                rows.append(row)
                print(f'trial={trial} mode={mode:10} payload={attack:20} '
                      f'stored={row["store_executed"]!s:5} '
                      f'session={row["session_latency_ms"]:7.1f}ms '
                      f'error={row["error_type"]}', flush=True)
                if row['error_type'] and args.stop_on_error:
                    return rows
    return rows


def summarize(rows):
    print('\n=== ROUND 2 AUTHORIZED CONTENT ABLATION ===')
    for mode in dict.fromkeys(row['mode'] for row in rows):
        data = [row for row in rows if row['mode'] == mode]
        bad = [r for r in data if r['labeled_attack'] and not r['error_type']]
        clean = [r for r in data if not r['labeled_attack'] and not r['error_type']]
        held = sum(r['store_executed'] is False for r in bad)
        benign_blocked = sum(r['store_executed'] is False for r in clean)
        err = sum(bool(r['error_type']) for r in data)
        print(f'{mode:10} attack_content_held={held}/{len(bad)} '
              f'benign_blocked={benign_blocked}/{len(clean)} errors={err}')
    print('CAUTION: All tasks were host-approved; these are content holds, not unauthorized exploit prevention.')
    print('store_latency_ms includes the MCP tool call plus gateway/guard work, not backend setup.')
    print('session_latency_ms includes process startup, MCP transport and any LLM API calls.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--payload-file', help='JSON path; omitted means built-in fixtures')
    p.add_argument('--trials', type=int, default=1)
    p.add_argument('--max-cases', type=int, default=0, help='Limit fixtures for smoke runs')
    p.add_argument('--modes', nargs='+', choices=MODES, default=list(MODES))
    p.add_argument('--stop-on-error', action='store_true')
    args = p.parse_args()
    if args.trials < 1:
        p.error('--trials must be >= 1')
    if args.max_cases < 0:
        p.error('--max-cases must be >= 0')
    rows = asyncio.run(run(args))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    output = ROOT/'results'/f'round2_ablation_{stamp}.csv'
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', newline='', encoding='utf8') as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    summarize(rows)
    print('CSV:', output)
    return int(any(r['error_type'] or r['replay_executed'] is True for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())
