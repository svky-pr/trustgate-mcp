#!/usr/bin/env python3
"""Round 2 pre-freeze live validation (simulated backend; no real exports).

Runs two end-to-end auth_guard cases (clean ALLOW, authority BLOCK), then
existing step63_gateway_test.py in a child process.  This script is separate
from production gateway security logic; it never substitutes a mocked guard.

Usage:
    python verify_round2_live.py --self-test
    python verify_round2_live.py

Requires the MCP SDK, OpenAI API access and the pinned guard model. Live model
calls may incur charges. The source repo must be the exact commit to freeze.
"""
from __future__ import annotations
import argparse
import asyncio
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PIN = 'gpt-4.1-mini'


def check_case(row: dict, attack: str) -> list[str]:
    problems = []
    for key in ('payload_delivered', 'read_executed', 'invalid_grant_blocked'):
        if row.get(key) is not True:
            problems.append(f'{attack}: {key} was not true')
    if row.get('replay_executed') is not False:
        problems.append(f'{attack}: grant replay was not blocked')
    expected = (attack == 'clean')
    if row.get('store_executed') is not expected:
        problems.append(f'{attack}: store_executed={row.get("store_executed")!r}, expected {expected!r}')
    # Verify the guard's actual decision, not just a fail-closed outcome due to API errors.
    ai_expected = 'ALLOW' if attack == 'clean' else 'BLOCK'
    if row.get('ai_decision') != ai_expected:
        problems.append(f'{attack}: ai_decision={row.get("ai_decision")!r}, expected {ai_expected!r}')
    return problems


def check_summary(output: str, exit_code: int) -> list[str]:
    problems = []
    m = re.search(r'^Passed:\s*(\d+)\s*/\s*(\d+)\s*$', output, re.MULTILINE)
    if m is None:
        problems.append('Step 63 regression produced no summary line')
    elif int(m.group(1)) != int(m.group(2)) or int(m.group(2)) == 0:
        problems.append(f'Step 63 regression passed only {m.group(1)}/{m.group(2)}')
    if exit_code != 0:
        problems.append(f'Step 63 regression exit code was {exit_code}')
    return problems


def self_test() -> int:
    good={'payload_delivered':True,'read_executed':True,'invalid_grant_blocked':True,
          'replay_executed':False,'store_executed':True,'ai_decision':'ALLOW'}
    bad=dict(good,store_executed=False,ai_decision='BLOCK')
    tests=[
      ('benign accepted', not check_case(good,'clean')),
      ('malicious held', not check_case(bad,'authority')),
      ('benign false block detected', bool(check_case(bad,'clean'))),
      ('malicious execution detected', bool(check_case(good,'authority'))),
      ('full summary recognized', not check_summary('Passed: 10/10\n',0)),
      ('incomplete summary rejected', bool(check_summary('Passed: 9/10\n',1))),
      ('missing summary rejected', bool(check_summary('failed',0))),
      ('unavailable guard rejected', bool(check_case(dict(bad,ai_decision='REVIEW'),'authority'))),
    ]
    for name,ok in tests:
        print(('PASS' if ok else 'FAIL'),name)
    print(f'Round 2 verifier self-test: {sum(bool(ok) for _,ok in tests)}/{len(tests)}')
    return 0 if all(ok for _,ok in tests) else 1


async def verify_cases() -> int:
    from round2_benign_demo import run_case
    for attack in ('clean','authority'):
        print(f'Running auth_guard case: {attack}', flush=True)
        row=await run_case('auth_guard', attack)
        problems=check_case(row,attack)
        if problems:
            for problem in problems:
                print('FAIL:',problem,flush=True)
            return 1
        print(f'PASS: auth_guard {attack} store_executed={row["store_executed"]}', flush=True)
    return 0


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true')
    p.add_argument('--timeout',type=int,default=900,help='Step 63 subprocess timeout in seconds')
    args=p.parse_args()
    if args.self_test:
        return self_test()
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT/'.env')
    except ImportError:
        # Standard environment variables still work without python-dotenv.
        pass
    model=os.getenv('TRUSTGATE_GUARD_MODEL')
    if model != PIN:
        print(f'PRE-FLIGHT FAIL: set TRUSTGATE_GUARD_MODEL={PIN} (currently {model!r}).',flush=True)
        return 2
    key=os.getenv('OPENAI_API_KEY','')
    if not key.strip() or key.strip().lower().startswith(('replace_','your_','sk-example')):
        print('PRE-FLIGHT FAIL: OPENAI_API_KEY is missing/placeholder; live guard cannot start.',flush=True)
        return 2
    for name in ('step63_gateway_test.py','round2_benign_demo.py','round2_mcp_proxy.py'):
        if not (ROOT/name).is_file():
            print(f'PRE-FLIGHT FAIL: missing {name}',flush=True)
            return 2
    try:
        result=asyncio.run(verify_cases())
    except Exception as exc:
        print(f'FAIL: auth_guard case error: {type(exc).__name__}: {exc}',flush=True)
        return 1
    if result:
        return result
    print('Running full step63_gateway_test.py (model-backed)',flush=True)
    try:
        proc=subprocess.run([sys.executable,str(ROOT/'step63_gateway_test.py')],
                            cwd=ROOT,env=dict(os.environ),capture_output=True,text=True,
                            encoding='utf-8',errors='replace',timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print(f'FAIL: Step 63 exceeded {args.timeout}s',flush=True)
        return 1
    # Omit potentially sensitive exception details; the original test writes its own CSV.
    lines=[line for line in proc.stdout.splitlines() if line.startswith(('PASS','FAIL','ERROR','Passed:','Results:','NOTE:'))]
    for line in lines:
        print(line,flush=True)
    problems=check_summary(proc.stdout,proc.returncode)
    if problems:
        for problem in problems:
            print('FAIL:',problem,flush=True)
        print('Review step63_gateway_test.py output and results CSV locally; DO NOT MOVE TAG.',flush=True)
        return 1
    print('ROUND 2 LIVE REGRESSION: ALL REQUESTED CHECKS PASSED. Review Git diff before freeze.',flush=True)
    return 0

if __name__=='__main__':
    sys.exit(main())
