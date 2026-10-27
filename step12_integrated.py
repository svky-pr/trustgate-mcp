"""Step 12: deterministic, end-to-end MCP authorization evaluation.
Run from the TrustGate-MCP project directory: python step12_integrated.py
Requires Step 11 intent_guard.py with IntentPolicy support.
No LLM or external data transfer is used; server.py's store_document is simulated.
"""
import asyncio
import csv
import sys
from pathlib import Path
from datetime import datetime, timezone

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from intent import get_demo_intent
from tracker import ActivityTracker
from guard import TrustGateGuard
from provenance import ProvenanceMiddleware
from taint import TaintState
from intent_guard import IntentGuard, IntentPolicy

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'results'
OUT.mkdir(exist_ok=True)


def policy(actions, workspaces=(), confidential_export=False):
    return IntentPolicy(
        allowed_actions=frozenset(actions),
        storage_workspaces=frozenset(workspaces),
        allow_confidential_external=confidential_export,
    )

READ_ONLY = policy(('read_report', 'summarize_report'))
PUBLIC_EXPORT = policy(('read_report', 'read_public_notice', 'summarize_report', 'store_document'), ('local', 'external'))
LOCAL_STORAGE = policy(('read_report', 'store_document'), ('local',))
CONFIDENTIAL_EXPORT = policy(('read_report', 'store_document'), ('external',), True)

CASES = [
    ('confidential_readonly_external', 'confidential', READ_ONLY, 'external', 'BLOCK'),
    ('verified_public_export', 'public', PUBLIC_EXPORT, 'external', 'ALLOW'),
    ('confidential_under_public_policy', 'confidential', PUBLIC_EXPORT, 'external', 'BLOCK'),
    ('confidential_local_storage', 'confidential', LOCAL_STORAGE, 'local', 'ALLOW'),
    ('unverified_public_export', 'unknown', PUBLIC_EXPORT, 'external', 'CONFIRM'),
    ('explicit_confidential_export', 'confidential', CONFIDENTIAL_EXPORT, 'external', 'ALLOW'),
    ('same_public_data_readonly', 'public', READ_ONLY, 'external', 'BLOCK'),
]


def extract_text(result):
    return '\n'.join(item.text for item in result.content if getattr(item, 'type', None) == 'text')


async def mcp_call(session, tool, arguments):
    result = await session.call_tool(tool, arguments=arguments)
    if result.isError:
        raise RuntimeError(f'MCP {tool} returned an error: {extract_text(result)}')
    return extract_text(result)


async def run_case(session, available_tools, name, kind, selected_policy, workspace, expected):
    tracker = ActivityTracker(get_demo_intent())
    provenance = ProvenanceMiddleware(tracker)
    taint = TaintState()
    intent_guard = IntentGuard(selected_policy)
    # Kept to expose compatibility with the earlier guard, not used as the
    # final authority: it has a static intent and an unknown-provenance hold.
    old_guard = TrustGateGuard(tracker)

    if kind == 'confidential':
        tool = 'read_report'
        document = await mcp_call(session, tool, {})
        data_id = provenance.observe_result(tool, {}, document)
        taint.observe_access(tool, 'confidential', success=True)
    elif kind == 'public':
        tool = 'read_public_notice'
        document = await mcp_call(session, tool, {})
        data_id = provenance.observe_result(tool, {}, document)
    else:
        document = 'Unverified content created outside the trusted MCP provenance chain.'
        data_id = None

    diagnostic = provenance.diagnose(document)
    matched_id = diagnostic.get('data_id')
    classification = tracker.get_classification(matched_id) if matched_id is not None else None
    verified = bool(diagnostic.get('exact_match')) and matched_id is not None

    # Fail closed if a tool result was expected to be registered but wasn't.
    if kind in ('public', 'confidential'):
        assert data_id is not None, f'{tool} did not register a provenance ID'
        assert verified, f'{tool} output did not resolve to a verified fingerprint'
        assert classification == kind, (
            f'{tool} classified as {classification!r}; expected {kind!r}'
        )
    elif verified:
        raise AssertionError('Unknown-data fixture unexpectedly matched registered content')

    arguments = {'document': document, 'workspace': workspace}
    intent_result = intent_guard.evaluate(
        'store_document', arguments, classification=classification or 'unknown'
    )
    taint_result = taint.assess_transfer(classification, workspace)
    legacy = old_guard.evaluate('store_document', arguments, data_id=matched_id)

    # Composition: trusted intent authorization is mandatory; verified public
    # and explicitly authorized confidential exports may proceed. Unknown
    # provenance can never be exported automatically. Local storage can be
    # authorized by the trusted policy even if the old guard says CONFIRM.
    decision = intent_result.decision
    if workspace != 'local' and not verified and decision == 'ALLOW':
        decision = 'CONFIRM'
    if workspace != 'local' and classification == 'confidential' and not selected_policy.allow_confidential_external:
        decision = 'BLOCK'

    executed = False
    if decision == 'ALLOW':
        if 'store_document' not in available_tools:
            raise RuntimeError('MCP server does not expose store_document')
        await mcp_call(session, 'store_document', arguments)
        executed = True

    passed = decision == expected and executed == (expected == 'ALLOW')
    print(f"{'PASS' if passed else 'FAIL'} {name}: expected={expected} actual={decision} "
          f'classification={classification or "unknown"} verified={verified} executed={executed}')
    return {
        'scenario': name,
        'data_kind': kind,
        'workspace': workspace,
        'expected': expected,
        'decision': decision,
        'intent_decision': intent_result.decision,
        'intent_violation': intent_result.violation,
        'legacy_guard_decision': legacy.decision,
        'taint_risk': taint_result['risk'],
        'provenance_verified': verified,
        'classification': classification or 'unknown',
        'executed': executed,
        'passed': passed,
    }


async def main():
    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / 'server.py')])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {tool.name for tool in (await session.list_tools()).tools}
            required = {'read_report', 'read_public_notice', 'store_document'}
            missing = required - tools
            if missing:
                raise RuntimeError(f'MCP server missing required tools: {sorted(missing)}')
            rows = []
            for case in CASES:
                rows.append(await run_case(session, tools, *case))

    # The same verified public data is tested under two distinct trusted
    # policies; only authorization differs.
    public_allowed = next(r for r in rows if r['scenario'] == 'verified_public_export')
    public_denied = next(r for r in rows if r['scenario'] == 'same_public_data_readonly')
    differential_passed = (public_allowed['decision'], public_denied['decision']) == ('ALLOW', 'BLOCK')
    print(f"{'PASS' if differential_passed else 'FAIL'} public_export_intent_differential")

    filename = OUT / f'step12_integrated_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.csv'
    with filename.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    passed = sum(r['passed'] for r in rows)
    print(f'\nSTEP 12 RESULTS: {passed}/{len(rows)} scenarios passed; '
          f'intent differential={differential_passed}')
    print(f'CSV: {filename}')
    assert passed == len(rows) and differential_passed, 'Integrated evaluation failed'


if __name__ == '__main__':
    asyncio.run(main())
