#!/usr/bin/env python3
"""Step 45: session-bound explicit authorization at the gateway execution boundary.

Application code (not an agent or MCP document) creates grants using TrustedGrantIssuer.
The gateway verifies a single-use grant before invoking the GenAI guard or storing.
Existing ReferenceGateway.store_ref is the only execution path used by this wrapper.
No network calls or storage operations occur when running this file's self-tests.

IMPORTANT: This is a prototype API. Production code must authenticate the grant issuer,
keep the issuer out of agent-visible tools, and protect the execution boundary against
alternative calls directly to the underlying MCP client.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuthorizedDecision:
    decision: str
    reason: str
    executed: bool = False
    policy_decision: str = 'NOT_EVALUATED'
    ai_decision: str = 'NOT_EVALUATED'


@dataclass
class _GrantRecord:
    session_id: str
    document_ref: str
    action: str
    destination: str
    consumed: bool = False


class TrustedGrantIssuer:
    """Application-owned grant registry. Never expose issue() as an MCP/agent tool.

    A grant binds to a specific gateway session, document reference, action and
    destination. Tokens are random, unguessable, single-use bearer capabilities.
    """

    def __init__(self):
        self._records: dict[str, _GrantRecord] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    def issue(self, *, session_id: str, document_ref: str,
              action: str, destination: str) -> str:
        if not all(isinstance(v, str) and v for v in
                   (session_id, document_ref, action, destination)):
            raise ValueError('Grant fields must be nonempty strings')
        if action != 'store_document_ref' or destination not in ('local', 'external'):
            raise ValueError('Unsupported grant scope')
        token = secrets.token_urlsafe(32)
        self._records[self._key(token)] = _GrantRecord(
            session_id, document_ref, action, destination)
        return token

    async def consume(self, *, token: str, session_id: str,
                      document_ref: str, action: str, destination: str) -> bool:
        if not isinstance(token, str) or not token:
            return False
        async with self._lock:
            record = self._records.get(self._key(token))
            if record is None or record.consumed:
                return False
            # Do not consume on a mismatch, so a malicious caller cannot burn
            # someone else's grant merely by submitting a wrong destination.
            matched = (hmac.compare_digest(record.session_id, session_id)
                       and hmac.compare_digest(record.document_ref, document_ref)
                       and hmac.compare_digest(record.action, action)
                       and hmac.compare_digest(record.destination, destination))
            if matched:
                record.consumed = True  # reserve BEFORE any await to avoid replay
            return matched


class AuthorizedReferenceGateway:
    """Execution gate: trusted grant AND policy AND GenAI must all allow.

    reference_gateway must expose _resolve_reference(), evaluate_storage(),
    and async store_ref(). ai_guard must expose async assess().
    """

    def __init__(self, *, reference_gateway: Any, ai_guard: Any,
                 issuer: TrustedGrantIssuer, session_id: str):
        self._gateway = reference_gateway
        self._guard = ai_guard
        self._issuer = issuer
        self._session_id = session_id

    async def store_ref(self, *, document_ref: str, workspace: str,
                        grant_token: str, user_request: str,
                        tool_output: str) -> AuthorizedDecision:
        if not await self._issuer.consume(
            token=grant_token, session_id=self._session_id,
            document_ref=document_ref, action='store_document_ref',
            destination=workspace):
            return AuthorizedDecision('BLOCK', 'Missing, mismatched, or reused trusted grant')

        handle = self._gateway._resolve_reference(document_ref)
        if handle is None:
            return AuthorizedDecision('BLOCK', 'Invalid document reference')

        try:
            policy = self._gateway.evaluate_storage(handle, workspace)
            policy_decision = policy.decision
        except Exception as exc:
            return AuthorizedDecision('BLOCK', f'Policy evaluation error: {type(exc).__name__}')
        if policy_decision != 'ALLOW':
            return AuthorizedDecision('BLOCK', 'Deterministic policy denied',
                                      policy_decision=policy_decision)

        try:
            assessment = await self._guard.assess(
                user_request=user_request,
                tool_output=tool_output,
                proposed_tool='store_document_ref',
                proposed_arguments={'document_ref': document_ref,
                                    'workspace': workspace},
                classification=policy.classification)
            ai_decision = assessment.recommended_action
        except Exception as exc:
            return AuthorizedDecision('BLOCK', f'GenAI guard error: {type(exc).__name__}',
                                      policy_decision=policy_decision)
        if ai_decision != 'ALLOW':
            return AuthorizedDecision('BLOCK', 'GenAI guard did not authorize',
                                      policy_decision=policy_decision,
                                      ai_decision=ai_decision)

        # Only reached when all three independent gates have passed.
        try:
            outcome = await self._gateway.store_ref(document_ref, workspace)
        except Exception as exc:
            return AuthorizedDecision('BLOCK', f'Storage call failed: {type(exc).__name__}',
                                      policy_decision=policy_decision,
                                      ai_decision=ai_decision)
        return AuthorizedDecision(outcome.decision, outcome.reason,
                                  bool(outcome.executed), policy_decision, ai_decision)


# Deterministic tests using fake dependencies: safe, fast, and API-free.
class _Policy:
    def __init__(self, decision):
        self.decision = decision
        self.classification = 'PUBLIC'


class _Assessment:
    def __init__(self, decision):
        self.recommended_action = decision


class _FakeGuard:
    def __init__(self, decision='ALLOW'):
        self.decision = decision
        self.calls = 0

    async def assess(self, **kwargs):
        self.calls += 1
        return _Assessment(self.decision)


class _FakeGateway:
    def __init__(self, policy='ALLOW'):
        self.policy = policy
        self.stores = 0

    def _resolve_reference(self, ref):
        return 'internal_handle' if ref == 'doc-1' else None

    def evaluate_storage(self, handle, workspace):
        return _Policy(self.policy)

    async def store_ref(self, ref, workspace):
        self.stores += 1
        return AuthorizedDecision('ALLOW', 'Simulated store', True)


async def self_test():
    issuer = TrustedGrantIssuer()
    backend = _FakeGateway()
    guard = _FakeGuard()
    gate = AuthorizedReferenceGateway(reference_gateway=backend, ai_guard=guard,
                                      issuer=issuer, session_id='session-A')
    async def attempt(token, destination='external'):
        return await gate.store_ref(document_ref='doc-1', workspace=destination,
                                    grant_token=token, user_request='Test request',
                                    tool_output='Untrusted document')

    checks = []
    checks.append(('no grant', (await attempt('')).decision == 'BLOCK'))
    t = issuer.issue(session_id='session-A', document_ref='doc-1',
                     action='store_document_ref', destination='external')
    checks.append(('wrong destination', (await attempt(t, 'local')).decision == 'BLOCK'))
    checks.append(('valid grant executes', (await attempt(t)).executed))
    checks.append(('replay blocked', (await attempt(t)).decision == 'BLOCK'))
    checks.append(('single execution', backend.stores == 1))

    other = AuthorizedReferenceGateway(reference_gateway=backend, ai_guard=guard,
                                       issuer=issuer, session_id='session-B')
    t = issuer.issue(session_id='session-A', document_ref='doc-1',
                     action='store_document_ref', destination='external')
    result = await other.store_ref(document_ref='doc-1', workspace='external',
                                   grant_token=t, user_request='Test', tool_output='')
    checks.append(('cross-session blocked', result.decision == 'BLOCK'))

    backend.policy = 'BLOCK'
    checks.append(('policy blocks', (await attempt(t)).decision == 'BLOCK'))
    backend.policy = 'ALLOW'
    guard.decision = 'BLOCK'
    t = issuer.issue(session_id='session-A', document_ref='doc-1',
                     action='store_document_ref', destination='external')
    checks.append(('AI blocks', (await attempt(t)).decision == 'BLOCK'))
    guard.decision = 'ALLOW'
    checks.append(('no extra executions', backend.stores == 1))

    print('=== STEP 45 AUTHORIZED GATEWAY SELF-TEST ===')
    for label, passed in checks:
        print(f'{label:27s} {"PASS" if passed else "FAIL"}')
    print(f'Result: {sum(ok for _, ok in checks)}/{len(checks)} passed')
    print('Simulated storage calls:', backend.stores)
    if not all(ok for _, ok in checks):
        raise SystemExit(1)


if __name__ == '__main__':
    asyncio.run(self_test())
