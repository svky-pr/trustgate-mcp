#!/usr/bin/env python3
"""Round 2 unit/regression tests. No MCP SDK, OpenAI API or network needed."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from round2_baseline import PassThroughGateway
from round2_host import host_control, issue_grant
from round2_mode import AuthorizationOnlyGuard, resolve_mode
from round2_payloads import load_payload_file, select_payload, is_benign_class
from step45_authorized_gateway import TrustedGrantIssuer, AuthorizedReferenceGateway


class ModeTests(unittest.TestCase):
    def test_unset_is_legacy_full(self):
        self.assertEqual(resolve_mode({}), 'auth_guard')
        self.assertEqual(resolve_mode({'TG_MODE': ''}), 'auth_guard')

    def test_three_modes(self):
        for value in ('none', 'auth_only', 'auth_guard'):
            self.assertEqual(resolve_mode({'TG_MODE': value}), value)

    def test_invalid_mode_is_error(self):
        with self.assertRaises(ValueError):
            resolve_mode({'TG_MODE': 'disabled'})


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'payloads.json'
        load_payload_file.cache_clear()

    def write(self, entries):
        self.path.write_text(json.dumps({'payloads': entries}), encoding='utf8')
        load_payload_file.cache_clear()

    def test_builtins_unchanged_by_default(self):
        self.assertEqual(select_payload('authority', {'clean': '', 'authority': 'ORIGINAL'}),
                         ('ORIGINAL', 'built_in'))

    def test_uppercase_id_and_class_are_accepted(self):
        self.write([{'id': 'A11.A', 'class': 'Authority Spoofing', 'text': 'PAYLOAD'}])
        self.assertEqual(select_payload('a11.a', {}, str(self.path)),
                         ('PAYLOAD', 'Authority Spoofing'))

    def test_external_id_and_class(self):
        self.write([{'id': 'r2_abc', 'class': 'authority_spoofing', 'text': 'PAYLOAD'}])
        self.assertEqual(select_payload('r2_abc', {'clean': ''}, str(self.path)),
                         ('PAYLOAD', 'authority_spoofing'))

    def test_builtins_still_work_with_file(self):
        self.write([{'id': 'r2_abc', 'class': 'workflow', 'text': 'PAYLOAD'}])
        self.assertEqual(select_payload('clean', {'clean': ''}, str(self.path)), ('', 'built_in'))

    def test_duplicate_ids_fail_closed(self):
        self.write([{'id': 'dup', 'class': 'workflow', 'text': 'A'},
                    {'id': 'dup', 'class': 'workflow', 'text': 'B'}])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            select_payload('dup', {'clean': ''}, str(self.path))

    def test_builtin_collision_rejected(self):
        self.write([{'id': 'clean', 'class': 'workflow', 'text': 'A'}])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            select_payload('clean', {'clean': ''}, str(self.path))

    def test_malformed_json_fails_closed(self):
        self.path.write_text('{invalid', encoding='utf8')
        with self.assertRaises(ValueError):
            select_payload('clean', {'clean': ''}, str(self.path))

    def test_benign_class_labeling(self):
        self.assertTrue(is_benign_class('benign_quote'))
        self.assertTrue(is_benign_class('CONTROL'))
        self.assertFalse(is_benign_class('authority_spoofing'))

    def test_text_is_not_executable_python(self):
        self.write([{'id': 'sample', 'class': 'workflow', 'text': '__import__("os")'}])
        self.assertEqual(select_payload('sample', {}, str(self.path))[0], '__import__("os")')


class FakeSession:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, dict(arguments)))
        if name == 'read_public_notice':
            text = 'Public synthetic notice'
        elif name == 'read_report':
            text = 'CONFIDENTIAL synthetic report'
        elif name == 'store_document':
            text = ('SIMULATED_STORE_OK workspace=' + arguments['workspace']
                    if arguments['workspace'] in ('local', 'external') else 'REJECTED')
        else:
            raise AssertionError(name)
        return SimpleNamespace(isError=False, content=[SimpleNamespace(type='text', text=text)])


class BaselineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = FakeSession()
        self.proxy = PassThroughGateway(self.backend)

    async def test_reference_store_ignores_grant(self):
        read = json.loads(await self.proxy.dispatch('read_public_notice', {}))
        ref = read['data']['document_ref']
        stored = json.loads(await self.proxy.dispatch('store_document_ref', {
            'document_ref': ref, 'workspace': 'external', 'grant_token': 'forged'}))
        self.assertTrue(stored['executed'])
        self.assertEqual(self.backend.calls[-1], ('store_document', {
            'document': 'Public synthetic notice', 'workspace': 'external'}))

    async def test_read_report_is_unrestricted_in_baseline(self):
        result = json.loads(await self.proxy.dispatch('read_report', {}))
        self.assertTrue(result['executed'])

    async def test_protocol_unknown_ref_cannot_store(self):
        result = json.loads(await self.proxy.dispatch('store_document_ref', {
            'document_ref': 'not-mapped', 'workspace': 'external', 'grant_token': 'forged'}))
        self.assertFalse(result['executed'])
        self.assertFalse(any(call[0] == 'store_document' for call in self.backend.calls))


class FakePolicy:
    decision = 'ALLOW'
    classification = 'PUBLIC'


class FakeGateway:
    def __init__(self):
        self.store_calls = 0

    def _resolve_reference(self, ref):
        return 'handle' if ref == 'doc-1' else None

    def evaluate_storage(self, handle, workspace):
        return FakePolicy()

    async def store_ref(self, ref, workspace):
        self.store_calls += 1
        return SimpleNamespace(decision='ALLOW', reason='Simulated', executed=True)


class AuthorizationOnlyTests(unittest.IsolatedAsyncioTestCase):
    async def test_preserves_grants_and_policy_without_llm(self):
        gateway = FakeGateway()
        issuer = TrustedGrantIssuer()
        proxy = AuthorizedReferenceGateway(
            reference_gateway=gateway, ai_guard=AuthorizationOnlyGuard(),
            issuer=issuer, session_id='session')
        async def attempt(token):
            return await proxy.store_ref(document_ref='doc-1', workspace='external',
                                         grant_token=token, user_request='Approved export',
                                         tool_output='Untrusted content')
        self.assertFalse((await attempt('forged')).executed)
        token = issuer.issue(session_id='session', document_ref='doc-1',
                             action='store_document_ref', destination='external')
        self.assertTrue((await attempt(token)).executed)
        self.assertFalse((await attempt(token)).executed)
        self.assertEqual(gateway.store_calls, 1)

    async def test_guard_never_inspects_content(self):
        guard = AuthorizationOnlyGuard()
        result = await guard.assess(tool_output='anything', user_request='any')
        self.assertEqual(result.recommended_action, 'ALLOW')


class HostHelperTests(unittest.IsolatedAsyncioTestCase):
    async def test_grant_helper_roundtrip(self):
        secret = 's' * 48
        async def server(reader, writer):
            line = await reader.readline()
            request = json.loads(line)
            self.assertEqual(request['secret'], secret)
            self.assertEqual(request['operation'], 'issue')
            self.assertEqual(request['destination'], 'external')
            writer.write(b'{"ok": true, "grant_token": "test-token"}\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        listener = await asyncio.start_server(server, '127.0.0.1', 0)
        try:
            port = listener.sockets[0].getsockname()[1]
            self.assertEqual(await issue_grant(port, secret, 'doc-1', 'external'), 'test-token')
        finally:
            listener.close()
            await listener.wait_closed()


if __name__ == '__main__':
    unittest.main(verbosity=2)
