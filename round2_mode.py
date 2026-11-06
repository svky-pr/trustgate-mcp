#!/usr/bin/env python3
"""Round 2 gateway mode selection, independent of MCP imports.

Unset TG_MODE intentionally preserves the existing Step63 hybrid configuration.
The legacy numbered experiment modules do not read this setting.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

MODES = ('none', 'auth_only', 'auth_guard')


def resolve_mode(environ=None) -> str:
    env = os.environ if environ is None else environ
    raw = env.get('TG_MODE')
    if raw is None or raw == '':
        return 'auth_guard'
    if raw not in MODES:
        raise ValueError(f'Invalid TG_MODE={raw!r}; expected one of {", ".join(MODES)}')
    return raw


class AuthorizationOnlyGuard:
    """Step67 authorization_only equivalent: no content or model inspection.

    The *existing* Step45 authorization boundary still verifies and consumes
    trusted host grants and checks provenance and deterministic policy first.
    """

    async def assess(self, **_ignored):
        return SimpleNamespace(recommended_action='ALLOW')
