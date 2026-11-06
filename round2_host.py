#!/usr/bin/env python3
"""Trusted host helper for Round 2 localhost grant control.

Never expose TG52_HOST_SECRET or this channel as an MCP tool.
The authenticated channel is a local *prototype*, not production authentication.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os


async def host_control(port: int, secret: str, operation: str,
                       *, document_ref: str | None = None,
                       destination: str | None = None) -> dict:
    if not isinstance(secret, str) or len(secret) < 40:
        raise ValueError('TG52_HOST_SECRET must be at least 40 characters')
    if not (1024 <= port <= 65535):
        raise ValueError('Host port must be between 1024 and 65535')
    request = {'secret': secret, 'operation': operation}
    if operation == 'issue':
        if not document_ref or destination not in ('external', 'local'):
            raise ValueError('Grant request requires document_ref and external/local destination')
        request.update(document_ref=document_ref, destination=destination)
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    try:
        writer.write((json.dumps(request) + '\n').encode('utf-8'))
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=8)
        if not raw or len(raw) > 8192:
            raise RuntimeError('Host grant response missing or oversized')
        answer = json.loads(raw.decode('utf-8'))
        if not isinstance(answer, dict):
            raise ValueError('Host grant response must be an object')
        return answer
    finally:
        writer.close()
        await writer.wait_closed()


async def issue_grant(port: int, secret: str, document_ref: str,
                      destination: str) -> str:
    """Called by the TRUSTED host only after it confirms user approval.

    Gateway independently checks trusted request, allowed destination and that
    document_ref came from read_public_notice in the same gateway session.
    Tokens are single-use and bound to session/ref/action/destination.
    """
    answer = await host_control(port, secret, 'issue',
                                document_ref=document_ref, destination=destination)
    if answer.get('ok') is not True or not isinstance(answer.get('grant_token'), str):
        raise PermissionError(answer.get('reason', 'Host grant denied'))
    return answer['grant_token']


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=int(os.getenv('TG52_HOST_PORT', '0')))
    parser.add_argument('--health', action='store_true')
    parser.add_argument('--document-ref')
    parser.add_argument('--destination', choices=('external', 'local'), default='external')
    args = parser.parse_args()
    secret = os.getenv('TG52_HOST_SECRET', '')
    async def run():
        if args.health:
            return await host_control(args.port, secret, 'health')
        if not args.document_ref:
            parser.error('Specify --document-ref or --health')
        # Do not issue a grant unless the trusted host has independently
        # confirmed that this matches the user's approved requested action.
        return await host_control(args.port, secret, 'issue',
                                  document_ref=args.document_ref,
                                  destination=args.destination)
    answer = asyncio.run(run())
    print(json.dumps(answer))
    return 0 if answer.get('ok') is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
