#!/usr/bin/env python3
"""External JSON payload corpus loader for the simulated Step58 backend.

This module never evaluates payload text and never alters gateway policy.
Loading is cached per absolute filename so an MCP backend process uses a
consistent snapshot of its corpus for its lifetime.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z')
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TEXT_LENGTH = 256 * 1024


def _safe_id(value, kind: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f'Invalid payload {kind}: expected letters, digits, dots, underscores or hyphens')
    return value.lower()


@lru_cache(maxsize=16)
def load_payload_file(filename: str, built_in_ids: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """Read {"payloads": [{"id", "class", "text"}]} or a list of records.

    External IDs may not replace built-in attacks. Duplicate IDs are rejected.
    A relative path is resolved against the project root, not process cwd.
    """
    root = Path(__file__).resolve().parent
    path = Path(filename).expanduser()
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    if not path.is_file():
        raise ValueError(f'TG_PAYLOAD_FILE is not a readable file: {path}')
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError('TG_PAYLOAD_FILE exceeds 2 MiB limit')
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'Invalid TG_PAYLOAD_FILE JSON: {type(exc).__name__}') from exc
    entries = obj.get('payloads') if isinstance(obj, dict) else obj
    if not isinstance(entries, list):
        raise ValueError('Payload JSON must be an array or an object with payloads array')
    result = {}
    for i, item in enumerate(entries):
        if not isinstance(item, dict) or set(item) != {'id', 'class', 'text'}:
            raise ValueError(f'Payload entry {i} must contain exactly id, class, text')
        ident = _safe_id(item['id'], 'id')
        category = item['class']
        if not isinstance(category, str) or not category.strip() or len(category) > 128:
            raise ValueError(f'Payload {ident} class must be a nonempty string <= 128 characters')
        value = item['text']
        if not isinstance(value, str) or not value or len(value) > _MAX_TEXT_LENGTH:
            raise ValueError(f'Payload {ident} text must be a nonempty string <= 256 KiB')
        if ident in built_in_ids or ident in result:
            raise ValueError(f'Duplicate or built-in payload ID: {ident}')
        result[ident] = {'id': ident, 'class': category, 'text': value}
    return result


def select_payload(attack: str, built_ins: dict[str, str], filename: str | None = None) -> tuple[str, str]:
    """Return (payload text, category); built-ins are unchanged by default."""
    external = load_payload_file(filename, tuple(sorted(built_ins))) if filename else {}
    attack = attack.lower()
    if attack in built_ins:
        return built_ins[attack], 'built_in'
    if attack in external:
        record = external[attack]
        return record['text'], record['class']
    raise ValueError(f'Unknown TG58_ATTACK={attack!r}; available: {list(built_ins) + list(external)}')


def is_benign_class(category: str) -> bool:
    """Explicit fixture-label convention for cross-mode false-positive counts."""
    label = category.strip().lower()
    return label in ('clean', 'control') or label.startswith('benign')
