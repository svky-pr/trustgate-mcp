#!/usr/bin/env python3
"""Rename Git-tracked stepNN_* source files without modifying their security logic.

Usage (from a CLEAN non-main branch):
  python rename_step_files.py --preview
  python rename_step_files.py --apply

The preview is read-only. Apply changes only file names and filename/module
references. It deliberately leaves results/, archives/, and frozen tags intact.
"""
from __future__ import annotations

import argparse
import ast
from collections import defaultdict
from pathlib import Path
import re
import subprocess
import sys

PREFIX = re.compile(r'^step(?P<version>\d+[a-z]?)_(?P<body>.+)$', re.I)
SOURCE_EXTS = {'.py', '.json', '.yaml', '.yml', '.toml', '.cfg', '.ini', '.ps1', '.sh', '.bat'}
TEXT_EXTS = SOURCE_EXTS | {'.md', '.txt', '.rst', '.ipynb'}
TEXT_NAMES = {'.env.example', 'Dockerfile', 'Makefile'}
SKIP_PARTS = {'results', 'archive', 'archives', '.git', '.venv', 'venv', '__pycache__', 'node_modules', '.pytest_cache'}


def git(root: Path, *args: str, capture: bool = False) -> str:
    proc = subprocess.run(['git', *args], cwd=root, check=True, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None)
    return proc.stdout.decode('utf-8', errors='replace').strip() if capture else ''


def tracked(root: Path) -> list[Path]:
    raw = subprocess.run(['git', 'ls-files', '-z'], cwd=root, check=True, stdout=subprocess.PIPE).stdout
    items = []
    for x in raw.split(b'\0'):
        if not x:
            continue
        p = Path(x.decode('utf-8', errors='surrogateescape'))
        if any(part.lower() in SKIP_PARTS for part in p.parts):
            continue
        if (root / p).is_file():
            items.append(p)
    return sorted(items, key=lambda x: x.as_posix())


def build_plan(root: Path, paths: list[Path]) -> dict[Path, Path]:
    entries = [(p, PREFIX.fullmatch(p.stem)) for p in paths if p.suffix.lower() in SOURCE_EXTS]
    entries = [(p, m) for p, m in entries if m]
    proposed = defaultdict(list)
    for p, m in entries:
        proposed[(p.parent, m.group('body').lower(), p.suffix.lower())].append(p)
    occupied = {(p.parent, p.name.lower()) for p in paths}
    result = {}
    for p, m in entries:
        suffix = p.suffix
        body = m.group('body')
        candidate = f'{body}{suffix}'
        collision = (len(proposed[(p.parent, body.lower(), suffix.lower())]) > 1 or
                     (p.parent, candidate.lower()) in occupied or
                     (root / p.parent / candidate).exists())
        if collision:
            candidate = f'{body}_v{m.group("version")}{suffix}'
        if (p.parent, candidate.lower()) in occupied or (root / p.parent / candidate).exists():
            raise RuntimeError(f'Cannot safely rename {p}: destination {candidate} is occupied')
        occupied.add((p.parent, candidate.lower()))
        result[p] = p.with_name(candidate)
    return result


def build_reference_map(plan: dict[Path, Path]) -> dict[str, str]:
    replacements = {}
    for old, new in plan.items():
        for a, b in ((old.as_posix(), new.as_posix()), (old.name, new.name),
                     (old.stem, new.stem) if old.suffix.lower()=='.py' else ('', '')):
            if not a:
                continue
            if a in replacements and replacements[a] != b:
                raise RuntimeError(f'Ambiguous reference to {a}: {replacements[a]} vs {b}')
            replacements[a] = b
    return replacements


def rewrite(content: str, refs: dict[str, str]) -> str:
    if not refs:
        return content
    # Avoid replacing the first part of a longer identifier or historical filename.
    pat = re.compile(r'(?<![A-Za-z0-9_])(?:' + '|'.join(re.escape(k) for k in sorted(refs, key=len, reverse=True)) + r')(?![A-Za-z0-9_])')
    return pat.sub(lambda match: refs[match.group(0)], content)


def prepare_edits(root: Path, paths: list[Path], refs: dict[str, str]):
    edits = {}
    for p in paths:
        if p.suffix.lower() not in TEXT_EXTS and p.name not in TEXT_NAMES:
            continue
        raw = (root / p).read_bytes()
        if b'\x00' in raw:
            continue
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            continue
        updated = rewrite(text, refs)
        if updated == text:
            continue
        if p.suffix.lower() == '.py':
            ast.parse(updated, filename=str(p))
        # Preserve newline conventions and original UTF-8 BOM if present.
        edits[p] = (updated.encode('utf-8-sig') if raw.startswith(b'\xef\xbb\xbf') else updated.encode('utf-8'))
    return edits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--preview', action='store_true')
    mode.add_argument('--apply', action='store_true')
    ap.add_argument('--root', type=Path, default=Path('.'))
    args = ap.parse_args()
    root = args.root.resolve()
    try:
        git(root, 'rev-parse', '--show-toplevel', capture=True)
        paths = tracked(root)
        plan = build_plan(root, paths)
        refs = build_reference_map(plan)
        edits = prepare_edits(root, paths, refs)
        print(f'Repository: {root}')
        print(f'Tracked filenames to rename: {len(plan)}')
        print(f'Text files requiring reference updates: {len(edits)}')
        print('\nProposed names:')
        for old, new in plan.items():
            print(f'  {old.as_posix()}  ->  {new.as_posix()}')
        if args.preview:
            print('\nPREVIEW ONLY: no files changed.')
            return 0
        branch = git(root, 'branch', '--show-current', capture=True)
        if branch in {'', 'main', 'master'} or branch.startswith('round2-freeze'):
            raise RuntimeError(f'Refusing changes on branch {branch!r}. Create a dedicated cleanup branch.')
        if git(root, 'status', '--porcelain', '--untracked-files=no', capture=True):
            raise RuntimeError('Tracked working tree/index is not clean. Commit or stash changes first.')
        for old, new in plan.items():
            git(root, 'mv', '--', old.as_posix(), new.as_posix())
        for old, contents in edits.items():
            target = root / plan.get(old, old)
            target.write_bytes(contents)
        print('\nAPPLIED. Review git diff, compile, and run all regressions before committing.')
        print('Frozen tags and historical results/ were not modified.')
        print('If anything fails, stop and share the error; do not push to main.')
        return 0
    except (subprocess.CalledProcessError, OSError, SyntaxError, RuntimeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
