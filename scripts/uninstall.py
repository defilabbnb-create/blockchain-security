#!/usr/bin/env python3
"""Remove only explicitly managed local analysis state.

The default mode is a preview. Destructive removal requires both ``--apply``
and ``--yes``; source code, lock files, reports, tool binaries and credentials
are never part of the default managed set.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys


ROOT = Path(__file__).resolve().parent.parent
MANAGED_PATHS = (
    Path('work/raw'), Path('work/standard'), Path('work/analysis'),
    Path('work/audit'), Path('work/analysis-task-evidence'),
    Path('work/setup-state.json'),
)
TOOL_DEPENDENCY_PATHS = (
    Path('flare-scan/tools/solc-0819/node_modules'),
    Path('flare-scan/tools/solc-0823/node_modules'),
    Path('flare-scan/tools/solc-0828/node_modules'),
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _relative(root, path):
    return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()


def build_plan(root=ROOT, *, include_tool_dependencies=False):
    root = Path(root).resolve()
    paths = list(MANAGED_PATHS)
    if include_tool_dependencies:
        paths.extend(TOOL_DEPENDENCY_PATHS)
    entries = []
    for relative in paths:
        path = root / relative
        entries.append({
            'path': relative.as_posix(), 'exists': path.exists() or path.is_symlink(),
            'kind': ('symlink' if path.is_symlink() else 'directory' if path.is_dir() else 'file' if path.is_file() else 'missing'),
        })
    return {'schemaVersion': 1, 'kind': 'analysis-environment-uninstall', 'state': 'planned', 'createdAt': _now(), 'entries': entries, 'limitations': ['只处理脚本声明的受控路径。', '不会删除源码、报告、toolchain.lock.json、密钥或用户配置。']}


def apply_plan(plan, root=ROOT):
    root = Path(root).resolve()
    result = dict(plan, state='applied', appliedAt=_now(), removed=[])
    for entry in plan['entries']:
        if not entry['exists']:
            continue
        path = root / entry['path']
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        result['removed'].append(entry['path'])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--include-tool-dependencies', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--yes', action='store_true', help='确认删除受控目录')
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args(argv)
    if args.yes and not args.apply:
        parser.error('--yes requires --apply')
    if args.apply and not args.yes:
        parser.error('--apply requires --yes')
    root = args.root.resolve()
    plan = build_plan(root, include_tool_dependencies=args.include_tool_dependencies)
    result = apply_plan(plan, root) if args.apply else plan
    output = args.output or root / 'work' / 'uninstall-state.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'state': result['state'], 'output': _relative(root, output), 'removed': len(result.get('removed', [])), 'candidates': len(result['entries'])}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
