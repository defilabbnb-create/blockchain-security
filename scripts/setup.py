#!/usr/bin/env python3
"""Prepare the local analysis workspace without changing project sources.

The default mode is a dry-run plan. ``--apply`` creates only directories that
are explicitly owned by the analysis pipeline. Dependency installation is
separate and requires ``--install`` so an unavailable optional tool never
blocks the core scanner.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
MANAGED_DIRECTORIES = (
    Path('work/raw'),
    Path('work/standard'),
    Path('work/analysis'),
    Path('work/audit'),
    Path('work/analysis-task-evidence'),
)
NPM_PROJECTS = (
    Path('.'),
    Path('flare-scan/tools/solc-0819'),
    Path('flare-scan/tools/solc-0823'),
    Path('flare-scan/tools/solc-0828'),
)


def _load_module(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _relative(root, path):
    return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()


def build_plan(root=ROOT, *, install=False, offline=False):
    root = Path(root).resolve()
    plan = {
        'schemaVersion': 1,
        'kind': 'analysis-environment-setup',
        'state': 'planned',
        'createdAt': _now(),
        'platform': platform.system(),
        'architecture': platform.machine(),
        'managedDirectories': [_relative(root, root / item) for item in MANAGED_DIRECTORIES],
        'commands': [],
        'optionalFailures': [],
        'limitations': [
            '依赖安装默认关闭；核心扫描不依赖 Docker、PostgreSQL 或 Redis。',
            'setup 不下载反编译器、编译器或模型；工具来源和哈希由 toolchain-lock 管理。',
        ],
    }
    for project in NPM_PROJECTS:
        directory = root / project
        lock = directory / 'package-lock.json'
        manifest = directory / 'package.json'
        if not manifest.is_file():
            continue
        if not lock.is_file():
            plan['optionalFailures'].append({
                'project': project.as_posix(), 'reason': 'package-lock.json missing',
            })
            continue
        command = ['npm', 'ci', '--ignore-scripts']
        if offline:
            command.append('--offline')
        plan['commands'].append({
            'cwd': project.as_posix() or '.', 'command': command,
            'required': project == Path('.'),
            'selected': bool(install),
        })
    return plan


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
            output.write('\n')
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def apply_plan(plan, root=ROOT, *, install=False, runner=subprocess.run):
    root = Path(root).resolve()
    result = dict(plan, state='applied', appliedAt=_now(), createdDirectories=[], commandResults=[])
    for relative in plan['managedDirectories']:
        directory = root / relative
        directory.mkdir(parents=True, exist_ok=True)
        result['createdDirectories'].append(relative)
    if install:
        for item in plan['commands']:
            if not item['selected']:
                continue
            try:
                completed = runner(item['command'], cwd=root / item['cwd'], check=False,
                                   capture_output=True, text=True, timeout=900)
                entry = {
                    **item, 'returncode': completed.returncode,
                    'stdoutTail': (completed.stdout or '')[-1200:],
                    'stderrTail': (completed.stderr or '')[-1200:],
                }
                result['commandResults'].append(entry)
                if completed.returncode != 0:
                    result['state'] = 'partial'
                    result['optionalFailures'].append({
                        'project': item['cwd'], 'reason': 'npm ci failed',
                        'returncode': completed.returncode,
                    })
            except (OSError, subprocess.SubprocessError) as error:
                result['state'] = 'partial'
                result['commandResults'].append({
                    **item, 'returncode': None, 'error': f'{type(error).__name__}: {error}',
                })
                result['optionalFailures'].append({'project': item['cwd'], 'reason': str(error)[:300]})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--apply', action='store_true', help='创建受控工作目录并写入状态')
    parser.add_argument('--install', action='store_true', help='在 --apply 下执行锁定的 npm ci')
    parser.add_argument('--offline', action='store_true', help='为 npm ci 增加 --offline')
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args(argv)
    if args.install and not args.apply:
        parser.error('--install requires --apply')
    root = args.root.resolve()
    plan = build_plan(root, install=args.install, offline=args.offline)
    result = apply_plan(plan, root, install=args.install) if args.apply else plan
    output = args.output or root / 'work' / 'setup-state.json'
    _atomic_json(output, result)
    print(json.dumps({
        'state': result['state'], 'output': _relative(root, output),
        'managedDirectories': len(result['managedDirectories']),
        'commands': len(result['commands']),
        'commandResults': len(result.get('commandResults', [])),
        'optionalFailures': len(result.get('optionalFailures', [])),
    }, ensure_ascii=False))
    return 0 if result['state'] in ('planned', 'applied') else 1


if __name__ == '__main__':
    sys.exit(main())
