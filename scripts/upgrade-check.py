#!/usr/bin/env python3
"""Compare the current offline toolchain with the recorded lock file."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent


def _load_lock_module():
    filename = Path(__file__).with_name('toolchain-lock.py')
    spec = importlib.util.spec_from_file_location('toolchain_lock_for_upgrade_check', filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _diff(expected, actual, path='$'):
    if type(expected) is not type(actual):
        return [{'path': path, 'expected': expected, 'actual': actual}]
    if isinstance(expected, dict):
        changes = []
        for key in sorted(set(expected) | set(actual)):
            if key not in expected:
                changes.append({'path': f'{path}.{key}', 'expected': '<missing>', 'actual': actual[key]})
            elif key not in actual:
                changes.append({'path': f'{path}.{key}', 'expected': expected[key], 'actual': '<missing>'})
            else:
                changes.extend(_diff(expected[key], actual[key], f'{path}.{key}'))
        return changes
    if isinstance(expected, list):
        changes = []
        for index in range(max(len(expected), len(actual))):
            if index >= len(expected):
                changes.append({'path': f'{path}[{index}]', 'expected': '<missing>', 'actual': actual[index]})
            elif index >= len(actual):
                changes.append({'path': f'{path}[{index}]', 'expected': expected[index], 'actual': '<missing>'})
            else:
                changes.extend(_diff(expected[index], actual[index], f'{path}[{index}]'))
        return changes
    return [] if expected == actual else [{'path': path, 'expected': expected, 'actual': actual}]


def compare(lock_path, root=ROOT, lock_module=None):
    lock_path = Path(lock_path)
    generated_at = datetime.now(timezone.utc).isoformat()
    result = {
        'schemaVersion': 1, 'kind': 'toolchain-upgrade-check',
        'checkedAt': generated_at, 'lockFile': str(lock_path),
        'state': 'unknown', 'changes': [], 'recommendedActions': [],
    }
    if not lock_path.is_file():
        result.update(state='lock_missing', recommendedActions=['运行 npm run toolchain:lock 生成基线'])
        return result
    try:
        recorded = json.loads(lock_path.read_text(encoding='utf-8'))
        if not isinstance(recorded, dict) or recorded.get('schemaVersion') != 1 or not isinstance(recorded.get('inventory'), dict):
            raise ValueError('invalid toolchain lock structure')
        module = lock_module or _load_lock_module()
        current = module.collect_inventory(root)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        result.update(state='error', error=f'{type(error).__name__}: {str(error)[:500]}')
        return result
    result['changes'] = _diff(recorded['inventory'], current, '$.inventory')
    if result['changes']:
        result['state'] = 'changes_available'
        result['recommendedActions'] = [
            '确认工具来源和哈希后运行 npm run toolchain:lock 更新基线',
            '对编译器、反编译器和静态分析器重新执行定向回归',
        ]
    else:
        result['state'] = 'up_to_date'
    result['currentInventory'] = current
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--lock', type=Path, default=None)
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    result = compare(args.lock or root / 'toolchain.lock.json', root)
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    return 0 if result['state'] == 'up_to_date' else 1


if __name__ == '__main__':
    sys.exit(main())
