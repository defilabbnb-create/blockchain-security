#!/usr/bin/env python3
"""Record and verify the installed local analysis toolchain without network access."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOLC_DIRS = ('solc-0819', 'solc-0823', 'solc-0828')
HEIMDALL_RELEASE_TAG = '0.9.3'
HEIMDALL_RELEASE_URL = 'https://github.com/Jon-Becker/heimdall-rs/releases/tag/0.9.3'
HEIMDALL_RELEASE_ASSETS = {
    ('Darwin', 'arm64'): {
        'name': 'heimdall-macos-arm64',
        'sha256': 'c279e92aa5a2178cb6327861f206eddee5d53209bb19a863915159b844cc0d23',
    },
    ('Darwin', 'x86_64'): {
        'name': 'heimdall-macos-amd64',
        'sha256': '5fd05a7ef935896592a81c99db031e887369897d482c408eb86ccdd53310be53',
    },
    ('Linux', 'x86_64'): {
        'name': 'heimdall-linux-amd64',
        'sha256': '8d58c97f56d584d5d0737d0d0895fc8c68b7b8b2b680f2a7842245789f0b4868',
    },
    ('Linux', 'aarch64'): {
        'name': 'heimdall-linux-arm64',
        'sha256': 'ef1d236e5e194e1722e12552b66303d3172e0c4cc267b096f7bc8a053f168df8',
    },
}


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def relative_path(root, path):
    path = Path(path).resolve()
    try:
        return path.relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return str(path)


def installation_record():
    return {'installedAt': None, 'installationTimeStatus': 'unknown_existing_install'}


def npm_package_name(lock_key, entry):
    if entry.get('name'):
        return entry['name']
    parts = lock_key.split('/')
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] != 'node_modules' or index + 1 >= len(parts):
            continue
        if parts[index + 1].startswith('@') and index + 2 < len(parts):
            return parts[index + 1] + '/' + parts[index + 2]
        return parts[index + 1]
    return lock_key


def npm_lock_snapshot(root, lock_path):
    root = Path(root)
    lock_path = Path(lock_path)
    relative_lock = relative_path(root, lock_path)
    manifest_path = lock_path.parent / 'package.json'
    result = {
        'available': lock_path.is_file(),
        'lockPath': relative_lock,
        'manifestPath': relative_path(root, manifest_path),
        'lockSha256': None,
        'manifestSha256': file_sha256(manifest_path) if manifest_path.is_file() else None,
        'manifestMissing': not manifest_path.is_file(),
        'packages': [],
        **installation_record(),
    }
    if not lock_path.is_file():
        result['reason'] = 'missing_lock'
        return result
    try:
        lock = json.loads(lock_path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f'invalid npm lock {relative_lock}: {type(error).__name__}')
    if not isinstance(lock, dict) or not isinstance(lock.get('packages'), dict):
        raise ValueError(f'invalid npm lock structure: {relative_lock}')
    result['lockSha256'] = file_sha256(lock_path)
    for key, item in lock['packages'].items():
        if not key:
            continue
        if not isinstance(item, dict):
            raise ValueError(f'invalid npm package entry: {key}')
        result['packages'].append({
            'name': npm_package_name(key, item),
            'lockKey': key,
            'version': item.get('version'),
            'resolved': item.get('resolved'),
            'integrity': item.get('integrity'),
            **installation_record(),
        })
    result['packages'].sort(key=lambda item: (item['name'], item['version'] or '', item['lockKey']))

    solc_lock = next((item for item in result['packages'] if item['name'] == 'solc'), None)
    installed_package = lock_path.parent / 'node_modules' / 'solc' / 'package.json'
    installed = {
        'available': installed_package.is_file(),
        'version': None,
        'matchesLock': None,
        'soljsonSha256': None,
        **installation_record(),
    }
    if installed_package.is_file():
        try:
            package = json.loads(installed_package.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(f'invalid installed solc metadata: {relative_path(root, installed_package)}') from error
        installed['version'] = package.get('version')
        installed['matchesLock'] = bool(solc_lock and installed['version'] == solc_lock['version'])
        soljson = installed_package.parent / 'soljson.js'
        if soljson.is_file():
            installed['soljsonSha256'] = file_sha256(soljson)
    result['installedSolc'] = installed
    return result


def command_version(executable, args):
    try:
        result = subprocess.run(
            [str(executable), *args], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def executable_snapshot(name, args):
    executable = shutil.which(name)
    return {
        'available': executable is not None,
        'path': str(Path(executable).resolve()) if executable else None,
        'version': command_version(executable, args) if executable else None,
        **installation_record(),
    }


def python_distribution_inventory(site_path):
    site_path = Path(site_path)
    if not site_path.is_dir():
        return {'available': False, 'path': relative_path(ROOT, site_path), 'distributions': []}
    distributions = []
    for distribution in importlib.metadata.distributions(path=[str(site_path)]):
        name = distribution.metadata.get('Name') or 'unknown'
        record_path = None
        for item in distribution.files or ():
            if str(item).endswith('.dist-info/RECORD'):
                candidate = Path(distribution.locate_file(item))
                if candidate.is_file():
                    record_path = candidate
                    break
        direct_url = None
        direct_url_status = 'unknown'
        try:
            direct_text = distribution.read_text('direct_url.json')
            if direct_text:
                direct_url = json.loads(direct_text)
                direct_url_status = 'recorded'
        except (OSError, UnicodeError, json.JSONDecodeError):
            direct_url_status = 'unreadable'
        distributions.append({
            'name': name,
            'version': distribution.version,
            'recordSha256': file_sha256(record_path) if record_path else None,
            'recordStatus': 'recorded' if record_path else 'missing',
            'directUrl': direct_url,
            'sourceStatus': direct_url_status,
            **installation_record(),
        })
    distributions.sort(key=lambda item: (item['name'].lower().replace('_', '-'), item['version']))
    return {
        'available': True,
        'path': relative_path(ROOT, site_path),
        'distributionCount': len(distributions),
        'distributions': distributions,
    }


def foundry_snapshot(root):
    binary = Path(root) / 'work/tools/forge'
    result = {
        'available': binary.is_file(),
        'path': relative_path(root, binary) if binary.is_file() else None,
        'version': command_version(binary, ['--version']) if binary.is_file() else None,
        'sha256': file_sha256(binary) if binary.is_file() else None,
        'sourceStatus': 'unknown_existing_install' if binary.is_file() else 'unavailable',
        **installation_record(),
    }
    return result


def heimdall_snapshot(root):
    binary = Path(root) / 'work/tools/heimdall/heimdall'
    available = binary.is_file()
    version = command_version(binary, ['--version']) if available else None
    digest = file_sha256(binary) if available else None
    asset = HEIMDALL_RELEASE_ASSETS.get((platform.system(), platform.machine()))
    reported_version = version.split()[-1] if version else None
    verified = digest == asset['sha256'] if digest and asset else None
    if not available:
        source_status = 'unavailable'
    elif verified is True:
        source_status = 'official_release_asset_hash_match'
    elif verified is False:
        source_status = 'official_release_asset_hash_mismatch'
    else:
        source_status = 'unsupported_platform_hash_unavailable'
    return {
        'available': available,
        'path': relative_path(root, binary) if available else None,
        'version': version,
        'sha256': digest,
        'releaseTag': HEIMDALL_RELEASE_TAG,
        'releaseUrl': HEIMDALL_RELEASE_URL,
        'expectedAsset': asset['name'] if asset else None,
        'expectedSha256': asset['sha256'] if asset else None,
        'verifiedReleaseAsset': verified,
        'releaseTagVersionMismatch': (reported_version != HEIMDALL_RELEASE_TAG
                                      if reported_version else None),
        'sourceStatus': source_status,
        **installation_record(),
    }


def collect_inventory(root=ROOT):
    root = Path(root).resolve()
    npm_locks = [root / 'package-lock.json'] + [
        root / 'flare-scan/tools' / name / 'package-lock.json' for name in SOLC_DIRS
    ]
    return {
        'platform': platform.system(),
        'architecture': platform.machine(),
        'node': executable_snapshot('node', ['--version']),
        'npm': executable_snapshot('npm', ['--version']),
        'python': {
            'available': True,
            'path': str(Path(sys.executable).resolve()),
            'version': platform.python_version(),
            **installation_record(),
        },
        'npmLockfiles': [npm_lock_snapshot(root, path) for path in npm_locks],
        'pythonDistributions': python_distribution_inventory(root / 'flare-scan/tools/pylibs'),
        'foundry': foundry_snapshot(root),
        'heimdall': heimdall_snapshot(root),
    }


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', dir=path.parent, delete=False,
        ) as output:
            temporary = Path(output.name)
            json.dump(data, output, ensure_ascii=False, indent=2, sort_keys=True)
            output.write('\n')
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'toolchain.lock.json')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    try:
        inventory = collect_inventory()
        if args.check:
            if not args.output.is_file():
                print(json.dumps({'matches': False, 'lockFile': str(args.output), 'reason': 'missing_lock'}))
                return 1
            existing = json.loads(args.output.read_text(encoding='utf-8'))
            comparable = ({key: value for key, value in existing.items() if key != 'observedAt'}
                          if isinstance(existing, dict) else None)
            matches = comparable == {'schemaVersion': 1, 'inventory': inventory}
            print(json.dumps({'matches': bool(matches), 'lockFile': str(args.output)}))
            return 0 if matches else 1
        snapshot = {
            'schemaVersion': 1,
            'observedAt': datetime.now(timezone.utc).isoformat(),
            'inventory': inventory,
        }
        atomic_write(args.output, snapshot)
        print(json.dumps({'written': str(args.output), 'schemaVersion': 1,
                          'npmLockfiles': len(inventory['npmLockfiles']),
                          'pythonDistributions': inventory['pythonDistributions'].get('distributionCount', 0)}))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({'error': type(error).__name__, 'detail': str(error)[:500]}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
