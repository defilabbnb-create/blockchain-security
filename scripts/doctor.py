#!/usr/bin/env python3
"""Offline environment checks; no credentials are printed and no network calls."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def record(checks, name, ok, detail, required=True):
    checks.append({
        'check': name,
        'ok': bool(ok),
        'detail': detail,
        'required': bool(required),
    })


def summarize_checks(checks):
    ready = all(check['ok'] for check in checks if check['required'])
    optional_failures = [
        check['check'] for check in checks
        if not check['required'] and not check['ok']
    ]
    return ready, optional_failures


def command_output(command):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def memory_diagnostics():
    total_memory_bytes = None
    available_memory_bytes = None
    system = platform.system()

    if system == 'Darwin':
        total = command_output(['sysctl', '-n', 'hw.memsize'])
        if total:
            try:
                total_memory_bytes = int(total)
            except ValueError:
                pass
        vm_stat = command_output(['vm_stat'])
        if vm_stat:
            page_size = None
            for line in vm_stat.splitlines():
                marker = 'page size of'
                lower = line.lower()
                start = lower.find(marker)
                if start < 0:
                    continue
                raw_size = lower[start + len(marker):].split('bytes', 1)[0].strip()
                try:
                    page_size = int(raw_size)
                except ValueError:
                    page_size = None
                break
            if page_size and page_size > 0:
                page_names = {
                    'Pages free', 'Pages inactive', 'Pages speculative', 'Pages purgeable',
                }
                pages = {}
                malformed = False
                for line in vm_stat.splitlines():
                    name, separator, raw_pages = line.partition(':')
                    name = name.strip()
                    if not separator or name not in page_names:
                        continue
                    try:
                        pages[name] = int(raw_pages.strip().rstrip('.').replace(',', ''))
                    except ValueError:
                        malformed = True
                        break
                if not malformed and 'Pages free' in pages:
                    available_memory_bytes = page_size * sum(pages.values())

    elif system == 'Linux':
        try:
            lines = Path('/proc/meminfo').read_text().splitlines()
        except OSError:
            lines = []
        values = {}
        for line in lines:
            name, separator, remainder = line.partition(':')
            if not separator or name not in ('MemTotal', 'MemAvailable'):
                continue
            fields = remainder.split()
            try:
                multiplier = 1024 if len(fields) > 1 and fields[1] == 'kB' else 1
                values[name] = int(fields[0]) * multiplier
            except (IndexError, ValueError):
                continue
        total_memory_bytes = values.get('MemTotal')
        available_memory_bytes = values.get('MemAvailable')

    else:
        try:
            page_size = os.sysconf('SC_PAGE_SIZE')
            total_memory_bytes = page_size * os.sysconf('SC_PHYS_PAGES')
            available_memory_bytes = page_size * os.sysconf('SC_AVPHYS_PAGES')
        except (AttributeError, OSError, ValueError):
            pass

    return {
        'totalMemoryBytes': total_memory_bytes,
        'availableMemoryBytes': available_memory_bytes,
    }


def environment_diagnostics(root=ROOT):
    try:
        free_disk_bytes = shutil.disk_usage(root).free
    except OSError:
        free_disk_bytes = None
    memory = memory_diagnostics()
    return {
        'platform': platform.system(),
        'architecture': platform.machine(),
        'pythonVersion': platform.python_version(),
        'cpuCount': os.cpu_count(),
        'totalMemoryBytes': memory['totalMemoryBytes'],
        'availableMemoryBytes': memory['availableMemoryBytes'],
        'freeDiskBytes': free_disk_bytes,
    }


def cloud_model_diagnostics():
    """Check cloud review configuration without revealing secrets or using the network."""
    base_url = os.environ.get('DEFI_CLOUD_AI_BASE_URL', '').strip()
    api_key = os.environ.get('DEFI_CLOUD_AI_API_KEY', '').strip()
    model = os.environ.get('DEFI_CLOUD_AI_MODEL', '').strip()
    parsed = None
    try:
        parsed = urlsplit(base_url)
        _ = parsed.port
    except ValueError:
        parsed = None
    valid_url = bool(parsed and parsed.scheme == 'https' and parsed.hostname
                     and not parsed.username and not parsed.password
                     and not parsed.query and not parsed.fragment)
    return {
        'configured': bool(valid_url and api_key and model),
        'environmentComplete': bool(base_url and api_key and model),
        'baseUrlValid': valid_url,
        'baseUrlHost': parsed.hostname if valid_url else None,
        'model': model or None,
        'networkRequested': False,
    }


def collect_checks(root=ROOT):
    tools = root / 'flare-scan/tools'
    checks = []

    node = shutil.which('node')
    node_version = command_output([node, '--version']) if node else None
    try:
        node_parts = tuple(int(part) for part in node_version.lstrip('v').split('.'))
        node_ok = node_parts >= (24, 5, 0)
    except (AttributeError, ValueError):
        node_ok = False
    node_detail = (node_version + ' (required >=24.5.0)'
                   if node_version else 'missing/unloadable')
    record(checks, 'Node.js', node_ok, node_detail)
    record(checks, 'Python', sys.version_info >= (3, 9),
           platform.python_version() + ' (required >=3.9)')

    for suffix in ('0819', '0823', '0828'):
        module = tools / ('solc-' + suffix) / 'node_modules/solc'
        version = command_output([
            node, '-e', 'console.log(require(process.argv[1]).version())', str(module),
        ]) if node else None
        record(checks, 'solc-' + suffix, version is not None,
               version if version is not None else 'module missing/unloadable')

    probe = (
        'import sys;sys.path.insert(0,sys.argv[1]);'
        'from slither.slither import Slither;'
        'from importlib.metadata import version;'
        'print(version("slither-analyzer"))'
    )
    slither_version = command_output([
        sys.executable, '-c', probe, str(tools / 'pylibs'),
    ])
    record(checks, 'Slither', slither_version is not None,
           slither_version if slither_version is not None else 'missing/unloadable')

    heimdall = root / 'work/tools/heimdall/heimdall'
    heimdall_version = command_output([str(heimdall), '--version']) if heimdall.is_file() else None
    heimdall_ok = bool(heimdall_version and heimdall_version.lower().startswith('heimdall'))
    record(checks, 'Heimdall decompiler', heimdall_ok,
           heimdall_version if heimdall_ok else 'missing/unloadable')

    optional_targets = (
        ('morpho-blue/src/Morpho.sol', 'local analysis target'),
        ('firelight-core/contracts/core/FirelightVault.sol', 'local analysis target'),
        ('firelight-core/node_modules/@openzeppelin/contracts/package.json',
         'optional local node_modules'),
    )
    for relative, detail in optional_targets:
        record(checks, relative, (root / 'flare-scan/contracts' / relative).is_file(),
               detail, required=False)

    optional_tools = (
        ('Rust', 'rustc', ['--version']),
        ('Docker', 'docker', ['--version']),
        ('PostgreSQL client', 'psql', ['--version']),
        ('Redis client', 'redis-cli', ['--version']),
    )
    for name, binary, args in optional_tools:
        executable = shutil.which(binary)
        version = command_output([executable, *args]) if executable else None
        record(checks, name, version is not None,
               version if version is not None else 'optional binary unavailable', required=False)

    return checks


def main():
    checks = collect_checks()
    ready, optional_failures = summarize_checks(checks)
    report = {
        'ready': ready,
        'checks': checks,
        'optionalFailures': optional_failures,
        'environment': environment_diagnostics(),
        'cloudAI': cloud_model_diagnostics(),
        'note': 'No RPC connectivity, API keys, deployed bytecode or contract safety checked. '
                'Database and cache client checks do not verify running services.',
    }
    print(json.dumps(report, indent=2))
    return 0 if ready else 1


if __name__ == '__main__':
    sys.exit(main())
