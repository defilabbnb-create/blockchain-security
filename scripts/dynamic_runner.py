"""Run generated invariant harnesses within explicit local/fork boundaries."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import re
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def _bounded_runner():
    spec = importlib.util.spec_from_file_location('review_static_runner', ROOT / 'scripts' / 'review-static.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_bounded, module.ProcessTreeMemoryLimitExceeded


def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _rpc_url_is_safe(value):
    try:
        parsed = urlsplit(value)
        return parsed.scheme == 'https' and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
    except Exception:
        return False


def _result(invariant_id, mode, state, *, reason=None, minimal_repro=None, gas_used=None, block_anchor=None, evidence=None):
    return {'schemaVersion': 1, 'invariantId': invariant_id, 'mode': mode, 'state': state,
            'minimalRepro': minimal_repro or [], 'gasUsed': gas_used,
            'blockAnchor': block_anchor, 'evidenceSha256': evidence,
            **({'reason': reason} if reason else {})}


def _forge_command(forge, harness_dir, manifest=None):
    # A bare `forge` cannot resolve a compiler for the pre-0.8 samples in the
    # benchmark corpus: with nothing installed for, say, `^0.4.10` it exits
    # before any test runs, and the failure then surfaces as "no assertion
    # executed" rather than as the compiler error it is.  When the caller hands
    # us the solc bridge, the run goes through it and one already-cached soljson
    # release is pinned with `--use`.  A harness that recorded the exact compiler
    # it was built with is honoured, because `auto` would otherwise take the
    # newest release the pragma range allows.
    forge = Path(forge)
    if forge.name == 'forge-with-solc.py':
        recorded = (manifest or {}).get('deployment', {}).get('compilerVersion')
        return [sys.executable, str(forge), '--compiler-version', recorded or 'auto',
                '--forge', str(_default_forge(harness_dir)),
                'test', '--root', str(harness_dir), '--json']
    return [str(forge), 'test', '--root', str(harness_dir), '--json']


def _rpc_block_hash(url, block_number):
    parsed = urlsplit(url)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=10,
                                               context=ssl.create_default_context())
    path = parsed.path or '/'
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber',
                       'params': [hex(block_number), False]}).encode('utf-8')
    try:
        connection.request('POST', path, body=body, headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('fixed_block_rpc_http_error')
        if response.getheader('Location'):
            raise ValueError('fixed_block_rpc_redirect_rejected')
        payload = json.loads(response.read(1_000_001))
        block = payload.get('result') if isinstance(payload, dict) else None
        block_hash = block.get('hash') if isinstance(block, dict) else None
        if not isinstance(block_hash, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', block_hash):
            raise ValueError('fixed_block_hash_unavailable')
        return block_hash.lower()
    finally:
        connection.close()


def _default_forge(harness_dir):
    """Resolve the bundled forge binary.

    A harness lives under a task directory, so walking up from it does not
    reliably reach the repository. Prefer the project's own tool location and
    keep the historical relative path as a fallback.
    """
    candidates = [
        Path(__file__).resolve().parent.parent / 'work' / 'tools' / 'forge',
        Path(harness_dir).resolve().parent.parent / 'tools' / 'forge',
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def run_harness(harness_dir, *, mode='local', forge=None, timeout_seconds=120, max_output_bytes=2_000_000,
                rpc_url=None, block_number=None, block_hash_before=None, block_hash_after=None,
                replay_enabled=False, max_process_tree_rss_bytes=3 * 1024 * 1024 * 1024):
    harness_dir = Path(harness_dir).resolve()
    manifest_path = harness_dir / 'harness.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    all_rows = manifest.get('tests', [])
    adapter_rows = [row for row in all_rows if row.get('status') == 'adapter_required']
    invariant_rows = [row for row in all_rows if row not in adapter_rows]

    def finish(rows):
        adapter_results = [_result(row['invariantId'], mode, 'unavailable', reason=row.get('reason', 'adapter_required'))
                           for row in adapter_rows]
        return adapter_results + rows

    if not invariant_rows:
        return finish([])
    forge = Path(forge or _default_forge(harness_dir)).expanduser().resolve()
    if mode not in ('local', 'fixed_block_fork', 'replay'):
        raise ValueError('mode must be local, fixed_block_fork, or replay')
    if mode == 'replay':
        reason = 'replay_disabled_by_default' if not replay_enabled else 'replay_adapter_not_configured'
        return finish([_result(row['invariantId'], mode, 'unavailable', reason=reason) for row in invariant_rows])
    deployment = manifest.get('deployment') or {}
    if deployment.get('state') == 'adapter_required':
        return [_result(row['invariantId'], mode, 'unavailable', reason='protocol_specific_deployment_adapter_required') for row in all_rows]
    if mode == 'fixed_block_fork':
        if not isinstance(rpc_url, str) or not _rpc_url_is_safe(rpc_url):
            return finish([_result(row['invariantId'], mode, 'unavailable', reason='fixed_block_fork_requires_https_rpc_without_credentials') for row in invariant_rows])
        if not isinstance(block_number, int) or block_number < 0:
            return finish([_result(row['invariantId'], mode, 'unavailable', reason='fixed_block_fork_requires_nonnegative_block') for row in invariant_rows])
        try:
            block_hash_before = _rpc_block_hash(rpc_url, block_number)
        except Exception as error:
            return finish([_result(row['invariantId'], mode, 'unavailable', reason=str(error)[:120]) for row in invariant_rows])
    if not forge.is_file():
        return finish([_result(row['invariantId'], mode, 'unavailable', reason='forge_not_found') for row in invariant_rows])
    command = _forge_command(forge, harness_dir, manifest)
    env = dict(os.environ)
    for key in ('RPC_URL', 'DYNAMIC_FORK_RPC_URL', 'DYNAMIC_FORK_BLOCK_NUMBER', 'ETH_RPC_URL', 'FOUNDRY_ETH_RPC_URL'):
        env.pop(key, None)
    env['FOUNDRY_OFFLINE'] = 'true' if mode == 'local' else 'false'
    if mode == 'local':
        env.pop('DYNAMIC_EXECUTION_MODE', None)
    if mode == 'fixed_block_fork':
        command.extend(['--fork-url', rpc_url, '--fork-block-number', str(block_number)])
        env['DYNAMIC_EXECUTION_MODE'] = 'fixed_block_fork'
        env['DYNAMIC_FORK_RPC_URL_SHA256'] = _sha256_bytes(rpc_url.encode('utf-8'))
        env['DYNAMIC_FORK_BLOCK_NUMBER'] = str(block_number)
    started = time.monotonic()
    try:
        run_bounded, memory_error = _bounded_runner()
        completed = run_bounded(command, timeout_seconds, cwd=harness_dir, env=env,
                                max_process_tree_rss_bytes=max_process_tree_rss_bytes)
        return_code = completed.returncode
        output = (completed.stdout or '').encode('utf-8', errors='replace') + (completed.stderr or '').encode('utf-8', errors='replace')
    except memory_error as error:
        evidence = _sha256_bytes((getattr(error, 'stdout', '') or '').encode('utf-8') + (getattr(error, 'stderr', '') or '').encode('utf-8'))
        return finish([_result(row['invariantId'], mode, 'timeout', reason='process_tree_memory_limit_exceeded', evidence=evidence) for row in invariant_rows])
    except subprocess.TimeoutExpired as error:
        evidence = _sha256_bytes((error.stdout or b'') + (error.stderr or b''))
        return finish([_result(row['invariantId'], mode, 'timeout', reason='forge_timeout', evidence=evidence) for row in invariant_rows])
    except Exception as error:
        return finish([_result(row['invariantId'], mode, 'unavailable', reason=f'runner_error:{type(error).__name__}') for row in invariant_rows])
    if len(output) > max_output_bytes:
        output = output[:max_output_bytes]
    evidence = _sha256_bytes(output)
    if mode == 'fixed_block_fork':
        try:
            block_hash_after = _rpc_block_hash(rpc_url, block_number)
        except Exception as error:
            return finish([_result(row['invariantId'], mode, 'unavailable', reason=str(error)[:120],
                            evidence=evidence, block_anchor={'number': block_number, 'hashBefore': block_hash_before,
                                                             'rpcUrlSha256': _sha256_bytes(rpc_url.encode('utf-8'))}) for row in invariant_rows])
        if block_hash_after != block_hash_before:
            return finish([_result(row['invariantId'], mode, 'unavailable', reason='block_anchor_changed', evidence=evidence,
                            block_anchor={'number': block_number, 'hashBefore': block_hash_before,
                                          'hashAfter': block_hash_after,
                                          'rpcUrlSha256': _sha256_bytes(rpc_url.encode('utf-8'))}) for row in invariant_rows])
    output_text = output.decode('utf-8', errors='replace').lower()
    unavailable = any(marker in output_text for marker in ('compilation failed', 'compiler run failed',
        'invariant_target', 'failed to resolve', 'could not find'))
    if return_code == 0:
        state = 'passed'
        reason = None
    elif unavailable:
        state = 'unavailable'
        reason = 'harness_not_executable_or_target_adapter_missing'
    else:
        state = 'violated'
        reason = 'forge_assertion_or_compilation_failed'
    return finish([_result(row['invariantId'], mode, state, reason=reason,
                    block_anchor=({'number': block_number, 'hash': block_hash_before,
                                   'rpcUrlSha256': _sha256_bytes(rpc_url.encode('utf-8'))} if mode == 'fixed_block_fork' else None),
                    evidence=evidence) for row in invariant_rows])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('harness', type=Path)
    parser.add_argument('--mode', choices=('local', 'fixed_block_fork', 'replay'), default='local')
    parser.add_argument('--forge', type=Path)
    parser.add_argument('--timeout-seconds', type=float, default=120)
    parser.add_argument('--rpc-url')
    parser.add_argument('--block-number', type=int)
    parser.add_argument('--block-hash-before')
    parser.add_argument('--block-hash-after')
    parser.add_argument('--enable-replay', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    results = run_harness(args.harness, mode=args.mode, forge=args.forge,
                          timeout_seconds=args.timeout_seconds, rpc_url=args.rpc_url,
                          block_number=args.block_number, block_hash_before=args.block_hash_before,
                          block_hash_after=args.block_hash_after, replay_enabled=args.enable_replay)
    payload = results[0] if len(results) == 1 else {'schemaVersion': 1, 'results': results}
    text = json.dumps(payload, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        import tempfile
        descriptor, temporary = tempfile.mkstemp(prefix=f'.{args.output.name}.', dir=args.output.parent)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
                output.write(text)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, args.output)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    else:
        print(text, end='')
    # "Nothing ran" must never look like "everything passed". When every
    # invariant ended up unavailable the harness produced no evidence, so the
    # exit status has to distinguish that from an actual passing run.
    states = [item.get('state') for item in results]
    if states and all(state == 'unavailable' for state in states):
        return 2
    return 0 if all(state in ('passed', 'unavailable') for state in states) else 1


if __name__ == '__main__':
    raise SystemExit(main())
