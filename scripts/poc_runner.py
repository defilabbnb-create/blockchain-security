"""Execute generated PoC adapters locally, then optionally against a pinned fork."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('poc_generator', ROOT / 'scripts' / 'poc_generator.py')
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


def _bounded_runner():
    spec = importlib.util.spec_from_file_location('review_static_runner', ROOT / 'scripts' / 'review-static.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_bounded, module.ProcessTreeMemoryLimitExceeded


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def binary_search_minimum_capital(eth_call_probe, low, high, *, iterations=256):
    """Find the smallest value accepted by a read-only eth_call probe."""
    if not callable(eth_call_probe) or any(isinstance(x, bool) or not isinstance(x, int) for x in (low, high)):
        raise ValueError('eth_call_probe and integer bounds are required')
    if low < 0 or high < low or not 1 <= iterations <= 256:
        raise ValueError('invalid capital search bounds')
    if not eth_call_probe(high):
        return None
    left, right = low, high
    while left < right and iterations:
        middle = (left + right) // 2
        if eth_call_probe(middle):
            right = middle
        else:
            left = middle + 1
        iterations -= 1
    return left


def _run_attempt(harness_dir, *, mode, forge, timeout_seconds, rpc_url=None, block_number=None):
    manifest = json.loads((harness_dir / 'poc.json').read_text(encoding='utf-8'))
    if manifest.get('adapterState') != 'ready':
        return {'state': 'unconfirmed', 'reason': 'poc_adapter_required', 'evidenceSha256': manifest['evidenceSha256']}
    test_name = manifest['testName']
    if not re.fullmatch(r'testPoC_[a-f0-9]{16}', test_name):
        return {'state': 'error', 'reason': 'invalid_poc_test_name'}
    forge = Path(forge or ROOT / 'work' / 'tools' / 'forge')
    if not forge.is_file():
        return {'state': 'error', 'reason': 'forge_not_found'}
    if mode not in ('local', 'fixed_block_fork'):
        raise ValueError('PoC mode must be local or fixed_block_fork')
    command = [str(forge), 'test', '--root', str(harness_dir), '--match-test', test_name, '-vv']
    env = dict(os.environ)
    for name in ('RPC_URL', 'DYNAMIC_FORK_RPC_URL', 'DYNAMIC_FORK_BLOCK_NUMBER', 'ETH_RPC_URL', 'FOUNDRY_ETH_RPC_URL'):
        env.pop(name, None)
    env['FOUNDRY_OFFLINE'] = 'true' if mode == 'local' else 'false'
    if mode == 'fixed_block_fork':
        from dynamic_runner import _rpc_block_hash, _rpc_url_is_safe
        if not _rpc_url_is_safe(rpc_url) or isinstance(block_number, bool) or not isinstance(block_number, int) or block_number < 0:
            return {'state': 'error', 'reason': 'fixed_block_fork_requires_safe_https_rpc_and_block'}
        try:
            before = _rpc_block_hash(rpc_url, block_number)
        except Exception as error:
            return {'state': 'error', 'reason': f'block_anchor_unavailable:{type(error).__name__}'}
        command.extend(['--fork-url', rpc_url, '--fork-block-number', str(block_number)])
    started = time.monotonic()
    try:
        run_bounded, memory_error = _bounded_runner()
        completed = run_bounded(command, timeout_seconds, cwd=harness_dir, env=env,
                                max_process_tree_rss_bytes=3 * 1024 * 1024 * 1024)
        output = ((completed.stdout or '') + (completed.stderr or '')).encode('utf-8', errors='replace')[:2_000_000]
        return_code = completed.returncode
    except memory_error as error:
        output = ((getattr(error, 'stdout', '') or '') + (getattr(error, 'stderr', '') or '')).encode('utf-8', errors='replace')
        return {'state': 'error', 'reason': 'process_tree_memory_limit_exceeded', 'evidenceSha256': hashlib.sha256(output).hexdigest()}
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b'') + (error.stderr or b'')
        return {'state': 'error', 'reason': 'poc_timeout', 'evidenceSha256': hashlib.sha256(output).hexdigest()}
    except Exception as error:
        return {'state': 'error', 'reason': f'runner_error:{type(error).__name__}'}
    output_text = output.decode('utf-8', errors='replace')
    evidence = hashlib.sha256(output).hexdigest()
    if mode == 'fixed_block_fork':
        from dynamic_runner import _rpc_block_hash
        try:
            after = _rpc_block_hash(rpc_url, block_number)
        except Exception as error:
            return {'state': 'error', 'reason': f'block_anchor_unavailable_after_run:{type(error).__name__}', 'evidenceSha256': evidence}
        if after != before:
            return {'state': 'error', 'reason': 'block_anchor_changed', 'evidenceSha256': evidence}
        anchor = {'number': block_number, 'hash': before,
                  'rpcUrlSha256': hashlib.sha256(rpc_url.encode('utf-8')).hexdigest()}
    else:
        anchor = None
    passed = re.search(rf'\[PASS\]\s+{re.escape(test_name)}\b', output_text) is not None
    state = 'confirmed' if return_code == 0 and passed else 'unconfirmed' if return_code != 0 else 'error'
    return {'state': state, 'reason': None if state == 'confirmed' else 'poc_assertion_failed' if return_code else 'poc_test_success_not_observed',
            'evidenceSha256': evidence, 'blockAnchor': anchor,
            'durationMs': round((time.monotonic() - started) * 1000),
            'diagnostic': output_text[-12000:]}


def run_poc(harness_dir, *, forge=None, timeout_seconds=120, rpc_url=None, block_number=None,
            repair_callback=None, eth_call_probe=None, capital_bounds=None, max_repairs=3,
            result_path=None):
    harness_dir = Path(harness_dir).resolve()
    manifest_path = harness_dir / 'poc.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if isinstance(max_repairs, bool) or not isinstance(max_repairs, int) or not 0 <= max_repairs <= 3:
        raise ValueError('max_repairs must be between 0 and 3')
    test_path = harness_dir / manifest.get('testPath', '')
    if test_path.resolve().parent != (harness_dir / 'test').resolve():
        raise ValueError('PoC test path escaped harness')
    attempts = []
    final = None
    modes = ['local']
    if rpc_url is not None or block_number is not None:
        modes.append('fixed_block_fork')
    for mode in modes:
        for attempt in range(1, max_repairs + 2):
            final = _run_attempt(harness_dir, mode=mode, forge=forge, timeout_seconds=timeout_seconds,
                                 rpc_url=rpc_url, block_number=block_number)
            attempts.append({'mode': mode, 'attempt': attempt, 'state': final['state'],
                             'reason': final.get('reason'), 'evidenceSha256': final.get('evidenceSha256')})
            if final['state'] == 'confirmed' or final['state'] == 'error' and final.get('reason') in ('forge_not_found', 'poc_adapter_required'):
                break
            if attempt > max_repairs or not callable(repair_callback):
                break
            repaired = repair_callback({'findingId': manifest['findingId'], 'mode': mode,
                                        'attempt': attempt, 'diagnostic': final.get('diagnostic', ''),
                                        'reason': final.get('reason')})
            if not isinstance(repaired, str) or len(repaired.encode('utf-8')) > 256_000:
                final = {'state': 'error', 'reason': 'repair_callback_returned_invalid_test_source'}
                break
            if len(re.findall(r'function\s+' + re.escape(manifest['testName']) + r'\s*\(', repaired)) != 1:
                final = {'state': 'error', 'reason': 'repair_callback_changed_poc_test_identity'}
                break
            GENERATOR._atomic_write(test_path, repaired.rstrip() + '\n')
            manifest['evidenceSha256'] = GENERATOR.canonical_sha256({
                'findingSha256': manifest['findingSha256'], 'sourceSha256': manifest['sourceSha256'],
                'testSource': repaired.rstrip() + '\n'})
            _atomic_json(manifest_path, manifest)
        if final and final.get('state') == 'confirmed':
            break
    capital = None
    if eth_call_probe is not None and capital_bounds is not None:
        capital = binary_search_minimum_capital(eth_call_probe, *capital_bounds)
    result = {'schemaVersion': 1, 'findingId': manifest['findingId'],
              'sourceSha256': manifest['sourceSha256'], 'sourceBundleSha256': manifest['sourceBundleSha256'],
              'pocState': final['state'] if final else 'error', 'pocArtifactPath': str(test_path),
              'pocEvidenceSha256': manifest['evidenceSha256'],
              'minCapitalRequiredWei': str(capital) if capital is not None else None,
              'severityFactors': manifest['severityFactors'], 'severityScore': manifest['severityScore'],
              'attempts': attempts, 'evidenceSha256': final.get('evidenceSha256') if final else None,
              'blockAnchor': final.get('blockAnchor') if final else None,
              'confirmedVulnerability': bool(final and final.get('state') == 'confirmed')}
    _atomic_json(result_path or harness_dir / 'poc-result.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('harness', type=Path)
    parser.add_argument('--forge', type=Path)
    parser.add_argument('--timeout-seconds', type=float, default=120)
    parser.add_argument('--rpc-url')
    parser.add_argument('--block-number', type=int)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--result-path', type=Path)
    args = parser.parse_args(argv)
    repair_callback = None
    endpoint = os.environ.get('DEFI_CLOUD_AI_BASE_URL', '').strip()
    api_key = os.environ.get('DEFI_CLOUD_AI_API_KEY', '').strip()
    model = os.environ.get('DEFI_CLOUD_AI_MODEL', '').strip()
    if endpoint and api_key and model:
        cloud_spec = importlib.util.spec_from_file_location('cloud_review', ROOT / 'scripts' / 'cloud_review.py')
        cloud = importlib.util.module_from_spec(cloud_spec)
        cloud_spec.loader.exec_module(cloud)
        endpoint = cloud.validate_endpoint(endpoint)

        def repair_callback(context):
            test_source = (Path(args.harness) / json.loads((Path(args.harness) / 'poc.json').read_text(encoding='utf-8'))['testPath']).read_text(encoding='utf-8')
            manifest_hash = GENERATOR.canonical_sha256({'findingId': context['findingId'],
                'testName': json.loads((Path(args.harness) / 'poc.json').read_text(encoding='utf-8'))['testName']})
            response, _evidence = cloud._request(endpoint, api_key, model, 'poc_repair', {
                'phase': 'poc_repair', 'manifestSha256': manifest_hash, 'findingId': context['findingId'],
                'testSource': test_source, 'diagnostic': context.get('diagnostic', '')[:12000],
                'reason': context.get('reason'), 'attempt': context['attempt'],
                'instruction': '仅返回 JSON，包含原样 manifestSha256 与 testSource。修正当前 PoC 测试；保留测试函数名，不要引入外部请求、环境变量读取或链上交易广播。'})
            if response.get('manifestSha256') != manifest_hash or not isinstance(response.get('testSource'), str):
                raise ValueError('cloud PoC repair response did not match manifest or omit testSource')
            return response['testSource']

    result = run_poc(args.harness, forge=args.forge, timeout_seconds=args.timeout_seconds,
                     rpc_url=args.rpc_url, block_number=args.block_number,
                     repair_callback=repair_callback, result_path=args.result_path)
    if args.output:
        _atomic_json(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['pocState'] in ('confirmed', 'unconfirmed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
