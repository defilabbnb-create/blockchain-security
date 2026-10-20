"""Generate evidence-bound Foundry PoC projects from explicit test adapters."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

try:
    from poc_template import render_test
except ModuleNotFoundError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from poc_template import render_test


def canonical_sha256(value):
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def _safe_source_path(name):
    if not isinstance(name, str) or not name or name.startswith('/') or '\\' in name:
        raise ValueError('source path is unsafe')
    parts = name.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('source path is unsafe')
    return Path(*parts)


def _atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def severity_score(category_weight, trigger_difficulty, reachable_assets_usd):
    if (isinstance(category_weight, bool) or not isinstance(category_weight, (int, float)) or category_weight < 0
            or isinstance(trigger_difficulty, bool) or not isinstance(trigger_difficulty, (int, float))
            or not 0 <= trigger_difficulty <= 1
            or isinstance(reachable_assets_usd, bool) or not isinstance(reachable_assets_usd, (int, float))
            or reachable_assets_usd < 0):
        raise ValueError('severity factors must be nonnegative and triggerDifficulty must be within [0, 1]')
    return float(category_weight) * float(trigger_difficulty) * float(reachable_assets_usd)


def generate_poc(finding, source_bundle, output_dir, *, test_source=None, cloud=None):
    if not isinstance(finding, dict):
        raise ValueError('finding must be an object')
    if not isinstance(source_bundle, dict) or not isinstance(source_bundle.get('sources'), dict):
        raise ValueError('verified source bundle requires sources')
    sources = source_bundle['sources']
    normalized = {}
    for name, entry in sources.items():
        if not isinstance(entry, dict) or not isinstance(entry.get('content'), str):
            raise ValueError('verified source entries must contain content')
        normalized[name] = entry['content']
        _safe_source_path(name)
    source_sha = canonical_sha256(normalized)
    expected_bundle = finding.get('sourceBundleSha256')
    if expected_bundle and expected_bundle != source_sha:
        raise ValueError('finding sourceBundleSha256 does not match verified source bundle')
    finding_source_sha = finding.get('sourceSha256')
    if finding_source_sha is not None and not re.fullmatch(r'[a-fA-F0-9]{64}', str(finding_source_sha)):
        raise ValueError('finding sourceSha256 must be a SHA-256 digest')
    finding_id = finding.get('id') or finding.get('findingId')
    if not isinstance(finding_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}', finding_id):
        finding_id = canonical_sha256(finding)
    short_id = hashlib.sha256(finding_id.encode('utf-8')).hexdigest()[:16]
    test_name = f'testPoC_{short_id}'
    adapter = test_source if test_source is not None else finding.get('pocTestSource')
    generated_from = 'explicit_adapter' if adapter is not None else None
    if adapter is None and cloud is not None:
        if callable(cloud):
            adapter = cloud(finding, source_bundle, test_name)
        elif hasattr(cloud, 'generate') and callable(cloud.generate):
            adapter = cloud.generate(finding, source_bundle, test_name)
        generated_from = 'cloud_review'
    if adapter is None:
        adapter = render_test(finding, source_bundle, test_name)
        generated_from = 'local_template' if adapter is not None else None
    valid_adapter = (isinstance(adapter, str) and len(adapter.encode('utf-8')) <= 256_000
                     and len(re.findall(r'function\s+' + re.escape(test_name) + r'\s*\(', adapter)) == 1
                     and 'contract ' in adapter and 'pragma solidity' in adapter)
    output_dir = Path(output_dir).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError('PoC output directory must be new or empty')
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in normalized.items():
        _atomic_write(output_dir / 'src' / _safe_source_path(name), content)
    test_path = output_dir / 'test' / f'PoC_{short_id}.t.sol'
    if valid_adapter:
        _atomic_write(test_path, adapter.rstrip() + '\n')
        adapter_state = 'ready'
    else:
        _atomic_write(test_path, f'''// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

contract PoC_{short_id} {{
    function {test_name}() public pure {{
        revert("POC_ADAPTER_REQUIRED");
    }}
}}
''')
        adapter_state = 'adapter_required'
    assets = finding.get('reachableAssetsUsd', 0)
    category_weight = finding.get('categoryWeight', 1)
    trigger_difficulty = finding.get('triggerDifficulty', 1)
    score = severity_score(category_weight, trigger_difficulty, assets)
    manifest = {'schemaVersion': 1, 'findingId': finding_id,
                'sourceSha256': str(finding_source_sha or source_sha).lower(),
                'sourceBundleSha256': source_sha,
                'findingSha256': canonical_sha256(finding), 'testName': test_name,
                'testPath': str(test_path.relative_to(output_dir)), 'adapterState': adapter_state,
                'generatedFrom': generated_from,
                'severityFactors': {'categoryWeight': category_weight,
                                    'triggerDifficulty': trigger_difficulty,
                                    'reachableAssetsUsd': assets},
                'severityScore': score,
                'evidenceSha256': canonical_sha256({'finding': finding, 'sourceSha256': source_sha,
                                                    'testSource': adapter if valid_adapter else None})}
    _atomic_write(output_dir / 'foundry.toml', '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\ncache_path = "cache"\nlibs = []\nauto_detect_solc = true\noffline = true\n')
    _atomic_write(output_dir / 'poc.json', json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    return manifest


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('finding', type=Path)
    parser.add_argument('verified_source_bundle', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--test-source', type=Path)
    args = parser.parse_args(argv)
    test_source = args.test_source.read_text(encoding='utf-8') if args.test_source else None
    manifest = generate_poc(json.loads(args.finding.read_text(encoding='utf-8')),
                            json.loads(args.verified_source_bundle.read_text(encoding='utf-8')),
                            args.output, test_source=test_source)
    print(json.dumps({'state': manifest['adapterState'], 'testPath': manifest['testPath'],
                      'findingId': manifest['findingId'], 'severityScore': manifest['severityScore']}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
