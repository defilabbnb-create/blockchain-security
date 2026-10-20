"""Create a bounded Foundry workspace for generated invariant checks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path


def _safe_source_path(name):
    if not isinstance(name, str) or not name or '\\' in name or name.startswith('/'):
        raise ValueError('source unit path is unsafe')
    parts = name.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('source unit path is unsafe')
    return Path(*parts)


def _source_digest(sources):
    normalized = {name: entry['content'] for name, entry in sorted(sources.items())}
    encoded = json.dumps(normalized, sort_keys=True, ensure_ascii=False,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def generate_harness(invariants, source_bundle, output_dir):
    if not isinstance(invariants, dict) or invariants.get('schemaVersion') != 1:
        raise ValueError('invariants document schemaVersion 1 is required')
    if not isinstance(source_bundle, dict) or not isinstance(source_bundle.get('sources'), dict):
        raise ValueError('verified source bundle requires a sources object')
    sources = source_bundle['sources']
    source_sha256 = _source_digest(sources)
    if invariants.get('sourceSha256') not in (None, source_sha256):
        raise ValueError('invariants sourceSha256 does not match verified source bundle')
    targets = (source_bundle.get('metadata') or {}).get('settings', {}).get('compilationTarget', {})
    if not isinstance(targets, dict) or len(targets) != 1:
        deployment = {'state': 'unavailable', 'reason': 'compilation_target_missing_or_ambiguous'}
        target_name = None
    else:
        source_name, contract_name = next(iter(targets.items()))
        target_name = contract_name if isinstance(contract_name, str) and re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', contract_name) else None
        deployment = {'state': 'adapter_required', 'reason': 'constructor_and_initialization_arguments_are_not_inferred',
                      'contract': target_name, 'sourceUnit': source_name}
    output_dir = Path(output_dir).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError('harness output directory must be new or empty')
    output_dir.mkdir(parents=True, exist_ok=True)
    source_root = output_dir / 'src'
    test_root = output_dir / 'test'
    source_root.mkdir(exist_ok=True)
    test_root.mkdir(exist_ok=True)
    for name, entry in sources.items():
        if not isinstance(entry, dict) or not isinstance(entry.get('content'), str):
            raise ValueError('verified source entries must contain source text')
        relative = _safe_source_path(name)
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry['content'], encoding='utf-8')

    generated = []
    seen_ids = set()
    for invariant in invariants.get('invariants', []):
        if not isinstance(invariant, dict):
            raise ValueError('invariant rows must be objects')
        invariant_id = invariant.get('invariantId')
        if not isinstance(invariant_id, str) or not re.fullmatch(r'[0-9a-f]{64}', invariant_id):
            raise ValueError('invariantId must be a lowercase SHA-256 digest')
        if invariant_id in seen_ids:
            raise ValueError('invariantId values must be unique')
        seen_ids.add(invariant_id)
        test_name = f'Invariant_{invariant_id[:16]}.t.sol'
        id_literal = '0x' + invariant_id
        description = json.dumps(str(invariant.get('description') or invariant.get('name') or ''))
        solidity = f'''// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

interface Vm {{
    function envAddress(string calldata name) external view returns (address);
}}

interface IInvariantObservation {{
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
}}

contract Invariant_{invariant_id[:16]} {{
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 public constant invariantId = {id_literal};
    string public constant description = {description};

    function testInvariantTargetObservationIsAvailable() public view {{
        // This is an evidence-binding smoke check. A protocol-specific stateful
        // adapter is required before this template can validate the property.
        address target = vm.envAddress("INVARIANT_TARGET");
        require(target.code.length > 0, "INVARIANT_TARGET has no code");
        IInvariantObservation(target).totalAssets();
        IInvariantObservation(target).totalSupply();
    }}
}}
'''
        (test_root / test_name).write_text(solidity, encoding='utf-8')
        generated.append({'invariantId': invariant_id, 'path': f'test/{test_name}',
                          'status': invariant.get('status', 'unverified')})
    foundry = '''[profile.default]
src = "src"
test = "test"
out = "out"
cache_path = "cache"
libs = []
auto_detect_solc = true
offline = true
'''
    (output_dir / 'foundry.toml').write_text(foundry, encoding='utf-8')
    manifest = {'schemaVersion': 1, 'sourceSha256': source_sha256,
                'invariantsSha256': hashlib.sha256(json.dumps(invariants, sort_keys=True,
                    ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest(),
                'deployment': deployment, 'tests': generated,
                'scope': 'Generated checks bind invariant metadata and read target observations; a protocol-specific stateful adapter is required to test properties.'}
    (output_dir / 'harness.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('invariants', type=Path)
    parser.add_argument('verified_source_bundle', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args(argv)
    manifest = generate_harness(json.loads(args.invariants.read_text(encoding='utf-8')),
                                json.loads(args.verified_source_bundle.read_text(encoding='utf-8')),
                                args.output)
    print(json.dumps({'state': 'generated', 'harness': str(args.output),
                      'testCount': len(manifest['tests']), 'deployment': manifest['deployment']}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
