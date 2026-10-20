import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('harness_gen', ROOT / 'scripts' / 'harness_gen.py')
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


def fixture():
    sources = {'Vault.sol': {'content': '''// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;
contract Vault {
    function totalAssets() external pure returns (uint256) { return 1; }
    function totalSupply() external pure returns (uint256) { return 1; }
}
'''}}
    source_hash = GEN._source_digest(sources)
    invariants = {'schemaVersion': 1, 'sourceSha256': source_hash,
                  'invariants': [{'invariantId': hashlib.sha256(b'fixture').hexdigest(),
                                  'template': 'share_price_monotonic',
                                  'params': {'assetsField': 'totalAssets', 'sharesField': 'totalSupply', 'toleranceBps': 0},
                                  'description': 'Vault share price', 'status': 'unverified'}]}
    bundle = {'sources': sources,
              'metadata': {'settings': {'compilationTarget': {'Vault.sol': 'Vault'}}}}
    return invariants, bundle


class HarnessGeneratorTests(unittest.TestCase):
    def test_generates_foundry_project_and_compiles(self):
        invariants, bundle = fixture()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'harness'
            manifest = GEN.generate_harness(invariants, bundle, output)
            self.assertEqual(len(manifest['tests']), 1)
            self.assertEqual(manifest['deployment']['state'], 'adapter_required')
            self.assertEqual(manifest['sourceSha256'], invariants['sourceSha256'])
            self.assertIn('function testInvariant()', (output / manifest['tests'][0]['path']).read_text())
            self.assertNotIn('smoke check', (output / manifest['tests'][0]['path']).read_text())
            forge = ROOT / 'work' / 'tools' / 'forge'
            if not forge.is_file():
                self.skipTest('bundled forge binary is unavailable')
            result = subprocess.run([str(forge), 'build', '--root', str(output), '--offline'],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_source_hash_mismatch_and_parent_traversal(self):
        invariants, bundle = fixture()
        invariants['sourceSha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'does not match'):
                GEN.generate_harness(invariants, bundle, Path(directory) / 'harness')
        invariants, bundle = fixture()
        bundle['sources'] = {'../outside.sol': {'content': 'contract Outside {}'}}
        invariants['sourceSha256'] = GEN._source_digest(bundle['sources'])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                GEN.generate_harness(invariants, bundle, Path(directory) / 'harness')


if __name__ == '__main__':
    unittest.main()
