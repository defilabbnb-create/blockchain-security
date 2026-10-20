import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('dynamic_runner', ROOT / 'scripts' / 'dynamic_runner.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def manifest(directory):
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    data = {'schemaVersion': 1, 'tests': [{'invariantId': hashlib.sha256(b'invariant').hexdigest()}]}
    (path / 'harness.json').write_text(json.dumps(data))
    return path


class DynamicRunnerTests(unittest.TestCase):
    def test_replay_is_unavailable_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            results = RUNNER.run_harness(manifest(directory), mode='replay', forge=Path('/missing/forge'))
            self.assertEqual(results[0]['state'], 'unavailable')
            self.assertEqual(results[0]['reason'], 'replay_disabled_by_default')

    def test_fixed_block_fork_requires_https_and_matching_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = manifest(directory)
            result = RUNNER.run_harness(path, mode='fixed_block_fork', forge=Path('/missing/forge'),
                                        rpc_url='http://localhost:8545', block_number=42,
                                        block_hash_before='0x' + 'a' * 64, block_hash_after='0x' + 'a' * 64)
            self.assertEqual(result[0]['state'], 'unavailable')
            self.assertIn('https', result[0]['reason'])

    def test_fixed_block_fork_checks_anchor_twice_and_stores_only_url_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = manifest(directory)
            forge = Path(directory) / 'forge-mock'
            forge.write_text('#!/bin/sh\nprintf "all tests passed\n"\nexit 0\n')
            forge.chmod(0o755)
            block_hash = '0x' + 'c' * 64
            with patch.object(RUNNER, '_rpc_block_hash', side_effect=[block_hash, block_hash]) as rpc_read:
                results = RUNNER.run_harness(path, mode='fixed_block_fork', forge=forge,
                    rpc_url='https://rpc.example.test/path', block_number=42)
            self.assertEqual(rpc_read.call_count, 2)
            self.assertEqual(results[0]['state'], 'passed')
            self.assertEqual(results[0]['blockAnchor']['hash'], block_hash)
            self.assertNotIn('rpc.example.test', json.dumps(results))
            self.assertEqual(len(results[0]['blockAnchor']['rpcUrlSha256']), 64)

    def test_local_runner_maps_assertion_failure_to_violated_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path = manifest(directory)
            forge = Path(directory) / 'forge-mock'
            forge.write_text('#!/bin/sh\nprintf "1 failed: invariant\n" >&2\nexit 1\n')
            forge.chmod(0o755)
            with patch.object(RUNNER, '_rpc_block_hash', side_effect=AssertionError('network called')):
                results = RUNNER.run_harness(path, mode='local', forge=forge)
            self.assertEqual(results[0]['state'], 'violated')
            self.assertEqual(len(results[0]['evidenceSha256']), 64)

    def test_compilation_failure_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = manifest(directory)
            forge = Path(directory) / 'forge-mock'
            forge.write_text('#!/bin/sh\nprintf "Compilation failed\n" >&2\nexit 1\n')
            forge.chmod(0o755)
            results = RUNNER.run_harness(path, mode='local', forge=forge)
            self.assertEqual(results[0]['state'], 'unavailable')

    def test_forge_fixture_that_breaks_an_invariant_is_violated(self):
        forge = ROOT / 'work' / 'tools' / 'forge'
        if not forge.is_file():
            self.skipTest('bundled forge binary is unavailable')
        with tempfile.TemporaryDirectory() as directory:
            path = manifest(directory)
            (path / 'test').mkdir()
            (path / 'test' / 'Invariant.t.sol').write_text('''// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;
contract InvariantFixture {
    function testInvariant() public pure { require(false, "invariant violated"); }
}
''')
            results = RUNNER.run_harness(path, mode='local', forge=forge)
            self.assertEqual(results[0]['state'], 'violated')
            self.assertEqual(len(results[0]['evidenceSha256']), 64)


if __name__ == '__main__':
    unittest.main()
