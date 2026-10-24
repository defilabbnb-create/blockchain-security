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
            # Realistic forge output.  The runner distinguishes an assertion that
            # broke from a harness that never started by looking for evidence
            # that a test actually ran, so a stub has to emit that evidence -- the
            # previous `1 failed: invariant` matched no branch of any format forge
            # produces, and it passed only because an unrecognised output used to
            # be read as `violated`.  The real-forge fixture below covers the
            # genuine path.
            forge.write_text('#!/bin/sh\n'
                             'printf "Ran 1 test for test/Invariant.t.sol\\n'
                             '[FAIL: invariant] testInvariant() (gas: 76755)\\n" >&2\nexit 1\n')
            forge.chmod(0o755)
            with patch.object(RUNNER, '_rpc_block_hash', side_effect=AssertionError('network called')):
                results = RUNNER.run_harness(path, mode='local', forge=forge)
            self.assertEqual(results[0]['state'], 'violated')
            self.assertEqual(len(results[0]['evidenceSha256']), 64)

    def test_output_that_cannot_tell_a_failure_from_a_broken_harness_is_unavailable(self):
        # A missing compiler, a bad toolchain, or anything else forge reports
        # without running a test is not a detection.  Read as `violated` it made
        # every collected bundle look like it had findings, with the real cause
        # sitting in the output text that nothing looked at.
        with tempfile.TemporaryDirectory() as directory:
            path = manifest(directory)
            forge = Path(directory) / 'forge-mock'
            forge.write_text('#!/bin/sh\n'
                             'printf "Error: Encountered invalid compiler version in src/A.sol: '
                             'No compiler version installed that matches >=0.6.0, <0.8.0\\n" >&2\nexit 1\n')
            forge.chmod(0o755)
            results = RUNNER.run_harness(path, mode='local', forge=forge)
            self.assertEqual(results[0]['state'], 'unavailable')
            self.assertEqual(results[0]['reason'], 'required_compiler_not_installed')

    def test_an_unrecognised_failure_is_unavailable_rather_than_violated(self):
        # The general rule: an error nobody anticipated is not evidence that a
        # protocol property broke.
        with tempfile.TemporaryDirectory() as directory:
            path = manifest(directory)
            forge = Path(directory) / 'forge-mock'
            forge.write_text('#!/bin/sh\nprintf "Error: something new\\n" >&2\nexit 1\n')
            forge.chmod(0o755)
            results = RUNNER.run_harness(path, mode='local', forge=forge)
            self.assertEqual(results[0]['state'], 'unavailable')

    def test_compilation_failure_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = manifest(directory)
            forge = Path(directory) / 'forge-mock'
            forge.write_text('#!/bin/sh\nprintf "Compilation failed\n" >&2\nexit 1\n')
            forge.chmod(0o755)
            results = RUNNER.run_harness(path, mode='local', forge=forge)
            self.assertEqual(results[0]['state'], 'unavailable')

    def _real_forge_run(self, suites, manifest_ids):
        """Run real forge over hand-written suites named the way the generator names them.

        `suites` maps invariantId -> the require() condition that suite uses;
        `manifest_ids` is what the manifest claims was generated, which may be
        more than what exists on disk.
        """
        forge = ROOT / 'work' / 'tools' / 'forge'
        if not forge.is_file():
            self.skipTest('bundled forge binary is unavailable')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test').mkdir(parents=True, exist_ok=True)
            (path / 'foundry.toml').write_text('[profile.default]\nsrc = "src"\ntest = "test"\n')
            for identifier, condition in suites.items():
                stem = 'Invariant_%s' % identifier[:16]
                (path / 'test' / (stem + '.t.sol')).write_text(
                    '// SPDX-License-Identifier: MIT\npragma solidity >=0.8.19;\n'
                    'contract %s {\n    function testInvariant() public pure { require(%s, "invariant violated"); }\n}\n'
                    % (stem, condition))
            (path / 'harness.json').write_text(json.dumps({'schemaVersion': 1, 'tests': [
                {'invariantId': identifier, 'path': 'test/Invariant_%s.t.sol' % identifier[:16],
                 'template': 'probe', 'status': 'unverified'} for identifier in manifest_ids]}))
            return {row['invariantId']: row for row in RUNNER.run_harness(path, mode='local', forge=forge)}

    def test_forge_fixture_that_breaks_an_invariant_is_violated(self):
        identifier = hashlib.sha256(b'invariant').hexdigest()
        rows = self._real_forge_run({identifier: 'false'}, [identifier])
        self.assertEqual(rows[identifier]['state'], 'violated')
        self.assertEqual(len(rows[identifier]['evidenceSha256']), 64)

    def test_real_forge_attributes_each_suite_and_reports_the_one_it_never_ran(self):
        # Against real forge, not a mock: the suite key forge emits must be the
        # key attribution looks for, or every assertion would read as missing.
        broken = hashlib.sha256(b'broken').hexdigest()
        holding = hashlib.sha256(b'holding').hexdigest()
        never_generated = hashlib.sha256(b'absent').hexdigest()
        rows = self._real_forge_run({broken: 'false', holding: 'true'},
                                    [broken, holding, never_generated])
        self.assertEqual(rows[broken]['state'], 'violated')
        self.assertEqual(rows[holding]['state'], 'passed')
        self.assertEqual(rows[never_generated]['state'], 'unavailable')
        self.assertEqual(rows[never_generated]['reason'], 'suite_result_missing')
        self.assertEqual(rows[broken]['suiteReconciliation'], {'generated': 3, 'recorded': 2, 'missing': 1})


if __name__ == '__main__':
    unittest.main()
