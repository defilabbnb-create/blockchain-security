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
            # Without constructor arguments the harness keeps the historical
            # shape: the target address comes from the environment, because
            # whatever supplies the address (a fork, or the runner that ran a
            # deployment script) is the only party that knows which instance the
            # assertion is meant to measure.
            self.assertEqual(manifest['deployment']['state'], 'env_address')
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


class InlineDeploymentTests(unittest.TestCase):
    """A harness that deploys its own target, for contracts taking arguments.

    Nothing can construct such a contract from the outside without knowing how,
    so the environment path left every parameterised contract stranded: the
    assertion could not be measured at all. These tests pin that supplying the
    arguments produces a `new` call that compiles and runs.
    """

    def _fixture(self, body=None):
        source = body or ('// SPDX-License-Identifier: MIT\npragma solidity 0.8.19;\n'
                          'contract Vault {\n'
                          '    uint256 public totalAssets;\n'
                          '    uint256 public totalSupply;\n'
                          '    constructor(uint256 seed) { totalAssets = seed; totalSupply = seed; }\n'
                          '    function deposit(uint256 a) external { require(a > 0);'
                          ' totalAssets += a; totalSupply += a; }\n}\n')
        abi = [{'type': 'constructor',
                'inputs': [{'name': 'seed', 'type': 'uint256', 'internalType': 'uint256'}]},
               {'type': 'function', 'name': 'totalAssets', 'inputs': [],
                'outputs': [{'type': 'uint256'}]},
               {'type': 'function', 'name': 'totalSupply', 'inputs': [],
                'outputs': [{'type': 'uint256'}]}]
        sources = {'Vault.sol': {'content': source}}
        invariants = {'schemaVersion': 1, 'sourceSha256': GEN._source_digest(sources),
                      'invariants': [{'invariantId': hashlib.sha256(b'inline').hexdigest(),
                                      'template': 'share_price_monotonic',
                                      'params': {'assetsField': 'totalAssets',
                                                 'sharesField': 'totalSupply',
                                                 'toleranceBps': 0}}]}
        bundle = {'sources': sources,
                  'metadata': {'settings': {'compilationTarget': {'Vault.sol': 'Vault'}},
                               'abi': abi}}
        return invariants, bundle

    def test_supplied_arguments_produce_an_inline_deployment(self):
        invariants, bundle = self._fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'harness'
            manifest = GEN.generate_harness(invariants, bundle, root,
                                            constructor_arguments={'seed': 1000})
            self.assertEqual(manifest['deployment']['state'], 'inline_deployment')
            self.assertEqual(manifest['deployment']['expression'], 'address(new Vault(1000))')
            text = (root / manifest['tests'][0]['path']).read_text()
            self.assertIn('address(new Vault(1000))', text)
            # The contract has to be in scope for `new` to resolve.
            self.assertIn('import "../src/Vault.sol"', text)
            # The entry point is what matters. `envAddress` still appears in the
            # cheat-code interface declaration, which is harmless -- what would
            # be wrong is the test reading the target from the environment,
            # because an unset variable yields address(0) and the assertion
            # measures nothing.
            entry = text[text.index('function testInvariant()'):]
            self.assertNotIn('envAddress', entry)

    def test_a_missing_argument_is_reported_rather_than_guessed(self):
        invariants, bundle = self._fixture()
        with tempfile.TemporaryDirectory() as directory:
            manifest = GEN.generate_harness(invariants, bundle,
                                            Path(directory) / 'harness',
                                            constructor_arguments={})
            # Deploying with a zero the caller never chose would produce a
            # contract that is not the one under review, and every property
            # measured on it would be about that other contract.
            self.assertEqual(manifest['deployment']['state'], 'adapter_required')
            self.assertEqual(manifest['deployment']['missing'], ['seed'])

    def test_the_inline_deployment_compiles_and_runs_the_assertion(self):
        invariants, bundle = self._fixture()
        forge = ROOT / 'work' / 'tools' / 'forge'
        if not forge.is_file():
            self.skipTest('bundled forge binary is unavailable')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'harness'
            manifest = GEN.generate_harness(invariants, bundle, root,
                                            constructor_arguments={'seed': 1000})
            result = subprocess.run([str(forge), 'test', '--root', str(root), '--offline',
                                     '--match-test', 'testInvariant'],
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # The assertion measured the freshly deployed contract: it passed,
            # and it passed by running rather than by being skipped.
            self.assertIn('[PASS] testInvariant()', result.stdout)
            self.assertNotIn('[SKIP]', result.stdout)


if __name__ == '__main__':
    unittest.main()
