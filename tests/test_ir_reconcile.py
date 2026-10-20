import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ir_reconcile', ROOT / 'scripts' / 'ir_reconcile.py')
RECONCILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECONCILE)
sys.path.insert(0, str(ROOT / 'flare-scan' / 'tools' / 'pylibs'))
from eth_hash.auto import keccak


def selector(signature):
    return '0x' + keccak(signature.encode())[:4].hex()


def source_ir():
    return {'schemaVersion': 1, 'state': 'available',
            'functions': [{'name': 'Vault::Vault.deposit(uint256)', 'entrypoint': True,
                           'sourceRef': {'kind': 'slither_ir', 'file': 'Vault.sol', 'lines': [10, 11]}}],
            'storageAccesses': [{'storageSlot': '0x01'}],
            'operations': [{'kind': 'external_call', 'target': '0x' + '1' * 40}],
            'events': [{'topic': '0x' + 'a' * 64}]}


def bytecode_ir():
    return {'schemaVersion': 1, 'state': 'available',
            'contract': {'address': '0x' + '2' * 40, 'bytecodeClassification': {'evidence': []}},
            'functions': [{'selector': selector('deposit(uint256)'), 'name': 'selector_deposit'}],
            'operations': [{'opcode': 'CALL', 'target': '0x' + '1' * 40}],
            'storageAccesses': [{'storageSlot': '0x01'}],
            'events': [{'topic': '0x' + 'a' * 64}]}


class IRReconciliationTests(unittest.TestCase):
    def test_matching_ir_has_full_score_and_no_divergence(self):
        result = RECONCILE.reconcile(source_ir(), bytecode_ir())
        self.assertEqual(result['sourceFaithfulnessScore'], 1.0)
        self.assertEqual(result['sourceOnlyFunctions'], [])
        self.assertEqual(result['bytecodeOnlyFunctions'], [])
        self.assertEqual(result['divergentControlFlow'], [])
        self.assertFalse(result['confirmedVulnerability'])

    def test_hidden_bytecode_selector_is_reported_with_risk_hints(self):
        bytecode = bytecode_ir()
        bytecode['functions'].append({'selector': '0xdeadbeef', 'name': 'selector_deadbeef'})
        bytecode['operations'].extend([{'opcode': 'DELEGATECALL', 'targetKind': 'dynamic'}, {'opcode': 'SSTORE'}])
        bytecode['storageAccesses'].append({'slotKind': 'dynamic'})
        result = RECONCILE.reconcile(source_ir(), bytecode)
        self.assertEqual(len(result['bytecodeOnlyFunctions']), 1)
        self.assertEqual(result['bytecodeOnlyFunctions'][0]['selector'], '0xdeadbeef')
        self.assertEqual(result['bytecodeOnlyFunctions'][0]['riskHints'],
                         ['DELEGATECALL', 'NONCONSTANT_DELEGATECALL_TARGET', 'ARBITRARY_SSTORE'])

    def test_missing_source_returns_explicit_unresolved_reason(self):
        result = RECONCILE.reconcile(None, bytecode_ir())
        self.assertTrue(result['unresolved']['reason'])
        self.assertIn('source IR is missing', result['unresolved']['reason'])
        self.assertEqual(result['sourceFaithfulnessScore'], 0.0)


if __name__ == '__main__':
    unittest.main()
