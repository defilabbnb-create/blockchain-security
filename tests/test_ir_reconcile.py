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

    def test_opcode_risk_hints_are_bound_to_function_pc_ranges(self):
        source = source_ir()
        source['functions'] = []
        bytecode = bytecode_ir()
        deposit_selector = selector('deposit(uint256)')
        withdraw_selector = selector('withdraw(uint256)')
        bytecode['functions'] = [
            {'selector': deposit_selector, 'name': 'selector_deposit'},
            {'selector': withdraw_selector, 'name': 'selector_withdraw'},
        ]
        bytecode['basicBlocks'] = [
            {'id': 'deposit-block', 'startPc': 0, 'endPc': 9},
            {'id': 'withdraw-block', 'startPc': 10, 'endPc': 19},
        ]
        bytecode['selectorDispatch'] = [
            {'selector': deposit_selector, 'basicBlockId': 'deposit-block'},
            {'selector': withdraw_selector, 'basicBlockId': 'withdraw-block'},
        ]
        bytecode['instructions'] = [
            {'pc': 2, 'opcode': 'SLOAD'},
            {'pc': 12, 'opcode': 'DELEGATECALL', 'targetKind': 'dynamic'},
            {'pc': 14, 'opcode': 'SSTORE', 'slotKind': 'dynamic'},
        ]
        result = RECONCILE.reconcile(source, bytecode)
        self.assertEqual(result['granularity'], 'function')
        self.assertEqual(result['unattributedOpcodes'], [])
        rows = {row['selector']: row for row in result['bytecodeOnlyFunctions']}
        self.assertEqual(rows[deposit_selector]['riskHints'], [])
        self.assertEqual(rows[withdraw_selector]['riskHints'],
                         ['DELEGATECALL', 'NONCONSTANT_DELEGATECALL_TARGET', 'ARBITRARY_SSTORE'])

    def test_missing_dispatch_ranges_falls_back_to_contract_granularity(self):
        bytecode = bytecode_ir()
        bytecode['functions'].append({'selector': '0xdeadbeef', 'name': 'selector_deadbeef'})
        bytecode['instructions'] = [{'pc': 10, 'opcode': 'DELEGATECALL', 'targetKind': 'dynamic'}]
        result = RECONCILE.reconcile(source_ir(), bytecode)
        self.assertEqual(result['granularity'], 'contract')
        self.assertIn('DELEGATECALL', result['bytecodeOnlyFunctions'][0]['riskHints'])
        self.assertTrue(any(item['kind'] == 'delegatecall_target' for item in result['unresolved']['details']))

    def test_unassigned_opcode_is_explicitly_unresolved(self):
        bytecode = bytecode_ir()
        bytecode['functions'] = [{'selector': selector('deposit(uint256)'), 'name': 'selector_deposit'}]
        bytecode['basicBlocks'] = [{'id': 'deposit', 'startPc': 0, 'endPc': 3}]
        bytecode['selectorDispatch'] = [{'selector': selector('deposit(uint256)'), 'basicBlockId': 'deposit'}]
        bytecode['instructions'] = [{'pc': 9, 'opcode': 'SELFDESTRUCT'}]
        result = RECONCILE.reconcile(source_ir(), bytecode)
        self.assertEqual(result['granularity'], 'function')
        self.assertEqual(result['unattributedOpcodes'][0]['opcode'], 'SELFDESTRUCT')
        self.assertEqual(result['unresolved']['details'][-1]['kind'], 'unattributed_opcodes')


if __name__ == '__main__':
    unittest.main()
