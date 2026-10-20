import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('invariant_gen', ROOT / 'scripts' / 'invariant_gen.py')
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


def erc4626_fixture(decimals=18):
    functions = []
    for name in ('totalAssets()', 'totalSupply()', 'deposit(uint256)', 'withdraw(uint256)', 'redeem(uint256)', 'mint(uint256)'):
        functions.append({'name': f'Vault::Vault.{name}', 'entrypoint': True,
                          'sourceRef': {'kind': 'slither_ir', 'file': 'Vault.sol', 'lines': [10]}})
    return {'schemaVersion': 1, 'documentId': 'vault-doc',
            'contract': {'id': 'contract-id', 'name': 'Vault', 'source': 'slither_ir',
                         'sourceSha256': 'a' * 64, 'metadata': {'decimals': decimals}},
            'functions': functions,
            'storageAccesses': [
                {'effect': {'variable': 'Vault.totalAssets'}, 'sourceRef': {'kind': 'slither_ir', 'file': 'Vault.sol', 'lines': [20]}},
                {'effect': {'variable': 'Vault.totalSupply'}, 'sourceRef': {'kind': 'slither_ir', 'file': 'Vault.sol', 'lines': [21]}},
            ],
            'operations': []}


class InvariantGeneratorTests(unittest.TestCase):
    def test_erc4626_generates_five_unverified_invariants_with_parameters(self):
        result = GEN.generate_invariants(erc4626_fixture())
        self.assertEqual(result['state'], 'available')
        self.assertEqual(result['detectedRoles'], ['erc4626'])
        self.assertEqual([item['template'] for item in result['invariants']], [
            'share_price_monotonic', 'withdraw_preserves_remaining_value',
            'donation_does_not_change_ledger', 'first_deposit_no_inflation',
            'rounding_direction_correct'])
        self.assertTrue(all(item['status'] == 'unverified' for item in result['invariants']))
        self.assertTrue(all(item['generatedTestPath'] is None for item in result['invariants']))
        self.assertTrue(all(item['params']['decimals'] == 18 for item in result['invariants']))
        self.assertTrue(all(item['sourceRefs'] for item in result['invariants']))

    def test_plain_erc20_does_not_receive_defi_templates(self):
        document = erc4626_fixture()
        document['functions'] = [
            {'name': 'Token::Token.transfer(address,uint256)', 'entrypoint': True,
             'sourceRef': {'kind': 'slither_ir', 'file': 'Token.sol', 'lines': [4]}}]
        document['storageAccesses'] = [{'effect': {'variable': 'Token.balances'}}]
        result = GEN.generate_invariants(document)
        self.assertEqual(result['state'], 'template_unavailable')
        self.assertEqual(result['detectedRoles'], [])
        self.assertEqual(result['invariants'], [])
        self.assertTrue(result['unresolved'])

    def test_decimal_precision_changes_invariant_parameters_and_identity(self):
        six = GEN.generate_invariants(erc4626_fixture(6))
        eighteen = GEN.generate_invariants(erc4626_fixture(18))
        self.assertEqual(six['invariants'][0]['params']['decimals'], 6)
        self.assertEqual(eighteen['invariants'][0]['params']['decimals'], 18)
        self.assertNotEqual(six['invariants'][0]['invariantId'], eighteen['invariants'][0]['invariantId'])

    def test_lending_pool_detects_composite_features(self):
        document = erc4626_fixture(8)
        document['functions'] = [
            {'name': 'Pool::Pool.totalBorrows()', 'entrypoint': True},
            {'name': 'Pool::Pool.totalSupply()', 'entrypoint': True},
            {'name': 'Pool::Pool.healthFactor(address)', 'entrypoint': True},
            {'name': 'Pool::Pool.borrow(uint256)', 'entrypoint': True},
            {'name': 'Pool::Pool.liquidate(address)', 'entrypoint': True},
        ]
        document['storageAccesses'] = [
            {'effect': {'variable': 'Pool.totalBorrows'}},
            {'effect': {'variable': 'Pool.totalSupply'}},
        ]
        result = GEN.generate_invariants(document)
        self.assertEqual(result['detectedRoles'], ['lending_pool'])
        self.assertEqual(len(result['invariants']), 3)
        risk_params = [item['params']['riskField'] for item in result['invariants'] if 'riskField' in item['params']]
        self.assertTrue(risk_params)
        self.assertTrue(all(value == 'healthFactor' for value in risk_params))

    def test_lending_helper_named_my_total_assets_does_not_become_erc4626(self):
        document = {
            'schemaVersion': 1,
            'functions': [
                {'name': 'Pool::Pool.myTotalAssets()', 'entrypoint': True},
                {'name': 'Pool::Pool.borrow(uint256)', 'entrypoint': True},
                {'name': 'Pool::Pool.liquidate(address)', 'entrypoint': True},
            ],
            'storageAccesses': [
                {'effect': {'variable': 'Pool.totalBorrows', 'type': 'uint256'}},
                {'effect': {'variable': 'Pool.totalSupply', 'type': 'uint256'}},
                {'effect': {'variable': 'Pool.healthFactor', 'type': 'uint256'}},
            ],
        }
        result = GEN.generate_invariants(document)
        self.assertNotIn('erc4626', result['detectedRoles'])
        self.assertGreaterEqual(result['roleFeatures']['erc4626']['confidence'], 0)
        self.assertIn('function.deposit', result['roleFeatures']['erc4626']['missingFeatures'])

    def test_prefixed_erc4626_methods_and_return_types_are_recognized(self):
        document = erc4626_fixture()
        document['functions'] = [
            {'name': f'Vault::Vault.vault{name[0].upper() + name[1:]}(uint256)' if name in ('deposit', 'withdraw', 'redeem', 'mint') else f'Vault::Vault.vault{name[0].upper() + name[1:]}(uint256)',
             'returns': ['uint256'], 'entrypoint': True}
            for name in ('deposit', 'withdraw', 'redeem', 'mint', 'convertToShares', 'convertToAssets')
        ]
        document['storageAccesses'] = [
            {'effect': {'variable': 'Vault.totalAssets', 'type': 'uint256'}},
            {'effect': {'variable': 'Vault.totalSupply', 'type': 'uint256'}},
        ]
        result = GEN.generate_invariants(document)
        self.assertIn('erc4626', result['detectedRoles'])
        self.assertGreaterEqual(result['roleFeatures']['erc4626']['confidence'], 0.7)

    def test_amm_and_staking_roles_have_confidence_and_templates(self):
        amm = {
            'schemaVersion': 1,
            'functions': [
                {'name': 'Pool.swap(uint256,uint256)', 'entrypoint': True},
                {'name': 'Pool.sync()', 'entrypoint': True},
            ],
            'storageAccesses': [
                {'effect': {'variable': 'Pool.reserve0', 'type': 'uint256'}},
                {'effect': {'variable': 'Pool.reserve1', 'type': 'uint256'}},
            ],
        }
        result = GEN.generate_invariants(amm)
        self.assertIn('amm_pool', result['detectedRoles'])
        self.assertEqual([item['template'] for item in result['invariants']],
                         ['k_never_decreases', 'fee_conserved', 'oracle_assumption_holds'])
        staking = {
            'schemaVersion': 1,
            'functions': [
                {'name': 'Rewards.stake(uint256)', 'entrypoint': True},
                {'name': 'Rewards.withdraw(uint256)', 'entrypoint': True},
                {'name': 'Rewards.claimRewards()', 'entrypoint': True},
                {'name': 'Rewards.rewardPerToken()', 'entrypoint': True},
            ],
            'storageAccesses': [
                {'effect': {'variable': 'Rewards.rewardRate', 'type': 'uint256'}},
            ],
        }
        staking_result = GEN.generate_invariants(staking)
        self.assertIn('staking_reward', staking_result['detectedRoles'])
        self.assertTrue(staking_result['roleFeatures']['staking_reward']['matchedFeatures'])

    def test_low_confidence_role_is_not_returned(self):
        result = GEN.generate_invariants({'schemaVersion': 1, 'functions': [
            {'name': 'Vault.totalAssets()', 'entrypoint': True}],
            'storageAccesses': []})
        self.assertNotIn('erc4626', result['detectedRoles'])
        self.assertLess(result['roleFeatures']['erc4626']['confidence'], 0.7)


if __name__ == '__main__':
    unittest.main()
