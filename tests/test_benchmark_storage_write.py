import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'benchmark_review_static', ROOT / 'scripts' / 'review-static.py')
STATIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATIC)


class BenchmarkStorageWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.compiler, cls.metadata = STATIC.compiler('0.4.25')
        except Exception as error:
            raise unittest.SkipTest(f'exact solc 0.4.25 unavailable: {error}')

    def test_array_length_underflow_overwrites_owner_and_withdraws_target_balance(self):
        source = ROOT / 'benchmark' / 'contracts' / '01-arbitrary_location_write_simple' / 'arbitrary_location_write_simple.sol'
        environment = {
            **os.environ,
            'CAMPAIGN_SOLJSON': str(self.compiler),
            'BENCHMARK_SOLC_VERSION': '0.4.25',
            'BENCHMARK_SOLC_SHA256': self.metadata['sha256'],
            'DYNAMIC_EXECUTION_MODE': 'isolated_in_process',
        }
        completed = subprocess.run(
            ['node', str(ROOT / 'scripts' / 'benchmark-dynamic-storage-write.cjs'),
             '01-arbitrary_location_write_simple', str(source)],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip().startswith('{')]
        self.assertEqual(len(rows), 1, completed.stdout)
        result = rows[0]
        self.assertEqual(result['caseId'], '01-arbitrary_location_write_simple')
        self.assertEqual(result['state'], 'passed')
        self.assertTrue(result['confirmedVulnerability'])
        self.assertEqual(result['vulnerability'], 'access_control')
        self.assertEqual(result['proofScope'], 'attacker_owner_takeover_and_contract_balance_drain')
        self.assertEqual(result['compilerVersion'].split('+', 1)[0], '0.4.25')
        self.assertEqual(result['compilerArtifactSha256'], self.metadata['sha256'])
        self.assertEqual(result['sourceSha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(result['ownerStorageSlot'], '1')
        self.assertEqual(result['arrayLengthBefore'], '0')
        self.assertEqual(int(result['arrayLengthAfter']), 2**256 - 1)
        self.assertNotEqual(int(result['ownerIndex']), 2**256 - 1)
        self.assertEqual(result['ownerBefore'], result['ownerAddress'].lower())
        self.assertEqual(result['ownerAfterWrite'], result['attackerAddress'].lower())
        self.assertEqual(int(result['targetBalanceBeforeWei']), 10**18)
        self.assertEqual(int(result['targetBalanceAfterWei']), 0)
        self.assertEqual(int(result['attackerNetProfitWei']), 10**18)
        self.assertGreater(int(result['attackGasCostWei']), 0)
        self.assertEqual(len(result['transactionHashes']), 5)
        self.assertEqual(result['transactionStatuses'], [1, 1, 1, 1, 1])
        self.assertTrue(all(re.fullmatch(r'0x[a-fA-F0-9]{64}', value)
                            for value in result['transactionHashes']))
        self.assertEqual(result['executionBoundary']['mode'], 'isolated_in_process')
        self.assertEqual(result['executionBoundary']['chainId'], 31337)
        self.assertFalse(result['executionBoundary']['externalTransactions'])
        self.assertEqual(result['executionBoundary']['networkWrites'], 'local_only')


if __name__ == '__main__':
    unittest.main()
