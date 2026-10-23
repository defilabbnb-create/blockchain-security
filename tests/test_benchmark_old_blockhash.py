import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('benchmark_review_static', ROOT / 'scripts' / 'review-static.py')
STATIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATIC)


class BenchmarkOldBlockhashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.compiler, cls.metadata = STATIC.compiler('0.4.24')
        except Exception as error:
            raise unittest.SkipTest(f'exact solc 0.4.24 unavailable: {error}')

    def test_expired_blockhash_guess_pays_out_and_makes_positive_net_profit(self):
        source = ROOT / 'benchmark' / 'contracts' / '09-old_blockhash' / 'old_blockhash.sol'
        environment = {
            **os.environ,
            'CAMPAIGN_SOLJSON': str(self.compiler),
            'BENCHMARK_SOLC_VERSION': '0.4.24',
            'BENCHMARK_SOLC_SHA256': self.metadata['sha256'],
        }
        completed = subprocess.run(
            ['node', str(ROOT / 'scripts' / 'benchmark-dynamic-old-blockhash.cjs'),
             '09-old_blockhash', str(source)],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith('{')]
        self.assertEqual(len(rows), 1, completed.stdout)
        result = rows[0]
        self.assertEqual(result['caseId'], '09-old_blockhash')
        self.assertTrue(result['confirmedVulnerability'], result)
        self.assertEqual(result['state'], 'passed')
        self.assertEqual(result['vulnerability'], 'bad_randomness')
        self.assertEqual(result['proofScope'], 'attacker_profit_and_contract_balance_depletion')
        self.assertEqual(result['guessedValue'], '0x' + '00' * 32)
        self.assertEqual(result['compilerVersion'].split('+', 1)[0], '0.4.24')
        self.assertEqual(result['compilerArtifactSha256'], self.metadata['sha256'])
        self.assertRegex(result['sourceSha256'], re.compile(r'^[a-f0-9]{64}$'))
        self.assertEqual(result['executionBoundary']['mode'], 'isolated_in_process')
        self.assertEqual(result['executionBoundary']['chainId'], 31337)
        self.assertFalse(result['executionBoundary']['externalTransactions'])
        self.assertEqual(int(result['ageBeforeSettlement']), 256)
        self.assertEqual(int(result['ageAtSettlement']), 257)
        self.assertEqual(int(result['targetSeedBalanceWei']), 10**18)
        self.assertEqual(int(result['targetBalanceBeforeSettlementWei']), 2 * 10**18)
        self.assertEqual(int(result['targetBalanceAfterSettlementWei']), 0)
        self.assertEqual(int(result['attackerNetProfitWei']), 10**18)
        self.assertEqual(result['attackerNetProfitWei'], result['expectedNetProfitWei'])
        self.assertEqual(len(result['transactionHashes']), 3)
        self.assertTrue(all(result['transactionHashes']))


if __name__ == '__main__':
    unittest.main()
