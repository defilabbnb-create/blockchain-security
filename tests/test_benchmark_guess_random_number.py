import hashlib
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


class BenchmarkGuessRandomNumberTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.compiler, cls.metadata = STATIC.compiler('0.4.21')
        except Exception as error:
            raise unittest.SkipTest(f'exact solc 0.4.21 unavailable: {error}')

    def test_observable_deployment_inputs_predict_answer_and_drain_seeded_prize(self):
        source_path = ROOT / 'benchmark' / 'contracts' / '08-guess_the_random_number' / 'guess_the_random_number.sol'
        source = source_path.read_bytes()
        environment = {
            **os.environ,
            'CAMPAIGN_SOLJSON': str(self.compiler),
            'BENCHMARK_SOLC_VERSION': '0.4.21',
            'BENCHMARK_SOLC_SHA256': self.metadata['sha256'],
            'DYNAMIC_EXECUTION_MODE': 'isolated_in_process',
        }
        completed = subprocess.run(
            ['node', str(ROOT / 'scripts' / 'benchmark-dynamic-predictable-randomness.cjs'),
             '08-guess_the_random_number', str(source_path)],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith('{')]
        self.assertEqual(len(rows), 1, completed.stdout)
        row = rows[0]
        self.assertEqual(row['caseId'], '08-guess_the_random_number')
        self.assertEqual(row['state'], 'passed')
        self.assertTrue(row['confirmedVulnerability'], row)
        self.assertEqual(row['vulnerability'], 'bad_randomness')
        self.assertEqual(row['proofScope'], 'attacker_profit_and_contract_balance_depletion')
        self.assertEqual(row['sourceSha256'], hashlib.sha256(source).hexdigest())
        self.assertEqual(row['compilerVersion'].split('+', 1)[0], '0.4.21')
        self.assertEqual(row['compilerArtifactSha256'], self.metadata['sha256'])
        self.assertRegex(row['randomnessSourceBlockHash'], re.compile(r'^0x[a-f0-9]{64}$'))
        self.assertGreaterEqual(row['predictedAnswer'], 0)
        self.assertLessEqual(row['predictedAnswer'], 255)
        self.assertEqual(row['targetBalanceBeforeGuessWei'], str(10**18))
        self.assertEqual(row['targetBalanceAfterGuessWei'], '0')
        self.assertTrue(row['isComplete'])
        self.assertEqual(row['attackerNetProfitWei'], row['expectedNetProfitWei'])
        self.assertEqual(int(row['attackerGrossProfitWei']), 10**18)
        self.assertGreater(int(row['guessGasCostWei']), 0)
        self.assertEqual(int(row['attackerNetProfitWei']), 10**18 - int(row['guessGasCostWei']))
        self.assertGreater(int(row['attackerNetProfitWei']), 0)
        self.assertEqual(row['executionBoundary']['mode'], 'isolated_in_process')
        self.assertEqual(row['executionBoundary']['chainId'], 31337)
        self.assertFalse(row['executionBoundary']['externalTransactions'])
        self.assertEqual(len(row['transactionHashes']), 2)
        self.assertTrue(all(row['transactionHashes']))


if __name__ == '__main__':
    unittest.main()
