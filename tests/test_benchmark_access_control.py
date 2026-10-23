import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('review_static_compiler', ROOT / 'scripts' / 'review-static.py')
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)


def run_case(case_id):
    case_dir = ROOT / 'benchmark' / 'contracts' / case_id
    truth = json.loads((case_dir / 'ground-truth.json').read_text(encoding='utf-8'))
    source_path = case_dir / truth['sourceFile']
    compiler, metadata = REVIEW.compiler(truth['solcVersion'])
    environment = {
        **os.environ,
        'CAMPAIGN_SOLJSON': str(compiler),
        'BENCHMARK_SOLC_VERSION': truth['solcVersion'],
        'BENCHMARK_SOLC_SHA256': metadata['sha256'],
        'DYNAMIC_EXECUTION_MODE': 'isolated_in_process',
    }
    completed = subprocess.run(
        ['node', str(ROOT / 'scripts' / 'benchmark-dynamic-access-control.cjs'), case_id, str(source_path)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90, check=False,
    )
    rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip().startswith('{')]
    if not rows:
        raise AssertionError(completed.stdout + completed.stderr)
    return completed, rows[-1], source_path.read_bytes(), metadata


class BenchmarkAccessControlDynamicTests(unittest.TestCase):
    def assert_takeover_withdrawal(self, case_id, takeover):
        completed, row, source, compiler = run_case(case_id)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(row['caseId'], case_id)
        self.assertEqual(row['state'], 'passed')
        self.assertTrue(row['confirmedVulnerability'])
        self.assertEqual(row['proofScope'], 'unauthorized_ownership_takeover_and_asset_withdrawal')
        self.assertEqual(row['sourceSha256'], hashlib.sha256(source).hexdigest())
        self.assertEqual(row['compilerVersion'].split('+', 1)[0], compiler['version'])
        self.assertEqual(row['compilerArtifactSha256'], compiler['sha256'])
        self.assertTrue(row['unauthorizedWithdrawRejected'])
        self.assertEqual(row['ownerAfter'], row['attackerAddress'].lower())
        self.assertEqual(row['beforeTargetBalanceWei'], '1000000000000000000')
        self.assertEqual(row['afterTargetBalanceWei'], '0')
        self.assertEqual(row['attackerReceivedWei'], '1000000000000000000')
        self.assertEqual(row['attackStatus'], 1)
        self.assertEqual(row['executionBoundary']['mode'], 'isolated_in_process')
        self.assertEqual(row['executionBoundary']['chainId'], 31337)
        self.assertFalse(row['executionBoundary']['externalTransactions'])
        self.assertEqual(len(row['transactionHashes']), 4)
        self.assertIn(takeover, row['reproduction'])

    def test_incorrect_constructor_name_1_allows_ownership_takeover_and_withdrawal(self):
        self.assert_takeover_withdrawal('02-incorrect_constructor_name1', 'IamMissing')

    def test_incorrect_constructor_name_2_allows_ownership_takeover_and_withdrawal(self):
        self.assert_takeover_withdrawal('03-simple_suicide', 'missing')

    def test_unprotected_change_owner_allows_unauthorized_owner_reassignment(self):
        completed, row, source, compiler = run_case('04-unprotected0')
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(row['caseId'], '04-unprotected0')
        self.assertEqual(row['state'], 'passed')
        self.assertTrue(row['confirmedVulnerability'])
        self.assertEqual(row['proofScope'], 'unauthorized_owner_reassignment')
        self.assertEqual(row['sourceSha256'], hashlib.sha256(source).hexdigest())
        self.assertEqual(row['compilerVersion'].split('+', 1)[0], compiler['version'])
        self.assertEqual(row['compilerArtifactSha256'], compiler['sha256'])
        self.assertNotEqual(row['ownerBefore'], '0x0000000000000000000000000000000000000000')
        self.assertNotEqual(row['ownerBefore'], row['ownerAfter'])
        self.assertEqual(row['ownerAfterTakeover'], row['attackerAddress'].lower())
        self.assertEqual(row['ownerAfter'], row['attackerAddress'].lower())
        self.assertTrue(row['unauthorizedOwnerChangeSucceeded'])
        self.assertIsNone(row['unauthorizedWithdrawRejected'])
        self.assertEqual(row['beforeTargetBalanceWei'], '0')
        self.assertEqual(row['afterTargetBalanceWei'], '0')
        self.assertEqual(row['attackerReceivedWei'], '0')
        self.assertEqual(row['attackStatus'], 1)
        self.assertEqual(row['executionBoundary']['mode'], 'isolated_in_process')
        self.assertEqual(row['executionBoundary']['chainId'], 31337)
        self.assertFalse(row['executionBoundary']['externalTransactions'])
        self.assertEqual(len(row['transactionHashes']), 2)
        self.assertIn('changeOwner', row['reproduction'])


if __name__ == '__main__':
    unittest.main()
