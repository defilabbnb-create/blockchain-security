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
    ground_truth = json.loads((case_dir / 'ground-truth.json').read_text(encoding='utf-8'))
    if ground_truth.get('solcVersion') != '0.8.19' or ground_truth.get('clean') is not True:
        raise AssertionError(f'{case_id} is not pinned as a clean 0.8.19 control')
    source_path = case_dir / ground_truth['sourceFile']
    compiler, metadata = REVIEW.compiler('0.8.19')
    environment = {
        **os.environ,
        'CAMPAIGN_SOLJSON': str(compiler),
        'BENCHMARK_SOLC_VERSION': '0.8.19',
        'BENCHMARK_SOLC_SHA256': metadata['sha256'],
    }
    completed = subprocess.run(
        ['node', str(ROOT / 'scripts' / 'benchmark-dynamic-clean-controls.cjs'), case_id, str(source_path)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60, check=False,
    )
    rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip().startswith('{')]
    if not rows:
        raise AssertionError(completed.stdout + completed.stderr)
    return completed, rows[-1]


class BenchmarkCleanControlTests(unittest.TestCase):
    def test_clean_vault_preserves_accounting_and_rejects_invalid_edges(self):
        completed, result = run_case('31-clean-vault')
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(result['state'], 'control_passed')
        self.assertTrue(result['controlPassed'])
        self.assertFalse(result['confirmedVulnerability'])
        self.assertEqual(result['observations'], {'shares': '3', 'totalAssets': '3'})
        self.assertEqual(len(result['transactionHashes']), 3)
        self.assertTrue(all(item['rejected'] for item in result['rejectedActions']))
        self.assertEqual(result['executionBoundary']['networkWrites'], 'local_only')
        self.assertTrue(result['sourceSha256'])

    def test_clean_lending_preserves_collateralization_and_rejects_edges(self):
        completed, result = run_case('32-clean-lending')
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(result['state'], 'control_passed')
        self.assertTrue(result['controlPassed'])
        self.assertFalse(result['confirmedVulnerability'])
        self.assertEqual(result['observations'], {
            'collateral': '100', 'debt': '40', 'healthFactor': '2500000000000000000',
        })
        self.assertEqual(len(result['transactionHashes']), 4)
        self.assertTrue(all(item['rejected'] for item in result['rejectedActions']))
        self.assertEqual(result['executionBoundary']['networkWrites'], 'local_only')
        self.assertTrue(result['sourceSha256'])

    def test_clean_amm_executes_a_valid_swap_and_rejects_outputs_without_input(self):
        completed, result = run_case('33-clean-amm')
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(result['state'], 'control_passed')
        self.assertTrue(result['controlPassed'])
        self.assertFalse(result['confirmedVulnerability'])
        self.assertFalse(result['invalidControl'])
        self.assertIsNone(result['reason'])
        self.assertTrue(result['observations']['validSwapSucceeded'])
        # HEAD 版 swap 只减储备并要求 k 不下降，因此只有零额取出能成功：
        # 储备与 k 都不变，任何非零取出都被恒定乘积检查拒绝。
        self.assertEqual(result['observations']['reserve0Before'], '100')
        self.assertEqual(result['observations']['reserve1Before'], '100')
        self.assertEqual(result['observations']['reserve0After'], '100')
        self.assertEqual(result['observations']['reserve1After'], '100')
        self.assertEqual(result['observations']['swapSignature'], 'swap(uint256,uint256)')
        self.assertEqual(result['observations']['newK'], result['observations']['oldK'])
        self.assertEqual([item['label'] for item in result['rejectedActions']],
                         ['output_without_input', 'empty_swap', 'nonzero_output_rejected'])
        self.assertTrue(all(item['rejected'] for item in result['rejectedActions']))


if __name__ == '__main__':
    unittest.main()
