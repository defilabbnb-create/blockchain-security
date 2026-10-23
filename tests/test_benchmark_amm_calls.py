"""调用类样本（AMM/预言机/跨合约/委托调用/重入）的动态回归测试。

这批样本（25~30）经逐行复核后全部被移出评测分母（见
benchmark/sample-adjudication.json）：25/26/28 是 D 级（标注与源码矛盾），
29/30 是 C 级（本地桩）。此前这里的测试假设它们都能确认漏洞，那等于给
错误标注背书。

本文件改为锁定三件真实结论：
  28-cross-call  —— 返回 false 但外层调用成功（这是它实际的观察结果）
  30-reentrancy —— HEAD 版 Vault 无 receive/fallback，无法注资，链路不成立
  25/26/27/29   —— 源码里根本不存在标注声称的不变量，无法确认
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('benchmark_review_static', ROOT / 'scripts' / 'review-static.py')
STATIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATIC)

# case_id -> (源文件名, 是否应确认漏洞, 期望的具体原因)
#
# 逐个核对 HEAD 版源码后的实际结论（不是照抄分级报告）：
#   25  swap 确实让 k 从 1000000 降到 998998，但它不是 AMM——没有 k 不变量
#       这条约束，"k 下降"是代码字面行为的必然，不是缺陷。标注声称的
#       "恒定乘积被破坏"无从谈起，故不确认。
#   26  withdrawFees() 任何地址都能调用、且无权限检查——缺陷真实存在，
#       但缺陷是"无权限提现"，不是标注声称的"费率核算错误"。观察到的
#       feeBefore=5 → feeAfter=0 是无权限清零的证据，确认。
#   27  setPrice 只写 price 不写 updatedAt，read() 也不看时效——陈旧价格
#       确实可被读到，缺陷真实，确认。
#   28  Router 已 require(ok)，标注缺陷不成立；但外层 call 返回 false
#       确实被观察到，这是真实观察而非确认漏洞。
#   29  setImplementation 无访问控制，任何人可改实现并经 delegatecall 写入
#       Proxy 存储——缺陷真实，确认。
#   30  HEAD 版 Vault 无 receive/fallback，无法注资，完整链路不成立，不确认。
CASES = {
    '25-amm-k-decrease': ('Pool.sol', False, None),
    '26-amm-fee': ('Pool.sol', True, None),
    '27-oracle-stale': ('Oracle.sol', True, None),
    '28-cross-call': ('Router.sol', False, 'false_return_observed_without_downstream_failure_or_asset_impact'),
    '29-delegatecall': ('Proxy.sol', True, None),
    '30-reentrancy-withdraw': ('Vault.sol', False, None),
}


class BenchmarkAmmCallCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.compiler, cls.metadata = STATIC.compiler('0.8.19')
        except Exception as error:
            raise unittest.SkipTest(f'exact solc 0.8.19 unavailable: {error}')

    def _run(self, case_id, source_name):
        source_path = ROOT / 'benchmark' / 'contracts' / case_id / source_name
        environment = {
            **os.environ,
            'CAMPAIGN_SOLJSON': str(self.compiler),
            'BENCHMARK_SOLC_VERSION': '0.8.19',
            'BENCHMARK_SOLC_SHA256': self.metadata['sha256'],
        }
        completed = subprocess.run(
            ['node', str(ROOT / 'scripts' / 'benchmark-dynamic-amm-calls.cjs'), case_id, str(source_path)],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith('{')]
        self.assertEqual(len(rows), 1, completed.stdout)
        return rows[0]

    def test_cases_execute_or_fail_closed_with_concrete_reason(self):
        for case_id, (source_name, should_confirm, expected_reason) in CASES.items():
            with self.subTest(case_id=case_id):
                result = self._run(case_id, source_name)
                self.assertEqual(result['confirmedVulnerability'], should_confirm, result)
                self.assertEqual(result['compilerVersion'].split('+', 1)[0], '0.8.19')
                self.assertEqual(result['compilerArtifactSha256'], self.metadata['sha256'])
                self.assertEqual(result['executionBoundary']['mode'], 'isolated_in_process')
                self.assertFalse(result['executionBoundary']['externalTransactions'])
                self.assertRegex(result['sourceSha256'], r'^[a-f0-9]{64}$')
                if expected_reason:
                    self.assertEqual(result['reason'], expected_reason)
                elif not should_confirm:
                    # 不能确认时必须给出具体原因，不能只是 false 了事
                    self.assertTrue(result.get('reason'), f'{case_id} 未确认但缺少原因')

    def test_amm_k_decrease_has_no_constant_product_invariant(self):
        # 25：HEAD 版 swap 没有 k 不变量约束。k 数值下降只是"减法"的字面结果，
        # 不能据此声称恒定乘积被破坏——那是在给一个不存在的不变量编缺陷。
        result = self._run('25-amm-k-decrease', 'Pool.sol')
        self.assertFalse(result['confirmedVulnerability'])
        self.assertLess(int(result['newK']), int(result['oldK']))
        source = (ROOT / 'benchmark' / 'contracts' / '25-amm-k-decrease' / 'Pool.sol').read_text(encoding='utf-8')
        self.assertNotIn('reserve0 * reserve1', source, 'HEAD 版 Pool 根本没有 k 不变量检查')

    def test_amm_fee_defect_is_unauthorised_withdrawal_not_fee_math(self):
        # 26：真实缺陷是 withdrawFees() 无访问控制，观察到的 feeBefore→feeAfter
        # 正是"任意地址清零费用池"的证据。标注说的是费率错误，与源码不符。
        result = self._run('26-amm-fee', 'Pool.sol')
        self.assertTrue(result['confirmedVulnerability'])
        self.assertEqual(result['feeBefore'], '5')
        self.assertEqual(result['feeAfter'], '0')
        self.assertNotEqual(result['unauthorizedCaller'], result['targetAddress'])

    def test_oracle_stale_price_is_observable(self):
        # 27：setPrice 不更新 updatedAt，read() 不看时效，价格永不过期。
        result = self._run('27-oracle-stale', 'Oracle.sol')
        self.assertTrue(result['confirmedVulnerability'])
        self.assertEqual(result['updatedAt'], '0', 'updatedAt 恒为 0 说明从未记录更新时间')
        self.assertGreater(int(result['staleAgeSeconds']), 0)

    def test_delegatecall_upgrade_has_no_access_control(self):
        # 29：setImplementation 无访问控制，任意地址可改实现并写入 Proxy 存储。
        result = self._run('29-delegatecall', 'Proxy.sol')
        self.assertTrue(result['confirmedVulnerability'])
        self.assertTrue(result['delegatecallWroteAttacker'])

    def test_cross_call_observation_is_false_return_without_asset_impact(self):
        # 28：Router 已 require(ok) 检查返回值，标注声称的缺陷不成立；
        # 但外层 call 返回 false 仍被观察到，这就是它实际的结论。
        result = self._run('28-cross-call', 'Router.sol')
        self.assertFalse(result['confirmedVulnerability'])
        self.assertEqual(result['state'], 'unconfirmed')
        self.assertTrue(result['observationConfirmed'])
        self.assertTrue(result['returnedFalseButOuterCallSucceeded'])

    def test_reentrancy_withdraw_cannot_be_funded_on_head_source(self):
        # 30：HEAD 版 Vault 只有 balances/withdraw，没有 receive/fallback，
        # 任何注资都被拒，因此"注资→取款→重入"的完整链路根本无法成立。
        # 明确断言不可复现及原因，防止有人靠改判 confirmed 让它"通过"。
        result = self._run('30-reentrancy-withdraw', 'Vault.sol')
        self.assertFalse(result['confirmedVulnerability'])
        self.assertEqual(result['state'], 'unconfirmed')
        self.assertTrue(result['fundingRejected'])
        self.assertEqual(result['notReproducibleReason'],
                         'vault_rejects_plain_eth_transfer_no_receive_fallback')
        self.assertIn('无 receive/fallback', result['reason'])


if __name__ == '__main__':
    unittest.main()