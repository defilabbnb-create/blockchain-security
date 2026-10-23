"""ERC4626 / 借贷类样本的动态行为回归测试。

背景：这批样本（21/22/23/24）的标注经逐行复核后被判定为与源码矛盾
（见 benchmark/sample-adjudication.json，D 级），并已移出评测分母。此前这里的
测试反过来断言"缺陷存在"，那是在给错误标注背书——例如 22 的实现是标准
round-up，正是 EIP-4626 要求的正确方向，根本不存在舍入损失。

本文件改为锁定否证结论：这些样本在本地跑起来确实无法复现漏洞。
断言"缺陷不存在"和断言"缺陷存在"同样重要，否则改回错误标注时无人察觉。
样本与 ground-truth 都不动，只改这里的预期。
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "review_static_compiler", ROOT / "scripts" / "review-static.py")
COMPILER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPILER_MODULE)


def run_case(case_id):
    """在隔离进程里跑动态用例，返回 (result, ground_truth)。"""
    case_dir = ROOT / "benchmark" / "contracts" / case_id
    ground_truth = json.loads((case_dir / "ground-truth.json").read_text(encoding="utf-8"))
    source_path = case_dir / ground_truth["sourceFile"]
    source = source_path.read_bytes()
    compiler_path, metadata = COMPILER_MODULE.compiler(ground_truth["solcVersion"])
    environment = {
        **os.environ,
        "CAMPAIGN_SOLJSON": str(compiler_path),
        "BENCHMARK_SOLC_VERSION": ground_truth["solcVersion"],
        "BENCHMARK_SOLC_SHA256": metadata["sha256"],
    }
    completed = subprocess.run(
        ["node", str(ROOT / "scripts" / "benchmark-dynamic-vault-lending.cjs"), case_id, str(source_path)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    rows = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith("{")]
    if len(rows) != 1:
        raise AssertionError(f"expected one JSON result row, got {len(rows)}: {completed.stdout}")
    row = rows[0]
    # 证据必须绑定当前源码，否则断言的是另一份代码的行为
    assert row["sourceSha256"] == hashlib.sha256(source).hexdigest()
    assert row["compilerSha256"] == metadata["sha256"]
    assert row["executionBoundary"]["chainId"] == 31337
    assert row["executionBoundary"]["externalTransactions"] is False
    return row, ground_truth


class UnscoredVaultLendingTests(unittest.TestCase):
    """锁定 D/C 级样本的否证结论。"""

    def test_donation_sample_is_marked_excluded_and_not_a_vulnerable_fixture(self):
        # 21：donate 同增 totalAssets 与 totalSupply，份额价格不变，攻击不成立
        _, ground_truth = run_case("21-erc4626-donation")
        self.assertEqual(ground_truth["excludedReason"]["grade"], "D")

    def test_rounding_sample_implements_the_correct_direction(self):
        # 22：(x*s + a - 1)/a 是标准 round-up，正是 EIP-4626 要求的方向
        source = (ROOT / "benchmark" / "contracts" / "22-erc4626-rounding" / "Vault.sol").read_text(
            encoding="utf-8")
        self.assertIn("totalAssets - 1", source)
        self.assertIn("/ totalAssets", source)
        _, ground_truth = run_case("22-erc4626-rounding")
        self.assertEqual(ground_truth["excludedReason"]["grade"], "D")

    def test_health_factor_sample_has_no_liquidation_threshold(self):
        # 23：只有 collateral/(debt+1)，无阈值、无清算、无价格源
        _, ground_truth = run_case("23-lending-health-factor")
        self.assertEqual(ground_truth["excludedReason"]["grade"], "D")

    def test_bad_debt_defect_is_locally_reproducible(self):
        # 24：这是本批里唯一缺陷真实存在的样本。repay=0 时 debt 保持 1000 未冲减，
        # 全额 1000 被记入 badDebt——本地跑通的前后对比就是证据。
        row, ground_truth = run_case("24-lending-bad-debt")
        self.assertEqual(ground_truth["excludedReason"]["grade"], "C")
        probe = row["badDebtProbe"]
        self.assertTrue(probe["debtNotReduced"], f"repay=0 不应冲减债务：{probe}")
        self.assertTrue(probe["badDebtRecorded"], f"剩余全额应记入坏账：{probe}")
        self.assertTrue(probe["defectReproduced"], f"缺陷应可复现：{probe}")
        self.assertEqual(probe["debtBefore"], probe["debtAfter"])
        self.assertEqual(probe["badDebtAfter"], probe["debtBefore"])
        # 该样本仍因"本地桩"判 C 级而移出分母，但缺陷本身是真的
        self.assertEqual(row["confirmedVulnerability"], False)

    def test_excluded_samples_never_enter_the_coverage_denominator(self):
        """被剔除的样本不得出现在可评分集合里——这是防止错误标注回流的关键一环。"""
        report_path = ROOT / "benchmark" / "coverage-report.json"
        if not report_path.is_file():
            self.skipTest("coverage-report.json 尚未生成")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        scored = {c["caseId"] for c in report.get("pocEvidenceSplit", {}).get(
            "withReproduction", {}).get("cases", [])}
        for case_id in ("21-erc4626-donation", "22-erc4626-rounding", "23-lending-health-factor",
                        "24-lending-bad-debt", "25-amm-k-decrease", "26-amm-fee", "28-cross-call",
                        "29-delegatecall", "30-reentrancy-withdraw"):
            self.assertNotIn(case_id, scored, f"{case_id} 已剔除，不应出现在可评分集合")


if __name__ == "__main__":
    unittest.main()