import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "training_dynamic_erc20_race", ROOT / "scripts/training-dynamic-erc20-race.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class TrainingDynamicErc20RaceTests(unittest.TestCase):
    def test_stable_allowance_ordering_runs_confirm(self):
        base = {"state": "confirmed", "confirmedVulnerability": True, "sourceSha256": module.EXPECTED_SHA256,
                "vulnerability": "erc20_approve_allowance_transaction_ordering",
                "additionalHolderTokenLoss": "100", "assertions": [{"passed": True}],
                "raced": {"totalSpent": "150", "allowanceAfter": "0", "oldAllowanceSpendStatus": 1,
                          "newAllowanceApprovalStatus": 1, "remainingAllowanceSpendStatus": 1,
                          "receiverBalanceGain": "150"},
                "safeOrder": {"totalSpent": "50", "allowanceAfter": "0", "oldAllowanceSpendStatus": 0,
                              "newAllowanceApprovalStatus": 1, "remainingAllowanceSpendStatus": 1,
                              "receiverBalanceGain": "50"}}
        self.assertEqual(module.classify_runs([dict(base, runnerExitCode=0) for _ in range(3)], []),
                         ("confirmed", True, True))

    def test_different_asset_effects_are_flaky(self):
        base = {"state": "confirmed", "confirmedVulnerability": True,
                "raced": {"totalSpent": "150"}, "safeOrder": {"totalSpent": "50"}}
        runs = [dict(base, runnerExitCode=0), dict(base, runnerExitCode=0),
                {**base, "runnerExitCode": 0, "raced": {"totalSpent": "149"}}]
        self.assertEqual(module.classify_runs(runs, []), ("flaky", False, False))

    def test_missing_runs_are_not_confirmed(self):
        self.assertEqual(module.classify_runs([], ["timeout"]), ("harness_not_feasible", False, True))

    def test_harness_binds_source_and_balance_effect(self):
        harness = (ROOT / "scripts/training-dynamic-erc20-race.cjs").read_text(encoding="utf-8")
        self.assertIn("TRAINING_SOURCE_SHA256", harness)
        self.assertIn("totalSpent", harness)
        self.assertIn("approve_new_then_spend", harness)
        self.assertIn("transferFrom", harness)

    def test_shard_writer_stays_under_d2_directory(self):
        sample = {"repo": module.SAMPLE[0], "commit": module.SAMPLE[1], "path": module.SAMPLE[2],
                  "sha256": module.EXPECTED_SHA256}
        analysis = {"dynamic": "passed", "dynamicReason": "test", "confirmedVulnerability": True}
        previous = module.SHARDS
        with tempfile.TemporaryDirectory() as directory:
            try:
                module.SHARDS = Path(directory) / "D2-transaction-ordering"
                shard = module.write_d2_shard(sample, analysis)
                self.assertTrue(shard.is_relative_to(module.SHARDS))
                self.assertTrue((module.SHARDS / "history").exists())
            finally:
                module.SHARDS = previous


if __name__ == "__main__":
    unittest.main()
