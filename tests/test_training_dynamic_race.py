import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("training_dynamic_race", ROOT / "scripts/training-dynamic-race.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class TrainingDynamicRaceTests(unittest.TestCase):
    def test_three_stable_asset_effect_runs_confirm(self):
        base = {"state": "confirmed", "confirmedVulnerability": True, "sourceSha256": module.EXPECTED_SHA256,
                "vulnerability": "transaction_ordering_price_front_run", "assertions": [{"passed": True}],
                "victimAdditionalTokenLoss": "100", "sequences": {
                    "buyFirst": {"tokenTransferToOwner": "100", "tokenLossByBuyer": "100",
                                 "contractEthBalanceWei": "200", "currentPrice": "100",
                                 "staleOwnerChangeReverted": True},
                    "priceChangeFirst": {"tokenTransferToOwner": "200", "tokenLossByBuyer": "200",
                                         "contractEthBalanceWei": "200", "currentPrice": "200"}}}
        runs = [dict(base, runnerExitCode=0) for _ in range(3)]
        self.assertEqual(module.classify_runs(runs, []), ("confirmed", True, True))

    def test_flaky_if_asset_effects_disagree(self):
        base = {"state": "confirmed", "confirmedVulnerability": True, "sourceSha256": module.EXPECTED_SHA256,
                "sequences": {"buyFirst": {"tokenLossByBuyer": "100"}, "priceChangeFirst": {"tokenLossByBuyer": "200"}}}
        runs = [dict(base, runnerExitCode=0) for _ in range(2)] + [
            {**base, "runnerExitCode": 0, "sequences": {"buyFirst": {"tokenLossByBuyer": "100"},
                                                       "priceChangeFirst": {"tokenLossByBuyer": "201"}}}]
        self.assertEqual(module.classify_runs(runs, []), ("flaky", False, False))

    def test_missing_runs_are_not_confirmed(self):
        self.assertEqual(module.classify_runs([], ["timeout"]), ("harness_not_feasible", False, True))

    def test_harness_binds_original_source_and_assets(self):
        harness = (ROOT / "scripts/training-dynamic-race.cjs").read_text(encoding="utf-8")
        self.assertIn(module.EXPECTED_SHA256, (ROOT / "training-data/github-vulnerabilities/manifest.json").read_text())
        self.assertIn("TRAINING_SOURCE_SHA256", harness)
        self.assertIn("victimAdditionalTokenLoss", harness)
        self.assertIn("staleOwnerChangeReverted", harness)
        self.assertIn("transactions.push", harness)
        self.assertIn("transaction_ordering_price_front_run", harness)


if __name__ == "__main__":
    unittest.main()
