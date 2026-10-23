import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("training_dynamic_odds", ROOT / "scripts/training-dynamic-odds.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class TrainingDynamicOddsTests(unittest.TestCase):
    def test_stable_front_run_payout_runs_confirm(self):
        base = {"state": "confirmed", "confirmedVulnerability": True, "sourceSha256": module.EXPECTED_SHA256,
                "vulnerability": "transaction_ordering_front_run_game_choice",
                "attackerAssetGainComparedToBlind": "1800000000000000000", "assertions": [{"passed": True}],
                "frontRun": {"attackerReceivedWei": "1800000000000000000", "victimReceivedWei": "0",
                             "attackerPlayBlock": 4, "victimPlayBlock": 5, "gameBalanceWei": "200000000000000000",
                             "emptyAfterRound": True, "transactionsSucceeded": True},
                "blindControl": {"attackerReceivedWei": "0", "victimReceivedWei": "1800000000000000000",
                                 "attackerPlayBlock": 8, "victimPlayBlock": 9, "gameBalanceWei": "200000000000000000",
                                 "emptyAfterRound": True, "transactionsSucceeded": True}}
        runs = [dict(base, runnerExitCode=0) for _ in range(3)]
        self.assertEqual(module.classify_runs(runs, []), ("confirmed", True, True))

    def test_effect_disagreement_is_flaky(self):
        base = {"state": "confirmed", "confirmedVulnerability": True, "sourceSha256": module.EXPECTED_SHA256,
                "frontRun": {"attackerReceivedWei": "1800000000000000000", "victimReceivedWei": "0"},
                "blindControl": {"attackerReceivedWei": "0", "victimReceivedWei": "1800000000000000000"}}
        runs = [dict(base, runnerExitCode=0), dict(base, runnerExitCode=0),
                {**base, "runnerExitCode": 0, "frontRun": {"attackerReceivedWei": "0", "victimReceivedWei": "1800000000000000000"}}]
        self.assertEqual(module.classify_runs(runs, []), ("flaky", False, False))

    def test_missing_runs_are_not_confirmed(self):
        self.assertEqual(module.classify_runs([], ["timeout"]), ("harness_not_feasible", False, True))

    def test_harness_binds_source_and_payout_effect(self):
        harness = (ROOT / "scripts/training-dynamic-odds.cjs").read_text(encoding="utf-8")
        self.assertIn(module.EXPECTED_SHA256, (ROOT / "training-data/github-vulnerabilities/manifest.json").read_text())
        self.assertIn("TRAINING_SOURCE_SHA256", harness)
        self.assertIn("attackerReceivedWei", harness)
        self.assertIn("blindControl", harness)
        self.assertIn("eth_getBalance", harness)
        self.assertIn("transactions: [...frontRun.transactions, ...blindControl.transactions]", harness)
        self.assertIn("transaction_ordering_front_run_game_choice", harness)


if __name__ == "__main__":
    unittest.main()
