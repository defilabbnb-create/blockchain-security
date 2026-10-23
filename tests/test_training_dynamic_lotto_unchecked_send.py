import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "training_dynamic_lotto_unchecked_send", ROOT / "scripts/training-dynamic-lotto-unchecked-send.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class TrainingDynamicLottoTests(unittest.TestCase):
    def result(self, **overrides):
        value = {
            "state": "confirmed", "confirmedVulnerability": True,
            "sourceSha256": module.EXPECTED_SHA256, "selectedSubpot": "4", "prizeWei": "5000000000000000000",
            "assertions": [{"passed": True}],
            "rejectingWinner": {"sendStatus": 1, "isCashed": True,
                "potBeforeWei": "160000000000000000000", "balanceBeforeWei": "160000000000000000000",
                "balanceAfterWei": "160000000000000000000", "recipientBalanceAfterWei": "0",
                "balanceAfterRetryWei": "160000000000000000000"},
            "acceptingControl": {"sendStatus": 1, "isCashed": True,
                "potBeforeWei": "160000000000000000000", "balanceBeforeWei": "160000000000000000000",
                "balanceAfterWei": "155000000000000000000", "recipientBalanceAfterWei": "5000000000000000000",
                "receivedWei": "5000000000000000000"},
            "runnerExitCode": 0,
        }
        value.update(overrides)
        return value

    def test_three_consistent_failed_payout_and_success_control_runs_confirm(self):
        runs = [self.result() for _ in range(3)]
        self.assertEqual(module.classify_runs(runs, []), ("confirmed", True, True))

    def test_asset_or_subpot_disagreement_is_flaky(self):
        runs = [self.result() for _ in range(2)] + [self.result(selectedSubpot="5")]
        self.assertEqual(module.classify_runs(runs, []), ("flaky", False, False))

    def test_missing_runs_do_not_confirm(self):
        self.assertEqual(module.classify_runs([], ["timeout"]), ("harness_not_feasible", False, True))

    def test_harness_binds_source_and_retries_failed_payout(self):
        harness = (ROOT / "scripts/training-dynamic-lotto-unchecked-send.cjs").read_text()
        self.assertIn(module.EXPECTED_SHA256, harness)
        self.assertIn("TRAINING_SOURCE_SHA256", harness)
        self.assertIn("cash_retry_cannot_recover_failed_payout", harness)
        self.assertIn("accepting_winner_control_receives_same_prize", harness)


if __name__ == "__main__":
    unittest.main()
