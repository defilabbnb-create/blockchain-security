import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "training_dynamic_unchecked", ROOT / "scripts/training-dynamic-unchecked.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TrainingDynamicUncheckedTests(unittest.TestCase):
    def test_hash_bound_harness_asserts_missing_call_and_recorded_credit_loss(self):
        self.assertEqual(MODULE.EXPECTED_SHA256,
                         "580b0f56fdf071e7d6831315c17498eb1a0e7b1d9857ebb964dcc9f9e37f3996")
        harness = (ROOT / "scripts/training-dynamic-unchecked-tokenbank.cjs").read_text(encoding="utf-8")
        source = (ROOT / "training-data/github-vulnerabilities/objects/58/580b0f56fdf071e7d6831315c17498eb1a0e7b1d9857ebb964dcc9f9e37f3996.sol").read_text(encoding="utf-8")
        self.assertIn("_addr.call.value(_wei);", source)
        for marker in ("EXPECTED_SOURCE_SHA256", "sourceBytes",
                       "rejectedPayoutAttempts", "acceptingRecipientObservation",
                       "two_withdrawals_clear_holder_credit_without_asset_transfer_or_fallback",
                       "isolated_in_process"):
            with self.subTest(marker=marker):
                self.assertIn(marker, harness)

    def test_three_run_classification_requires_source_binding_and_successful_runner(self):
        passing = {
            "state": "confirmed", "confirmedVulnerability": True,
            "sourceSha256": MODULE.EXPECTED_SHA256, "runnerExitCode": 0,
            "rejectingRecipient": {"afterSecondWithdrawal": {"holderCredit": "0"}},
            "successfulControl": {"recipientRecordedReceivedWei": "0"},
            "assertions": [{"passed": True}],
        }
        self.assertEqual(MODULE.classify_runs([passing] * 3, []), ("confirmed", True, True))
        changed = {**passing, "successfulControl": {"recipientRecordedReceivedWei": "1"}}
        self.assertEqual(MODULE.classify_runs([passing, passing, changed], []), ("flaky", False, False))
        bad_exit = {**passing, "runnerExitCode": 2}
        self.assertEqual(MODULE.classify_runs([bad_exit] * 3, []), ("unconfirmed", False, True))
        wrong_source = {**passing, "sourceSha256": "0" * 64}
        self.assertEqual(MODULE.classify_runs([wrong_source] * 3, []), ("unconfirmed", False, True))
        self.assertEqual(MODULE.classify_runs([], ["all runner executions failed"]),
                         ("harness_not_feasible", False, True))


if __name__ == "__main__":
    unittest.main()
