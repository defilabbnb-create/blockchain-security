import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("training_dynamic_kotet", ROOT / "scripts/training-dynamic-kotet.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class TrainingDynamicKotetTests(unittest.TestCase):
    def test_three_stable_state_and_asset_runs_confirm(self):
        evidence = {"sourceSha256": module.EXPECTED_SHA256, "state": "confirmed",
                    "confirmedVulnerability": True, "vulnerability": "unchecked_compensation_send_with_state_advance",
                    "scenarios": {"rejecting": {"contractBalanceAfterWei": "250", "receiverIncreaseWei": "0"},
                                  "accepting": {"contractBalanceAfterWei": "101.5", "receiverIncreaseWei": "148.5"}},
                    "assertions": [{"passed": True}], "runnerExitCode": 0}
        self.assertEqual(module.classify_runs([dict(evidence) for _ in range(3)], []),
                         ("confirmed", True, True))

    def test_disagreeing_asset_state_is_flaky(self):
        base = {"sourceSha256": module.EXPECTED_SHA256, "state": "confirmed",
                "confirmedVulnerability": True, "scenarios": {"rejecting": {"receiverIncreaseWei": "0"}},
                "runnerExitCode": 0}
        rows = [dict(base) for _ in range(2)] + [{**base, "scenarios": {"rejecting": {"receiverIncreaseWei": "1"}}}]
        self.assertEqual(module.classify_runs(rows, []), ("flaky", False, False))

    def test_missing_run_is_not_promoted(self):
        self.assertEqual(module.classify_runs([], ["compile failed"]), ("harness_not_feasible", False, True))

    def test_nonpayable_exact_source_is_not_called_a_confirmed_issue(self):
        record = {"sourceSha256": module.EXPECTED_SHA256, "state": "harness_not_feasible",
                  "confirmedVulnerability": False,
                  "reason": "collected_claim_and_fallback_entrypoints_are_nonpayable", "runnerExitCode": 0}
        self.assertEqual(module.classify_runs([dict(record) for _ in range(3)], []),
                         ("harness_not_feasible", False, True))

    def test_harness_hash_binds_original_source_and_asserts_state_and_eth(self):
        harness = (ROOT / "scripts/training-dynamic-kotet.cjs").read_text(encoding="utf-8")
        self.assertIn(module.EXPECTED_SHA256, harness)
        self.assertIn("TRAINING_SOURCE_SHA256", harness)
        self.assertIn("claim_and_fallback_entrypoints_are_nonpayable", harness)
        self.assertIn("throneAdvancedDespitePayoutOutcome", harness)
        self.assertIn("contractRetainedFailedCompensation", harness)
        self.assertIn("accepting_control_receives_compensation", harness)


if __name__ == "__main__":
    unittest.main()
