import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "training_dynamic_transfer", ROOT / "scripts/training-dynamic-transfer.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TrainingDynamicTransferTests(unittest.TestCase):
    def test_source_bound_false_return_harness_has_true_token_control(self):
        self.assertEqual(MODULE.EXPECTED_SHA256,
                         "b9c32c34e06c5b84561b827738b0f4d4fe60d4292516714f6a08cbc8925ccac0")
        source = (ROOT / "training-data/github-vulnerabilities/objects/b9/b9c32c34e06c5b84561b827738b0f4d4fe60d4292516714f6a08cbc8925ccac0.sol").read_text(encoding="utf-8")
        harness = (ROOT / "scripts/training-dynamic-unchecked-transfer.cjs").read_text(encoding="utf-8")
        self.assertIn("caddress.call(id,from,_tos[i],v[i]);", source)
        for marker in ("EXPECTED_SOURCE_SHA256", "FalseReturnToken", "SuccessfulToken",
                       "false_return_is_ignored_and_demo_returns_true_without_token_transfer",
                       "true_return_control_moves_token_balances", "isolated_in_process"):
            with self.subTest(marker=marker):
                self.assertIn(marker, harness)

    def test_three_run_classifier_separates_confirmation_flakiness_and_infeasibility(self):
        passing = {
            "state": "confirmed", "confirmedVulnerability": True,
            "sourceSha256": MODULE.EXPECTED_SHA256, "runnerExitCode": 0,
            "falseReturn": {"demoReturn": True, "balancesAfter": {"from": "17", "to": "0"}},
            "successfulControl": {"demoReturn": True, "balancesAfter": {"from": "0", "to": "17"}},
            "assertions": [{"passed": True}],
        }
        self.assertEqual(MODULE.classify_runs([passing] * 3, []), ("confirmed", True, True))
        changed = {**passing, "successfulControl": {"demoReturn": True, "balancesAfter": {"from": "1", "to": "16"}}}
        self.assertEqual(MODULE.classify_runs([passing, passing, changed], []), ("flaky", False, False))
        wrong_hash = {**passing, "sourceSha256": "0" * 64}
        self.assertEqual(MODULE.classify_runs([wrong_hash] * 3, []), ("unconfirmed", False, True))
        self.assertEqual(MODULE.classify_runs([], ["all executions failed"]),
                         ("harness_not_feasible", False, True))


if __name__ == "__main__":
    unittest.main()
