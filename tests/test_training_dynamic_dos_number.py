import hashlib
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "training_dynamic_dos_number", ROOT / "scripts/training-dynamic-dos-number.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class TrainingDynamicDosNumberTests(unittest.TestCase):
    def test_sample_source_and_harness_are_hash_bound(self):
        self.assertEqual(MODULE.SAMPLE, (
            "smartbugs/smartbugs-curated",
            "230e649123477eff332742a59a1c7cc6dc286cab",
            "dataset/denial_of_service/dos_number.sol",
        ))
        manifest = __import__("json").loads(
            (ROOT / "training-data/github-vulnerabilities/manifest.json").read_text())
        row = next(sample for sample in manifest["samples"] if sample["path"] == MODULE.SAMPLE[2])
        source = ROOT / row["objectPath"]
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), MODULE.EXPECTED_SHA256)
        harness = MODULE.HARNESS.read_text(encoding="utf-8")
        for marker in ("TRAINING_SOURCE_SHA256", "clear_dos_exceeds_local_block_gas_and_reverts_atomically",
                       "logical_clear_and_followup_insert_remain_available", "impactDemonstrated",
                       "isolated_local_evm"):
            with self.subTest(marker=marker):
                self.assertIn(marker, harness)

    def test_consistent_observed_clear_failure_remains_unconfirmed(self):
        run = {"state": "unconfirmed", "confirmedVulnerability": False, "impactDemonstrated": False,
               "sourceSha256": MODULE.EXPECTED_SHA256, "runnerExitCode": 0,
               "blockGasLimit": "30000000", "population": {"count": 7000},
               "observations": {"clearDOS": {"status": 0}, "logicalLengthAfterClearDOS": "7000",
                                "clear": {"status": 1}, "logicalLengthAfterClear": "0",
                                "insertAfterClear": {"status": 1}, "logicalLengthAfterFollowupInsert": "1"},
               "assertions": [{"name": "logical_clear_and_followup_insert_remain_available", "passed": True}],
               "reason": "clearDOS_reverts_at_block_limit_but_public_constant_cost_clear_and_followup_insert_succeed"}
        self.assertEqual(MODULE.classify_runs([run] * 3), ("unconfirmed", False, True))

    def test_only_stable_source_bound_confirmations_confirm(self):
        run = {"state": "confirmed", "confirmedVulnerability": True, "impactDemonstrated": True,
               "sourceSha256": MODULE.EXPECTED_SHA256, "runnerExitCode": 0,
               "blockGasLimit": "30000000", "population": {"count": 7000},
               "observations": {"clearDOS": {"status": 0}, "logicalLengthAfterClearDOS": "7000",
                                "clear": {"status": 0}, "logicalLengthAfterClear": "7000",
                                "insertAfterClear": {"status": 0}, "logicalLengthAfterFollowupInsert": "7000"},
               "assertions": [{"name": "victim_critical_function_blocked", "passed": True}],
               "reason": None}
        self.assertEqual(MODULE.classify_runs([run] * 3), ("confirmed", True, True))
        self.assertEqual(MODULE.classify_runs([{**run, "sourceSha256": "0" * 64}] * 3),
                         ("unconfirmed", False, True))
        changed = {**run, "observations": {**run["observations"], "insertAfterClear": {"status": 1}}}
        self.assertEqual(MODULE.classify_runs([run, run, changed]), ("flaky", False, False))
        self.assertEqual(MODULE.classify_runs([]), ("harness_not_feasible", False, True))


if __name__ == "__main__":
    unittest.main()
