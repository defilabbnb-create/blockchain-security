import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "training_dynamic_unchecked_token_false", ROOT / "scripts/training-dynamic-unchecked-token-false.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class TrainingDynamicUncheckedTokenFalseTests(unittest.TestCase):
    def test_candidate_is_not_run_and_hash_pinned(self):
        row, screen = MODULE.manifest_context()
        self.assertEqual((row["repo"], row["commit"], row["path"]), MODULE.SAMPLE)
        source = ROOT / row["objectPath"]
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), MODULE.EXPECTED_SHA256)
        # 语料合并会消耗 not_run 池：D3-unchecked-call 于 2026-10-22 把
        # 0xb7c5c5aa... 从 not_run 推进为 unconfirmed，not_run 由 47 降为 46。
        # 这里按当前 manifest 重新推导期望值，并保留 47 作为历史上界，
        # 避免每次新通道合并都需要手改断言。
        manifest = json.loads((ROOT / "training-data/github-vulnerabilities/manifest.json")
                              .read_text(encoding="utf-8"))
        unchecked_rows = [item for item in manifest.get("samples", [])
                          if item.get("category") == "unchecked_low_level_calls"]
        expected_not_run = [item for item in unchecked_rows
                            if item.get("analysis", {}).get("dynamic") == "not_run"]
        self.assertEqual(screen["uncheckedSampleCount"], len(unchecked_rows))
        self.assertEqual(screen["notRunSampleCount"], len(expected_not_run))
        self.assertLessEqual(screen["notRunSampleCount"], 47)
        self.assertEqual(row.get("analysis", {}).get("dynamic"), "not_run")
        self.assertEqual(screen["tokenTransferCandidateCount"], 5)
        text = MODULE.HARNESS.read_text(encoding="utf-8")
        for marker in ("TRAINING_SOURCE_SHA256", "CORPUS_DEFER_MERGE", "sendTokenAw",
                       "transferCalls", "numTransfersSlot", "returnedFalse"):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_three_matching_false_return_bookkeeping_runs_confirm(self):
        run = {"state": "confirmed", "confirmedVulnerability": True, "impactDemonstrated": True,
               "sourceSha256": MODULE.EXPECTED_SHA256, "runnerExitCode": 0,
               "storageObservation": {"before": "0", "after": "1"},
               "tokenObservation": {"transferCalls": "1", "returnedFalse": False,
                                    "daoBalanceBefore": "100", "daoBalanceAfter": "100",
                                    "recipientBalanceBefore": "0", "recipientBalanceAfter": "0"},
               "transaction": {"status": 1},
               "assertions": [{"name": "false_return", "passed": True},
                              {"name": "bookkeeping_advanced", "passed": True}], "reason": None}
        self.assertEqual(MODULE.classify_runs([run] * 3, []), ("confirmed", True, True))

    def test_failed_token_transfer_without_counter_effect_does_not_confirm(self):
        run = {"state": "unconfirmed", "confirmedVulnerability": False, "impactDemonstrated": False,
               "sourceSha256": MODULE.EXPECTED_SHA256, "runnerExitCode": 0,
               "storageObservation": {"before": "0", "after": "0"},
               "tokenObservation": {"transferCalls": "1", "returnedFalse": False,
                                    "daoBalanceBefore": "100", "daoBalanceAfter": "100",
                                    "recipientBalanceBefore": "0", "recipientBalanceAfter": "0"},
               "transaction": {"status": 1},
               "assertions": [{"name": "bookkeeping_advanced", "passed": False}],
               "reason": "false_return_or_bookkeeping_impact_assertion_failed"}
        self.assertEqual(MODULE.classify_runs([run] * 3, []), ("unconfirmed", False, True))

    def test_inconsistent_or_incomplete_runs_are_not_confirmed(self):
        run = {"state": "confirmed", "confirmedVulnerability": True, "impactDemonstrated": True,
               "sourceSha256": MODULE.EXPECTED_SHA256, "runnerExitCode": 0,
               "storageObservation": {"before": "0", "after": "1"},
               "tokenObservation": {"transferCalls": "1", "returnedFalse": False},
               "transaction": {"status": 1}, "assertions": [{"passed": True}], "reason": None}
        different = {**run, "storageObservation": {"before": "0", "after": "2"}}
        self.assertEqual(MODULE.classify_runs([run, run, different], []), ("flaky", False, False))
        self.assertEqual(MODULE.classify_runs([], [{"failure": "compile"}] * 3),
                         ("harness_not_feasible", False, True))


if __name__ == "__main__":
    unittest.main()
