#!/usr/bin/env python3
"""Tests for the analysis policy and the false-positive triage baseline.

Both files are constraints rather than measurements, so the tests check that the
constraints are still *expressed* and still *loadable*.  A policy that silently
stops being read would let the numbers it governs be quoted without it.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = ROOT / "benchmark"
CONTRACTS = BENCHMARK / "contracts"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MCC = _load("measure_class_coverage_policy_test", "measure-class-coverage.py")


class AnalysisPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(
            (BENCHMARK / "analysis-policy.json").read_text(encoding="utf-8"))

    def test_majority_vote_is_explicitly_forbidden(self):
        # Tools share heuristics, so a majority turns shared false positives into
        # a consensus result instead of removing them.
        self.assertIs(self.policy["consensus"]["majorityVoteAllowed"], False)

    def test_decompiler_pseudocode_is_not_an_analysis_input(self):
        self.assertEqual(self.policy["decompiler"]["analysisInput"], "bytecode_ir")
        self.assertIn("decompiled_pseudocode",
                      self.policy["decompiler"]["humanReadableOnly"])

    def test_taxonomy_is_dasp10_and_names_its_reference_dataset(self):
        self.assertEqual(self.policy["taxonomy"]["standard"], "DASP-10")
        self.assertIn("SmartBugs", self.policy["taxonomy"]["referenceDataset"])

    def test_raw_count_must_be_quoted_next_to_the_post_triage_count(self):
        rule = self.policy["triage"]["reportingRule"]
        self.assertIn("naive", rule)
        self.assertIn("afterReviewedBaseline", rule)

    def test_policy_is_actually_loaded_by_the_measurement(self):
        loaded = MCC._load_policy(CONTRACTS)
        self.assertTrue(loaded["available"])
        self.assertIs(loaded["majorityVoteAllowed"], False)
        self.assertEqual(loaded["decompilerAnalysisInput"], "bytecode_ir")


class TriageBaselineTests(unittest.TestCase):
    def setUp(self):
        self.baseline = json.loads(
            (BENCHMARK / "fp-triage-baseline.json").read_text(encoding="utf-8"))

    def test_every_acknowledged_entry_carries_a_reason(self):
        # A baseline entry without a reason cannot be re-checked, and would
        # silently swallow a real warning once the detector moves on.
        for entry in self.baseline["acknowledged"]:
            self.assertTrue(str(entry.get("reason", "")).strip(),
                            f"缺少判据：{entry.get('caseId')}/{entry.get('role')}")
            self.assertTrue(entry.get("category"),
                            f"缺少分类：{entry.get('caseId')}/{entry.get('role')}")

    def test_every_acknowledged_entry_names_a_real_case_and_role(self):
        case_ids = {path.name for path in CONTRACTS.iterdir() if path.is_dir()}
        roles = set()
        for path in CONTRACTS.glob("*/invariants.json"):
            roles.update(json.loads(path.read_text(encoding="utf-8"))
                         .get("detectedRoles") or [])
        for entry in self.baseline["acknowledged"]:
            self.assertIn(entry["caseId"], case_ids)
            self.assertIn(entry["role"], roles)

    def test_entries_without_a_reason_are_dropped_rather_than_suppressed(self):
        # The loader has to refuse an unreviewed entry; otherwise a malformed
        # baseline would quietly lower the reported false-positive count.
        loaded = MCC._load_triage_baseline(CONTRACTS)
        self.assertTrue(loaded["available"])
        self.assertEqual(loaded["reviewedCount"] + loaded["unreviewedDropped"],
                         loaded["declaredCount"])
        for entry in loaded["entries"]:
            self.assertTrue(entry["reason"].strip())

    def test_baseline_keys_are_canonicalised_like_the_scoring_path(self):
        loaded = MCC._load_triage_baseline(CONTRACTS)
        for case_id, role in loaded["keys"]:
            self.assertEqual(role, MCC._canonical_class(role))

    def test_no_entry_silently_stops_being_needed(self):
        # Baseline rot: an entry that no longer matches any false positive has
        # either been fixed or has drifted.  Either way it has to be re-labelled
        # explicitly, so the acknowledged set cannot quietly inflate the count of
        # findings that were "handled".
        report = json.loads((BENCHMARK / "coverage-report.json").read_text("utf-8"))
        current = {(row["caseId"], role)
                   for row in report["naive"]["cases"]
                   for role in (row.get("falsePositive") or [])}
        loaded = MCC._load_triage_baseline(CONTRACTS)
        stale = {key for key in loaded["keys"] if key not in current}
        for case_id, role in sorted(stale):
            entry = next(item for item in loaded["entries"]
                         if (item["caseId"], MCC._canonical_class(item["role"]))
                         == (case_id, role))
            self.assertEqual(entry.get("category"), "resolved",
                             f"{case_id}/{role} 已不再发生，需标记为 resolved 而非留在 acknowledged")


if __name__ == "__main__":
    unittest.main()