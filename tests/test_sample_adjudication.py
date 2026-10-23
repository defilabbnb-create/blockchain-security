"""Tests for the sample adjudication and the grade-gated coverage recount.

Two properties are locked here.  First, an adjudication must be grounded in a
source line: a verdict whose evidence list is empty is reported as uncertain, so
an opinion can never silently become a grade or a denominator.  Second, evidence
that was recorded against a different revision of a sample must never be scored:
the digest recorded by a run is compared with the source actually on disk, and a
mismatch removes the sample instead of reporting coverage for code that no longer
exists.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADJUDICATION = ROOT / "scripts/adjudicate_samples.py"
COVERAGE = ROOT / "scripts/measure-class-coverage.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ADJ = _load(ADJUDICATION, "adjudicate_samples_mod")
COV = _load(COVERAGE, "measure_class_coverage_mod")


class AdjudicationTests(unittest.TestCase):
    def test_every_graded_sample_cites_a_source_line(self):
        report = ADJ.adjudicate()
        self.assertEqual(report["ungradedCount"], 0,
                         "每个样本都必须有判定或有 ungraded 说明")
        for row in report["samples"]:
            if row.get("grade") and not row.get("uncertain"):
                self.assertTrue(row.get("evidence"),
                                f"{row['caseId']} 判为 {row['grade']} 却没有任何源码行号证据")
                for item in row["evidence"]:
                    self.assertIsInstance(item.get("line"), int,
                                          f"{row['caseId']} 的证据缺少行号")

    def test_evidence_line_numbers_are_inside_the_source(self):
        report = ADJ.adjudicate()
        contracts = ROOT / "benchmark" / "contracts"
        for row in report["samples"]:
            source = contracts / row["caseId"] / (row["sourceFile"] or "")
            if not source.is_file():
                continue
            total = len(source.read_text(encoding="utf-8").splitlines())
            for item in row.get("evidence", []):
                self.assertLessEqual(item["line"], total,
                                     f"{row['caseId']} 引用了不存在的第 {item['line']} 行"
                                     f"（文件共 {total} 行）")
                self.assertGreaterEqual(item["line"], 1)

    def test_grade_d_samples_declare_a_contradiction(self):
        report = ADJ.adjudicate()
        for row in report["samples"]:
            if row.get("grade") == "D":
                self.assertTrue(row.get("contradiction"),
                                f"{row['caseId']} 判为 D 必须说明标注与代码的矛盾之处")

    def test_all_thirty_three_samples_are_adjudicated(self):
        report = ADJ.adjudicate()
        self.assertEqual(len(report["samples"]), 33)

    def test_grade_matches_provenance_state(self):
        """A real upstream sample is A/B; only a synthetic fixture may be C/D."""
        report = ADJ.adjudicate()
        for row in report["samples"]:
            grade = row.get("grade")
            if row["provenanceState"] == "verified":
                self.assertIn(grade, {"A", "B"},
                              f"{row['caseId']} 来源为 verified，却判为 {grade}")
            elif row["provenanceState"] == "synthetic_local_fixture":
                self.assertIn(grade, {"B", "C", "D"},
                              f"{row['caseId']} 来源为 synthetic，却判为 {grade}")


class CoverageGradingTests(unittest.TestCase):
    def _case(self, folder: Path, case_id: str, source: str, recorded: str | None,
              detected: list[str], expected: list[str]) -> None:
        case_dir = folder / case_id
        case_dir.mkdir(parents=True)
        (case_dir / "Sample.sol").write_text(source, encoding="utf-8")
        (case_dir / "ground-truth.json").write_text(
            json.dumps({"knownIssues": expected, "clean": not expected,
                        "source": "https://example.invalid/x"}), encoding="utf-8")
        evidence = {"detectedRoles": detected, "state": "completed", "detectedIssues": []}
        if recorded is not None:
            import hashlib
            evidence["sourceSha256"] = recorded
        (case_dir / "invariants.json").write_text(json.dumps(evidence), encoding="utf-8")

    def test_evidence_recorded_against_another_revision_is_not_scored(self):
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = "contract C { function f() public { } }\n"
            digest = hashlib.sha256(source.encode()).hexdigest()
            self._case(root, "01-bound", source, digest, ["reentrancy"], ["reentrancy"])
            self._case(root, "02-stale", source, "0" * 64, ["reentrancy"], ["reentrancy"])
            rows = {row["caseId"]: row for row in COV._case_rows(root)}
            self.assertEqual(rows["01-bound"]["state"], "scored")
            self.assertEqual(rows["02-stale"]["state"], "evidence_not_bound")
            self.assertEqual(rows["02-stale"]["detected"], [],
                             "不匹配的证据不得贡献任何检出类别")

    def test_silence_on_a_clean_sample_is_a_true_negative(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = "contract C { function f() public { } }\n"
            import hashlib
            digest = hashlib.sha256(source.encode()).hexdigest()
            self._case(root, "01-clean", source, digest, [], [])
            rows = COV._case_rows(root)
            self.assertEqual(rows[0]["state"], "scored_clean_silence")
            score = COV._score(rows)
            self.assertEqual(score["falsePositiveCount"], 0)
            self.assertEqual(score["scoredSampleCount"], 1)

    def test_silence_on_a_sample_with_a_known_issue_is_a_miss(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = "contract C { function f() public { } }\n"
            import hashlib
            digest = hashlib.sha256(source.encode()).hexdigest()
            self._case(root, "01-vuln", source, digest, [], ["reentrancy"])
            rows = COV._case_rows(root)
            self.assertEqual(rows[0]["state"], "scored")
            score = COV._score(rows)
            self.assertEqual(score["falseNegativeCount"], 1)
            self.assertEqual(score["truePositiveCount"], 0)

    def test_grade_d_samples_are_never_counted_as_detector_misses(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = "contract C { function f() public { } }\n"
            import hashlib
            digest = hashlib.sha256(source.encode()).hexdigest()
            self._case(root, "01-good", source, digest, [], ["reentrancy"])
            self._case(root, "02-badlabel", source, digest, [], ["oracle_stale_price"])
            adjudication = root / "sample-adjudication.json"
            adjudication.write_text(json.dumps({"samples": [
                {"caseId": "01-good", "grade": "A"},
                {"caseId": "02-badlabel", "grade": "D"},
            ]}), encoding="utf-8")
            rows = COV._case_rows(root)
            loaded = COV._load_adjudication(root)
            split = COV._grade_split(rows, loaded)
            self.assertEqual(split["A_only"]["scoredSampleCount"], 1)
            self.assertEqual(split["A_only"]["falseNegativeCount"], 1)
            self.assertIn("02-badlabel",
                          split["A_only"]["excludedBecauseLabelContradictsSource"])
            self.assertNotIn("02-badlabel",
                             [item["caseId"] for item in split["A_only"]["cases"]],
                             "D 级样本不得进入检测器漏报分母")


if __name__ == "__main__":
    unittest.main()