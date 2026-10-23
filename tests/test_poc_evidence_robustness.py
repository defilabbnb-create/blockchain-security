"""Tests for the PoC evidence audit's handling of unreadable samples.

An evidence auditor that aborts on a truncated file reports nothing at all,
which is the worst outcome: the reader cannot tell a clean run from a crashed
one.  A file that is silently skipped is nearly as bad, because the denominator
shrinks and the missing sample reads as a pass.  So an unreadable case has to
appear in the report under its own verdict, counted separately, and block the
`--fail` gate rather than passing quietly.

These tests build the damage rather than describing it, so each guard is tied
to the specific failure mode it protects.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_SCRIPT = ROOT / "scripts" / "audit-poc-evidence.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("audit_poc_evidence_mod", AUDIT_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AP = _load_module()
REAL_REPORT = ROOT / "benchmark" / "poc-evidence-audit.json"


class UnreadableCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="poc-evidence-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.contracts = self.tmp / "contracts"
        self.contracts.mkdir()
        self._original = AP.CONTRACTS
        AP.CONTRACTS = self.contracts
        self.addCleanup(setattr, AP, "CONTRACTS", self._original)

    def _case(self, name, ground_truth=None, poc=None):
        case = self.contracts / name
        case.mkdir()
        if ground_truth is not None:
            (case / "ground-truth.json").write_text(ground_truth, encoding="utf-8")
        if poc is not None:
            (case / "poc-result.json").write_text(poc, encoding="utf-8")
        return case

    def test_truncated_ground_truth_is_reported_not_crashed(self):
        self._case("01-truncated",
                   ground_truth='{"clean": false, "knownIssues": ["reentrancy"]',
                   poc='{"state": "passed"}')
        report = AP.audit_all()
        self.assertEqual(report["counts"], {"unreadable": 1})
        self.assertEqual(report["unreadableIds"], ["01-truncated"])
        problems = report["cases"][0]["problems"]
        self.assertTrue(any("ground-truth.json" in item for item in problems),
                        f"损坏原因未写进 problems：{problems}")

    def test_top_level_array_poc_is_reported_not_crashed(self):
        self._case("02-array", ground_truth='{"clean": true}', poc="[1, 2, 3]")
        report = AP.audit_all()
        self.assertEqual(report["counts"], {"unreadable": 1})
        self.assertIn("顶层不是 JSON 对象",
                      " ".join(report["cases"][0]["problems"]))

    def test_missing_ground_truth_is_reported(self):
        self._case("03-no-gt", poc='{"state": "passed"}')
        report = AP.audit_all()
        self.assertEqual(report["counts"], {"unreadable": 1})
        self.assertIn("文件不存在", " ".join(report["cases"][0]["problems"]))

    def test_empty_ground_truth_is_reported(self):
        self._case("04-empty-gt", ground_truth="   \n")
        report = AP.audit_all()
        self.assertEqual(report["counts"], {"unreadable": 1})
        self.assertIn("文件为空", " ".join(report["cases"][0]["problems"]))

    def test_unreadable_case_stays_in_the_case_list(self):
        """Dropping the case would shrink the denominator silently."""
        self._case("05-truncated", ground_truth='{"clean": true')
        self._case("06-good", ground_truth='{"clean": false}',
                   poc='{"state": "unconfirmed"}')
        report = AP.audit_all()
        self.assertEqual(sorted(c["caseId"] for c in report["cases"]),
                         ["05-truncated", "06-good"])

    def test_unreadable_case_is_never_counted_as_clean_control_quiet(self):
        """A broken sample must not enter the clean-control denominator."""
        self._case("07-broken-clean", ground_truth='{"clean": true')
        report = AP.audit_all()
        self.assertEqual(report["cleanControls"]["total"], 0,
                         "无法读取 clean 字段的样本不应计入干净对照分母")

    def test_fail_gate_blocks_on_unreadable_input(self):
        self._case("08-truncated", ground_truth='{"clean": true')
        report = AP.audit_all()
        blocking = (report["counts"].get("fabricated", 0)
                    + report["counts"].get("evidence_stale", 0))
        self.assertEqual(blocking, 0,
                         "前置条件：本例不应同时存在 fabricated/stale")
        self.assertGreater(report["unreadableCount"], 0)

    def test_table_mentions_unreadable_count(self):
        self._case("09-truncated", ground_truth='{"clean": true')
        report = AP.audit_all()
        text = AP.render_table(report, {})
        self.assertIn("unreadable=1", text)
        self.assertIn("既不算通过", text)

    def test_broken_grading_report_does_not_abort_the_audit(self):
        """The grading report only supplies one column, so losing it must not
        take the audit down — the other cases still get verdicts.
        """
        self._case("10-good", ground_truth='{"clean": false}',
                   poc='{"state": "unconfirmed", "confirmedVulnerability": true}')
        bench = self.tmp / "benchmark"
        bench.mkdir()
        (bench / "sample-adjudication.json").write_text('{"samples": [{"caseId"',
                                                        encoding="utf-8")
        original_root = AP.ROOT
        AP.ROOT = self.tmp
        self.addCleanup(setattr, AP, "ROOT", original_root)
        stderr = StringIO()
        with redirect_stderr(stderr):
            grades = AP._load_grades()
        self.assertEqual(grades, {}, "损坏的分级报告应降级为空分级而非抛错")
        self.assertIn("分级报告不可用", stderr.getvalue())
        report = AP.audit_all()
        self.assertEqual(report["counts"], {"fabricated": 1})


class NoRegressionTests(unittest.TestCase):
    def test_real_report_verdicts_are_unchanged(self):
        """Recomputing must reproduce the verdicts already on disk."""
        stored = json.loads(REAL_REPORT.read_text(encoding="utf-8"))
        recomputed = {c["caseId"]: c["verdict"] for c in AP.audit_all()["cases"]}
        on_disk = {c["caseId"]: c["verdict"] for c in stored["cases"]}
        self.assertEqual(recomputed, on_disk,
                         "真实样本的判定发生了变化，请确认是否有意为之")
        self.assertEqual(AP.audit_all()["unreadableCount"], 0)

    def test_stored_report_has_no_unreadable_verdict(self):
        stored = json.loads(REAL_REPORT.read_text(encoding="utf-8"))
        self.assertNotIn("unreadable", stored["counts"],
                         "落盘的报告里出现了不可读样本，请检查 benchmark/contracts")


if __name__ == "__main__":
    unittest.main()