"""Tests for the evidence matrix's degradation when an input is unusable.

The property locked here is that the four evidence sources stay separate, so a
broken file in one of them cannot take the rest down and cannot quietly become
"nothing to report".  A truncated report used to raise straight out of
`collect()`, which meant one hand-mangled file produced no matrix at all rather
than a matrix with one column missing and a stated reason.

Each test names the input it breaks, so reverting the guard on one input fails
the test that covers it instead of quietly changing a count elsewhere.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "scripts" / "evidence-matrix.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("evidence_matrix_mod", MATRIX)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EM = _load_module()

ADJUDICATION = {
    "schemaVersion": 1,
    "samples": [{"caseId": "22-erc4626-rounding", "grade": "B"}],
}
AUDIT = {
    "schemaVersion": 1,
    "cases": [{
        "caseId": "22-erc4626-rounding", "verdict": "evidence_stale", "clean": False,
        "hasEvidence": True, "knownIssues": ["erc4626_rounding"],
        "sourceBinding": {"matched": False},
    }, {
        "caseId": "30-reentrancy-withdraw", "verdict": "reproduced", "clean": False,
        "hasEvidence": True, "knownIssues": ["reentrancy"],
        "sourceBinding": {"matched": True},
    }],
}
COVERAGE = {
    "schemaVersion": 1,
    "pocEvidenceSplit": {
        "withReproduction": {"cases": [{"caseId": "30-reentrancy-withdraw", "hit": True}]},
        "staticOnly": {"cases": [{"caseId": "22-erc4626-rounding", "falseNegative": True}]},
    },
}
TRUNCATED = '{"cases": [{"caseId": "22-erc4626-rounding", "verdict":'


class MatrixDegradationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="evidence-matrix-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._original_bench = EM.BENCH
        EM.BENCH = self.tmp
        self.addCleanup(setattr, EM, "BENCH", self._original_bench)

    def _write(self, filename, payload):
        body = payload if isinstance(payload, str) else json.dumps(payload)
        (self.tmp / filename).write_text(body, encoding="utf-8")

    def _write_all(self):
        self._write("sample-adjudication.json", ADJUDICATION)
        self._write("poc-evidence-audit.json", AUDIT)
        self._write("coverage-report.json", COVERAGE)

    def _input_by_name(self, inputs, name):
        return next(item for item in inputs if item["name"] == name)

    # --- the fix itself -------------------------------------------------
    def test_truncated_audit_report_does_not_abort_the_matrix(self):
        self._write_all()
        self._write("poc-evidence-audit.json", TRUNCATED)
        rows, inputs = EM.collect()
        # The remaining two inputs still align; the broken one is named.
        self.assertEqual(self._input_by_name(inputs, "audit")["available"], False)
        self.assertIn("JSON 解析失败",
                      self._input_by_name(inputs, "audit")["reason"])
        # Without the audit report there is no caseId to align on, so no row can
        # be claimed — and no row may be invented either.
        self.assertEqual(rows, [])
        text = EM.render(rows, None, inputs)
        self.assertIn("2/3 份可读", text)
        self.assertIn("poc-evidence-audit.json", text)
        self.assertIn("不等于通过", text)

    def test_truncated_adjudication_still_produces_rows_without_grades(self):
        """Losing the grading column is survivable; losing the row is not."""
        self._write_all()
        self._write("sample-adjudication.json", '{"samples": [{"caseId"')
        rows, inputs = EM.collect()
        self.assertEqual([row["caseId"] for row in rows],
                         ["22-erc4626-rounding", "30-reentrancy-withdraw"],
                         "分级报告损坏时其余两份证据仍应对齐出行")
        self.assertTrue(all(row["grade"] == "-" for row in rows),
                        "缺失的分级不应被推断成一个具体等级")
        self.assertIn("2/3", EM.render(rows, None, inputs))

    def test_truncated_coverage_still_produces_rows_without_detection(self):
        self._write_all()
        self._write("coverage-report.json", '{"pocEvidenceSplit": {"withRepro')
        rows, inputs = EM.collect()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["detectionBucket"] is None for row in rows),
                        "检出列缺失时应留空，而不是沿用上一轮结果")
        self.assertFalse(any(row["hit"] or row["falseNegative"] for row in rows))
        self.assertIn("2/3", EM.render(rows, None, inputs))

    def test_missing_file_is_reported_not_treated_as_empty_evidence(self):
        self._write_all()
        (self.tmp / "coverage-report.json").unlink()
        rows, inputs = EM.collect()
        self.assertEqual(len(rows), 2)
        coverage = self._input_by_name(inputs, "coverage")
        self.assertFalse(coverage["available"])
        self.assertEqual(coverage["reason"], "文件不存在")

    def test_empty_file_is_reported(self):
        self._write_all()
        self._write("coverage-report.json", "   \n")
        rows, inputs = EM.collect()
        self.assertEqual(len(rows), 2)
        self.assertEqual(self._input_by_name(inputs, "coverage")["reason"], "文件为空")

    def test_top_level_array_is_reported(self):
        self._write_all()
        self._write("coverage-report.json", "[1, 2, 3]")
        rows, inputs = EM.collect()
        self.assertEqual(len(rows), 2)
        self.assertIn("顶层不是 JSON 对象",
                      self._input_by_name(inputs, "coverage")["reason"])

    def test_all_inputs_missing_reports_zero_of_three(self):
        rows, inputs = EM.collect()
        self.assertEqual(rows, [])
        self.assertEqual([item["available"] for item in inputs], [False] * 3)
        self.assertIn("0/3", EM.render(rows, None, inputs))

    def test_all_inputs_intact_reports_three_of_three(self):
        self._write_all()
        rows, inputs = EM.collect()
        self.assertEqual(len(inputs), 3)
        self.assertTrue(all(item["available"] for item in inputs))
        self.assertIn("3/3", EM.render(rows, None, inputs))
        self.assertEqual(len(rows), 2)

    def test_json_output_carries_availability_like_the_web_route(self):
        """src/web-server.js answers available:false when nothing loads; the
        script must expose the same signal per input so callers can degrade.
        """
        self._write_all()
        self._write("poc-evidence-audit.json", TRUNCATED)
        rows, inputs = EM.collect()
        missing = [item for item in inputs if not item["available"]]
        payload = {
            "schemaVersion": 1,
            "available": not missing,
            "reason": None if not missing else f"{len(missing)}/{len(inputs)} 份输入不可用",
            "inputs": inputs,
            "rows": rows,
        }
        self.assertFalse(payload["available"])
        self.assertEqual(payload["reason"], "1/3 份输入不可用")
        self.assertEqual(len(payload["inputs"]), 3)

    # --- no regression on well-formed data ------------------------------
    def test_intact_inputs_keep_every_column_populated(self):
        self._write_all()
        rows, _ = EM.collect()
        by_id = {row["caseId"]: row for row in rows}
        stale = by_id["22-erc4626-rounding"]
        self.assertEqual(stale["grade"], "B")
        self.assertEqual(stale["detectionBucket"], "staticOnly")
        self.assertTrue(stale["falseNegative"])
        self.assertFalse(stale["bindingOk"])
        fresh = by_id["30-reentrancy-withdraw"]
        self.assertEqual(fresh["detectionBucket"], "withReproduction")
        self.assertTrue(fresh["hit"])
        self.assertTrue(fresh["bindingOk"])

    def test_real_repository_inputs_all_load(self):
        """The shipped reports must not trip the degradation path."""
        # Point back at the real benchmark directory that setUp replaced.
        EM.BENCH = ROOT / "benchmark"
        rows, inputs = EM.collect()
        self.addCleanup(setattr, EM, "BENCH", self._original_bench)
        unavailable = [item["file"] for item in inputs if not item["available"]]
        self.assertEqual(unavailable, [], f"仓库自带报告不可用：{unavailable}")
        self.assertGreater(len(rows), 0)
        self.assertEqual(len(rows), 33, f"实际对齐行数变了：{len(rows)}")


if __name__ == "__main__":
    unittest.main()