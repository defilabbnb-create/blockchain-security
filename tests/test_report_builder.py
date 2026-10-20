import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("report_builder", ROOT / "scripts" / "report_builder.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class ReportBuilderTests(unittest.TestCase):
    def test_builds_three_formats_and_preserves_tri_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "finding-index.json").write_text(json.dumps({"findings": [
                {"id": "f1", "kind": "reentrancy", "title": "<script>alert(1)</script>", "severity": "high", "status": "poc_confirmed", "sourceSha256": "a" * 64, "evidence": [{"file": "Vault.sol", "lineStart": 8, "lineEnd": 10, "quote": "x < y"}]},
                {"id": "f2", "kind": "oracle", "title": "价格依赖", "severity": "medium", "status": "static_signal", "sourceSha256": "b" * 64, "evidence": []},
            ]}), encoding="utf-8")
            report = REPORT.build_report(root, output_dir=root / "out")
            self.assertIn("未证实", report["markdown"])
            self.assertIn("未证实", report["markdown"])
            self.assertIn("&lt;script&gt;", report["html"])
            self.assertNotIn("<script>", report["html"])
            self.assertEqual(report["sarif"]["version"], "2.1.0")
            self.assertEqual(len(report["sarif"]["runs"][0]["results"]), 2)
            self.assertFalse(report["coverage"]["complete"])
            self.assertIn("成本披露", report["markdown"])
            self.assertIn("复现指引", report["markdown"])
            self.assertTrue((root / "out" / "report.sarif.json").is_file())

    def test_confirmation_requires_poc_evidence_bound_to_same_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "finding-index.json").write_text(json.dumps({"findings": [
                {"id": "f1", "kind": "reentrancy", "status": "confirmed", "confirmedVulnerability": True,
                 "sourceBundleSha256": "a" * 64}
            ]}), encoding="utf-8")
            (root / "poc-result.json").write_text(json.dumps({
                "findingId": "f1", "pocState": "confirmed", "confirmed_by_poc": True,
                "sourceBundleSha256": "a" * 64, "evidenceSha256": "b" * 64,
                "testName": "testPoC_0000000000000001", "pocManifestSha256": "d" * 64,
                "attempts": [{"state": "passed", "matchedTestPassed": True,
                              "testName": "testPoC_0000000000000001", "pocManifestSha256": "d" * 64,
                              "sourceBundleSha256": "a" * 64, "testSourceSha256": "e" * 64,
                              "evidenceSha256": "c" * 64}]
            }), encoding="utf-8")
            report = REPORT.build_report(root)
            self.assertEqual(report["findings"][0]["reportStatus"], "已证实")
            self.assertIn("已证实", report["markdown"])

            poc = json.loads((root / "poc-result.json").read_text(encoding="utf-8"))
            poc["findingId"] = "another-finding"
            (root / "poc-result.json").write_text(json.dumps(poc), encoding="utf-8")
            report = REPORT.build_report(root)
            self.assertEqual(report["findings"][0]["reportStatus"], "未证实")

    def test_confirmation_requires_attempt_output_hash_and_matching_bundle_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "finding-index.json").write_text(json.dumps({"findings": [
                {"id": "f1", "status": "poc_confirmed", "sourceBundleSha256": "a" * 64}
            ]}), encoding="utf-8")
            poc = {"findingId": "f1", "pocState": "confirmed", "confirmed_by_poc": True,
                   "sourceBundleSha256": "d" * 64, "evidenceSha256": "b" * 64,
                   "testName": "testPoC_0000000000000001", "pocManifestSha256": "f" * 64,
                   "attempts": [{"state": "passed", "matchedTestPassed": True,
                                 "testName": "testPoC_0000000000000001", "pocManifestSha256": "f" * 64,
                                 "sourceBundleSha256": "d" * 64, "testSourceSha256": "e" * 64,
                                 "evidenceSha256": "c" * 64}]}
            (root / "poc-result.json").write_text(json.dumps(poc), encoding="utf-8")
            report = REPORT.build_report(root)
            self.assertEqual(report["findings"][0]["reportStatus"], "未证实")
            poc["sourceBundleSha256"] = "a" * 64
            poc["attempts"][0]["evidenceSha256"] = "invalid"
            (root / "poc-result.json").write_text(json.dumps(poc), encoding="utf-8")
            report = REPORT.build_report(root)
            self.assertEqual(report["findings"][0]["reportStatus"], "未证实")

    def test_missing_inputs_are_explicit_and_no_absolute_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = REPORT.build_report(root)
            self.assertEqual(report["coverage"]["state"], "not_available")
            self.assertFalse(report["coverage"]["complete"])
            self.assertIn("not_available", report["markdown"])
            for text in (report["markdown"], report["html"]):
                self.assertNotIn("无漏洞", text)
                self.assertNotIn("安全", text)


if __name__ == "__main__":
    unittest.main()
