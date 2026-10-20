import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pipeline_review_stages", ROOT / "scripts" / "pipeline_review_stages.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReviewReportStageTests(unittest.TestCase):
    def write_index(self, directory: Path) -> Path:
        path = directory / "finding-index.json"
        path.write_text(json.dumps({
            "schemaVersion": 1,
            "coverage": {"complete": False, "reason": "dynamic evidence unavailable"},
            "findings": [{
                "id": "finding-12345678", "kind": "reentrancy", "title": "候选观察",
                "severity": "high", "status": "static_signal", "sourceSha256": "a" * 64,
                "evidence": [{"file": "Vault.sol", "lineStart": 1, "lineEnd": 2, "quote": "call"}],
            }],
        }), encoding="utf-8")
        return path

    def test_review_is_explicitly_unavailable_without_cloud_and_never_confirms(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            index = self.write_index(root)
            result = module.run_stage("review", {"findingIndex": str(index)}, root / "review", "local")
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["reason"], "cloud_review_not_configured")
            payload = json.loads((root / "review" / "review-local.json").read_text(encoding="utf-8"))
            self.assertFalse(any(row["confirmedVulnerability"] for row in payload["observations"]))
            self.assertEqual(payload["securityConclusion"], "unconfirmed_observations_only")
            self.assertEqual(payload["source"]["sha256"], module._sha256(index))

    def test_report_writes_three_hashed_outputs_atomically(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            index = self.write_index(root)
            result = module.run_stage("report", {"findingIndex": str(index)}, root / "report", "local")
            self.assertEqual(result["state"], "completed")
            self.assertFalse(result["coverageComplete"])
            self.assertEqual(set(result["outputs"]), {"report.md", "report.html", "report.sarif.json"})
            for name, digest in result["outputs"].items():
                self.assertEqual(digest, module._sha256(root / "report" / "reports" / name))
            self.assertTrue((root / "report" / "reports" / "report.sarif.json").is_file())

    def test_report_stage_reads_poc_evidence_from_target_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "inputs").mkdir()
            index = self.write_index(root / "inputs")
            stage = root / "target"
            stage.mkdir()
            (stage / "poc-result.json").write_text(json.dumps({
                "findingId": "finding-12345678", "pocState": "confirmed", "confirmed_by_poc": True,
                "sourceBundleSha256": "a" * 64, "evidenceSha256": "b" * 64,
                "testName": "testPoC_0000000000000001", "pocManifestSha256": "d" * 64,
                "attempts": [{"state": "passed", "matchedTestPassed": True,
                              "testName": "testPoC_0000000000000001", "pocManifestSha256": "d" * 64,
                              "sourceBundleSha256": "a" * 64, "testSourceSha256": "e" * 64,
                              "evidenceSha256": "c" * 64}]
            }), encoding="utf-8")
            result = module.run_stage("report", {"findingIndex": str(index)}, stage, "local")
            self.assertEqual(result["state"], "completed")
            markdown = (stage / "reports" / "report.md").read_text(encoding="utf-8")
            self.assertIn("已证实", markdown)

    def test_missing_index_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temp:
            result = module.run_stage("report", {}, Path(temp) / "run", "local")
            self.assertEqual(result, {"state": "unavailable", "reason": "finding_index_missing"})

    def test_review_generates_run_local_index_from_static_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stage = root / "review"
            stage.mkdir()
            (stage / "static.json").write_text(json.dumps({
                "state": "completed", "verifiedSourceFingerprint": "c" * 64,
                "findings": [{"check": "reentrancy", "impact": "High", "description": "external call"}],
            }), encoding="utf-8")
            result = module.run_stage("review", {}, stage, "local")
            self.assertEqual(result["state"], "unavailable")
            index = json.loads((stage / "finding-index.json").read_text(encoding="utf-8"))
            self.assertTrue(index["generatedByPipeline"])
            self.assertEqual(len(index["findings"]), 1)
            self.assertEqual(index["findings"][0]["status"], "unconfirmed_observation")
            report = module.run_stage("report", {}, stage, "local")
            self.assertEqual(report["state"], "completed")

    def test_explicit_mock_cloud_review_is_completed_but_unconfirmed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            index = self.write_index(root)
            result = module.run_stage("review", {"findingIndex": str(index), "mockCloudReview": True}, root / "mock", "local")
            self.assertEqual(result["state"], "completed")
            self.assertEqual(result["provider"], "mock_cloud_ai")
            payload = json.loads((root / "mock" / "review-mock.json").read_text(encoding="utf-8"))
            self.assertFalse(any(row["confirmedVulnerability"] for row in payload["observations"]))
            self.assertEqual(len(result["manifestSha256"]), 64)


if __name__ == "__main__":
    unittest.main()
