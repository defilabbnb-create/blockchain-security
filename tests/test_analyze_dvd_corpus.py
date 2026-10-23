import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "analyze_dvd_corpus", ROOT / "scripts" / "analyze-dvd-corpus.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AnalyzeDvdCorpusTests(unittest.TestCase):
    def _sample(self, root):
        source = root / "bundle/src/Pool.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Pool {}\n", encoding="utf-8")
        input_path = root / "bundle/static-input.json"
        input_path.write_text("{}\n", encoding="utf-8")
        return {
            "challenge": "side-entrance",
            "analysisBundle": {
                "directory": "bundle",
                "inputPath": "bundle/static-input.json",
                "inputSha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
                "sourceBundleSha256": "bundle-sha",
                "files": [{"path": "bundle/src/Pool.sol", "sourceUnit": "src/Pool.sol",
                           "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}],
            },
            "dependencyFiles": [],
        }

    def test_partial_analysis_is_persisted_with_traceable_finding_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sample = self._sample(root)
            payload = {
                "state": "partial", "compiler": "0.8.25", "contracts": 1, "detectors": 100,
                "findingCount": 4, "findingSemanticFingerprint": "finding-sha",
                "staticStages": {"compile": "completed", "callGraph": "partial", "detectors": "completed"},
                "callGraph": {"state": "partial"}, "unifiedIR": {"state": "partial"},
            }
            def run(*_args, **_kwargs):
                return subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "compiler warning\n")
            with patch.object(MODULE, "ROOT", root), \
                    patch.object(MODULE, "CORPUS", root / "corpus"), \
                    patch.object(MODULE, "ANALYZER", root / "review-static.py"):
                result = MODULE.analyze_sample(sample, command_runner=run)
                evidence = root / result["staticEvidence"]["path"]
                self.assertEqual(result["staticState"], "partial")
                self.assertEqual(result["staticReason"], "partial_static_stages:callGraph")
                self.assertEqual(result["staticFindingCount"], 4)
                self.assertEqual(result["staticEvidence"]["sha256"], hashlib.sha256(evidence.read_bytes()).hexdigest())
                self.assertEqual(json.loads(evidence.read_text())["findingSemanticFingerprint"], "finding-sha")

    def test_nonzero_analyzer_exit_cannot_be_recorded_as_completed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sample = self._sample(root)
            payload = {"state": "completed", "findingCount": 0}
            def run(*_args, **_kwargs):
                return subprocess.CompletedProcess([], 1, json.dumps(payload) + "\n", "failure\n")
            with patch.object(MODULE, "ROOT", root), \
                    patch.object(MODULE, "CORPUS", root / "corpus"), \
                    patch.object(MODULE, "ANALYZER", root / "review-static.py"):
                result = MODULE.analyze_sample(sample, command_runner=run)
            self.assertEqual(result["staticState"], "failed")
            self.assertEqual(result["staticReason"], "analyzer_exit_1")

    def test_manifest_update_merges_static_fields_without_dropping_dynamic_state(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest_path = Path(folder) / "manifest.json"
            manifest_path.write_text(json.dumps({"samples": [{
                "challenge": "side-entrance", "staticState": "not_run", "dynamicState": "confirmed",
            }]}), encoding="utf-8")
            updated = {"samples": [{
                "challenge": "side-entrance", "staticState": "partial", "staticReason": "incomplete_graph",
                "staticFindingCount": 4, "staticEvidence": {"path": "report.json", "sha256": "report-sha"},
                "dynamicState": "not_run",
            }]}
            with patch.object(MODULE, "MANIFEST", manifest_path):
                MODULE._write_manifest(updated)
            saved = json.loads(manifest_path.read_text(encoding="utf-8"))["samples"][0]
            self.assertEqual(saved["staticState"], "partial")
            self.assertEqual(saved["staticEvidence"]["sha256"], "report-sha")
            self.assertEqual(saved["dynamicState"], "confirmed")


if __name__ == "__main__":
    unittest.main()
