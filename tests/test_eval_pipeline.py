import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("eval_pipeline", ROOT / "scripts" / "eval_pipeline.py")
eval_pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(eval_pipeline)


class EvaluationPipelineTests(unittest.TestCase):
    def test_repository_benchmark_contains_thirty_three_source_bound_cases(self):
        cases = sorted((ROOT / "benchmark" / "contracts").glob("*/ground-truth.json"))
        self.assertEqual(len(cases), 33)
        clean_count = 0
        for path in cases:
            truth = json.loads(path.read_text())
            clean_count += int(truth["clean"])
            self.assertTrue(truth["source"].startswith("https://"))
            self.assertTrue((path.parent / truth["sourceFile"]).is_file())
        self.assertEqual(clean_count, 3)

    def add_case(self, root, case_id, truth, source="pragma solidity 0.8.19; contract Sample {}"):
        case = root / case_id
        case.mkdir(parents=True)
        (case / "ground-truth.json").write_text(json.dumps(truth), encoding="utf-8")
        bundle = {"sources": {"Sample.sol": {"content": source}},
                  "compilation": {"compilerVersion": "0.8.19"}}
        (case / "verified-source.json").write_text(json.dumps(bundle), encoding="utf-8")
        return case

    def test_counts_detector_ids_and_writes_input_bound_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "contracts"
            root.mkdir()
            self.add_case(root, "vulnerable", {"knownIssues": ["reentrancy-eth", "tx-origin"],
                                                "clean": False, "source": "https://example.org/source"})
            self.add_case(root, "clean", {"knownIssues": [], "clean": True,
                                           "source": "https://example.org/clean"})

            def analyzer(bundle, timeout):
                if bundle.parent.name == "vulnerable":
                    return {"findings": ["reentrancy-eth", "arbitrary-send-eth"], "analysisState": "completed"}
                return {"findings": [], "analysisState": "completed"}

            result_dir = Path(directory) / "results"
            report = eval_pipeline.run_evaluation(root, result_dir, analyzer=analyzer)
            self.assertEqual((report["truePositiveCount"], report["falsePositiveCount"],
                              report["falseNegativeCount"]), (1, 1, 1))
            self.assertEqual(report["precision"], 0.5)
            self.assertEqual(report["recall"], 0.5)
            self.assertEqual(report["costUsd"], 0.0)
            saved = json.loads(Path(report["resultPath"]).read_text())
            self.assertEqual(saved["samples"][0]["inputSourceSha256"], report["samples"][0]["inputSourceSha256"])

    def test_missing_selected_layers_are_unavailable_not_zero_scores(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "contracts"
            root.mkdir()
            self.add_case(root, "case", {"knownIssues": ["bug"], "clean": False,
                                           "source": "https://example.org/source"})

            def analyzer(bundle, timeout):
                return {"findings": ["bug"], "analysisState": "completed"}

            report = eval_pipeline.run_evaluation(root, Path(directory) / "results",
                                                  analyzer=analyzer,
                                                  layers=["slither", "ir-reconcile", "invariants", "poc"])
            self.assertEqual(report["layers"]["slither"]["sampleCount"], 1)
            for layer in ("ir-reconcile", "invariants", "poc"):
                metrics = report["layers"][layer]
                self.assertEqual(metrics["sampleCount"], 0)
                self.assertEqual(metrics["unavailableSampleCount"], 1)
                self.assertEqual(metrics["unavailableReasons"], {"evidence_not_recorded": 1})
                self.assertEqual(report["samples"][0]["layers"][layer]["state"], "unavailable")

    def test_explicit_empty_layer_is_measured_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "contracts"
            root.mkdir()
            self.add_case(root, "case", {"knownIssues": ["bug"], "clean": False,
                                           "source": "https://example.org/source"})

            def analyzer(bundle, timeout):
                return {"findings": [], "ir-reconcile": [], "invariants": [], "poc": []}

            report = eval_pipeline.run_evaluation(root, Path(directory) / "results",
                                                  analyzer=analyzer, layers=["ir-reconcile"])
            metrics = report["layers"]["ir-reconcile"]
            self.assertEqual(metrics["sampleCount"], 1)
            self.assertEqual(metrics["unavailableSampleCount"], 0)
            self.assertTrue(metrics["no_incremental_value_detected"])

    def test_explicit_unavailable_layer_keeps_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "contracts"
            root.mkdir()
            self.add_case(root, "case", {"knownIssues": ["bug"], "clean": False,
                                           "source": "https://example.org/source"})

            def analyzer(bundle, timeout):
                return {"findings": ["bug"], "ir-reconcile": {"state": "unavailable",
                                                                  "reason": "ir_missing"}}

            report = eval_pipeline.run_evaluation(root, Path(directory) / "results",
                                                  analyzer=analyzer, layers=["ir-reconcile"])
            self.assertEqual(report["layers"]["ir-reconcile"]["unavailableReasons"], {"ir_missing": 1})

    def test_truth_requires_consistent_labels_and_https_source(self):
        for truth in (
            {"knownIssues": [], "clean": False, "source": "https://example.org"},
            {"knownIssues": ["bug"], "clean": True, "source": "https://example.org"},
            {"knownIssues": [], "clean": True, "source": "http://example.org"},
        ):
            with self.subTest(truth=truth), self.assertRaises(eval_pipeline.BenchmarkError):
                eval_pipeline._validate_truth(truth, Path("ground-truth.json"))

    def test_bundle_path_cannot_escape_sample_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory) / "case"
            case.mkdir()
            with self.assertRaises(eval_pipeline.BenchmarkError):
                eval_pipeline._bundle_path(case, {"bundlePath": "../outside.json"})

    def test_changed_input_changes_source_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.add_case(root, "case", {"knownIssues": ["bug"], "clean": False,
                                           "source": "https://example.org"})
            bundle = root / "case" / "verified-source.json"
            first = eval_pipeline._source_hash(bundle)
            data = json.loads(bundle.read_text())
            data["sources"]["Sample.sol"]["content"] += " // changed"
            bundle.write_text(json.dumps(data))
            self.assertNotEqual(first, eval_pipeline._source_hash(bundle))


if __name__ == "__main__":
    unittest.main()
