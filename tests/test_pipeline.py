import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("pipeline", ROOT / "scripts" / "pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


class PipelineTests(unittest.TestCase):
    def targets(self, directory):
        path = Path(directory) / "targets.json"
        path.write_text(json.dumps({"targets": [{"id": "vault-a", "address": "0x" + "11" * 20}]}), encoding="utf-8")
        return path

    def test_resume_does_not_repeat_completed_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            target_file = self.targets(directory)
            calls = []

            def runner(stage, target, stage_dir, mode):
                calls.append(stage)
                return {"state": "completed", "costUsd": 0}

            output = Path(directory) / "run-1"
            pipeline.run_pipeline(target_file, stages=["recon", "repr"], output=output, runner=runner)
            pipeline.run_pipeline(target_file, stages=["recon", "repr"], output=output, resume=output, runner=runner)
            self.assertEqual(calls, ["recon", "repr"])

    def test_verified_source_and_unified_ir_paths_flow_to_dynamic_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = root / "targets.json"
            targets.write_text(json.dumps({"targets": [{"id": "flow"}]}), encoding="utf-8")
            seen = {}

            def runner(stage, target, stage_dir, mode):
                if stage == "collect":
                    return {"state": "completed", "sourcePath": str(root / "verified-source.json")}
                if stage == "static":
                    return {"state": "completed", "unifiedIR": str(root / "unified-ir.json"),
                            "sourceBundle": str(root / "verified-source.json")}
                if stage == "dynamic":
                    seen.update({key: target.get(key) for key in ("unifiedIR", "sourceBundle")})
                return {"state": "unavailable", "reason": "fixture"}

            pipeline.run_pipeline(targets, stages=["collect", "static", "dynamic"], output=root / "run", runner=runner)
            self.assertEqual(seen["unifiedIR"], str(root / "unified-ir.json"))
            self.assertEqual(seen["sourceBundle"], str(root / "verified-source.json"))

    def test_static_cli_failure_is_not_reported_as_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_bundle = root / "verified-source.json"
            source_bundle.write_text(json.dumps({
                "sources": {"Vault.sol": {"content": "pragma solidity 0.8.19; contract Vault {}"}},
                "compilation": {"compilerVersion": "0.8.19"},
            }), encoding="utf-8")
            completed = type("Completed", (), {"returncode": 0, "stdout": '{"state":"failed","error":"compiler unavailable"}', "stderr": ""})()
            with patch.object(pipeline.subprocess, "run", return_value=completed):
                result = pipeline._default_runner("static", {"sourcePath": str(source_bundle)}, root / "target", "local")
            self.assertEqual(result["state"], "failed")
            self.assertEqual(result["analysisState"], "failed")
            self.assertEqual(result["analysisReason"], "compiler unavailable")
            self.assertEqual(result["representation"]["semanticsProven"], False)

    def test_static_cli_non_object_json_is_not_reported_as_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_bundle = root / "verified-source.json"
            source_bundle.write_text(json.dumps({"sources": {"Vault.sol": {"content": "contract Vault {}"}}}), encoding="utf-8")
            completed = type("Completed", (), {"returncode": 0, "stdout": "[]", "stderr": ""})()
            with patch.object(pipeline.subprocess, "run", return_value=completed):
                result = pipeline._default_runner("static", {"sourcePath": str(source_bundle)}, root / "target", "local")
            self.assertEqual(result["state"], "failed")
            self.assertEqual(result["reason"], "static_stage_returned_invalid_schema")

    def test_static_hypotheses_feed_local_review_and_report_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Vault.sol"
            source.write_text("pragma solidity 0.8.19; contract Vault {}\n", encoding="utf-8")
            targets = root / "targets.json"
            targets.write_text(json.dumps({"targets": [{"id": "vault", "source": str(source)}]}), encoding="utf-8")

            def runner(stage, target, stage_dir, mode):
                if stage == "collect":
                    return pipeline._default_runner(stage, target, stage_dir, mode)
                if stage == "static":
                    parsed = {"state": "completed", "sourceSha256": "a" * 64,
                              "findings": [{"ruleId": "reentrancy", "impact": "High", "description": "candidate"}]}
                    pipeline._atomic_json(stage_dir / "static.json", parsed)
                    index = pipeline._write_pipeline_finding_index(stage_dir, parsed, parsed["sourceSha256"])
                    return {"state": "completed", "findingIndex": str(index)}
                if stage == "review":
                    self.assertTrue(Path(target["findingIndex"]).is_file())
                return {"state": "completed"}

            result = pipeline.run_pipeline(targets, stages=["collect", "static", "review"],
                                           output=root / "run", runner=runner)
            self.assertEqual(result["state"], "completed")
            index = json.loads((root / "run" / "vault" / "finding-index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["findings"][0]["status"], "static_signal")
            self.assertFalse(index["findings"][0]["confirmedVulnerability"])

    def test_failure_blocks_downstream_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            target_file = self.targets(directory)

            def runner(stage, target, stage_dir, mode):
                if stage == "repr":
                    return {"state": "failed", "reason": "fixture_failure"}
                return {"state": "completed"}

            result = pipeline.run_pipeline(target_file, stages=["recon", "repr", "static"],
                                           output=Path(directory) / "run-2", runner=runner)
            stages = result["targets"][0]["stages"]
            self.assertEqual(stages["repr"]["state"], "failed")
            self.assertEqual(stages["static"], {"state": "blocked", "reason": "upstream_stage_failed"})
            self.assertEqual(result["state"], "partial")

    def test_missing_adapter_is_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            target_file = self.targets(directory)
            result = pipeline.run_pipeline(target_file, stages=["collect"], output=Path(directory) / "run-3")
            self.assertEqual(result["targets"][0]["stages"]["collect"]["state"], "unavailable")
            self.assertEqual(result["state"], "partial")

    def test_rejects_unknown_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            target_file = self.targets(directory)
            with self.assertRaises(pipeline.PipelineError):
                pipeline.run_pipeline(target_file, stages=["unknown"], output=Path(directory) / "run-4")

    def test_local_collection_and_report_stages_write_hash_bound_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Vault.sol"
            source.write_text("pragma solidity 0.8.19; contract Vault {}\n", encoding="utf-8")
            index = root / "finding-index.json"
            index.write_text(json.dumps({"schemaVersion": 1, "findings": []}), encoding="utf-8")
            targets = root / "targets.json"
            targets.write_text(json.dumps({"targets": [{"id": "vault", "source": str(source),
                                                        "findingIndex": str(index)}]}), encoding="utf-8")
            output = root / "run-5"
            result = pipeline.run_pipeline(targets, stages=["collect", "report"], output=output)
            stages = result["targets"][0]["stages"]
            self.assertEqual(stages["collect"]["state"], "completed")
            self.assertEqual(stages["report"]["state"], "completed")
            self.assertEqual(result["state"], "completed")
            self.assertTrue((output / "vault" / "source" / "verified-source.json").is_file())
            self.assertTrue((output / "vault" / "reports" / "report.sarif.json").is_file())


if __name__ == "__main__":
    unittest.main()
