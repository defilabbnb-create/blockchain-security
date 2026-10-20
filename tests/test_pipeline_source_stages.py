import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pipeline_source_stages", ROOT / "scripts" / "pipeline_source_stages.py")
stages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stages)


class PipelineSourceStagesTests(unittest.TestCase):
    def test_collect_validates_hash_and_confines_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Vault.sol"
            source.write_text("pragma solidity 0.8.19; contract Vault { function ping() external {} }\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            result = stages.run_stage("collect", {"source": str(source), "sourceSha256": digest}, root / "run", "local")
            self.assertEqual(result["state"], "completed")
            output = Path(result["sourcePath"])
            self.assertTrue(output.is_file())
            self.assertEqual(output.parent.parent, (root / "run").resolve())
            bad = stages.run_stage("collect", {"source": str(source), "sourceSha256": "0" * 64}, root / "bad", "local")
            self.assertEqual(bad["state"], "failed")
            self.assertIn("sha256", bad["reason"])

    def test_repr_caches_source_bundle_and_labels_other_representations_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Vault.sol"
            source.write_text("pragma solidity 0.8.19; contract Vault {}\n", encoding="utf-8")
            collected = stages.collect_source({"source": str(source)}, root / "run")
            result = stages.run_stage("repr", {"sourcePath": collected["sourcePath"]}, root / "run", "local")
            self.assertEqual(result["state"], "completed")
            self.assertTrue(Path(result["artifactPath"]).is_file())
            artifact = json.loads(Path(result["artifactPath"]).read_text(encoding="utf-8"))
            self.assertEqual(artifact["representation"], "source_bundle")
            self.assertEqual(result["representationStates"]["bytecode-ir.json"], "not_available")
            self.assertEqual(set(result["artifactPaths"]), {
                "source-ir.json", "bytecode-ir.json", "decompiled.json", "ir-reconciliation.json"})
            self.assertFalse(artifact["document"]["semanticsProven"])

    def test_repr_binds_supplied_artifacts_by_content_and_rejects_wrong_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Vault.sol"
            source.write_text("pragma solidity 0.8.19; contract Vault {}\n", encoding="utf-8")
            collected = stages.collect_source({"source": str(source)}, root / "run")
            ir = {"schemaVersion": 1, "functions": [], "operations": [], "storageAccesses": [], "events": []}
            bytecode_ir = {"schemaVersion": 1, "functions": [], "operations": [], "storageAccesses": [], "events": []}
            ir_path = root / "ir.json"
            bytecode_path = root / "bytecode-ir.json"
            ir_path.write_text(json.dumps(ir), encoding="utf-8")
            bytecode_path.write_text(json.dumps(bytecode_ir), encoding="utf-8")
            result = stages.run_stage("repr", {"sourcePath": collected["sourcePath"],
                                                "unifiedIR": str(ir_path),
                                                "bytecodeIR": str(bytecode_path),
                                                "decompilerInput": "PUSH1 0x01\nSTOP"}, root / "run", "local")
            self.assertEqual(result["state"], "completed")
            self.assertEqual(result["representationStates"]["ir-reconciliation.json"], "completed")
            self.assertIsNotNone(result["sourceIrSha256"])
            bad = stages.run_stage("repr", {"sourcePath": collected["sourcePath"], "unifiedIR": str(ir_path),
                                              "sourceIRSha256": "0" * 64}, root / "bad", "local")
            self.assertEqual(bad["state"], "failed")
            self.assertIn("sha256_mismatch", bad["reason"])

    def test_non_local_mode_never_reads_or_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            result = stages.run_stage("collect", {"source": str(Path(directory) / "missing")}, Path(directory) / "run", "fixed_block_fork")
            self.assertEqual(result["state"], "unavailable")

    def test_collect_rejects_env_files_without_copying_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / ".env"
            secret.write_text("API_KEY=should-not-be-read\n", encoding="utf-8")
            result = stages.run_stage("collect", {"source": str(secret)}, root / "run", "local")
            self.assertEqual(result, {"state": "failed", "reason": "secret_source_path_rejected"})
            self.assertFalse((root / "run" / "source" / "verified-source.json").exists())


if __name__ == "__main__":
    unittest.main()
