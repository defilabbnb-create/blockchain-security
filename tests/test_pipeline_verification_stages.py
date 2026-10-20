import importlib.util
import json
import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verification", ROOT / "scripts" / "pipeline_verification_stages.py")
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


class VerificationStageTests(unittest.TestCase):
    def test_dynamic_builds_invariants_and_harness_from_ir_but_missing_adapter_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = "pragma solidity >=0.8.19; contract Vault { function totalAssets() external pure returns(uint){return 1;} }"
            bundle = {"sources": {"Vault.sol": {"content": source}},
                      "metadata": {"settings": {"compilationTarget": {"Vault.sol": "Vault"}}}}
            ir = {"schemaVersion": 1, "documentId": "vault-ir",
                  "contract": {"sourceSha256": "a" * 64, "metadata": {"decimals": 18}},
                  "functions": [{"name": f"Vault::{name}()", "sourceRef": {"file": "Vault.sol", "lines": [1]}}
                                for name in ("totalAssets", "totalSupply", "deposit", "withdraw", "redeem", "mint")],
                  "storageAccesses": [{"effect": {"variable": "Vault.totalAssets"}},
                                       {"effect": {"variable": "Vault.totalSupply"}}],
                  "operations": []}
            target = {"unifiedIR": ir, "sourceBundle": bundle}
            result = verification.run_stage("dynamic", target, root / "stage", "local")
            generated = json.loads((root / "stage" / "invariants.json").read_text())
            self.assertEqual(len(generated["invariants"]), 3)
            self.assertEqual((root / "stage" / "harness" / "harness.json").is_file(), True)
            self.assertEqual(result["state"], "unavailable")
            dynamic = json.loads((root / "stage" / "dynamic-result.json").read_text())
            self.assertEqual([row["state"] for row in dynamic["results"]], ["unavailable"] * 3)
            self.assertNotEqual(result["state"], "completed")

    def test_dynamic_ir_path_requires_both_ir_and_verified_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            result = verification.run_stage("dynamic", {"unifiedIR": {}}, Path(directory) / "stage", "local")
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["reason"], "unified_ir_or_verified_source_bundle_missing")

    def test_dynamic_local_fixture_is_read_only_and_records_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "harness"
            harness.mkdir()
            (harness / "harness.json").write_text(json.dumps({"tests": [{"invariantId": "inv-1"}]}), encoding="utf-8")
            result_rows = [{"invariantId": "inv-1", "mode": "local", "state": "violated", "evidenceSha256": "x" * 64}]
            with patch.object(verification, "run_harness", return_value=result_rows):
                result = verification.run_stage("dynamic", {"harness": str(harness)}, root / "stage", "local")
            self.assertEqual(result["state"], "completed")
            self.assertEqual(result["outcome"], "invariant_violated")
            artifact = json.loads((root / "stage" / "dynamic-result.json").read_text())
            self.assertEqual(len(artifact["evidenceSha256"]), 64)

    def test_explicit_harness_can_be_preferred_over_automatic_ir_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "harness"
            harness.mkdir()
            (harness / "harness.json").write_text(json.dumps({"deployment": {"state": "ready"},
                "tests": [{"invariantId": "a" * 64}]}), encoding="utf-8")
            rows = [{"invariantId": "a" * 64, "state": "passed"}]
            with patch.object(verification, "run_harness", return_value=rows):
                result = verification.run_stage("dynamic", {
                    "unifiedIR": {"functions": []}, "sourceBundle": {"sources": {}},
                    "harness": str(harness), "preferHarness": True}, root / "stage", "local")
            self.assertEqual(result["state"], "completed")
            self.assertEqual(result["outcome"], "passed")

    def test_decompile_semantics_is_explicitly_heuristic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = verification.run_stage("decompile", {"bytecode": "0x600060005560006000f4ff"}, root / "stage")
            self.assertEqual(result["state"], "completed")
            self.assertFalse(result["semanticsProven"])
            self.assertTrue((root / "stage" / "decompiled-semantics.json").is_file())

    def _poc_inputs(self, root):
        source = "pragma solidity >=0.8.19; contract Vault { function ping() external {} }"
        bundle = {"sources": {"Vault.sol": {"content": source}}}
        finding = {"id": "finding-verification-1", "reachableAssetsUsd": 10}
        bundle_path = root / "bundle.json"
        finding_path = root / "finding.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        finding_path.write_text(json.dumps(finding), encoding="utf-8")
        return finding_path, bundle_path, finding, bundle

    def test_poc_without_adapter_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding, bundle, _, _ = self._poc_inputs(root)
            result = verification.run_stage("poc", {"finding": str(finding), "sourceBundle": str(bundle)}, root / "stage")
            self.assertEqual(result["state"], "completed")
            self.assertEqual(result["pocState"], "unconfirmed")
            self.assertFalse(json.loads((root / "stage" / "poc-result.json").read_text())["confirmed_by_poc"])

    def test_poc_confirmed_only_after_real_successful_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding, bundle, finding_data, bundle_data = self._poc_inputs(root)
            import hashlib
            test_name = "testPoC_" + hashlib.sha256(finding_data["id"].encode()).hexdigest()[:16]
            adapter = f"pragma solidity >=0.8.19; contract Proof {{ function {test_name}() public pure {{}} }}"
            result = verification.run_stage(
                "poc", {"finding": str(finding), "sourceBundle": str(bundle), "pocTestSource": adapter},
                root / "stage", forge_runner=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, f"[PASS] {test_name}() (gas: 123)".encode(), b""))
            self.assertEqual(result["pocState"], "confirmed")
            payload = json.loads((root / "stage" / "poc-result.json").read_text())
            self.assertTrue(payload["confirmed_by_poc"])
            self.assertTrue(payload["attempts"][0]["matchedTestPassed"])
            self.assertEqual(payload["attempts"][0]["testName"], test_name)

    def test_poc_zero_exit_without_matching_pass_output_stays_unconfirmed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding, bundle, finding_data, _ = self._poc_inputs(root)
            import hashlib
            test_name = "testPoC_" + hashlib.sha256(finding_data["id"].encode()).hexdigest()[:16]
            adapter = f"pragma solidity >=0.8.19; contract Proof {{ function {test_name}() public pure {{}} }}"
            for output in (b"", b"forge test passed", b"[PASS] testPoC_0000000000000000"):
                stage = root / f"stage-{len(list(root.glob('stage-*')))}"
                result = verification.run_stage(
                    "poc", {"finding": str(finding), "sourceBundle": str(bundle), "pocTestSource": adapter}, stage,
                    forge_runner=lambda *args, _output=output, **kwargs: subprocess.CompletedProcess(args[0], 0, _output, b""))
                self.assertEqual(result["pocState"], "unconfirmed")
                payload = json.loads((stage / "poc-result.json").read_text())
                self.assertFalse(payload["confirmed_by_poc"])
                self.assertNotEqual(payload["attempts"][0]["state"], "passed")


if __name__ == "__main__":
    unittest.main()
