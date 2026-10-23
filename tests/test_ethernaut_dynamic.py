import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ethernaut_dynamic", ROOT / "scripts" / "run-ethernaut-dynamic.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EthernautDynamicTests(unittest.TestCase):
    def _sample(self):
        return {"challenge": "telephone", "sourceBundleSha256": "bundle"}

    def _runner_result(self, *, compiler_sha="0xcompiler", chain_id=31337, mode="isolated_in_process"):
        return {
            "state": "confirmed", "confirmedVulnerability": True,
            "executionBoundary": {"mode": mode, "chainId": chain_id},
            "compilerArtifact": {"sha256": compiler_sha},
        }

    def test_compiler_hash_and_execution_boundary_are_required_for_confirmation(self):
        compiler_path = Path(tempfile.gettempdir()) / "ethernaut-test-soljson.cjs"
        compiler_path.write_text("compiler", encoding="utf-8")
        metadata = {"version": "0.8.29", "longVersion": "0.8.29+commit.test", "sha256": "0xcompiler"}
        with patch.object(MODULE.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(
                ["node"], 0, json.dumps(self._runner_result()), "")
            result = MODULE.run_one(self._sample(), compiler_path, metadata, 5)
        self.assertEqual(result["state"], "confirmed")
        self.assertTrue(result["confirmedVulnerability"])

        for bad in (
            self._runner_result(compiler_sha="0xother"),
            self._runner_result(chain_id=1),
            self._runner_result(mode="fixed_block_fork"),
        ):
            with patch.object(MODULE.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess(["node"], 0, json.dumps(bad), "")
                result = MODULE.run_one(self._sample(), compiler_path, metadata, 5)
            self.assertEqual(result["state"], "failed")
            self.assertFalse(result["confirmedVulnerability"])

    def test_timeout_is_explicit_failure(self):
        compiler_path = Path(tempfile.gettempdir()) / "ethernaut-test-soljson.cjs"
        compiler_path.write_text("compiler", encoding="utf-8")
        metadata = {"version": "0.8.29", "longVersion": "0.8.29+commit.test", "sha256": "0xcompiler"}
        timeout = subprocess.TimeoutExpired(["node"], 5, output=b"partial", stderr=b"timed out")
        with patch.object(MODULE.subprocess, "run", side_effect=timeout):
            result = MODULE.run_one(self._sample(), compiler_path, metadata, 5)
        self.assertEqual(result["state"], "timeout")
        self.assertFalse(result["confirmedVulnerability"])
        self.assertEqual(result["reason"], "dynamic_runner_timeout")


if __name__ == "__main__":
    unittest.main()
