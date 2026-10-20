import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from representation_pipeline import build_representations


class RepresentationPipelineTests(unittest.TestCase):
    def setUp(self):
        self.bundle = {
            "sources": {"Vault.sol": {"content": "pragma solidity 0.8.19; contract Vault {}"}},
            "compilation": {"compilerVersion": "0.8.19"},
            "metadata": {"settings": {"optimizer": {"enabled": True, "runs": 200}}},
        }
        self.source_ir = {"schemaVersion": 1, "functions": [], "operations": [], "storageAccesses": [], "events": []}
        self.bytecode_ir = {"schemaVersion": 1, "functions": [], "operations": [], "storageAccesses": [], "events": []}

    def test_four_artifacts_share_cache_and_bind_input_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            first = build_representations(self.bundle, source_ir=self.source_ir, bytecode_ir=self.bytecode_ir,
                                          decompiler_input="PUSH1 0x01\nSTOP", cache_root=directory)
            second = build_representations(self.bundle, source_ir=self.source_ir, bytecode_ir=self.bytecode_ir,
                                           decompiler_input="PUSH1 0x01\nSTOP", cache_root=directory)
            self.assertFalse(first["cacheHit"])
            self.assertTrue(second["cacheHit"])
            self.assertEqual(set(first["artifacts"]), {
                "source-ir.json", "bytecode-ir.json", "decompiled.json", "ir-reconciliation.json"})
            self.assertEqual(first["artifacts"]["source-ir.json"]["representationSha256"],
                             hashlib.sha256(json.dumps(self.source_ir, sort_keys=True, ensure_ascii=False,
                                                       separators=(",", ":")).encode()).hexdigest())
            self.assertEqual(first["artifacts"]["ir-reconciliation.json"]["sourceBundleSha256"],
                             first["sourceBundleSha256"])
            self.assertFalse(first["semanticsProven"])

    def test_rejects_mismatched_source_or_ir_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "source_bundle_sha256_mismatch"):
                build_representations(self.bundle, source_sha256="0" * 64, cache_root=directory)
            with self.assertRaisesRegex(ValueError, "source_ir_sha256_mismatch"):
                build_representations(self.bundle, source_ir=self.source_ir, source_ir_sha256="0" * 64,
                                      cache_root=directory)

    def test_missing_ir_is_explicit_and_never_confirms(self):
        with tempfile.TemporaryDirectory() as directory:
            result = build_representations(self.bundle, cache_root=directory)
            reconciliation = result["artifacts"]["ir-reconciliation.json"]
            self.assertEqual(reconciliation["state"], "not_available")
            self.assertFalse(reconciliation["confirmedVulnerability"])
            self.assertEqual(result["artifacts"]["decompiled.json"]["state"], "not_available")


if __name__ == "__main__":
    unittest.main()
