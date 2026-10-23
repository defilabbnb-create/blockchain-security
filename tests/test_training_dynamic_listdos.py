import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("training_dynamic_listdos", ROOT / "scripts/training-dynamic-listdos.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class TrainingDynamicListDosTests(unittest.TestCase):
    def test_source_identity_is_pinned(self):
        self.assertEqual(MODULE.SAMPLE, (
            "crytic/not-so-smart-contracts",
            "020dbdbde3e0c2e8de5f3944e7455e438b0995d5",
            "denial_of_service/list_dos.sol",
        ))
        source = ROOT / "training-data/github-vulnerabilities/objects/34/34dcd7cbad1f1cb261b3310e60fe0e8e7447ffd7aef3639df06a45a3c9e414dc.sol"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), MODULE.EXPECTED_SHA256)

    def test_feasibility_runner_does_not_patch_collected_source(self):
        harness = (ROOT / "scripts/training-dynamic-listdos.cjs").read_text(encoding="utf-8")
        self.assertIn("training_listdos_source_hash_mismatch", harness)
        self.assertIn("original_source_does_not_compile_as_collected", harness)
        self.assertIn("refundAmount[i]", harness)
        self.assertIn("confirmedVulnerability: false", harness)
        self.assertNotIn("source.replace", harness)


if __name__ == "__main__":
    unittest.main()
