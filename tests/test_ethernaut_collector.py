import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ethernaut_collector", ROOT / "scripts" / "collect-ethernaut-selected.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EthernautCollectorTests(unittest.TestCase):
    def test_pinned_source_and_allowlist(self):
        self.assertEqual(MODULE.COMMIT, "c6174bb3b68dde01ff15571e67ad5254cc6939a9")
        self.assertEqual(MODULE.LICENSE, "MIT")
        self.assertEqual(set(MODULE.CHALLENGES), {"fallback", "telephone", "coinflip", "force", "king"})

    def test_rejects_duplicate_or_unknown_challenges(self):
        with self.assertRaises(ValueError):
            MODULE.collect(challenges=["fallback", "fallback"])
        with self.assertRaises(ValueError):
            MODULE.collect(challenges=["missing"])

    def test_collects_selected_challenge_and_keeps_dynamic_not_run(self):
        challenge = "telephone"
        spec = MODULE.CHALLENGES[challenge]
        license_bytes = b"The MIT License (MIT)\n"
        contents = {
            spec["targetPath"]: b"pragma solidity ^0.8.0; contract Telephone { address public owner; }\n",
            spec["attackPath"]: b"pragma solidity ^0.8.0; contract TelephoneAttack {}\n",
            spec["promptPath"]: b"# Telephone\n",
            spec["harnessPath"]: b"it('should allow the player to solve the level', async function () {});\n",
            MODULE.LICENSE_PATH: license_bytes,
        }
        license_hash = hashlib.sha256(license_bytes).hexdigest()
        with tempfile.TemporaryDirectory(dir=ROOT) as folder, patch.object(MODULE, "CORPUS", Path(folder)), \
                patch.object(MODULE, "LICENSE_SHA256", license_hash), \
                patch.object(MODULE, "request_bytes", side_effect=lambda path, _timeout: contents[path]):
            manifest = MODULE.collect(challenges=[challenge], workers=4)
            self.assertEqual(manifest["collectedCount"], 1)
            self.assertEqual(manifest["failedCount"], 0)
            sample = manifest["samples"][0]
            self.assertEqual(sample["dynamicState"], "not_run")
            self.assertFalse(sample["harness"]["requiresExternalRpc"])
            object_path = ROOT / sample["sourceFiles"][0]["objectPath"]
            self.assertTrue(object_path.is_file())
            self.assertEqual(hashlib.sha256(object_path.read_bytes()).hexdigest(), sample["sourceFiles"][0]["sha256"])

    def test_license_failure_is_explicit(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE, "CORPUS", Path(folder)), \
                patch.object(MODULE, "request_bytes", return_value=b"not a license"):
            manifest = MODULE.collect(challenges=["fallback"], workers=1)
        self.assertEqual(manifest["collectedCount"], 0)
        self.assertEqual(manifest["failedCount"], 1)
        self.assertIn("license", manifest["failures"][0]["failureReason"])


if __name__ == "__main__":
    unittest.main()
