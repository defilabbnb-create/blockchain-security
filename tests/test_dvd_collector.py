import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("dvd_collector", ROOT / "scripts" / "collect-dvd-selected.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DvdCollectorTests(unittest.TestCase):
    def test_allowlist_is_small_and_commit_is_fixed(self):
        self.assertEqual(set(MODULE.CHALLENGES), {"side-entrance", "naive-receiver", "truster"})
        self.assertEqual(MODULE.COMMIT, "64fddf9f96de2782f8868898d68673acb295119c")
        self.assertEqual(MODULE.LICENSE, "MIT")

    def test_rejects_unlisted_challenge_before_network_access(self):
        with self.assertRaisesRegex(ValueError, "allowlist"):
            MODULE.collect(challenges=["backdoor"])

    def test_single_challenge_caps_default_worker_count(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE, "CORPUS", Path(folder)), patch.object(
            MODULE, "_collect_challenge", return_value={"status": "collected", "challenge": "side-entrance"}
        ):
            manifest = MODULE.collect(challenges=["side-entrance"], workers=3)
        self.assertEqual(manifest["workerCount"], 1)

    def test_collects_only_selected_files_and_records_not_run(self):
        challenge = "side-entrance"
        spec = MODULE.CHALLENGES[challenge]
        license_bytes = b"The MIT License (MIT)\n"
        # The pinned upstream license fingerprint is enforced; mock it at the
        # byte boundary so this unit test does not depend on network access.
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE, "CORPUS", Path(folder)):
            contents = {
                spec["sourcePaths"][0]: b"pragma solidity =0.8.25; contract Pool {}\n",
                spec["promptPath"]: b"# Side Entrance\n",
                spec["harnessPath"]: f"function {spec['testName']}() public {{\n    \n}}\n".encode(),
                MODULE.LICENSE_PATH: license_bytes,
            }
            with patch.object(MODULE, "_fetch_file", side_effect=lambda path, _timeout: contents[path]), patch.object(
                MODULE, "_sha256_bytes", side_effect=lambda content: "ed4450f0d63ff98ad63473635714117a9bfa2ba1175768b0163f76c3f1425468" if content == license_bytes else hashlib.sha256(content).hexdigest()
            ):
                manifest = MODULE.collect(challenges=[challenge], workers=1)
            self.assertEqual(manifest["failures"], [])
            self.assertEqual(manifest["candidateCount"], 1)
            self.assertEqual(manifest["collectedCount"], 1)
            self.assertEqual(manifest["samples"][0]["commit"], MODULE.COMMIT)
            self.assertEqual(manifest["samples"][0]["sourceLicense"], "MIT")
            self.assertEqual(manifest["samples"][0]["dynamicState"], "not_run")
            self.assertTrue(manifest["samples"][0]["harness"]["templateOnly"])
            self.assertFalse(manifest["samples"][0]["harness"]["requiresExternalRpc"])
            saved = Path(folder) / "manifest.json"
            self.assertTrue(saved.is_file())
            self.assertTrue(Path(folder, "metadata", challenge, "prompt.md").is_file())
            self.assertTrue(Path(folder, "metadata", challenge, "harness.t.sol").is_file())

    def test_rejects_license_fingerprint_mismatch(self):
        challenge = "side-entrance"
        spec = MODULE.CHALLENGES[challenge]
        contents = {
            spec["sourcePaths"][0]: b"pragma solidity =0.8.25; contract Pool {}\n",
            spec["promptPath"]: b"# Side Entrance\n",
            spec["harnessPath"]: f"function {spec['testName']}() public {{}}\n".encode(),
            MODULE.LICENSE_PATH: b"Not MIT\n",
        }
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE, "_fetch_file", side_effect=lambda path, _timeout: contents[path]), patch.object(MODULE, "CORPUS", Path(folder)):
            with self.assertRaisesRegex(ValueError, "license"):
                MODULE._collect_challenge(challenge, spec, 1)
            self.assertFalse(Path(folder, "objects").exists())

    def test_resolves_relative_imports_and_preserves_dependency_source_units(self):
        self.assertEqual(
            MODULE._resolve_source_unit("src/truster/TrusterLenderPool.sol", "../DamnValuableToken.sol"),
            "src/DamnValuableToken.sol",
        )
        self.assertEqual(
            MODULE._resolve_source_unit("src/side-entrance/SideEntranceLenderPool.sol",
                                        "solady/utils/SafeTransferLib.sol"),
            "solady/utils/SafeTransferLib.sol",
        )
        self.assertEqual(
            MODULE._dependency_location("@openzeppelin/contracts/utils/Address.sol")[2],
            "contracts/utils/Address.sol",
        )
        with self.assertRaisesRegex(ValueError, "unsafe_repository_path"):
            MODULE._resolve_source_unit("src/A.sol", "../../outside.sol")

    def test_import_scanner_ignores_commented_out_imports(self):
        source = b'''// import "solmate/not-real.sol";\nimport {X} from "solady/utils/X.sol";\n/* import "bad.sol"; */\n'''
        self.assertEqual(MODULE._source_unit_imports(source), ["solady/utils/X.sol"])

    def test_analysis_bundle_mirrors_source_units_and_dependency_provenance(self):
        target = "src/example/Pool.sol"
        dependency = "solady/utils/Helper.sol"
        source_units = {
            target: b"pragma solidity =0.8.25; contract Pool {}\n",
            dependency: b"pragma solidity ^0.8.4; library Helper {}\n",
        }
        origins = {dependency: {
            "repo": "vectorized/solady", "commit": "77b41d04aa0aa80d6c455d8c9a379ae067ab4c98",
            "path": "src/utils/Helper.sol", "url": "https://example.invalid/Helper.sol", "license": "MIT",
        }}
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE, "CORPUS", Path(folder)):
            bundle = MODULE._materialize_analysis_bundle(
                "example", {"sourcePaths": [target]}, source_units, origins
            )
            self.assertTrue((Path(folder) / "bundles/example" / dependency).is_file())
            self.assertEqual(bundle["targets"], {target: "Pool"})
            self.assertEqual(bundle["sourceUnitCount"], 2)
            self.assertEqual(bundle["dependencyFiles"][0]["importPath"], dependency)
            self.assertEqual(bundle["dependencyFiles"][0]["commit"], origins[dependency]["commit"])
            analysis_input = json.loads((Path(folder) / "bundles/example/static-input.json").read_text())
            self.assertEqual(set(analysis_input["sources"]), {target, dependency})


if __name__ == "__main__":
    unittest.main()
