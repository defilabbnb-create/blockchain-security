import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/prepare-solc-cache.py"
SPEC = importlib.util.spec_from_file_location("prepare_solc_cache", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PrepareSolcCacheTests(unittest.TestCase):
    def test_manifest_versions_are_exact_deduplicated_and_sorted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            path.write_text(json.dumps({"samples": [
                {"analysis": {"compilerVersion": "0.8.28"}},
                {"analysis": {"compilerVersion": "0.4.18+commit.9cf6e910",
                              "compilerPinnedVersion": "0.4.18"}},
                {"analysis": {"compilerVersion": "^0.7.0"}},
            ]}), encoding="utf-8")
            self.assertEqual(MODULE.versions_from_manifest(path), ["0.4.18", "0.8.28"])

    def test_manifest_accepts_full_compiler_build_version_without_pin(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            path.write_text(json.dumps({"samples": [
                {"analysis": {"compilerVersion": "0.4.18+commit.9cf6e910"}},
                {"analysis": {"compilerVersion": "0.8.28+commit.7893614a.Emscripten.clang"}},
            ]}), encoding="utf-8")
            self.assertEqual(MODULE.versions_from_manifest(path), ["0.4.18", "0.8.28"])

    def test_manifest_exact_pragma_is_collected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            path.write_text(json.dumps({"samples": [
                {"compilerPragmas": ["=0.4.18"]},
                {"compilerPragmas": ["^0.8.0"]},
            ]}), encoding="utf-8")
            self.assertEqual(MODULE.versions_from_manifest(path), ["0.4.18"])

    def test_manifest_range_uses_one_selected_release_when_catalog_is_supplied(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            path.write_text(json.dumps({"samples": [
                {"compilerPragmas": ["^0.8.0"]},
                {"compilerPragmas": ["^0.4.18"]},
            ]}), encoding="utf-8")
            versions = MODULE.versions_from_manifest(
                path,
                released_versions={"0.4.18", "0.4.26", "0.8.19", "0.8.28"},
                cached_versions={"0.4.18", "0.8.19"},
            )
            self.assertEqual(versions, ["0.4.18", "0.8.19"])

    def test_malformed_compiler_pragmas_are_ignored_without_losing_exact_version(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            path.write_text(json.dumps({"samples": [
                {"analysis": {"compilerVersion": "0.4.18"}, "compilerPragmas": None},
                {"compilerPragmas": "^0.8.0"},
            ]}), encoding="utf-8")
            self.assertEqual(MODULE.versions_from_manifest(path), ["0.4.18"])

    def test_benchmark_pins_are_deduplicated_and_sorted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, version in (("one", "0.8.19"), ("two", "0.4.18"), ("bad", "^0.8.0")):
                target = root / name
                target.mkdir()
                (target / "ground-truth.json").write_text(json.dumps({"solcVersion": version}), encoding="utf-8")
            self.assertEqual(MODULE.versions_from_benchmarks(root), ["0.4.18", "0.8.19"])

    def test_all_manifest_paths_only_returns_manifest_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "alpha").mkdir()
            (root / "beta").mkdir()
            (root / "alpha" / "manifest.json").write_text("{}", encoding="utf-8")
            (root / "beta" / "manifest.json").write_text("{}", encoding="utf-8")
            self.assertEqual([p.parent.name for p in MODULE.all_manifest_paths(root)], ["alpha", "beta"])

    def test_distinct_versions_prefetch_in_parallel_and_duplicates_once(self):
        barrier = threading.Barrier(2)
        calls = []
        lock = threading.Lock()

        def loader(version):
            with lock:
                calls.append(version)
            barrier.wait(timeout=2)
            return Path(f"/cache/{version}"), {"sha256": f"sha-{version}",
                                                   "longVersion": version, "catalogSha256": "catalog"}

        results = MODULE.prefetch(["0.4.18", "0.8.28", "0.4.18"], workers=2,
                                  compiler_loader=loader)
        self.assertEqual(calls.count("0.4.18"), 1)
        self.assertEqual(calls.count("0.8.28"), 1)
        self.assertEqual([row["version"] for row in results], ["0.4.18", "0.8.28"])
        self.assertTrue(all(row["state"] == "ready" for row in results))

    def test_failure_is_recorded_without_cancelling_other_versions(self):
        def loader(version):
            if version == "0.4.18":
                raise ValueError("not in catalog")
            return Path(f"/cache/{version}"), {"sha256": "sha"}

        rows = MODULE.prefetch(["0.4.18", "0.8.28"], workers=2, compiler_loader=loader)
        self.assertEqual([row["state"] for row in rows], ["failed", "ready"])
        self.assertIn("not in catalog", rows[0]["reason"])

    def test_invalid_release_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid Solidity release"):
            MODULE.prefetch(["latest"])

    def test_boolean_worker_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "workers must be 1..16"):
            MODULE.prefetch(["0.4.18"], workers=True, compiler_loader=lambda version: None)


if __name__ == "__main__":
    unittest.main()
