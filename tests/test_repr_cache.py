import hashlib
import importlib.util
import json
import multiprocessing
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repr_cache", ROOT / "scripts" / "repr_cache.py")
repr_cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repr_cache)


def _concurrent_cache_build(cache_root, calls_path, barrier):
    key = "a" * 64
    barrier.wait()

    def build():
        with Path(calls_path).open("a") as calls:
            calls.write("build\n")
        time.sleep(0.05)
        return {"source-ir.json": {"state": "completed", "value": 1}}

    repr_cache.get_or_build(key, build, cache_root=Path(cache_root),
                            inputs={"sourceBundleSha256": "b" * 64},
                            tool_versions={"compiler": "0.8.19"},
                            required_artifacts=("source-ir.json",))


class RepresentationCacheTests(unittest.TestCase):
    def test_key_uses_source_hash_version_and_canonical_settings(self):
        source = {"sources": {"A.sol": {"content": "contract A {}"}}}
        digest = repr_cache.source_bundle_sha256(source)
        first = repr_cache.cache_key(digest, "0.8.19", {"optimizer": {"enabled": True, "runs": 200}})
        same = repr_cache.cache_key(digest, "0.8.19", {"optimizer": {"runs": 200, "enabled": True}})
        self.assertEqual(first, same)
        self.assertNotEqual(first, repr_cache.cache_key(digest, "0.8.23", {"optimizer": {"runs": 200, "enabled": True}}))

    def test_miss_builds_and_hit_verifies_every_artifact_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_root = Path(directory)
            key = "a" * 64
            calls = []

            def build():
                calls.append("built")
                return {"source-ir.json": {"state": "completed", "functions": []}}

            first = repr_cache.get_or_build(key, build, cache_root=cache_root, required_artifacts=("source-ir.json",))
            second = repr_cache.get_or_build(key, build, cache_root=cache_root, required_artifacts=("source-ir.json",))
            self.assertFalse(first["cacheHit"])
            self.assertTrue(second["cacheHit"])
            self.assertTrue(second["meta"]["cacheHit"])
            self.assertEqual(calls, ["built"])
            meta = json.loads((cache_root / key / "meta.json").read_text())
            artifact = (cache_root / key / "source-ir.json").read_bytes()
            self.assertEqual(meta["artifactsSha256"]["source-ir.json"], hashlib.sha256(artifact).hexdigest())

    def test_corrupt_artifact_is_rebuilt(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_root = Path(directory)
            key = "c" * 64
            repr_cache.get_or_build(key, lambda: {"source-ir.json": {"state": "completed", "n": 1}},
                                    cache_root=cache_root, required_artifacts=("source-ir.json",))
            (cache_root / key / "source-ir.json").write_text('{"state":"completed","n":999}')
            result = repr_cache.get_or_build(key, lambda: {"source-ir.json": {"state": "completed", "n": 2}},
                                             cache_root=cache_root, required_artifacts=("source-ir.json",))
            self.assertFalse(result["cacheHit"])
            self.assertEqual(json.loads(result["artifacts"]["source-ir.json"])["n"], 2)

    def test_required_unavailable_representation_is_built_and_existing_is_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_root = Path(directory)
            key = "d" * 64
            repr_cache.get_or_build(key, lambda: {"source-ir.json": {"state": "completed", "n": 1}},
                                    cache_root=cache_root, required_artifacts=("source-ir.json",))
            result = repr_cache.get_or_build(key, lambda: {"bytecode-ir.json": {"state": "completed", "n": 2}},
                                             cache_root=cache_root, required_artifacts=("bytecode-ir.json",))
            self.assertFalse(result["cacheHit"])
            self.assertEqual(json.loads(result["artifacts"]["source-ir.json"])["n"], 1)
            self.assertEqual(json.loads(result["artifacts"]["bytecode-ir.json"])["n"], 2)

    def test_concurrent_builders_publish_one_complete_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_root = Path(directory) / "cache"
            calls = Path(directory) / "calls.log"
            context = multiprocessing.get_context("fork")
            barrier = context.Barrier(4)
            processes = [context.Process(target=_concurrent_cache_build,
                                          args=(str(cache_root), str(calls), barrier)) for _ in range(4)]
            for process in processes:
                process.start()
            for process in processes:
                process.join(10)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(calls.read_text().splitlines(), ["build"])
            entry = cache_root / ("a" * 64)
            meta = json.loads((entry / "meta.json").read_text())
            for name, digest in meta["artifactsSha256"].items():
                self.assertEqual(hashlib.sha256((entry / name).read_bytes()).hexdigest(), digest)

    def test_lru_removes_oldest_entries_when_limit_is_exceeded(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_root = Path(directory)
            older, newer = "1" * 64, "2" * 64
            for key in (older, newer):
                repr_cache.get_or_build(
                    key, lambda: {"source-ir.json": {"state": "completed", "payload": "x" * 100}},
                    cache_root=cache_root, required_artifacts=("source-ir.json",), max_cache_bytes=10_000)
            old_meta_path = cache_root / older / "meta.json"
            old_meta = json.loads(old_meta_path.read_text())
            old_meta["lastAccessAt"] = "2020-01-01T00:00:00+00:00"
            old_meta_path.write_text(json.dumps(old_meta))
            repr_cache.get_or_build(
                "3" * 64, lambda: {"source-ir.json": {"state": "completed", "payload": "y" * 100}},
                cache_root=cache_root, required_artifacts=("source-ir.json",), max_cache_bytes=1)
            self.assertFalse((cache_root / older).exists())
            self.assertTrue((cache_root / ("3" * 64)).exists())


if __name__ == "__main__":
    unittest.main()
