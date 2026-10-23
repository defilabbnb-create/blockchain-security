import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import atomic_json, digest, sample_id, write_shard
from corpus_merge import merge


class CorpusMergeTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "Sample.sol"
        source.write_text("pragma solidity 0.4.26; contract Sample {}\n")
        sample = {"repo": "example/corpus", "commit": "a" * 40, "path": "Sample.sol",
                  "objectPath": "Sample.sol", "sha256": digest(source.read_bytes()),
                  "analysis": {"decompiler": "not_run", "externalSentinel": "preserved"}}
        manifest = root / "manifest.json"
        atomic_json(manifest, {"samples": [sample], "metadataSentinel": "preserved"})
        return manifest, sample

    def test_two_process_writers_ten_iterations_do_not_lose_other_layer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, sample = self.fixture(root)
            shard_dir = root / "corpus-shards"
            worker = """
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from corpus_shards import write_shard
from corpus_merge import merge
root=Path(sys.argv[2]); layer=sys.argv[3]
sample=json.loads((root/'manifest.json').read_text())['samples'][0]
for i in range(10):
    patch={layer:'passed', layer+'Reason':str(i)}
    write_shard(sample,layer,patch,lane_id=layer,tool_versions={'test':'1'},shard_dir=(root/'corpus-shards'/layer))
    merge(root/'manifest.json',root/'corpus-shards',root)
"""
            processes = [subprocess.Popen([sys.executable, "-c", worker, str(ROOT / "scripts"), str(root), layer],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                         for layer in ("static", "dynamic")]
            for process in processes:
                _out, err = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, err)
            report = merge(manifest, shard_dir, root)
            saved = json.loads(manifest.read_text())
            analysis = saved["samples"][0]["analysis"]
            self.assertEqual((analysis["staticReason"], analysis["dynamicReason"]), ("9", "9"))
            self.assertEqual(analysis["externalSentinel"], "preserved")
            self.assertEqual(analysis["decompiler"], "not_run")
            self.assertEqual(saved["metadataSentinel"], "preserved")
            self.assertEqual(len(list((root / "corpus-shard-history" / sample_id(sample)).glob("*.json"))), 20)
            self.assertEqual(report["sampleCount"], 1)
            self.assertEqual(report["mergedShards"], 0)

    def test_deferred_merge_keeps_manifest_unchanged_and_reads_lane_shards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, sample = self.fixture(root)
            shard_root = root / "corpus-shards"
            write_shard(sample, "dynamic", {"dynamic": "unconfirmed"}, lane_id="D-dos",
                        tool_versions={"test": "1"}, shard_dir=shard_root / "D-dos")
            original = manifest.read_bytes()
            env = {**__import__("os").environ, "CORPUS_DEFER_MERGE": "1"}
            completed = subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py"),
                                        "--manifest", str(manifest), "--shards", str(shard_root),
                                        "--root", str(root)], env=env, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["state"], "deferred")
            self.assertEqual(manifest.read_bytes(), original)
            merged = merge(manifest, shard_root, root)
            saved = json.loads(manifest.read_text())
            self.assertEqual(merged["mergedShards"], 1)
            self.assertEqual(saved["samples"][0]["analysis"]["dynamic"], "unconfirmed")

    def test_invalid_shard_rejects_entire_merge_without_modifying_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, sample = self.fixture(root)
            shard_dir = root / "corpus-shards"
            path = write_shard(sample, "dynamic", {"dynamic": "passed"}, lane_id="D",
                               tool_versions={"test": "1"}, shard_dir=shard_dir)
            row = json.loads(path.read_text())
            row["analysis"]["static"] = "passed"
            atomic_json(path, row)
            original = manifest.read_bytes()
            with self.assertRaises(ValueError):
                merge(manifest, shard_dir, root)
            self.assertEqual(manifest.read_bytes(), original)

    def test_rejects_changed_source_and_preserves_prior_failed_shard_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, sample = self.fixture(root)
            shard_dir = root / "corpus-shards"
            for state in ("failed", "passed"):
                write_shard(sample, "dynamic", {"dynamic": state}, lane_id="D",
                            tool_versions={"test": "1"}, shard_dir=shard_dir)
            (root / "Sample.sol").write_text("changed")
            with self.assertRaises(ValueError):
                merge(manifest, shard_dir, root)
            states = {json.loads(path.read_text())["analysis"]["dynamic"] for path in
                      (root / "corpus-shard-history" / sample_id(sample)).glob("*.json")}
            self.assertEqual(states, {"failed", "passed"})


if __name__ == "__main__":
    unittest.main()
