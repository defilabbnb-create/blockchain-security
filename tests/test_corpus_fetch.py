import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("corpus_fetch", ROOT / "scripts" / "corpus_fetch.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CorpusFetchTests(unittest.TestCase):
    def source(self):
        return {"repo": "example/repo", "commit": "a" * 40, "license": "MIT",
                "licensePath": "LICENSE", "kind": "原仓库分类", "prefixes": [""], "default": True}

    def test_allowlist_rejects_duplicate_or_unpinned_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "allowlist.json"
            path.write_text(json.dumps({"sources": [self.source(), self.source()]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_allowlist(path)
            bad = self.source()
            bad["commit"] = "main"
            path.write_text(json.dumps({"sources": [bad]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_allowlist(path)

    def test_fetch_is_text_only_hash_bound_and_offline_repeatable(self):
        source = self.source()
        tree = {"truncated": False, "tree": [
            {"type": "blob", "path": "contracts/Victim.sol"},
            {"type": "blob", "path": "README.md"},
            {"type": "tree", "path": "contracts/Skip.sol"},
        ]}
        body = b"\xef\xbb\xbfpragma solidity 0.4.26;\r\ncontract Victim {}\r\n"

        def request(url, timeout, *, json_response):
            return tree if json_response else body

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output, cache = root / "v2", root / "cache"
            with patch.object(MODULE, "load_allowlist", return_value=[source]), \
                 patch.object(MODULE, "existing_duplicates", return_value={}), \
                 patch.object(MODULE, "request", side_effect=request):
                first = MODULE.collect(output=output, cache=cache, workers=2)
            self.assertEqual((first["candidateCount"], first["collectedCount"], first["failedCount"]), (1, 1, 0))
            manifest = json.loads((output / "manifest.json").read_text())
            row = manifest["samples"][0]
            self.assertEqual(row["sha256"], MODULE.sha256(body[3:].replace(b"\r\n", b"\n")))
            self.assertEqual(row["labelSource"]["kind"], "原仓库分类")
            self.assertTrue((root / row["objectPath"]).is_file())
            with patch.object(MODULE, "load_allowlist", return_value=[source]), \
                 patch.object(MODULE, "existing_duplicates", return_value={}), \
                 patch.object(MODULE, "request", side_effect=AssertionError("network used in offline mode")):
                second = MODULE.collect(output=output, cache=cache, workers=1, offline=True)
            self.assertEqual(second["samples"][0]["sha256"], row["sha256"])
            self.assertEqual(second["samples"][0]["rawSha256"], row["rawSha256"])

    def test_existing_hash_is_marked_duplicate_and_excluded(self):
        source = self.source()
        tree = {"truncated": False, "tree": [{"type": "blob", "path": "Victim.sol"}]}
        body = b"pragma solidity 0.4.26; contract Victim {}"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(MODULE, "load_allowlist", return_value=[source]), \
                 patch.object(MODULE, "existing_duplicates", return_value={MODULE.sha256(body): "v1:existing"}), \
                 patch.object(MODULE, "request", side_effect=lambda _url, _timeout, *, json_response: tree if json_response else body):
                result = MODULE.collect(output=root / "v2", cache=root / "cache")
            row = result["samples"][0]
            self.assertEqual(row["duplicateOf"], "v1:existing")
            self.assertFalse(row["analysisEligible"])


if __name__ == "__main__":
    unittest.main()
