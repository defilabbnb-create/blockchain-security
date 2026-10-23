import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("github_collector", ROOT / "scripts" / "collect-github-vulnerabilities.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GithubCollectorTests(unittest.TestCase):
    def test_category_uses_source_directory_names(self):
        self.assertEqual(MODULE._category("dataset/access_control/0xabc.sol"), "access_control")
        self.assertEqual(MODULE._category("dataset/arithmetic/overflow.sol"), "arithmetic")
        self.assertEqual(MODULE._category("dataset/unchecked_low_level_calls/unchecked.sol"), "unchecked_low_level_calls")
        self.assertEqual(MODULE._category("reentrancy/Reentrancy.sol"), "reentrancy")

    def test_safe_path_rejects_traversal_and_accepts_nested_solidity(self):
        self.assertEqual(MODULE._safe_path("reentrancy/Reentrancy.sol"), "reentrancy/Reentrancy.sol")
        for value in ("../escape.sol", "/absolute.sol", "a\\b.sol", "a/../b.sol", ""):
            with self.assertRaises(ValueError):
                MODULE._safe_path(value)

    def test_collect_one_is_content_addressed_and_pinned(self):
        content = b"pragma solidity 0.8.19; contract Example {}\n"
        dataset = {"repo": "crytic/not-so-smart-contracts", "commit": "a" * 40, "license": "Apache-2.0"}
        item = {"path": "reentrancy/Reentrancy.sol"}
        with tempfile.TemporaryDirectory() as folder, patch.object(MODULE, "CORPUS", Path(folder)):
            with patch.object(MODULE, "_request_bytes", return_value=content):
                row = MODULE._collect_one(dataset, item, 1)
            self.assertEqual(row["status"], "collected")
            self.assertEqual(row["commit"], "a" * 40)
            self.assertEqual(row["sha256"], MODULE._sha256_bytes(content))
            saved = Path(folder) / "objects" / row["sha256"][:2] / (row["sha256"] + ".sol")
            self.assertEqual(saved.read_bytes(), content)
            self.assertEqual(row["analysis"], {"static": "not_run", "dynamic": "not_run", "decompiler": "not_run"})

    def test_collect_records_fetch_failure_without_claiming_analysis(self):
        dataset = {"repo": "crytic/not-so-smart-contracts", "commit": "b" * 40, "license": "Apache-2.0"}
        item = {"path": "reentrancy/Reentrancy.sol"}
        with patch.object(MODULE, "_request_bytes", side_effect=TimeoutError("slow")):
            row = MODULE._collect_one(dataset, item, 1)
        self.assertEqual(row["status"], "failed")
        self.assertIn("TimeoutError", row["failureReason"])
        self.assertNotIn("analysis", row)


if __name__ == "__main__":
    unittest.main()
