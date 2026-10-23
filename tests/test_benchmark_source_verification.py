import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_benchmark_sources", ROOT / "scripts" / "verify-benchmark-sources.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BenchmarkSourceVerificationTests(unittest.TestCase):
    def create_case(self, root, source_url):
        case = root / "sample"
        case.mkdir()
        content = b"pragma solidity 0.8.19; contract Sample {}\n"
        (case / "Sample.sol").write_bytes(content)
        (case / "ground-truth.json").write_text(json.dumps({
            "source": source_url, "sourceFile": "Sample.sol",
        }), encoding="utf-8")
        return case, content

    def test_builds_raw_url_only_for_fixed_github_blob_commits(self):
        self.assertEqual(
            MODULE._raw_url("https://github.com/org/repo/blob/" + "a" * 40 + "/contracts/A.sol"),
            "https://raw.githubusercontent.com/org/repo/" + "a" * 40 + "/contracts/A.sol")
        self.assertIsNone(MODULE._raw_url("https://github.com/org/repo/blob/main/A.sol"))
        self.assertIsNone(MODULE._raw_url("https://example.org/source"))

    def test_verifies_exact_remote_bytes_and_flags_modified_local_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            case, content = self.create_case(Path(directory),
                "https://github.com/org/repo/blob/" + "a" * 40 + "/Sample.sol")
            result = MODULE.verify_case(case, fetch=lambda _url, _timeout: content)
            self.assertEqual(result["state"], "verified")
            self.assertEqual(result["sourceSha256"], result["remoteContentSha256"])
            self.assertTrue(result["remoteContentVerified"])

            mismatch = MODULE.verify_case(case, fetch=lambda _url, _timeout: content + b"// changed")
            self.assertEqual(mismatch["state"], "mismatch")
            self.assertFalse(mismatch["remoteContentVerified"])

    def test_synthetic_sources_are_not_fetched_or_labeled_as_remote_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            case, _content = self.create_case(Path(directory), "https://example.org/local-fixture")
            result = MODULE.verify_case(case, fetch=lambda *_args: self.fail("synthetic source must not fetch"))
            self.assertEqual(result["state"], "synthetic_local_fixture")
            self.assertFalse(result["remoteContentVerified"])


if __name__ == "__main__":
    unittest.main()
