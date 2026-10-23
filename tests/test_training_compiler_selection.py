import importlib.util
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-training-corpus.py"
SPEC = importlib.util.spec_from_file_location("training_compiler_selection", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TrainingCompilerSelectionTests(unittest.TestCase):
    def test_local_benchmark_ground_truth_exposes_smartbugs_pin(self):
        self.assertEqual(
            MODULE.BENCHMARK_COMPILER_PINS.get((
                "smartbugs/smartbugs-curated",
                "230e649123477eff332742a59a1c7cc6dc286cab",
                "dataset/reentrancy/reentrance.sol",
            )),
            "0.4.18",
        )

    def test_exact_pragma_keeps_the_exact_release(self):
        self.assertEqual(
            MODULE.infer_version("pragma solidity 0.4.18;", {"0.4.18", "0.4.25"}, {"0.4.18", "0.4.25"}),
            ("0.4.18", "pragma_exact_cached"),
        )

    def test_caret_range_uses_highest_compatible_cached_release(self):
        self.assertEqual(
            MODULE.infer_version("pragma solidity ^0.4.23;", {"0.4.2", "0.4.24", "0.5.17"}, {"0.4.2", "0.4.24", "0.5.17"}),
            ("0.4.24", "pragma_range_cached"),
        )

    def test_range_download_falls_back_to_official_release_catalog(self):
        self.assertEqual(
            MODULE.infer_version("pragma solidity >=0.4.18 <0.5.0;", {"0.4.2"}, {"0.4.18", "0.4.26", "0.5.0"}),
            ("0.4.26", "pragma_range_download"),
        )

    def test_or_ranges_are_evaluated_as_alternatives(self):
        self.assertTrue(MODULE.version_satisfies("0.5.17", "^0.4.18 || ^0.5.10"))
        self.assertFalse(MODULE.version_satisfies("0.6.0", "^0.4.18 || ^0.5.10"))

    def test_wildcard_and_partial_versions_expand_to_minor_bounds(self):
        for expression in ("0.4.x", "0.4.*", "0.4"):
            self.assertTrue(MODULE.version_satisfies("0.4.26", expression))
            self.assertFalse(MODULE.version_satisfies("0.5.0", expression))

    def test_caret_and_tilde_accept_partial_versions(self):
        self.assertTrue(MODULE.version_satisfies("0.4.26", "^0.4"))
        self.assertFalse(MODULE.version_satisfies("0.5.0", "^0.4"))
        self.assertTrue(MODULE.version_satisfies("0.4.26", "~0.4"))
        self.assertFalse(MODULE.version_satisfies("0.5.0", "~0.4"))

    def test_missing_pragma_is_not_guessed(self):
        self.assertEqual(MODULE.infer_version("contract A {}", {"0.4.18"}), (None, "pragma_missing"))

    def test_comments_do_not_create_a_pragma(self):
        source = "/* pragma solidity 0.8.28; */\npragma solidity 0.4.18;\ncontract A {}"
        self.assertEqual(
            MODULE.infer_version(source, {"0.4.18", "0.8.28"}, {"0.4.18", "0.8.28"}),
            ("0.4.18", "pragma_exact_cached"),
        )

    def test_multiple_pragmas_use_their_intersection(self):
        source = "pragma solidity >=0.4.18 <0.5.0;\npragma solidity ^0.4.23;\ncontract A {}"
        self.assertEqual(
            MODULE.infer_version(source, {"0.4.18", "0.4.24", "0.5.17"},
                                 {"0.4.18", "0.4.24", "0.5.17"}),
            ("0.4.24", "pragma_range_cached"),
        )

    def test_no_pragma_uses_bounded_historical_matrix(self):
        candidates, reason = MODULE.compiler_candidates(
            "contract A {}", {"0.4.18", "0.5.17"}, {"0.4.18", "0.4.25", "0.5.17"}
        )
        self.assertEqual(reason, "pragma_missing_matrix")
        self.assertEqual(candidates, ["0.4.18", "0.4.25", "0.5.17"])

    def test_range_keeps_best_uncached_release_in_bounded_candidates(self):
        candidates, reason = MODULE.compiler_candidates(
            "pragma solidity >=0.4.18 <0.5.0; contract A {}",
            {"0.4.18", "0.4.19", "0.4.21", "0.4.24", "0.4.25"},
            {"0.4.18", "0.4.19", "0.4.21", "0.4.24", "0.4.25", "0.4.26"},
        )
        self.assertEqual(reason, "pragma_range_cached")
        self.assertIn("0.4.26", candidates)

    def test_range_keeps_newest_release_when_cache_has_many_old_versions(self):
        released = {f"0.4.{patch}" for patch in range(18, 31)}
        cached = set(sorted(released)[:-1])
        candidates, reason = MODULE.compiler_candidates(
            "pragma solidity >=0.4.18 <0.5.0; contract A {}", cached, released
        )
        self.assertEqual(reason, "pragma_range_cached")
        self.assertEqual(candidates[0], "0.4.29")
        self.assertIn("0.4.30", candidates)

    def test_benchmark_pin_overrides_a_pragma_range_for_reproducibility(self):
        candidates, reason = MODULE.compiler_candidates(
            "pragma solidity ^0.4.18; contract A {}",
            {"0.4.18", "0.4.26"}, {"0.4.18", "0.4.26"}, "0.4.18"
        )
        self.assertEqual(candidates, ["0.4.18"])
        self.assertEqual(reason, "benchmark_pinned_cached")

    def test_benchmark_pin_must_satisfy_pragma(self):
        candidates, reason = MODULE.compiler_candidates(
            "pragma solidity ^0.8.0; contract A {}",
            {"0.4.18"}, {"0.4.18", "0.8.28"}, "0.4.18"
        )
        self.assertEqual(candidates, [])
        self.assertEqual(reason, "benchmark_pin_violates_pragma")

    def test_summary_recomputes_all_stages_without_dropping_existing_evidence(self):
        samples = [
            {"analysis": {"static": "passed", "dynamic": "passed",
                          "confirmedVulnerability": True, "decompiler": "completed"}},
            {"analysis": {"static": "partial", "dynamic": "not_run", "decompiler": "failed"}},
            {"analysis": {"static": "failed", "dynamic": "unavailable", "decompiler": "partial"}},
        ]
        summary = MODULE.build_analysis_summary(samples, catalog_versions=120, cached_versions=42)
        self.assertEqual(summary["staticPassed"], 1)
        self.assertEqual(summary["staticPartial"], 1)
        self.assertEqual(summary["staticFailed"], 1)
        self.assertEqual(summary["dynamicPassed"], 1)
        self.assertEqual(summary["dynamicNotRun"], 1)
        self.assertEqual(summary["dynamicFailed"], 1)
        self.assertEqual(summary["dynamicConfirmed"], 1)
        self.assertEqual(summary["decompilerCompleted"], 1)
        self.assertEqual(summary["decompilerPartial"], 1)
        self.assertEqual(summary["decompilerFailed"], 1)
        self.assertEqual(summary["compilerCatalogVersions"], 120)
        self.assertEqual(summary["cachedCompilerVersions"], 42)

    def test_nonzero_analyzer_exit_cannot_be_reported_as_passed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "work").mkdir()
            source = (Path(__file__).resolve().parents[1] /
                      "benchmark/contracts/14-reentrance/reentrance.sol").read_text(encoding="utf-8")
            (root / "source.sol").write_text(source, encoding="utf-8")
            sample = {"objectPath": "source.sol", "path": "dataset/reentrancy/reentrance.sol",
                      "repo": "smartbugs/smartbugs-curated",
                      "commit": "230e649123477eff332742a59a1c7cc6dc286cab",
                      "sha256": hashlib.sha256(source.encode()).hexdigest()}
            completed = subprocess.CompletedProcess(
                ["review-static.py"], 1,
                json.dumps({"state": "completed", "findingCount": 0,
                            "compilerProvenance": {"sha256": "0xcompiler-hash",
                                                   "longVersion": "0.4.18+commit.test",
                                                   "build": "commit.test",
                                                   "catalogSha256": "0xcatalog-hash"}}) + "\n", ""
            )
            with patch.object(MODULE, "ROOT", root), \
                    patch.object(MODULE, "ANALYZER", root / "review-static.py"), \
                    patch.object(MODULE, "EVIDENCE_ROOT", root / "evidence"), \
                    patch.object(MODULE.subprocess, "run", return_value=completed):
                result = MODULE.run_one(sample, 5, {"0.4.18"}, {"0.4.18"})
            self.assertEqual(result["analysis"]["static"], "failed")
            self.assertEqual(result["analysis"]["staticReason"], "analyzer_exit_1")
            self.assertEqual(result["analysis"]["compilerVersion"], "0.4.18")
            self.assertEqual(result["analysis"]["compilerSelection"], "benchmark_pinned_cached")
            self.assertEqual(result["analysis"]["compilerAttempts"][0]["compilerSha256"], "0xcompiler-hash")
            self.assertEqual(result["analysis"]["compilerAttempts"][0]["compilerLongVersion"], "0.4.18+commit.test")
            self.assertEqual(result["analysis"]["compilerAttempts"][0]["compilerCatalogSha256"], "0xcatalog-hash")


if __name__ == "__main__":
    unittest.main()
