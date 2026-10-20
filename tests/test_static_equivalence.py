import copy
import json
import io
import os
import contextlib
import tempfile
import unittest
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("compare_static_analysis", ROOT / "scripts" / "compare-static-analysis.py")
mod = module_from_spec(spec)
spec.loader.exec_module(mod)

VALID = {
    "state": "partial",
    "compiler": "0.8.28",
    "compilerProvenance": {"version": "0.8.28"},
    "contracts": 1,
    "detectors": 10,
    "findingCount": 1,
    "findings": [{"check": "demo", "impact": "High", "elements": []}],
    
    "verifiedSourceFingerprint": "a" * 64,
    "staticStages": {"compile": "completed", "detectors": "completed", "callGraph": "partial"},
    "callGraph": {"state": "partial", "edgeCount": 2, "report": "left/call-graph.json"},
    "localTests": {"state": "not_performed", "reason": "no harness"},
}

VALID["findingSemanticFingerprint"] = mod.semantic_finding_fingerprint(VALID["findings"])

class TestStaticEquivalence(unittest.TestCase):
    def test_identical_reports_equal(self):
        r = copy.deepcopy(VALID)
        self.assertTrue(mod.compare_reports(r, r)["equivalent"])

    def test_timings_paths_differ_still_equal(self):
        left = copy.deepcopy(VALID)
        right = copy.deepcopy(VALID)
        right["timings"] = {"analysisWallMs": 123}
        right["localTests"]["report"] = "right/local-tests.json"
        right["analysisExecution"] = {"start": "2024-01-02", "end": "2024-01-03"}
        right["callGraph"]["report"] = "right/call-graph.json"
        self.assertTrue(mod.compare_reports(left, right)["equivalent"])

    def test_volatile_slither_fields_recompute_equal(self):
        left = copy.deepcopy(VALID)
        right = copy.deepcopy(VALID)
        right["findings"][0]["id"] = "new-id"
        right["findings"][0]["description"] = "new desc"
        right["findings"][0]["markdown"] = "new md"
        self.assertTrue(mod.compare_reports(left, right)["equivalent"])

    def test_impact_change_mismatch(self):
        left = copy.deepcopy(VALID)
        right = copy.deepcopy(VALID)
        right["findings"][0]["impact"] = "Medium"
        right["findingSemanticFingerprint"] = mod.semantic_finding_fingerprint(right["findings"])
        self.assertFalse(mod.compare_reports(left, right)["equivalent"])

    def test_edgeCount_change_mismatch(self):
        left = copy.deepcopy(VALID)
        right = copy.deepcopy(VALID)
        right["callGraph"]["edgeCount"] = 3
        self.assertFalse(mod.compare_reports(left, right)["equivalent"])

    def test_unknown_callGraph_field_change_mismatch(self):
        left = copy.deepcopy(VALID)
        right = copy.deepcopy(VALID)
        right["callGraph"]["unknown"] = "x"
        self.assertFalse(mod.compare_reports(left, right)["equivalent"])

    def test_compilerProvenance_change_mismatch(self):
        left = copy.deepcopy(VALID)
        right = copy.deepcopy(VALID)
        right["compilerProvenance"]["version"] = "0.8.29"
        self.assertFalse(mod.compare_reports(left, right)["equivalent"])

    def test_missing_source_fingerprint_invalid(self):
        r = copy.deepcopy(VALID)
        del r["verifiedSourceFingerprint"]
        with self.assertRaises(ValueError):
            mod.validate_report(r)

    def test_wrong_declared_finding_hash_invalid(self):
        r = copy.deepcopy(VALID)
        r["findingSemanticFingerprint"] = "b" * 64
        with self.assertRaises(ValueError):
            mod.validate_report(r)

    def test_contracts_bool_invalid(self):
        r = copy.deepcopy(VALID)
        r["contracts"] = True
        with self.assertRaises(ValueError):
            mod.validate_report(r)

    def test_findingCount_bool_invalid(self):
        r = copy.deepcopy(VALID)
        r["findingCount"] = True
        with self.assertRaises(ValueError):
            mod.validate_report(r)

    def test_asymmetric_dependency_fingerprint_invalid(self):
        r = copy.deepcopy(VALID)
        r["verifiedDependencyFingerprint"] = "c" * 64
        with self.assertRaises(ValueError):
            mod.compare_reports(VALID, r)

    def test_compare_reports_does_not_mutate_inputs(self):
        left = copy.deepcopy(VALID)
        right = copy.deepcopy(VALID)
        left["callGraph"]["report"] = "left/call-graph.json"
        right["callGraph"]["report"] = "right/call-graph.json"
        mod.compare_reports(left, right)
        self.assertEqual(left["callGraph"]["report"], "left/call-graph.json")
        self.assertEqual(right["callGraph"]["report"], "right/call-graph.json")



class StaticEquivalenceCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.left = self.folder / "left.json"
        self.right = self.folder / "right.json"
        self.left.write_text(json.dumps(VALID))
        self.right.write_text(json.dumps(VALID))

    def invoke(self, *extra):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = mod.main(["--left", str(self.left), "--right", str(self.right), *map(str, extra)])
        return code, json.loads(stream.getvalue())

    def test_identical_exit_zero_and_new_output_matches_stdout(self):
        output = self.folder / "new" / "nested" / "result.json"
        code, result = self.invoke("--output", output)
        self.assertEqual(code, 0)
        self.assertTrue(result["equivalent"])
        self.assertEqual(json.loads(output.read_text()), result)

    def test_mismatch_exit_one(self):
        right = copy.deepcopy(VALID)
        right["callGraph"]["edgeCount"] += 1
        self.right.write_text(json.dumps(right))
        code, result = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(result["equivalent"])
        self.assertIn({"name": "callGraph", "pass": False}, result["checks"])

    def test_invalid_exit_two_with_same_error_file(self):
        right = copy.deepcopy(VALID)
        right["findingSemanticFingerprint"] = "b" * 64
        self.right.write_text(json.dumps(right))
        output = self.folder / "errors" / "result.json"
        code, result = self.invoke("--output", output)
        self.assertEqual(code, 2)
        self.assertIn("error", result)
        self.assertEqual(json.loads(output.read_text()), result)

    def test_input_output_aliases_preserve_bytes(self):
        before = self.left.read_bytes()
        symlink = self.folder / "symlink.json"
        symlink.symlink_to(self.left)
        hardlink = self.folder / "hardlink.json"
        os.link(self.left, hardlink)
        for output in (self.left, self.right, symlink, hardlink):
            with self.subTest(output=output):
                code, result = self.invoke("--output", output)
                self.assertEqual(code, 2)
                self.assertIn("error", result)
                self.assertEqual(self.left.read_bytes(), before)
                self.assertEqual(self.right.read_bytes(), before)

    def test_malformed_json_exit_two(self):
        self.left.write_text("{bad")
        code, result = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("error", result)

    def test_directory_output_exit_two_and_no_leaked_temp(self):
        output = self.folder / "directory"
        output.mkdir()
        before = sorted(p.name for p in self.folder.iterdir())
        code, result = self.invoke("--output", output)
        self.assertEqual(code, 2)
        self.assertIn("error", result)
        self.assertEqual(sorted(p.name for p in self.folder.iterdir()), before)


class StableDynamicSummaryTests(unittest.TestCase):
    def test_only_scenario_duration_is_ignored_and_inputs_are_preserved(self):
        left = copy.deepcopy(VALID)
        left["localTests"] = {"state": "passed", "report": "left.json", "tests": 1, "passed": 1, "failed": 0,
                              "results": [{"id": "scenario", "state": "passed", "durationMs": 11, "operations": 7}]}
        right = copy.deepcopy(left)
        right["localTests"]["results"][0]["durationMs"] = 99
        right["localTests"]["report"] = "right.json"
        snapshots = copy.deepcopy((left, right))
        self.assertTrue(mod.compare_reports(left, right)["equivalent"])
        self.assertEqual((left, right), snapshots)
        right["localTests"]["results"][0]["operations"] = 8
        self.assertFalse(mod.compare_reports(left, right)["equivalent"])

    def test_dependency_source_path_is_ignored_but_fingerprint_is_compared(self):
        left = copy.deepcopy(VALID)
        right = copy.deepcopy(VALID)
        left["verifiedDependencyFingerprint"] = "c" * 64
        right["verifiedDependencyFingerprint"] = "c" * 64
        left["localTests"]["verifiedDependencySource"] = "/tmp/run-a/dependency.json"
        right["localTests"]["verifiedDependencySource"] = "/tmp/run-b/dependency.json"
        self.assertTrue(mod.compare_reports(left, right)["equivalent"])
        right["verifiedDependencyFingerprint"] = "d" * 64
        self.assertFalse(mod.compare_reports(left, right)["equivalent"])

    def test_unknown_stable_fields_and_dynamic_failures_are_not_ignored(self):
        right = copy.deepcopy(VALID)
        right["localTests"]["extra"] = {"durationMs": 1}
        self.assertFalse(mod.compare_reports(VALID, right)["equivalent"])
        for state in ("failed", "unavailable", "running", True):
            right = copy.deepcopy(VALID)
            right["localTests"]["state"] = state
            with self.subTest(state=state), self.assertRaises(ValueError):
                mod.validate_report(right)



if __name__ == "__main__":
    unittest.main()
