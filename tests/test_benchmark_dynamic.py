import copy
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'benchmark_static_analysis', ROOT / 'scripts' / 'benchmark-static-analysis.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DynamicEvidenceValidationTests(unittest.TestCase):
    def valid(self):
        return {'state': 'passed', 'tests': 1, 'passed': 1, 'failed': 0,
                'results': [{'state': 'passed'}]}

    def test_accepts_complete_passed_evidence_without_mutating_it(self):
        evidence = self.valid()
        original = copy.deepcopy(evidence)
        MODULE.validate_dynamic(evidence)
        self.assertEqual(evidence, original)

    def test_rejects_nonpassed_states(self):
        for state in ('failed', 'unavailable', 'not_performed', 'running', True):
            evidence = self.valid()
            evidence['state'] = state
            with self.subTest(state=state), self.assertRaises(ValueError):
                MODULE.validate_dynamic(evidence)

    def test_rejects_inconsistent_or_boolean_counts(self):
        for key, value in (('tests', True), ('passed', True), ('failed', False),
                           ('tests', 0), ('passed', 0), ('failed', 1)):
            evidence = self.valid()
            evidence[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                MODULE.validate_dynamic(evidence)

    def test_rejects_missing_or_failed_scenario_results(self):
        for results in (None, [], [{'state': 'failed'}], [None]):
            evidence = self.valid()
            evidence['results'] = results
            with self.subTest(results=results), self.assertRaises(ValueError):
                MODULE.validate_dynamic(evidence)

    def test_invalid_cli_inputs_exit_two_without_creating_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'new-output'
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                result = MODULE.main(['--source', str(root / 'missing.json'),
                                      '--output', str(output)])
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())
            self.assertIn('"status": "invalid"', stream.getvalue())


if __name__ == '__main__':
    unittest.main()
