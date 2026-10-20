import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'benchmark_static_analysis_evidence_test_target',
    ROOT / 'scripts' / 'benchmark-static-analysis.py',
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BenchmarkEvidenceConsistencyTests(unittest.TestCase):
    def test_collect_evidence_rejects_companion_graph_mismatch(self):
        fingerprint = 'a' * 64
        dynamic = {
            'state': 'passed',
            'tests': 1,
            'passed': 1,
            'failed': 0,
            'results': [{'state': 'passed'}],
        }

        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            report = {
                'state': 'completed',
                'analysisExecution': {'staticDynamicStages': 'serial'},
                'staticStages': {},
                'findingCount': 0,
                'findingSemanticFingerprint': 'b' * 64,
                'verifiedSourceFingerprint': fingerprint,
                'localTests': {**dynamic, 'verifiedSourceFingerprint': fingerprint},
                'callGraph': {'state': 'completed', 'edgeCount': 1},
            }
            local = {
                **dynamic,
                'verifiedSourceFingerprint': fingerprint,
                'sourceCoverage': {},
                'traces': [],
                'staticCorrelation': {},
            }
            graph = {'state': 'completed', 'edgeCount': 2}
            (folder / 'stdout.json').write_text(json.dumps(report))
            (folder / 'local-tests.json').write_text(json.dumps(local))
            (folder / 'call-graph.json').write_text(json.dumps(graph))

            with mock.patch.object(MODULE.comparator, 'validate_report'):
                with self.assertRaisesRegex(ValueError, 'edgeCount'):
                    MODULE.collect_evidence(folder, {'mode': 'serial'})


if __name__ == '__main__':
    unittest.main()
