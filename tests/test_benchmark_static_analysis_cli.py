import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'benchmark-static-analysis.py'


class BenchmarkCliValidationTests(unittest.TestCase):
    def run_cli(self, output, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), '--source', str(output.parent / 'missing.json'), '--output', str(output), *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_rounds_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'out.json'
            result = self.run_cli(output, '--rounds', '0')
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)['status'], 'invalid')
            self.assertFalse(output.exists())

    def test_duplicate_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'out.json'
            result = self.run_cli(output, '--rounds', '1', '--modes', 'serial', 'serial', 'parallel')
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)['status'], 'invalid')
            self.assertFalse(output.exists())

    def test_missing_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'out.json'
            result = self.run_cli(output, '--rounds', '1', '--modes', 'serial')
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)['status'], 'invalid')
            self.assertFalse(output.exists())

    def test_invalid_timeouts_are_rejected_before_output_creation(self):
        for timeout in ('nan', 'inf', '-inf', '0'):
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / 'out.json'
                result = self.run_cli(output, '--rounds', '1', f'--timeout={timeout}')
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)['status'], 'invalid')
                self.assertFalse(output.exists())
