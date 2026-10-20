import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('benchmark_process', ROOT / 'scripts' / 'benchmark_process.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BenchmarkProcessTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.folder = Path(temp.name)
        self.addCleanup(temp.cleanup)

    def sampler(self, _pid):
        return {'rssKiB': 2048, 'maxProcessRssKiB': 1024, 'processCount': 1}

    def run_child(self, code, timeout=5, sampler=None):
        return MODULE.run_analyzer([sys.executable, '-c', code], ROOT, os.environ.copy(),
                                   self.folder, timeout, sampler or self.sampler)

    def test_sample_group_rss_filters_process_group_and_skips_bad_rows(self):
        output = '1 0 200 77\n2 1 300 77\n3 0 900 88\nbad row\n'
        with mock.patch.object(MODULE.subprocess, 'run', return_value=mock.Mock(stdout=output)):
            result = MODULE.sample_group_rss_kib(77)
        self.assertEqual(result, {'rssKiB': 500, 'maxProcessRssKiB': 300, 'processCount': 2})

    def test_sampler_error_is_explicit(self):
        with mock.patch.object(MODULE.subprocess, 'run', side_effect=OSError):
            self.assertEqual(MODULE.sample_group_rss_kib(77), {'samplingError': 'OSError'})

    def test_success_captures_output_and_memory_samples(self):
        result = self.run_child('import time; time.sleep(.25); print(42)')
        self.assertEqual(result['exitCode'], 0)
        self.assertIn('42', (self.folder / 'stdout.json').read_text())
        self.assertEqual(result['peakGroupRssMiB'], 2)
        self.assertEqual(result['peakProcessRssMiB'], 1)
        self.assertGreater(result['rssSamples'], 0)
        self.assertNotIn('error', result)

    def test_timeout_kills_and_reaps_child_process(self):
        result = self.run_child('import time; time.sleep(30)', timeout=.2)
        self.assertEqual(result['error'], 'analyzer_timeout')
        self.assertLess(result['exitCode'], 0)
        self.assertLess(result['wallSeconds'], 5)

    def test_spawn_failure_is_recorded_and_outputs_exist(self):
        result = MODULE.run_analyzer(['/missing/benchmark-command'], ROOT, os.environ.copy(),
                                    self.folder, 5, self.sampler)
        self.assertIn('FileNotFoundError', result['error'])
        self.assertTrue((self.folder / 'stdout.json').exists())
        self.assertTrue((self.folder / 'stderr.log').exists())
        self.assertGreater(result['wallSeconds'], 0)

    def test_sampler_failure_kills_and_reaps_child_process(self):
        def fail(_pid):
            raise RuntimeError('sampler failed')
        result = self.run_child('import time; time.sleep(30)', sampler=fail)
        self.assertIn('RuntimeError', result['error'])
        self.assertLess(result['exitCode'], 0)

    def test_success_kills_long_lived_descendant_after_leader_exit(self):
        pid_file = self.folder / 'descendant.pid'
        code = f"import subprocess, sys; child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); open({str(pid_file)!r}, 'w').write(str(child.pid))"
        result = self.run_child(code)
        self.assertEqual(result['exitCode'], 0)
        child_pid = int(pid_file.read_text())
        for _ in range(20):
            status = subprocess.run(
                ['ps', '-o', 'stat=', '-p', str(child_pid)],
                capture_output=True, text=True,
            ).stdout.strip()
            if not status or status.lstrip().startswith('Z'):
                break
            time.sleep(0.1)
        self.assertTrue(
            not status or status.lstrip().startswith('Z'),
            'descendant remained alive after leader exit',
        )


if __name__ == '__main__':
    unittest.main()
