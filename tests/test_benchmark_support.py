import copy
import importlib.util
import math
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('benchmark_support', ROOT / 'scripts' / 'benchmark_support.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BenchmarkSummaryTests(unittest.TestCase):
    def test_means_peaks_auto_and_input_immutability(self):
        runs = [
            {'mode': 'serial', 'wallSeconds': 10, 'peakGroupRssMiB': 100},
            {'mode': 'serial', 'wallSeconds': 6, 'peakGroupRssMiB': 120},
            {'mode': 'parallel', 'wallSeconds': 4, 'peakGroupRssMiB': 150},
            {'mode': 'parallel', 'wallSeconds': 4, 'peakGroupRssMiB': 140},
            {'mode': 'auto', 'wallSeconds': 5, 'peakGroupRssMiB': 160},
        ]
        original = copy.deepcopy(runs)
        result = MODULE.summarize_performance(runs)
        self.assertEqual(result['byMode']['serial'], {'runs': 2, 'meanSeconds': 8, 'peakGroupRssMiB': 120})
        self.assertEqual(result['byMode']['parallel'], {'runs': 2, 'meanSeconds': 4, 'peakGroupRssMiB': 150})
        self.assertEqual(result['byMode']['auto'], {'runs': 1, 'meanSeconds': 5, 'peakGroupRssMiB': 160})
        self.assertEqual(result['speedup'], 2)
        self.assertEqual(result['wallTimeReductionPercent'], 50)
        self.assertEqual(runs, original)

    def test_invalid_rows_and_measurements_rejected(self):
        for value in (0, -1, True, math.nan, math.inf, -math.inf, None, '1'):
            with self.subTest(wallSeconds=value), self.assertRaises(ValueError):
                MODULE.summarize_performance([{'mode': 'serial', 'wallSeconds': value, 'peakGroupRssMiB': 1}])
        for value in (-1, True, math.nan, math.inf, None, '1'):
            with self.subTest(peakGroupRssMiB=value), self.assertRaises(ValueError):
                MODULE.summarize_performance([{'mode': 'serial', 'wallSeconds': 1, 'peakGroupRssMiB': value}])

    def test_invalid_shapes_modes_and_missing_required_modes(self):
        for rows in ([], ['row'], [{'mode': 'other', 'wallSeconds': 1, 'peakGroupRssMiB': 1}],
                     [{'mode': 'serial', 'wallSeconds': 1, 'peakGroupRssMiB': 1}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                MODULE.summarize_performance(rows)

    def test_invalid_wall_seconds_are_rejected(self):
        for value in (0, -1, True, math.nan, math.inf, -math.inf, None, '1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.summarize_performance([
                    {'mode': 'serial', 'wallSeconds': value, 'peakGroupRssMiB': 1}])

    def test_invalid_memory_measurements_are_rejected(self):
        for value in (-1, True, math.nan, math.inf, None, '1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.summarize_performance([
                    {'mode': 'serial', 'wallSeconds': 1, 'peakGroupRssMiB': value}])
