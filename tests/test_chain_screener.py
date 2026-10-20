import json
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('chain_screener', ROOT / 'scripts/chain-screener.py')
chain_screener = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chain_screener)


class ChainScreenerTests(unittest.TestCase):
    def test_historical_stats_ignores_malformed_and_nonfinite_values(self):
        stats = chain_screener.historical_stats([
            {'date': 1, 'tvl': 10}, {'date': 'bad', 'tvl': 5},
            {'date': 2, 'tvl': float('nan')}, {'date': 3, 'tvl': 100},
        ])
        self.assertEqual(stats['points'], 2)
        self.assertEqual(stats['peakTvlUsd'], 100)

    def test_config_rejects_duplicate_chain_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'chains.json'
            path.write_text(json.dumps({'chains': [
                {'name': 'a', 'chainId': 1}, {'name': 'b', 'chainId': 1}
            ]}))
            with self.assertRaisesRegex(ValueError, '重复'):
                chain_screener.load_config(path)

    def test_cache_is_atomic_and_reused(self):
        calls = []
        def fake_fetch(url, **kwargs):
            calls.append(url)
            return {'value': 1}
        with tempfile.TemporaryDirectory() as directory, patch.object(chain_screener, 'fetch_json', fake_fetch):
            cache = Path(directory)
            self.assertEqual(chain_screener.cached_json('https://example.test/x', cache_dir=cache, cache_ttl=100, timeout=1), {'value': 1})
            self.assertEqual(chain_screener.cached_json('https://example.test/x', cache_dir=cache, cache_ttl=100, timeout=1), {'value': 1})
            self.assertEqual(calls, ['https://example.test/x'])
            self.assertFalse(list(cache.glob('*.tmp')))

    def test_score_rewards_history_and_connections_without_calling_them_safety(self):
        low = chain_screener.score_chain(0, 200_000_000, 0, min_peak=1_000_000)
        high = chain_screener.score_chain(10_000_000, 200_000_000, 2, min_peak=1_000_000)
        self.assertGreater(high['priorityScore'], low['priorityScore'])
        self.assertEqual(low['currentToPeakRatio'], 0)

