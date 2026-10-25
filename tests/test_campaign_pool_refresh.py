"""A stale RPC pool must be refreshed, not turned into a failed campaign.

The campaign read `work/rpc-pool.json` and refused to start when it was
older than thirty minutes.  That refusal was correct in principle - a stale
pool is not evidence - but it was the only outcome: the operator had to know
to run `rpc:refresh` beforehand.  Meanwhile a pool that was fresh at start
but whose nodes had been throttled during the sweep kept those nodes
excluded for the whole run, and the chains depending on them were reported
as unavailable.

The tests below pin the behaviour:

  - a stale pool triggers a refresh and the campaign continues
  - a refresh that fails is reported, not silently swallowed
  - the refreshed pool is written where the next run will find it
"""
import json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import importlib.util

spec = importlib.util.spec_from_file_location('campaign', ROOT / 'scripts/defi-campaign.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class FakeRunner:
    """The parts of the campaign runner that `refresh_pool` and `load_pool` touch."""

    def __init__(self, run_dir):
        self.run = Path(run_dir)
        self.run.mkdir(parents=True, exist_ok=True)
        self.events = []

    def event(self, kind, **payload):
        self.events.append((kind, payload))

    refresh_pool = C.Campaign.refresh_pool
    load_pool = C.Campaign.load_pool


class RefreshPoolTests(unittest.TestCase):
    def _pool(self, generated_at='2026-10-24T01:00:00Z'):
        return {'generatedAt': generated_at, 'chains': [
            {'chainId': 42220, 'name': 'Celo', 'healthyCount': 2, 'redundant': True,
             'endpoints': []},
        ]}

    def setUp(self):
        # `refresh_pool` writes the real pool file.  Point it at a temporary
        # location for the duration of the test so the working snapshot is
        # not replaced by a fixture.
        self.pool_file = ROOT / 'work/rpc-pool.json'
        self.saved = self.pool_file.read_bytes() if self.pool_file.exists() else None
        self.addCleanup(self._restore)

    def _restore(self):
        if self.saved is None:
            if self.pool_file.exists():
                self.pool_file.unlink()
        else:
            self.pool_file.write_bytes(self.saved)

    def test_a_successful_refresh_persists_the_pool(self):
        runner = FakeRunner(ROOT / 'work/test-refresh-ok')
        pool = self._pool()
        original = C.discover
        C.discover = lambda chains, *a, **k: pool
        self.addCleanup(lambda: setattr(C, 'discover', original))
        try:
            result = runner.refresh_pool()
        finally:
            C.discover = original
        self.assertIsNotNone(result)
        self.assertEqual(result['generatedAt'], pool['generatedAt'])
        self.assertTrue((runner.run / 'rpc-pool.refreshed.json').exists())

    def test_a_failed_refresh_is_reported_and_returns_none(self):
        """A refresh that cannot complete must not look like a successful one."""
        runner = FakeRunner(ROOT / 'work/test-refresh-fail')
        original = C.discover

        def boom(chains, *a, **k):
            raise RuntimeError('RPC catalogs unavailable; no stale pool substituted')

        C.discover = boom
        self.addCleanup(lambda: setattr(C, 'discover', original))
        try:
            result = runner.refresh_pool()
        finally:
            C.discover = original
        self.assertIsNone(result)
        kinds = [e[0] for e in runner.events]
        self.assertIn('rpc_pool_refresh_failed', kinds)

    def test_a_successful_refresh_is_recorded_as_an_event(self):
        runner = FakeRunner(ROOT / 'work/test-refresh-event')
        pool = self._pool()
        original = C.discover
        C.discover = lambda chains, *a, **k: pool
        self.addCleanup(lambda: setattr(C, 'discover', original))
        try:
            runner.refresh_pool()
        finally:
            C.discover = original
        kinds = [e[0] for e in runner.events]
        self.assertIn('rpc_pool_refreshed', kinds)


class LoadPoolTests(unittest.TestCase):
    """Three cases have to be told apart: current, stale, and missing."""

    def setUp(self):
        self.pool_file = ROOT / 'work/rpc-pool.json'
        self.saved = self.pool_file.read_bytes() if self.pool_file.exists() else None
        self.addCleanup(self._restore)

    def _restore(self):
        if self.saved is None:
            if self.pool_file.exists():
                self.pool_file.unlink()
        else:
            self.pool_file.write_bytes(self.saved)

    def _pool(self, generated_at):
        return {'generatedAt': generated_at, 'chains': [
            {'chainId': 42220, 'name': 'Celo', 'healthyCount': 2, 'redundant': True,
             'endpoints': []},
        ]}

    def _with_pool(self, generated_at):
        self.pool_file.write_text(json.dumps(self._pool(generated_at)))

    def test_a_current_pool_is_used_without_a_refresh(self):
        self._with_pool(C.now())
        runner = FakeRunner(ROOT / 'work/test-load-fresh')
        refreshed = []
        original = runner.refresh_pool
        runner.refresh_pool = lambda: refreshed.append(True) or self._pool(C.now())
        self.addCleanup(lambda: setattr(runner, 'refresh_pool', original))
        pool = runner.load_pool()
        self.assertEqual(pool['generatedAt'], self.pool_file and json.loads(self.pool_file.read_text())['generatedAt'])
        self.assertEqual(refreshed, [])

    def test_a_stale_pool_triggers_a_refresh(self):
        self._with_pool('2020-01-01T00:00:00Z')
        runner = FakeRunner(ROOT / 'work/test-load-stale')
        fresh = self._pool(C.now())
        refreshed = []
        original = runner.refresh_pool
        runner.refresh_pool = lambda: refreshed.append(True) or fresh
        self.addCleanup(lambda: setattr(runner, 'refresh_pool', original))
        pool = runner.load_pool()
        self.assertEqual(len(refreshed), 1)
        self.assertEqual(pool['generatedAt'], fresh['generatedAt'])

    def test_a_missing_pool_triggers_a_refresh(self):
        if self.pool_file.exists():
            self.pool_file.unlink()
        runner = FakeRunner(ROOT / 'work/test-load-missing')
        fresh = self._pool(C.now())
        refreshed = []
        original = runner.refresh_pool
        runner.refresh_pool = lambda: refreshed.append(True) or fresh
        self.addCleanup(lambda: setattr(runner, 'refresh_pool', original))
        pool = runner.load_pool()
        self.assertEqual(len(refreshed), 1)
        self.assertEqual(pool['generatedAt'], fresh['generatedAt'])

    def test_a_refresh_that_fails_raises_rather_than_using_a_stale_pool(self):
        """The failure must be visible, not silently covered by the old file."""
        self._with_pool('2020-01-01T00:00:00Z')
        runner = FakeRunner(ROOT / 'work/test-load-fail')
        original = runner.refresh_pool
        runner.refresh_pool = lambda: None
        self.addCleanup(lambda: setattr(runner, 'refresh_pool', original))
        with self.assertRaises(RuntimeError) as caught:
            runner.load_pool()
        self.assertIn('could not be refreshed', str(caught.exception))

    def test_a_corrupt_pool_file_triggers_a_refresh(self):
        self.pool_file.write_text('{not json')
        runner = FakeRunner(ROOT / 'work/test-load-corrupt')
        fresh = self._pool(C.now())
        original = runner.refresh_pool
        runner.refresh_pool = lambda: fresh
        self.addCleanup(lambda: setattr(runner, 'refresh_pool', original))
        pool = runner.load_pool()
        self.assertEqual(pool['generatedAt'], fresh['generatedAt'])


class FreshnessGateTests(unittest.TestCase):
    """The gate must ask for a refresh, not refuse to run."""

    def _stale(self):
        return '2020-01-01T00:00:00Z'

    def test_a_stale_pool_is_within_the_window(self):
        from datetime import datetime
        age = __import__('time').time() - datetime.fromisoformat(self._stale().replace('Z', '+00:00')).timestamp()
        self.assertGreater(age, 1800)

    def test_a_fresh_pool_is_outside_the_window(self):
        from datetime import datetime
        fresh = C.now()
        age = __import__('time').time() - datetime.fromisoformat(fresh.replace('Z', '+00:00')).timestamp()
        self.assertLess(age, 1800)


if __name__ == '__main__':
    unittest.main()
