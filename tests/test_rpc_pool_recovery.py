"""A throttled node is a passing condition, not a verdict about the node.

The pool snapshot records one moment.  A provider that answered one request
with HTTP 429, or timed out, or returned a gateway error at that moment was
recorded as `healthy: false` and never looked at again.  The snapshot then
lived for hours, so a chain whose nodes happened to be throttled when the
sweep ran was reported as unavailable for the rest of that period - while the
same nodes answered every request minutes later.

This is the "silent wrong value" pattern in a new place: the state was
structurally valid (`healthy: false`, `healthyCount: 0`) and semantically
wrong (the node was fine; the moment was bad).  The tests below pin the
distinction in both directions:

  - a passing condition must not disqualify a node permanently
  - a verdict (wrong chain, stale block, peer disagreement) still must

Both directions matter.  Fixing only the first would let a node that serves
the wrong chain back into the pool, which is the more dangerous half.
"""
import json, sys, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rpc_pool


def endpoint(url, **kwargs):
    item = {'url': url, 'host': url.split('//')[-1].split('/')[0], 'chainId': 42220,
            'observedAt': rpc_pool.now(), 'healthy': False, 'latencyMs': 120}
    item.update(kwargs)
    return item


class FailureClassificationTests(unittest.TestCase):
    """A throttle must be distinguishable from a wrong answer."""

    def test_rate_limiting_is_a_passing_condition(self):
        import urllib.error, io
        error = urllib.error.HTTPError('https://x.invalid', 429, 'Too Many Requests', {}, io.BytesIO(b''))
        self.assertTrue(rpc_pool.is_transient(error))

    def test_gateway_and_timeout_errors_are_passing_conditions(self):
        import urllib.error, io, socket
        for code in (500, 502, 503, 504, 408):
            error = urllib.error.HTTPError('https://x.invalid', code, 'err', {}, io.BytesIO(b''))
            self.assertTrue(rpc_pool.is_transient(error), code)
        self.assertTrue(rpc_pool.is_transient(socket.timeout('timed out')))
        self.assertTrue(rpc_pool.is_transient(urllib.error.URLError('EOF occurred')))

    def test_a_wrong_answer_is_not_a_passing_condition(self):
        self.assertFalse(rpc_pool.is_transient(ValueError('wrong chain ID: 1')))
        self.assertFalse(rpc_pool.is_transient(ValueError('stale/future block: age=6409254s')))
        self.assertFalse(rpc_pool.is_transient(ValueError('invalid block')))

    def test_a_legacy_snapshot_is_read_back_with_the_same_rules(self):
        """A snapshot written before this distinction must not mean something else."""
        throttled = endpoint('https://a.invalid', error='HTTPError: HTTP Error 429: Too Many Requests')
        self.assertEqual(rpc_pool.endpoint_failure_kind(throttled), 'transient')
        cooldown = endpoint('https://b.invalid', error='provider cooldown after HTTP 403/429')
        self.assertEqual(rpc_pool.endpoint_failure_kind(cooldown), 'transient')
        stale = endpoint('https://c.invalid', error='ValueError: stale/future block: age=6409254s')
        self.assertEqual(rpc_pool.endpoint_failure_kind(stale), 'verdict')

    def test_an_explicit_failure_kind_wins_over_the_text(self):
        item = endpoint('https://a.invalid', error='HTTPError: HTTP Error 429: Too Many Requests',
                        failureKind='verdict')
        self.assertEqual(rpc_pool.endpoint_failure_kind(item), 'verdict')

    def test_a_node_that_refuses_heights_is_limited_not_broken(self):
        """A node serving only the live view is not a broken node."""
        item = endpoint('https://a.invalid',
                        error='common block probe failed: HTTP Error 400: Bad Request')
        self.assertEqual(rpc_pool.endpoint_failure_kind(item), 'capability')

    def test_a_height_refusal_is_not_treated_as_a_throttle(self):
        item = endpoint('https://a.invalid',
                        error='common block probe failed: HTTP Error 400: Bad Request')
        self.assertNotEqual(rpc_pool.endpoint_failure_kind(item), 'transient')


class PoolKeepsPassingConditionsAsCandidatesTests(unittest.TestCase):
    """The pool must remember the rejected node instead of forgetting it."""

    def _report(self):
        return {'chains': [{'chainId': 42220, 'endpoints': [
            endpoint('https://live.invalid', healthy=True, latencyMs=50),
            endpoint('https://throttled.invalid', error='HTTPError: HTTP Error 429: Too Many Requests'),
            endpoint('https://stale.invalid', error='ValueError: stale/future block: age=6409254s'),
        ]}]}

    def test_a_throttled_node_is_kept_as_a_revalidation_candidate(self):
        pool = rpc_pool.RpcPool(self._report())
        candidates = [e['url'] for e in pool.candidates.get(42220, [])]
        self.assertIn('https://throttled.invalid', candidates)

    def test_a_node_that_serves_the_wrong_chain_is_not_a_candidate(self):
        pool = rpc_pool.RpcPool(self._report())
        candidates = [e['url'] for e in pool.candidates.get(42220, [])]
        self.assertNotIn('https://stale.invalid', candidates)


class RevalidationBringsNodesBackTests(unittest.TestCase):
    """The node that failed for a passing condition must come back."""

    def _report(self):
        return {'chains': [{'chainId': 42220, 'endpoints': [
            endpoint('https://throttled.invalid', error='HTTPError: HTTP Error 429: Too Many Requests'),
        ]}]}

    def test_a_node_that_answers_on_revalidation_is_restored(self):
        pool = rpc_pool.RpcPool(self._report())
        healthy = {'url': 'https://throttled.invalid', 'host': 'throttled.invalid', 'chainId': 42220,
                   'healthy': True, 'observedAt': '2026-10-24T01:00:00Z', 'latencyMs': 90,
                   'height': 100, 'error': None}
        original = rpc_pool.probe
        rpc_pool.probe = lambda *a, **k: healthy
        self.addCleanup(lambda: setattr(rpc_pool, 'probe', original))
        revived = pool.revalidate(42220)
        self.assertEqual(revived, ['https://throttled.invalid'])
        row = pool.rows[42220]
        self.assertEqual(row['healthyCount'], 1)
        self.assertEqual(row['assurance'], 'single endpoint only')
        self.assertEqual(pool.snapshot()['recovered'], {'42220': 1})
        # The node answered, so it is not probed again on the next refresh.
        self.assertEqual(pool.candidates.get(42220, []), [])

    def test_a_node_that_still_fails_on_a_verdict_stays_out(self):
        pool = rpc_pool.RpcPool(self._report())
        broken = {'url': 'https://throttled.invalid', 'host': 'throttled.invalid', 'chainId': 42220,
                  'healthy': False, 'observedAt': '2026-10-24T01:00:00Z',
                  'error': 'ValueError: wrong chain ID: 1', 'failureKind': 'verdict'}
        original = rpc_pool.probe
        rpc_pool.probe = lambda *a, **k: broken
        self.addCleanup(lambda: setattr(rpc_pool, 'probe', original))
        revived = pool.revalidate(42220)
        self.assertEqual(revived, [])
        self.assertEqual(pool.rows[42220]['healthyCount'], 0)
        # A verdict is final: the node is not probed again on every refresh.
        self.assertEqual(pool.candidates.get(42220, []), [])
        self.assertEqual(pool.snapshot()['revalidationFailures'], {'42220': 1})

    def test_a_node_that_is_still_throttled_is_kept_as_a_candidate(self):
        """A second throttle is still a passing condition, not a verdict."""
        pool = rpc_pool.RpcPool(self._report())
        still = {'url': 'https://throttled.invalid', 'host': 'throttled.invalid', 'chainId': 42220,
                 'healthy': False, 'observedAt': '2026-10-24T01:00:00Z',
                 'error': 'HTTPError: HTTP Error 429: Too Many Requests', 'failureKind': 'transient'}
        original = rpc_pool.probe
        rpc_pool.probe = lambda *a, **k: still
        self.addCleanup(lambda: setattr(rpc_pool, 'probe', original))
        revived = pool.revalidate(42220)
        self.assertEqual(revived, [])
        self.assertEqual(len(pool.candidates.get(42220, [])), 1)


class CallRevalidatesWhenAChainLooksDeadTests(unittest.TestCase):
    """The chain must not be reported as dead before the nodes are re-checked."""

    def _report(self):
        return {'chains': [{'chainId': 42220, 'endpoints': [
            endpoint('https://throttled.invalid', error='HTTPError: HTTP Error 429: Too Many Requests'),
        ]}]}

    def test_a_call_revives_the_chain_before_failing(self):
        pool = rpc_pool.RpcPool(self._report())
        healthy = {'url': 'https://throttled.invalid', 'host': 'throttled.invalid', 'chainId': 42220,
                   'healthy': True, 'observedAt': '2026-10-24T01:00:00Z', 'latencyMs': 90,
                   'height': 100, 'error': None}
        original_probe = rpc_pool.probe
        original_rpc = rpc_pool.rpc
        rpc_pool.probe = lambda *a, **k: healthy
        rpc_pool.rpc = lambda *a, **k: '0x64'
        self.addCleanup(lambda: (setattr(rpc_pool, 'probe', original_probe),
                                  setattr(rpc_pool, 'rpc', original_rpc)))
        value, url = pool.call(42220, 'eth_blockNumber', [])
        self.assertEqual(value, '0x64')
        self.assertEqual(url, 'https://throttled.invalid')

    def test_a_chain_with_no_candidates_still_fails_honestly(self):
        """With nothing to revalidate the call must raise, not invent a value."""
        report = {'chains': [{'chainId': 42220, 'endpoints': [
            endpoint('https://stale.invalid', error='ValueError: stale/future block: age=6409254s'),
        ]}]}
        pool = rpc_pool.RpcPool(report)
        with self.assertRaises(RuntimeError) as caught:
            pool.call(42220, 'eth_blockNumber', [])
        self.assertIn('No usable verified RPC', str(caught.exception))


class ConcurrentRevalidationTests(unittest.TestCase):
    """Several workers reaching one chain must not probe it several times."""

    def test_only_one_worker_probes_the_chain(self):
        report = {'chains': [{'chainId': 42220, 'endpoints': [
            endpoint('https://throttled.invalid', error='HTTPError: HTTP Error 429: Too Many Requests'),
        ]}]}
        pool = rpc_pool.RpcPool(report)
        calls = []
        import threading

        def slow_probe(chain_id, url, timeout, raw_sink=None):
            calls.append(url)
            time.sleep(0.2)
            return {'url': url, 'host': 'throttled.invalid', 'chainId': chain_id,
                    'healthy': True, 'observedAt': rpc_pool.now(), 'latencyMs': 90,
                    'height': 100, 'error': None}

        original = rpc_pool.probe
        rpc_pool.probe = slow_probe
        self.addCleanup(lambda: setattr(rpc_pool, 'probe', original))

        results = []
        threads = [threading.Thread(target=lambda: results.append(pool.revalidate(42220)))
                   for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(len(calls), 1, 'the chain was probed %d times' % len(calls))
        self.assertEqual(pool.rows[42220]['healthyCount'], 1)


class ArchiveCapabilityTests(unittest.TestCase):
    """A node that serves only the live view is skipped for height reads."""

    def test_a_height_read_is_detected(self):
        self.assertTrue(rpc_pool.needs_historical('eth_getBlockByNumber', ['0x64']))
        self.assertTrue(rpc_pool.needs_historical('eth_getCode', ['0x' + 'ab' * 20, '0x64']))
        self.assertFalse(rpc_pool.needs_historical('eth_getBlockByNumber', ['latest', False]))
        self.assertFalse(rpc_pool.needs_historical('eth_blockNumber', []))
        self.assertFalse(rpc_pool.needs_historical('eth_getTransactionByHash', ['0x' + 'ab' * 32]))

    def test_a_live_read_still_uses_a_node_that_cannot_serve_heights(self):
        report = {'chains': [{'chainId': 42220, 'endpoints': [
            endpoint('https://liveonly.invalid', healthy=True, historicalUnavailable=True, latencyMs=50),
        ]}]}
        pool = rpc_pool.RpcPool(report)
        original = rpc_pool.rpc
        rpc_pool.rpc = lambda *a, **k: '0x1'
        self.addCleanup(lambda: setattr(rpc_pool, 'rpc', original))
        value, url = pool.call(42220, 'eth_blockNumber', [])
        self.assertEqual(url, 'https://liveonly.invalid')

    def test_a_height_read_skips_a_node_that_cannot_serve_heights(self):
        report = {'chains': [{'chainId': 42220, 'endpoints': [
            endpoint('https://liveonly.invalid', healthy=True, historicalUnavailable=True, latencyMs=50),
            endpoint('https://archive.invalid', healthy=True, latencyMs=80),
        ]}]}
        pool = rpc_pool.RpcPool(report)
        original = rpc_pool.rpc
        rpc_pool.rpc = lambda *a, **k: {'number': '0x64', 'hash': '0x' + 'ab' * 32}
        self.addCleanup(lambda: setattr(rpc_pool, 'rpc', original))
        value, url = pool.call(42220, 'eth_getBlockByNumber', ['0x64', False])
        self.assertEqual(url, 'https://archive.invalid')


class ConsensusAgreementTests(unittest.TestCase):
    """A sole witness must not be reported as agreement by several endpoints."""

    def _row(self, endpoints, votes=None):
        row = {'chainId': 1, 'endpoints': endpoints}
        if votes is not None:
            row['consensusVotes'] = votes
        return row

    def test_one_witness_is_not_reported_as_multiple_endpoint_agreement(self):
        pool = rpc_pool.RpcPool({'chains': [self._row([
            {'url': 'https://a.invalid', 'healthy': True, 'latencyMs': 10, 'commonBlockHash': '0xabc'},
            {'url': 'https://b.invalid', 'healthy': True, 'latencyMs': 20},
        ])]})
        row = pool.rows[1]
        self.assertEqual(row['healthyCount'], 2)
        self.assertEqual(row['assurance'], 'single endpoint only')

    def test_two_agreeing_witnesses_are_reported_as_agreement(self):
        pool = rpc_pool.RpcPool({'chains': [self._row([
            {'url': 'https://a.invalid', 'healthy': True, 'latencyMs': 10, 'commonBlockHash': '0xabc'},
            {'url': 'https://b.invalid', 'healthy': True, 'latencyMs': 20, 'commonBlockHash': '0xabc'},
        ], votes=2)]})
        self.assertEqual(pool.rows[1]['assurance'], 'multiple endpoint block agreement')

    def test_a_legacy_snapshot_without_votes_is_counted_from_its_hashes(self):
        """The hashes are the votes; a legacy snapshot must not be downgraded."""
        pool = rpc_pool.RpcPool({'chains': [self._row([
            {'url': 'https://a.invalid', 'healthy': True, 'latencyMs': 10, 'commonBlockHash': '0xabc'},
            {'url': 'https://b.invalid', 'healthy': True, 'latencyMs': 20, 'commonBlockHash': '0xabc'},
        ])]})
        self.assertEqual(pool.rows[1]['assurance'], 'multiple endpoint block agreement')

    def test_one_witness_among_two_healthy_endpoints_is_not_agreement(self):
        """Two endpoints that could not both serve a block is not agreement."""
        pool = rpc_pool.RpcPool({'chains': [self._row([
            {'url': 'https://a.invalid', 'healthy': True, 'latencyMs': 10, 'commonBlockHash': '0xabc'},
            {'url': 'https://b.invalid', 'healthy': True, 'latencyMs': 20},
        ])]})
        self.assertEqual(pool.rows[1]['assurance'], 'single endpoint only')

    def test_a_chain_with_no_healthy_endpoint_is_unavailable(self):
        pool = rpc_pool.RpcPool({'chains': [self._row([
            {'url': 'https://a.invalid', 'healthy': False, 'error': 'ValueError: stale/future block'},
        ])]})
        self.assertEqual(pool.rows[1]['assurance'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
