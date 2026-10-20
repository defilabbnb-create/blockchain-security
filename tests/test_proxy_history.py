import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('proxy_history', ROOT / 'scripts' / 'proxy_history.py')
proxy_history = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy_history)


class ProxyRpc:
    def __init__(self):
        self.proxy = '0x' + '11' * 20
        self.impl_a = '0x' + '22' * 20
        self.impl_b = '0x' + '33' * 20
        self.hashes = {100: '0x' + 'aa' * 32, 120: '0x' + 'bb' * 32, 150: '0x' + 'cc' * 32}
        self.calls = []

    def __call__(self, method, params):
        self.calls.append((method, params))
        tag = params[-1] if params else None
        block = int(tag, 16) if isinstance(tag, str) and tag.startswith('0x') else None
        if method == 'eth_getBlockByNumber':
            block = int(params[0], 16)
            return {'number': hex(block), 'hash': self.hashes.get(block, '0x' + 'dd' * 32)}
        if method == 'eth_getStorageAt':
            slot = params[1]
            if slot == proxy_history.IMPL_SLOT:
                impl = self.impl_b if block >= 150 else self.impl_a
                return '0x' + '00' * 12 + impl[2:]
            return '0x' + '00' * 32
        if method == 'eth_getCode':
            address = params[0].lower()
            return '0x6001' if address == self.proxy.lower() else ('0x6002' if address == self.impl_a.lower() else '0x6003')
        if method == 'eth_getLogs':
            from_block = int(params[0]['fromBlock'], 16)
            to_block = int(params[0]['toBlock'], 16)
            return [row for row in [
                {'address': self.proxy, 'blockNumber': '0x78', 'blockHash': self.hashes[120], 'transactionIndex': '0x0', 'logIndex': '0x0', 'topics': [proxy_history.UPGRADED_TOPIC], 'data': '0x', 'transactionHash': '0x' + '12' * 32},
                {'address': self.proxy, 'blockNumber': '0x96', 'blockHash': self.hashes[150], 'transactionIndex': '0x0', 'logIndex': '0x0', 'topics': [proxy_history.UPGRADED_TOPIC], 'data': '0x', 'transactionHash': '0x' + '13' * 32},
            ] if from_block <= int(row['blockNumber'], 16) <= to_block]
        raise AssertionError(f'unexpected RPC method: {method}')


class ProxyHistoryTests(unittest.TestCase):
    def test_resolve_proxy_is_bound_to_block_and_hash(self):
        rpc = ProxyRpc()
        result = proxy_history.resolve_proxy_at_block(rpc, rpc.proxy, 100, expected_block_hash=rpc.hashes[100])
        self.assertEqual(result['state'], 'verified')
        self.assertEqual(result['implementation'], rpc.impl_a)
        self.assertEqual(result['implementationCode']['sha256'], __import__('hashlib').sha256(bytes.fromhex('6002')).hexdigest())
        mismatch = proxy_history.resolve_proxy_at_block(rpc, rpc.proxy, 100, expected_block_hash=rpc.hashes[120])
        self.assertEqual(mismatch['state'], 'failed')
        self.assertIn('block hash mismatch', mismatch['error'])

    def test_history_produces_two_distinct_upgrade_snapshots(self):
        rpc = ProxyRpc()
        result = proxy_history.proxy_history(rpc, rpc.proxy, 100, 150, page_size=25)
        self.assertEqual(result['state'], 'verified')
        self.assertTrue(result['complete'])
        self.assertEqual([row['block'] for row in result['events']], [120, 150])
        self.assertEqual([row['implementation'] for row in result['snapshots']], [rpc.impl_a, rpc.impl_b])
        self.assertGreaterEqual(result['pages'], 2)

    def test_history_fails_closed_on_unsupported_logs(self):
        rpc = ProxyRpc()
        original = rpc.__call__
        def unsupported(method, params):
            if method == 'eth_getLogs':
                raise RuntimeError('method not found (-32601)')
            return original(method, params)
        result = proxy_history.proxy_history(unsupported, rpc.proxy, 100, 150)
        self.assertEqual(result['state'], 'unsupported')
        self.assertFalse(result['complete'])

    def test_resolver_rejects_malformed_slot_and_empty_implementation(self):
        rpc = ProxyRpc()
        original = rpc.__call__
        def malformed(method, params):
            if method == 'eth_getStorageAt' and params[1] == proxy_history.IMPL_SLOT:
                return '0x1234'
            return original(method, params)
        result = proxy_history.resolve_proxy_at_block(malformed, rpc.proxy, 100)
        self.assertEqual(result['state'], 'failed')
        self.assertIn('slot', result['error'])

        def empty_impl(method, params):
            if method == 'eth_getCode' and params[0].lower() == rpc.impl_a.lower():
                return '0x'
            return original(method, params)
        result = proxy_history.resolve_proxy_at_block(empty_impl, rpc.proxy, 100)
        self.assertEqual(result['state'], 'failed')
        self.assertIn('no code', result['error'])

    def test_same_block_upgrade_events_are_retained_but_not_claimed_complete(self):
        rpc = ProxyRpc()
        original = rpc.__call__
        def same_block(method, params):
            if method == 'eth_getLogs':
                return [{
                    'address': rpc.proxy, 'blockNumber': '0x78', 'blockHash': rpc.hashes[120],
                    'transactionIndex': '0x0', 'logIndex': hex(index), 'topics': [proxy_history.UPGRADED_TOPIC],
                    'data': '0x', 'transactionHash': '0x' + ('12' if index == 0 else '13') * 32,
                } for index in (0, 1)]
            return original(method, params)
        result = proxy_history.proxy_history(same_block, rpc.proxy, 100, 120)
        self.assertEqual(result['state'], 'partial')
        self.assertFalse(result['complete'])
        self.assertEqual(result['sameBlockOrderingUncertain'], [120])


if __name__ == '__main__':
    unittest.main()
