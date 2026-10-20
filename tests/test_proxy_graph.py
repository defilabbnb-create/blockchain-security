import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("proxy_graph", ROOT / "scripts" / "proxy_graph.py")
proxy_graph = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy_graph)


class RpcFixture:
    def __init__(self):
        self.proxy = "0x" + "11" * 20
        self.impl = "0x" + "22" * 20
        self.block_hash = "0x" + "aa" * 32
        self.calls = []

    def __call__(self, method, params):
        self.calls.append((method, params))
        if method == "eth_getBlockByNumber":
            return {"number": params[0], "hash": self.block_hash}
        if method == "eth_getStorageAt":
            value = self.impl if params[0].lower() == self.proxy and params[1] == proxy_graph.history.IMPL_SLOT else "0x" + "00" * 20
            return "0x" + "00" * 12 + value[2:]
        if method == "eth_getCode":
            return "0x6001" if params[0].lower() == self.proxy else "0x6002"
        if method == "eth_call":
            if params[0].get("to", "").lower() == self.impl and params[0].get("data") == proxy_graph.PROXIABLE_UUID_SELECTOR:
                return proxy_graph.history.IMPL_SLOT
            return "0x" + "00" * 32
        raise AssertionError(f"unexpected method {method}")


class ProxyGraphTests(unittest.TestCase):
    def test_uups_chain_matches_implementation_storage_at_fixed_block(self):
        rpc = RpcFixture()
        fetch_source = lambda provider, address: {"bytecode": "0x6001", "source": "contract A {}"}
        graph = proxy_graph.build_proxy_graph(rpc, rpc.proxy, 1, 123, max_rpc_calls=20,
                                              fetch_source=fetch_source)
        self.assertEqual(graph["implementationChain"][0]["address"], rpc.impl)
        self.assertEqual(graph["implementationChain"][0]["slot"], proxy_graph.history.IMPL_SLOT)
        self.assertEqual(graph["implementationChain"][0]["proxyKind"], "uups")
        slot_reads = [params for method, params in rpc.calls if method == "eth_getStorageAt"]
        self.assertTrue(any(params[1] == proxy_graph.history.IMPL_SLOT for params in slot_reads))
        self.assertEqual(graph["coverage"]["complete"], True)

    def test_budget_exhaustion_returns_incomplete_coverage_with_reason(self):
        rpc = RpcFixture()
        graph = proxy_graph.build_proxy_graph(rpc, rpc.proxy, 1, 123, max_rpc_calls=1)
        self.assertFalse(graph["coverage"]["complete"])
        self.assertTrue(graph["coverage"]["gaps"])
        self.assertTrue(graph["limitations"])

    def test_source_disagreement_marks_conflict(self):
        rpc = RpcFixture()

        def source(provider, address):
            return {"bytecode": "0x6001" if provider == "sourcify" else "0x6002",
                    "source": "contract A {}"}

        graph = proxy_graph.build_proxy_graph(rpc, rpc.proxy, 1, 123, max_rpc_calls=20,
                                              fetch_source=source)
        self.assertTrue(graph["sourceConflict"])
        self.assertIn(rpc.proxy, graph["sourceVerification"]["conflictingAddresses"])


if __name__ == "__main__":
    unittest.main()
