import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("recon", ROOT / "scripts" / "recon.py")
recon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recon)


class RpcFixture:
    def __init__(self):
        self.calls = []
        self.target = "0x" + "11" * 20
        self.tx_hashes = ["0x" + f"{number:02x}" * 32 for number in range(1, 4)]

    def __call__(self, method, params):
        self.calls.append((method, params))
        if method == "eth_getBlockByNumber":
            block = int(params[0], 16)
            if params[1] is True:
                return {"transactions": [
                    {"hash": self.tx_hashes[0], "to": self.target, "input": "0x12345678"},
                    {"hash": self.tx_hashes[1], "to": self.target, "input": "0x12345678"},
                    {"hash": self.tx_hashes[2], "to": self.target, "input": "0x87654321"},
                ]}
            return {"number": hex(block), "hash": "0x" + "aa" * 32}
        if method == "eth_getStorageAt":
            return "0x" + "00" * 32
        if method == "eth_getCode":
            return "0x6001"
        if method == "eth_getLogs":
            return []
        if method == "debug_traceTransaction":
            return {"structLogs": []}
        raise AssertionError(f"unexpected RPC method: {method}")


class ReconTests(unittest.TestCase):
    def profile(self, rpc, assets=1000):
        return recon.build_recon_profile(rpc, rpc.target, chain_id=1, block=100,
                                         from_block=99, reachable_assets_usd=assets,
                                         block_scan_limit=1)

    def test_upgrade_probe_reports_event_count_without_claiming_unavailable_history(self):
        rpc = RpcFixture()
        result = self.profile(rpc)
        upgrades = result["probes"]["upgrades"]
        self.assertEqual(upgrades["upgradeCount"], 0)
        self.assertEqual(upgrades["state"], "verified")
        self.assertTrue(upgrades["complete"])

    def test_call_distribution_sums_to_sample_transaction_count(self):
        rpc = RpcFixture()
        result = self.profile(rpc)
        calls = result["probes"]["callDistribution"]
        self.assertEqual(sum(calls["distribution"].values()), calls["sampleTransactions"])
        self.assertEqual(calls["sampleTransactions"], 3)
        self.assertAlmostEqual(calls["concentration"], 2 / 3)
        self.assertEqual(len([call for call in rpc.calls if call[0] == "debug_traceTransaction"]), 3)

    def test_score_increases_with_reachable_assets_when_other_evidence_is_equal(self):
        low = self.profile(RpcFixture(), assets=100)
        high = self.profile(RpcFixture(), assets=1000)
        self.assertGreater(high["score"], low["score"])

    def test_rpc_access_is_read_only(self):
        rpc = RpcFixture()
        self.profile(rpc)
        self.assertTrue(all(method in {"eth_getBlockByNumber", "eth_getStorageAt", "eth_getCode", "eth_getLogs", "debug_traceTransaction"}
                            for method, _ in rpc.calls))


if __name__ == "__main__":
    unittest.main()
