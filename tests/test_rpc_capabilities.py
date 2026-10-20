import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("rpc_pool", ROOT / "scripts/rpc_pool.py")
rpc_pool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rpc_pool)


class RpcCapabilityProbeTests(unittest.TestCase):
    def test_probe_records_each_read_capability_and_trace_without_transaction(self):
        def observed(_url, method, _params, _timeout, _sink, _chain):
            values = {
                "eth_getBlockByNumber": {"number": "0x100"},
                "eth_getCode": "0x",
                "eth_getLogs": [],
                "eth_getProof": {},
                "debug_traceTransaction": {},
                "trace_transaction": [],
            }
            return values[method]

        with patch.object(rpc_pool, "_rpc_observed", side_effect=observed), patch.object(
            rpc_pool, "_batch_probe", return_value={"state": "available", "method": "json-rpc-batch"}
        ):
            result = rpc_pool.probe_capabilities(100, "https://rpc.example", 256, tx_hash=None)

        self.assertEqual(result["schemaVersion"], 1)
        self.assertEqual(result["archive"]["state"], "available")
        self.assertEqual(result["historicalCode"]["state"], "available")
        self.assertEqual(result["logs"]["state"], "available")
        self.assertEqual(result["proof"]["state"], "available")
        self.assertEqual(result["batch"]["state"], "available")
        self.assertEqual(result["debug_traceTransaction"]["state"], "not_tested")
        self.assertEqual(result["trace_transaction"]["state"], "not_tested")
        self.assertEqual(result["rateLimit"]["state"], "observed_only")

    def test_probe_distinguishes_unsupported_methods_from_transport_failure(self):
        def unsupported(_url, _method, _params, _timeout, _sink, _chain):
            raise ValueError("RPC error -32601")

        with patch.object(rpc_pool, "_rpc_observed", side_effect=unsupported), patch.object(
            rpc_pool, "_batch_probe", return_value={"state": "unsupported", "method": "json-rpc-batch"}
        ):
            result = rpc_pool.probe_capabilities(1, "https://rpc.example", 2048, tx_hash="0x" + "11" * 32)

        for name in ("archive", "historicalCode", "logs", "proof", "debug_traceTransaction", "trace_transaction"):
            self.assertEqual(result[name]["state"], "unsupported", name)

    def test_probe_exposes_basic_health_separately_from_optional_capabilities(self):
        def observed(_url, method, params, _timeout, _sink, _chain):
            if method == "eth_chainId":
                return "0x64"
            if method == "eth_getBlockByNumber":
                if params[1] is True:
                    return {"number": "0x100", "transactions": []}
                return {"number": "0x100", "timestamp": hex(int(rpc_pool.time.time())), "hash": "0x" + "aa" * 32}
            raise ValueError("RPC error -32601")

        with patch.object(rpc_pool, "_rpc_observed", side_effect=observed), patch.object(
            rpc_pool, "probe_capabilities", return_value={"schemaVersion": 1, "logs": {"state": "unsupported"}}
        ):
            result = rpc_pool.probe(100, "https://rpc.example")

        self.assertTrue(result["healthy"])
        self.assertEqual(result["capabilities"]["logs"]["state"], "unsupported")


if __name__ == "__main__":
    unittest.main()
