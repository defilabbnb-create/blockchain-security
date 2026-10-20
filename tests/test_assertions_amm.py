import unittest

from scripts.invariant_assertions import amm


class AMMAssertionTests(unittest.TestCase):
    context = {"contract_name": "Pool", "target_addr_expr": "target"}

    def test_amm_templates_render_parameterized_reserves(self):
        source = amm.RENDERERS["k_never_decreases"](
            {"reserve0Field": "tokenAReserve", "reserve1Field": "tokenBReserve", "toleranceBps": 5}, self.context)
        self.assertIn("tokenAReserve()", source)
        self.assertIn("tokenBReserve()", source)
        self.assertIn("constant product k decreased", source)
        source = amm.RENDERERS["fee_conserved"](
            {"reserve0Field": "r0", "reserve1Field": "r1", "feeField": "feeLedger"}, self.context)
        self.assertIn("feeLedger()", source)

    def test_invalid_tolerance_requires_adapter(self):
        self.assertIsNone(amm.RENDERERS["k_never_decreases"](
            {"reserve0Field": "r0", "reserve1Field": "r1", "toleranceBps": 10001}, self.context))


if __name__ == "__main__":
    unittest.main()
