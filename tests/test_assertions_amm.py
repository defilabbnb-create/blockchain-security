import unittest

from scripts.invariant_assertions import amm


class AMMAssertionTests(unittest.TestCase):
    context = {"contract_name": "Pool", "target_addr_expr": "target"}

    def test_the_transition_assertions_do_not_render_an_executable_check(self):
        # Both properties are transition properties: the constant product and
        # the fee ledger are each compared across a swap.  The harness has no
        # adapter that performs a swap, so the "before" and "after" readings
        # were two reads of an unchanged pool and the comparison was decided
        # before any protocol action happened.  Rendering it produced a
        # passing verdict that measured the harness rather than the pool, so
        # both renderers now decline.
        for template in ("k_never_decreases", "fee_conserved"):
            source = amm.RENDERERS[template](
                {"reserve0Field": "r0", "reserve1Field": "r1", "feeField": "feeLedger",
                 "toleranceBps": 0}, self.context)
            self.assertIsNone(source, f"{template} must not render an executable check")

    def test_the_declined_templates_name_the_adapter_they_need(self):
        for template in ("k_never_decreases", "fee_conserved"):
            self.assertIn(template, amm.UNAVAILABLE_REASONS)
            self.assertTrue(amm.UNAVAILABLE_REASONS[template].strip())

    def test_invalid_tolerance_requires_adapter(self):
        self.assertIsNone(amm.RENDERERS["k_never_decreases"](
            {"reserve0Field": "r0", "reserve1Field": "r1", "toleranceBps": 10001}, self.context))


if __name__ == "__main__":
    unittest.main()
