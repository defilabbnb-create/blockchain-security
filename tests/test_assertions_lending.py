import unittest

from scripts.invariant_assertions import lending


class LendingAssertionTests(unittest.TestCase):
    context = {"contract_name": "Pool", "target_addr_expr": "target"}

    def test_lending_templates_render_real_getters_and_failures(self):
        cases = {
            "health_factor_monotonic_on_borrow": {"riskField": "healthFactor"},
            "liquidation_does_not_create_bad_debt": {"badDebtField": "badDebt", "toleranceBps": 10},
            "interest_accrual_conserves_value": {"debtField": "totalBorrows", "supplyField": "totalSupply"},
        }
        for name, params in cases.items():
            with self.subTest(template=name):
                source = lending.RENDERERS[name](params, self.context)
                self.assertIn("require(", source)
                self.assertIn("unavailable", source)

    def test_invalid_fields_are_not_interpolated(self):
        self.assertIsNone(lending.RENDERERS["health_factor_monotonic_on_borrow"](
            {"riskField": "healthFactor()"}, self.context))


if __name__ == "__main__":
    unittest.main()
