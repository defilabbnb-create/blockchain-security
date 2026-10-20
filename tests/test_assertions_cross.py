import unittest

from scripts.invariant_assertions import cross


class CrossAssertionTests(unittest.TestCase):
    context = {
        "contract_name": "Borrower",
        "target_addr_expr": "target",
        "dependency_addr_expr": "oracle",
    }

    def test_dependency_templates_render_when_dependency_is_bound(self):
        oracle = cross.RENDERERS["oracle_assumption_holds"](
            {"oracleField": "price", "maxOracleValue": 10**18}, self.context)
        self.assertIn("oracle", oracle)
        self.assertIn("price()", oracle)
        bounds = cross.RENDERERS["dependency_return_bounds"](
            {"dependencyField": "quote", "minReturn": 1, "maxReturn": 100}, self.context)
        self.assertIn("quote()", bounds)
        self.assertIn("outside the caller bounds", bounds)

    def test_dependency_templates_return_none_without_dependency(self):
        context = {"target_addr_expr": "target"}
        self.assertIsNone(cross.RENDERERS["oracle_assumption_holds"](
            {"oracleField": "price", "maxOracleValue": 10}, context))
        self.assertIsNone(cross.RENDERERS["dependency_return_bounds"](
            {"dependencyField": "quote", "minReturn": 1, "maxReturn": 10}, context))


if __name__ == "__main__":
    unittest.main()
