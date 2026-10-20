import unittest

from scripts.invariant_assertions import erc4626


class ERC4626AssertionTests(unittest.TestCase):
    def setUp(self):
        self.context = {"contract_name": "Vault", "target_addr_expr": "target"}

    def test_all_templates_render_with_custom_fields_and_failure_messages(self):
        params = {"assetsField": "managedAssets", "sharesField": "issuedShares", "toleranceBps": 25}
        for name in ("share_price_monotonic", "withdraw_preserves_remaining_value",
                     "donation_does_not_change_ledger", "first_deposit_no_inflation",
                     "rounding_direction_correct"):
            with self.subTest(template=name):
                source = erc4626.RENDERERS[name](params, self.context)
                self.assertIsInstance(source, str)
                self.assertIn("managedAssets()", source)
                self.assertIn("issuedShares()", source)
                self.assertIn("25", source)
                self.assertIn("require(", source)

    def test_missing_target_or_invalid_field_requires_adapter(self):
        self.assertIsNone(erc4626.RENDERERS["share_price_monotonic"](
            {"assetsField": "managedAssets", "sharesField": "issuedShares"}, {}))
        self.assertIsNone(erc4626.RENDERERS["share_price_monotonic"](
            {"assetsField": "totalAssets();", "sharesField": "issuedShares"}, self.context))


if __name__ == "__main__":
    unittest.main()
