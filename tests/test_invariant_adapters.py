"""Tests for resolving the state transition a transition property needs.

A property that compares two readings only means anything if something
happens between them.  These tests pin where that something comes from: the
interface the compilation reported.  A template that needs an action and finds
no matching entry point is left without one, which is what makes the renderer
decline instead of comparing two identical readings.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from invariant_adapters import resolve_adapters


class AdapterResolutionTests(unittest.TestCase):
    def test_a_numeric_argument_is_read_from_the_contract_rather_than_fixed(self):
        # A literal zero is refused by anything that checks its input, and a
        # literal large enough to clear that check can still mint a single wei
        # of shares once the share price has risen -- a call that succeeds and
        # moves nothing, which no failure path reports.  The amount is therefore
        # resolved inside the harness, where the ledger is readable.
        resolved = resolve_adapters(
            ["share_price_monotonic"],
            [{"name": "Vault::Vault.deposit(uint256,address)"}])
        action = resolved["share_price_monotonic"]
        self.assertIn("_adapterAmount(target)", action)
        self.assertNotIn('deposit(uint256,address)", 0,', action)

    def test_every_numeric_argument_carries_the_derived_amount(self):
        resolved = resolve_adapters(
            ["k_never_decreases"], [{"name": "Pool.swap(uint256,uint256)"}])
        action = resolved["k_never_decreases"]
        self.assertEqual(action.count("_adapterAmount(target)"), 2)

    def test_an_address_argument_still_names_the_calling_contract(self):
        resolved = resolve_adapters(
            ["share_price_monotonic"],
            [{"name": "Vault.deposit(uint256,address)"}])
        self.assertIn("address(this)", resolved["share_price_monotonic"])

    def test_a_swap_in_the_ir_resolves_the_constant_product_action(self):
        resolved = resolve_adapters(
            ["k_never_decreases"],
            [{"name": "Pool::Pool.swap(uint256,uint256)", "visibility": "external"}])
        self.assertIn("k_never_decreases", resolved)
        action = resolved["k_never_decreases"]
        self.assertIn('swap(uint256,uint256)', action)
        self.assertIn("target.call", action)

    def test_a_borrow_resolves_the_health_factor_action(self):
        resolved = resolve_adapters(
            ["health_factor_monotonic_on_borrow"],
            [{"name": "Pool::Pool.borrow(uint256)"}])
        self.assertIn("borrow(uint256)", resolved["health_factor_monotonic_on_borrow"])

    def test_a_zero_argument_entry_point_resolves_without_placeholders(self):
        resolved = resolve_adapters(["share_price_monotonic"], [{"name": "Vault.deposit()"}])
        self.assertIn("deposit()", resolved["share_price_monotonic"])
        self.assertIn("target.call", resolved["share_price_monotonic"])

    def test_a_template_with_no_matching_entry_point_stays_unresolved(self):
        resolved = resolve_adapters(["k_never_decreases"], [{"name": "Vault.deposit()"}])
        self.assertEqual(resolved, {})

    def test_an_entry_point_whose_arguments_cannot_be_carried_is_not_used(self):
        # A struct or an array parameter has no placeholder that would make the
        # call dispatch, so using it would produce an action that always reverts
        # and leaves the two readings equal -- the defect the adapter exists to
        # remove.
        resolved = resolve_adapters(
            ["k_never_decreases"], [{"name": "Pool.swap(uint256[],uint256)"}])
        self.assertEqual(resolved, {})

    def test_empty_evidence_resolves_nothing(self):
        self.assertEqual(resolve_adapters(["k_never_decreases"], []), {})

    def test_a_template_with_no_declared_action_is_not_resolved(self):
        # Nothing here names an action for this template, so no entry point may
        # be picked for it however many the evidence reports.
        self.assertEqual(resolve_adapters(["some_unknown_template"], [{"name": "Pool.swap()"}]), {})

    def test_an_address_parameter_is_filled_with_the_calling_address(self):
        resolved = resolve_adapters(["share_price_monotonic"],
                                    [{"name": "Vault.deposit(address)"}])
        self.assertIn("address(this)", resolved["share_price_monotonic"])

    def test_a_storage_location_in_a_declared_type_does_not_reach_the_call(self):
        resolved = resolve_adapters(
            ["k_never_decreases"], [{"name": "Pool.swap(uint256 calldata input)"}])
        self.assertIn("swap(uint256)", resolved["k_never_decreases"])


class HarnessInjectionTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from harness_gen import generate_harness
        self.generate_harness = generate_harness

    def _bundle(self):
        return {
            "sources": {"Pool.sol": {"content":
                                     "pragma solidity ^0.8.20;\n"
                                     "contract Pool { uint256 public reserve0; uint256 public reserve1; }"}},
            "metadata": {"settings": {"compilationTarget": {"Pool.sol": "Pool"}}},
            "abi": [],
        }

    def _invariants(self):
        return {"schemaVersion": 1, "sourceSha256": None, "invariants": [
            {"invariantId": "a" * 64, "template": "k_never_decreases",
             "params": {"reserve0Field": "reserve0", "reserve1Field": "reserve1",
                        "toleranceBps": 0}}]}

    def test_without_an_adapter_the_transition_property_is_recorded_as_unavailable(self):
        import shutil, tempfile
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.generate_harness(self._invariants(), self._bundle(),
                                             Path(directory) / "harness")
            rows = [row for row in manifest["tests"] if row.get("template") == "k_never_decreases"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["status"], "adapter_required")
            self.assertEqual(
                rows[0]["reason"],
                "constant_product_comparison_requires_a_swap_between_the_two_reserve_readings")

    def test_with_an_adapter_the_action_is_written_between_the_two_readings(self):
        import shutil, tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "harness"
            action = '{ (bool ok,) = target.call(abi.encodeWithSignature("swap()")); require(ok, "x"); }'
            manifest = self.generate_harness(self._invariants(), self._bundle(), root,
                                             adapters={"k_never_decreases": action})
            rows = [row for row in manifest["tests"] if row.get("template") == "k_never_decreases"]
            self.assertEqual(rows[0]["status"], "unverified")
            text = (root / rows[0]["path"]).read_text(encoding="utf-8")
            self.assertIn("swap()", text)
            # The marker line is gone: leaving it would mean the action was
            # never placed between the readings.
            self.assertNotIn("// The adapter", text)

    def test_the_default_call_is_unchanged_when_no_adapter_is_passed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.generate_harness(self._invariants(), self._bundle(),
                                             Path(directory) / "harness")
            # The adapter-requiring template declines either way; the point is
            # that the call signature still accepts the historical invocation.
            self.assertEqual(manifest["adapterRequiredCount"], 1)

    def test_the_harness_carries_the_two_helpers_the_action_depends_on(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "harness"
            manifest = self.generate_harness(
                self._invariants(), self._bundle(), root,
                adapters={"k_never_decreases":
                          '{ (bool ok,) = target.call(abi.encodeWithSignature("swap()")); '
                          'if (!ok) { _skipUnavailable(); } }'})
            text = self._harness_text(root, manifest)
            # The emitted action calls both, so a harness missing either produces
            # a call that fails to resolve -- a compile error rather than a
            # measurement, which every consumer would read as a broken fixture.
            self.assertIn("function _skipUnavailable()", text)
            self.assertIn("function _adapterAmount(", text)
            self.assertIn("skip(true)", text)

    def test_the_derived_amount_scales_with_the_ledger(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "harness"
            manifest = self.generate_harness(
                self._invariants(), self._bundle(), root,
                adapters={"k_never_decreases":
                          '{ (bool ok,) = target.call(abi.encodeWithSignature("swap()")); '
                          'if (!ok) { _skipUnavailable(); } }'})
            text = self._harness_text(root, manifest)
            # A tenth of the ledger when the contract holds something, and a
            # constant big enough to clear a rounding check when it does not.
            # Both directions matter: the first keeps the action inside the
            # contract's current scale, the second keeps it from being refused.
            self.assertIn("held / 10", text)
            self.assertIn("1e24", text)

    def _harness_text(self, root: Path, manifest: dict) -> str:
        rows = [row for row in manifest["tests"] if row.get("path")]
        self.assertTrue(rows, "the generator produced no test to inspect")
        return (root / rows[0]["path"]).read_text(encoding="utf-8")

    def test_a_non_mapping_adapter_argument_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.generate_harness(self._invariants(), self._bundle(),
                                      Path(directory) / "harness", adapters=["not", "a", "mapping"])


if __name__ == "__main__":
    unittest.main()