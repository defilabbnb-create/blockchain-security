import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from decompiler_semantics import extract_semantics


class DecompilerSemanticsTests(unittest.TestCase):
    def test_pseudocode_extracts_entities_and_dynamic_delegatecall(self):
        report = extract_semantics("""
        function upgrade(address next) selector 0x3659cfe6
        sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, next)
        delegatecall(gas(), target, 0, 0, 0, 0, 0)
        """)
        self.assertEqual(report["inputKind"], "pseudocode")
        self.assertTrue(any(item["kind"] == "function" for item in report["entities"]))
        self.assertIn("DELEGATECALL_DYNAMIC", {item["kind"] for item in report["riskHints"]})
        self.assertFalse(report["semanticsProven"])

    def test_bytecode_only_input_emits_risk_hints_and_low_confidence(self):
        report = extract_semantics("0x600060005560006000f4ff")
        kinds = {item["kind"] for item in report["riskHints"]}
        self.assertEqual(report["inputKind"], "bytecode")
        self.assertIn("ARBITRARY_SSTORE", kinds)
        self.assertIn("DELEGATECALL_DYNAMIC", kinds)
        self.assertIn("SELFDESTRUCT", kinds)
        self.assertFalse(report["semanticsProven"])


if __name__ == "__main__":
    unittest.main()
