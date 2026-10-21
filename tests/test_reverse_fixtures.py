import json
import tempfile
import unittest
from pathlib import Path

from scripts import verify_reverse_fixtures


class ReverseFixtureGateTests(unittest.TestCase):
    def test_real_forge_gate_passes_every_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "reverse-fixtures.json"
            report = verify_reverse_fixtures.verify(output=report_path)
            self.assertEqual(report["state"], "passed")
            self.assertEqual(report["fixtureCount"], 7)
            self.assertTrue(report["assertionsIdentical"])
            persisted = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["fixtureCount"], 7)
            for row in persisted["fixtures"]:
                self.assertEqual(row["correct"]["returnCode"], 0)
                self.assertNotEqual(row["violating"]["returnCode"], 0)
                self.assertFalse(row["correct"]["compileError"])
                self.assertFalse(row["violating"]["compileError"])

    def test_missing_forge_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "forge executable unavailable"):
            verify_reverse_fixtures.verify(forge=Path("/missing/forge"))


if __name__ == "__main__":
    unittest.main()
