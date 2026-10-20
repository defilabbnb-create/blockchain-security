import json
import pathlib
import unittest

from scripts.invariant_assertions import RENDERER_MODULES, load_renderers


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "assertions"


class W0FoundationTests(unittest.TestCase):
    def test_registry_contract_has_expected_modules_and_is_empty_before_p1(self):
        self.assertEqual(RENDERER_MODULES, ("erc4626", "lending", "amm", "cross"))
        self.assertEqual(load_renderers(), {})

    def test_every_assertion_fixture_has_correct_and_violating_sources(self):
        fixture_dirs = [path for path in FIXTURES.iterdir() if path.is_dir()]
        self.assertEqual(len(fixture_dirs), 7)
        for fixture_dir in fixture_dirs:
            with self.subTest(fixture=fixture_dir.name):
                self.assertTrue((fixture_dir / "correct").is_dir())
                self.assertTrue((fixture_dir / "violating").is_dir())
                meta = json.loads((fixture_dir / "meta.json").read_text())
                self.assertIn("role", meta)
                self.assertIn("template", meta)
                self.assertEqual(meta["expectedOnCorrect"], "passed")
                self.assertEqual(meta["expectedOnViolating"], "violated")
