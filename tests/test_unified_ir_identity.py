"""Regression tests for the unified IR entity identity.

Every entity id has to be derived from the entity's content rather than its
position in a list.  The call graph reports one modifier gate in two places --
under `entrypoints[].permissionCandidates` and under the document-level
`permissions` -- so an id built from the row index made the same gate look like
two different permissions and the duplicate check rejected the whole document.
The visible effect was that ordinary contracts produced no IR at all, which in
turn left every downstream role undetectable for a reason unrelated to
detection.
"""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


unified_ir = _load("unified_ir_under_test", "unified_ir.py")


def _call_graph(case_id):
    path = (ROOT / "benchmark" / "contracts" / case_id / "deep-layers-work"
            / "call-graph.json")
    if not path.is_file():
        raise unittest.SkipTest(f"{case_id} 缺少 call-graph.json")
    return json.loads(path.read_text(encoding="utf-8"))


class SemanticEntityIdentityTests(unittest.TestCase):
    def _row(self, name="gate"):
        return {"kind": "modifier_gate_candidate", "modifier": f"M.{name}()",
                "function": "C::C.f()", "confidence": "heuristic",
                "semanticsProven": False,
                "location": {"file": "C.sol", "lines": [1], "start": 0, "length": 4}}

    def test_identical_rows_from_different_positions_share_an_id(self):
        row = self._row()
        first = unified_ir._semantic_entities([row], kind="permission",
                                              contract_id="c1", evidence_id="e1")
        second = unified_ir._semantic_entities([row], kind="permission",
                                               contract_id="c1", evidence_id="e1")
        self.assertEqual(first[0]["id"], second[0]["id"])

    def test_entity_id_does_not_depend_on_list_position(self):
        rows = [self._row("a"), self._row("b"), self._row("c")]
        together = unified_ir._semantic_entities(rows, kind="permission",
                                                 contract_id="c1", evidence_id="e1")
        alone = unified_ir._semantic_entities([rows[2]], kind="permission",
                                              contract_id="c1", evidence_id="e1")
        self.assertEqual(together[2]["id"], alone[0]["id"])

    def test_differing_rows_still_get_different_ids(self):
        first = unified_ir._semantic_entities([self._row("a")], kind="permission",
                                              contract_id="c1", evidence_id="e1")
        second = unified_ir._semantic_entities([self._row("b")], kind="permission",
                                               contract_id="c1", evidence_id="e1")
        self.assertNotEqual(first[0]["id"], second[0]["id"])

    def test_location_is_folded_into_source_ref_consistently(self):
        rows = unified_ir._with_permission_source_ref([self._row()])
        self.assertNotIn("location", rows[0])
        self.assertIn("sourceRef", rows[0])

    def test_normalisation_is_idempotent(self):
        once = unified_ir._with_permission_source_ref([self._row()])
        twice = unified_ir._with_permission_source_ref(once)
        self.assertEqual(once, twice)

    def test_normalisation_rejects_malformed_rows(self):
        with self.assertRaises(ValueError):
            unified_ir._with_permission_source_ref(["not-a-dict"])


class CallGraphRoundTripTests(unittest.TestCase):
    """The reported gate must appear once, not twice."""

    def test_duplicate_gate_merges_into_one_permission(self):
        document = unified_ir.from_call_graph(_call_graph("03-simple_suicide"))
        modifiers = [row.get("modifier") for row in document["permissions"]]
        self.assertEqual(len(modifiers), len(set(modifiers)))

    def test_permissions_carry_a_source_reference(self):
        document = unified_ir.from_call_graph(_call_graph("03-simple_suicide"))
        for row in document["permissions"]:
            self.assertIn("sourceRef", row)

    def test_reentrant_contract_still_builds(self):
        document = unified_ir.from_call_graph(_call_graph("14-reentrance"))
        self.assertTrue(document["functions"])


if __name__ == "__main__":
    unittest.main()