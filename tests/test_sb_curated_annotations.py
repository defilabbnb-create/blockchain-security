#!/usr/bin/env python3
"""Tests for the SB Curated inline-annotation audit.

The audit compares two independent statements of the same fact: the dataset's
own `<yes> <report>` annotations and the project's `knownIssues`.  Agreement is
the result worth protecting -- it is what lets coverage be quoted against public
numbers -- so these tests assert agreement, and assert that a disagreement would
be reported rather than resolved by rewriting either side.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = ROOT / "benchmark"
CONTRACTS = BENCHMARK / "contracts"

SPEC = importlib.util.spec_from_file_location(
    "sb_curated_annotations", ROOT / "scripts" / "sb-curated-annotations.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class AnnotationParsingTests(unittest.TestCase):
    def test_single_and_multiple_annotations_are_read(self):
        text = ("contract C {\n"
                "  // <yes> <report> REENTRANCY\n"
                "  /* <yes> <report> UNCHECKED_LL_CALLS */\n"
                "  // <yes> <report> ARITHMETIC\n"
                "}")
        annotated, unknown = MODULE.annotated_classes(text)
        self.assertEqual(unknown, [])
        self.assertEqual(annotated, ['arithmetic', 'reentrancy', 'unchecked_low_level_call'])

    def test_unknown_spelling_is_reported_not_dropped(self):
        # Dropping it would make the sample look unannotated.
        annotated, unknown = MODULE.annotated_classes(
            "contract C { // <yes> <report> SOME_FUTURE_CLASS\n }")
        self.assertEqual(annotated, [])
        self.assertEqual(unknown, ['SOME_FUTURE_CLASS'])

    def test_plain_source_without_annotations_reads_as_unannotated(self):
        annotated, unknown = MODULE.annotated_classes("contract C { uint x; }")
        self.assertEqual((annotated, unknown), ([], []))

    def test_blanking_preserves_length_and_offsets(self):
        # Detection anchors on source offsets; blanking must not shift them.
        text = "contract C {\n  // <yes> <report> REENTRANCY\n  uint x;\n}"
        blanked = MODULE.strip_annotation_comment(text)
        self.assertEqual(len(blanked), len(text))
        self.assertNotIn('<yes>', blanked)
        self.assertEqual(blanked.count('\n'), text.count('\n'))
        self.assertIn('uint x;', blanked)


class AuditAgreementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = MODULE.compare(MODULE.load_cases(CONTRACTS))
        cls.annotated = [case for case in cls.report["cases"]
                         if case["annotatedClasses"]]

    def test_every_annotated_case_agrees_with_known_issues(self):
        disagreements = [case["caseId"] for case in self.annotated
                         if case["annotationNotInKnownIssues"]]
        self.assertEqual(disagreements, [],
                         f"标注有而 knownIssues 未收录：{disagreements}")

    def test_the_sb_curated_portion_is_non_trivial(self):
        # A vacuous "everything agrees" over zero samples would also pass the
        # test above, so the population itself is asserted.
        self.assertGreaterEqual(len(self.annotated), 20)

    def test_no_unknown_annotation_spelling_exists(self):
        self.assertEqual(self.report["unknownAnnotationSpellings"], {})

    def test_audit_does_not_rewrite_ground_truth(self):
        # The audit is read-only by construction; assert the file on disk still
        # says what it said, so a future "helpful" edit is caught.
        for case in self.report["cases"]:
            truth = json.loads(
                (CONTRACTS / case["caseId"] / "ground-truth.json").read_text("utf-8"))
            self.assertEqual(sorted(truth.get("knownIssues") or []),
                             case["knownIssues"], case["caseId"])

    def test_self_built_samples_are_reported_as_having_no_annotation(self):
        # 21-30 are the project's own fixtures, so they carry no dataset
        # annotation; they must show up as a difference rather than be hidden.
        without = self.report["knownIssuesWithoutAnnotation"]
        self.assertTrue(any(item["caseId"] == "27-oracle-stale" for item in without))


if __name__ == "__main__":
    unittest.main()