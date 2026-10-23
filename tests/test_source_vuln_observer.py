"""Regression tests for the source-level vulnerability observer.

Each test here pins a specific defect that made a real benchmark sample
unobservable.  They are written as positive *and* negative pairs on purpose:
a rule that fires on the vulnerable sample but also fires on a clean control is
worse than no rule at all, because it turns one missed detection into a false
positive that costs analyst time.
"""
import glob
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
    spec.loader.exec_module(module)
    return module


observer = _load("source_vuln_evidence_under_test", "source_vuln_evidence.py")


def _source(case_id):
    matches = glob.glob(str(ROOT / "benchmark" / "contracts" / case_id / "*.sol"))
    if not matches:
        raise unittest.SkipTest(f"{case_id} 缺少 Solidity 源文件")
    return Path(matches[0]).read_text(encoding="utf-8")


class ArithmeticDetectionTests(unittest.TestCase):
    """`count -= input` is the canonical SWC-101 shape.

    The observer used to recognise only `unchecked { ... }` and explicit casts,
    so every bare compound assignment was invisible.
    """

    def test_bare_compound_assignment_with_caller_operand_is_flagged(self):
        for case_id in ("06-integer_overflow_minimal", "07-overflow_simple_add"):
            with self.subTest(case=case_id):
                self.assertTrue(observer.observe(_source(case_id))["arithmetic"])

    def test_clean_ledger_accounting_is_not_flagged(self):
        """`shares[msg.sender] += assets` is bookkeeping, not an overflow.

        The clean controls debit and credit the caller's own entry.  Flagging
        them would trade one missed detection for three false positives.
        """
        for case_id in ("31-clean-vault", "32-clean-lending", "33-clean-amm"):
            with self.subTest(case=case_id):
                self.assertFalse(observer.observe(_source(case_id))["arithmetic"])

    def test_bounded_operand_is_not_flagged(self):
        """A caller-supplied value behind a require cannot wrap."""
        source = """
        pragma solidity ^0.8.0;
        contract Vault {
            uint256 public total;
            function deposit(uint256 amount) external {
                require(amount > 0);
                total += amount;
            }
        }
        """
        self.assertFalse(observer.observe(source)["arithmetic"])

    def test_caller_keyed_write_is_not_flagged(self):
        """Subtracting from the caller's own entry is an ordinary withdrawal."""
        source = """
        pragma solidity ^0.8.0;
        contract Vault {
            mapping(address => uint256) public shares;
            function withdraw(uint256 assets) external {
                require(shares[msg.sender] >= assets);
                shares[msg.sender] -= assets;
            }
        }
        """
        self.assertFalse(observer.observe(source)["arithmetic"])

    def test_evidence_records_the_offending_expression(self):
        rows = observer.observe(_source("06-integer_overflow_minimal"))["unwrappedArithmetic"]
        self.assertTrue(rows)
        self.assertTrue(any("input" in row["operandFromCaller"] for row in rows))


class AccessControlDetectionTests(unittest.TestCase):
    """Function headers must survive normal code formatting.

    The header pattern used to require every modifier to carry an argument list,
    so `function changeOwner(address x)` followed by `public` then `{` matched
    nothing -- and the observer reported zero functions for every formatted
    contract in the corpus.
    """

    def test_multiline_formatted_header_is_parsed(self):
        source = """
        pragma solidity ^0.4.15;
        contract Unprotected {
            address private owner;
            function changeOwner(address _newOwner)
                public
            {
                owner = _newOwner;
            }
        }
        """
        facts = observer.observe(source)
        self.assertIn("changeOwner", facts["functionModifiers"])
        self.assertEqual(facts["unguardedPrivilegedEntries"], ["changeOwner"])

    def test_guard_modifier_is_recognised(self):
        source = """
        pragma solidity ^0.4.15;
        contract Vault {
            address private owner;
            function setOwner(address next)
                public
                onlyOwner
            {
                owner = next;
            }
        }
        """
        facts = observer.observe(source)
        self.assertEqual(facts["unguardedPrivilegedEntries"], [])
        self.assertIn("onlyOwner", facts["functionModifiers"]["setOwner"])

    def test_semantically_privileged_names_are_flagged(self):
        """`changeOwner` is privileged by what it does, not by being listed."""
        for case_id in ("01-arbitrary_location_write_simple",
                        "02-incorrect_constructor_name1", "04-unprotected0"):
            with self.subTest(case=case_id):
                self.assertTrue(observer.observe(_source(case_id))["unguardedPrivilegedEntries"])

    def test_constructor_is_not_a_reachable_entrypoint(self):
        """Deployment assigning `owner = msg.sender` is not a missing guard."""
        source = """
        pragma solidity ^0.4.15;
        contract Owned {
            address private owner;
            function Owned() public { owner = msg.sender; }
            function transfer(address next) public onlyOwner { owner = next; }
        }
        """
        self.assertEqual(observer.observe(source)["unguardedPrivilegedEntries"], [])

    def test_misspelled_constructor_is_flagged(self):
        """SWC-118: a constructor the compiler did not recognise stays callable."""
        source = """
        pragma solidity ^0.4.24;
        contract Missing {
            address private owner;
            function IamMissing() public { owner = msg.sender; }
        }
        """
        self.assertEqual(observer.observe(source)["unguardedPrivilegedEntries"], ["IamMissing"])

    def test_case_differing_name_is_not_treated_as_the_constructor(self):
        """Solidity matches a constructor by exact name, so `missing()` is not
        the constructor of `contract Missing` -- it is a callable entrypoint that
        hands ownership to whoever calls it.  Folding case here hid the sample."""
        source = """
        pragma solidity ^0.4.24;
        contract Missing {
            address private owner;
            function missing() public { owner = msg.sender; }
        }
        """
        self.assertEqual(observer.observe(source)["unguardedPrivilegedEntries"], ["missing"])

    def test_user_facing_vault_entrypoint_is_not_privileged(self):
        facts = observer.observe(_source("31-clean-vault"))
        self.assertEqual(facts["unguardedPrivilegedEntries"], [])

    def test_function_names_are_not_truncated(self):
        """A lazy modifier group used to steal the name's last character."""
        source = """
        pragma solidity ^0.8.0;
        contract V {
            function withdraw(uint256 a) external returns (uint256) { return a; }
        }
        """
        self.assertIn("withdraw", observer.observe(source)["functionModifiers"])


class ObservationShapeTests(unittest.TestCase):
    def test_empty_source_matches_analysed_shape(self):
        """A caller must never have to distinguish 'nothing found' from 'nothing
        looked at' by which keys exist."""
        facts = observer.observe("")
        self.assertEqual(facts, observer.observe(""))

    def test_arithmetic_evidence_key_present_when_empty(self):
        facts = observer.observe("")
        self.assertIn("unwrappedArithmetic", facts)
        self.assertEqual(facts["unwrappedArithmetic"], [])
        self.assertFalse(facts["arithmetic"])


class BenchmarkCorpusTests(unittest.TestCase):
    """End-to-end checks over the shipped corpus.

    These fail loudly if a benchmark sample is removed or renamed, which is the
    point: a rule tuned until it passes has to keep passing on the real files.
    """

    def _cases(self):
        directory = ROOT / "benchmark" / "contracts"
        if not directory.is_dir():
            self.skipTest("benchmark/contracts 不存在")
        return sorted(directory.iterdir())

    def test_clean_controls_are_never_flagged_as_arithmetic(self):
        for case_dir in self._cases():
            truth_path = case_dir / "ground-truth.json"
            if not truth_path.is_file():
                continue
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
            if truth.get("knownIssues"):
                continue
            for source_path in case_dir.glob("*.sol"):
                with self.subTest(case=case_dir.name):
                    self.assertFalse(observer.observe(
                        source_path.read_text(encoding="utf-8"))["arithmetic"])

    def test_clean_controls_have_no_privileged_entrypoint(self):
        for case_dir in self._cases():
            truth_path = case_dir / "ground-truth.json"
            if not truth_path.is_file():
                continue
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
            if truth.get("knownIssues"):
                continue
            for source_path in case_dir.glob("*.sol"):
                with self.subTest(case=case_dir.name):
                    self.assertEqual(observer.observe(
                        source_path.read_text(encoding="utf-8"))["unguardedPrivilegedEntries"], [])

    def test_reentrancy_samples_still_yield_a_candidate(self):
        for case_id in ("13-etherstore", "14-reentrance", "15-reentrancy_simple",
                        "16-simple_dao", "20-reentrancy_cross_function",
                        "30-reentrancy-withdraw"):
            with self.subTest(case=case_id):
                self.assertGreater(
                    observer.observe(_source(case_id))["reentrancyCandidateCount"], 0)


if __name__ == "__main__":
    unittest.main()