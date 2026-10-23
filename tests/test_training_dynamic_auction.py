import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "training_dynamic_auction", ROOT / "scripts/training-dynamic-auction.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TrainingDynamicAuctionTests(unittest.TestCase):
    def test_sample_identity_is_hash_pinned_and_runner_has_negative_control(self):
        self.assertEqual(MODULE.SAMPLE, (
            "crytic/not-so-smart-contracts",
            "020dbdbde3e0c2e8de5f3944e7455e438b0995d5",
            "denial_of_service/auction.sol",
        ))
        self.assertEqual(MODULE.EXPECTED_SHA256,
                         "ba00c0f265d3830ea62584ae293b3f89224201a801968723d240703179fab86e")
        harness = (ROOT / "scripts/training-dynamic-auction.cjs").read_text(encoding="utf-8")
        for marker in ("RejectingBidder", "DosAuction", "SecureAuction", "TRAINING_SOURCE_SHA256",
                       "rejecting_leader_blocks_higher_bid_and_preserves_stuck_state",
                       "pull_refund_control_accepts_victim_bid_and_credits_prior_bidder",
                       "isolated_in_process"):
            with self.subTest(marker=marker):
                self.assertIn(marker, harness)

    def test_consistent_failure_flaky_and_infeasible_are_separate_states(self):
        passing = {"confirmedVulnerability": True, "state": "confirmed",
                   "vulnerability": "denial_of_service_push_refund", "checkedReverted": True,
                   "transactionStatus": 1, "runnerExitCode": 0, "sourceSha256": MODULE.EXPECTED_SHA256,
                   "vulnerableAuction": {"bidAfterWei": "1"}, "secureControl": {"bidAfterWei": "2"},
                   "assertions": [{"passed": True}]}
        state, confirmed, consistent = MODULE.classify_runs([passing] * 3, [], 3, MODULE.EXPECTED_SHA256)
        self.assertEqual((state, confirmed, consistent), ("confirmed", True, True))
        self.assertEqual(MODULE.classify_runs([passing] * 3, [], 3, "0" * 64),
                         ("unconfirmed", False, True))
        unconfirmed = {**passing, "confirmedVulnerability": False, "state": "unconfirmed",
                       "runnerExitCode": 1}
        self.assertEqual(MODULE.classify_runs([unconfirmed] * 3, [], 3, MODULE.EXPECTED_SHA256),
                         ("unconfirmed", False, True))
        changed = {**passing, "secureControl": {"bidAfterWei": "9"}}
        self.assertEqual(MODULE.classify_runs([passing, passing, changed], [], 3, MODULE.EXPECTED_SHA256),
                         ("flaky", False, False))
        self.assertEqual(MODULE.classify_runs([], ["all runner executions failed"], 3, MODULE.EXPECTED_SHA256),
                         ("harness_not_feasible", False, True))


if __name__ == "__main__":
    unittest.main()
