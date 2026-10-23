import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "training_dynamic_auction_smartbugs", ROOT / "scripts/training-dynamic-auction-smartbugs.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SmartBugsAuctionTests(unittest.TestCase):
    def test_exact_sample_hash_and_victim_impact_assertions_are_pinned(self):
        self.assertEqual(MODULE.EXPECTED_SHA256,
                         "85952d4855d88d2870b14816dddd238c13f5b70bea0950564c1563e1a80f2438")
        harness = (ROOT / "scripts/training-dynamic-auction-smartbugs.cjs").read_text(encoding="utf-8")
        for marker in ("TRAINING_SOURCE_SHA256", "rejecting_leader_blocks_higher_bid_and_preserves_victim_visible_state",
                       "pull_refund_control_accepts_victim_bid_and_records_refund", "isolated_local_evm"):
            with self.subTest(marker=marker):
                self.assertIn(marker, harness)

    def test_three_run_signature_ignores_random_addresses_and_hashes(self):
        base = {"state": "confirmed", "confirmedVulnerability": True,
                "sourceSha256": MODULE.EXPECTED_SHA256,
                "blockedTransaction": {"status": 0, "hash": "0xaaa"},
                "vulnerableAuction": {"bidBeforeWei": "1", "bidAfterWei": "1",
                                      "balanceBeforeWei": "1", "balanceAfterWei": "1", "leaderBefore": "0x1"},
                "secureControl": {"bidAfterWei": "2", "balanceAfterWei": "3",
                                  "priorBidderRefundWei": "1", "leaderAfter": "0x2"},
                "assertions": [{"name": "impact", "passed": True}], "txHash": "0x1"}
        changed_addresses = {**base, "blockedTransaction": {"status": 0, "hash": "0xbbb"},
                             "vulnerableAuction": {**base["vulnerableAuction"], "leaderBefore": "0x3"},
                             "secureControl": {**base["secureControl"], "leaderAfter": "0x4"}}
        self.assertEqual(MODULE.signature(base), MODULE.signature(changed_addresses))
        changed_impact = {**changed_addresses,
                          "vulnerableAuction": {**changed_addresses["vulnerableAuction"], "balanceAfterWei": "2"}}
        self.assertNotEqual(MODULE.signature(base), MODULE.signature(changed_impact))


if __name__ == "__main__":
    unittest.main()
