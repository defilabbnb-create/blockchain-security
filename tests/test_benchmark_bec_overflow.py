import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "review_static_compiler", ROOT / "scripts" / "review-static.py")
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)


class BecBatchTransferOverflowTests(unittest.TestCase):
    def test_overflow_mints_transferable_balances_above_total_supply(self):
        case_id = "05-BECToken"
        case_dir = ROOT / "benchmark" / "contracts" / case_id
        ground_truth = json.loads((case_dir / "ground-truth.json").read_text(encoding="utf-8"))
        source_path = case_dir / ground_truth["sourceFile"]
        source = source_path.read_bytes()
        compiler_path, compiler_metadata = REVIEW.compiler(ground_truth["solcVersion"])
        environment = {
            **os.environ,
            "CAMPAIGN_SOLJSON": str(compiler_path),
            "BENCHMARK_SOLC_VERSION": ground_truth["solcVersion"],
            "BENCHMARK_SOLC_SHA256": compiler_metadata["sha256"],
            "DYNAMIC_EXECUTION_MODE": "isolated_in_process",
        }
        completed = subprocess.run(
            ["node", str(ROOT / "scripts" / "benchmark-dynamic-bectoken-overflow.cjs"),
             case_id, str(source_path)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
        )
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith("{")]
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(len(rows), 1, completed.stdout + completed.stderr)
        row = rows[0]
        self.assertEqual(row["caseId"], case_id)
        self.assertEqual(row["state"], "passed")
        self.assertTrue(row["confirmedVulnerability"])
        self.assertEqual(row["proofScope"], "token_supply_invariant_violation_and_transferability")
        self.assertEqual(row["sourceSha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(row["compilerVersion"].split("+", 1)[0], "0.4.16")
        self.assertEqual(row["compilerArtifactSha256"].removeprefix("0x"),
                         compiler_metadata["sha256"].removeprefix("0x"))
        self.assertEqual(row["recipientCount"], 20)
        self.assertEqual(int(row["overflowValue"]) * 20 - 2**256, 4)
        self.assertEqual(row["wrappedDebit"], "4")
        self.assertEqual(int(row["aggregateBalancesAfterBatch"]), int(row["initialSupply"]) + 2**256)
        self.assertGreater(int(row["aggregateBalancesAfterBatch"]), int(row["supplyAfterBatch"]))
        self.assertEqual(int(row["firstBalanceAfterTransfer"]) + 1, int(row["overflowValue"]))
        self.assertEqual(int(row["secondBalanceAfterTransfer"]), int(row["overflowValue"]) + 1)
        self.assertEqual(row["aggregateAfterTransfer"], row["aggregateBalancesAfterBatch"])
        self.assertEqual(row["executionBoundary"]["mode"], "isolated_in_process")
        self.assertEqual(row["executionBoundary"]["chainId"], 31337)
        self.assertFalse(row["executionBoundary"]["externalTransactions"])
        self.assertEqual(len(row["transactionHashes"]), 3)
        self.assertTrue(all(re.fullmatch(r"0x[a-f0-9]{64}", value) for value in row["transactionHashes"]))


if __name__ == "__main__":
    unittest.main()
