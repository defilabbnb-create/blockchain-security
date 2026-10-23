import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "review_static_compiler", ROOT / "scripts" / "review-static.py")
COMPILER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPILER)
RUNNER = ROOT / "scripts" / "benchmark-dynamic-reentrancy-extra.cjs"


def run_case(case_id):
    case_dir = ROOT / "benchmark" / "contracts" / case_id
    truth = json.loads((case_dir / "ground-truth.json").read_text(encoding="utf-8"))
    source_path = case_dir / truth["sourceFile"]
    source = source_path.read_bytes()
    compiler_path, metadata = COMPILER.compiler(truth["solcVersion"])
    environment = {
        **os.environ,
        "CAMPAIGN_SOLJSON": str(compiler_path),
        "BENCHMARK_SOLC_VERSION": truth["solcVersion"],
        "BENCHMARK_SOLC_SHA256": metadata["sha256"],
    }
    completed = subprocess.run(
        ["node", str(RUNNER), case_id, str(source_path)],
        cwd=ROOT, env=environment, capture_output=True, text=True,
        timeout=90, check=False,
    )
    rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip().startswith("{")]
    if len(rows) != 1:
        raise AssertionError(completed.stdout + completed.stderr)
    row = rows[0]
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    assert row["sourceSha256"] == hashlib.sha256(source).hexdigest()
    assert row["compilerArtifactSha256"] == metadata["sha256"]
    assert row["compilerVersion"].split("+", 1)[0] == truth["solcVersion"]
    assert row["executionBoundary"]["mode"] == "isolated_in_process"
    assert row["executionBoundary"]["chainId"] == 31337
    assert row["executionBoundary"]["externalTransactions"] is False
    assert row["executionBoundary"]["networkWrites"] == "local_only"
    return row


class SmartBugsExtraReentrancyTests(unittest.TestCase):
    def assert_attack_evidence(self, row):
        self.assertEqual(row["state"], "passed")
        self.assertTrue(row["confirmedVulnerability"])
        self.assertEqual(row["proofScope"], "attacker_profit_and_victim_balance_change")
        self.assertEqual(int(row["beforeTargetBalanceWei"]), 3 * 10**18)
        self.assertEqual(int(row["afterTargetBalanceWei"]), 10**18)
        self.assertEqual(int(row["extractedWei"]), 2 * 10**18)
        self.assertEqual(int(row["profitWei"]), 10**18)
        self.assertEqual(int(row["victimCreditBeforeWei"]), 2 * 10**18)
        self.assertEqual(row["victimCreditAfterWei"], row["victimCreditBeforeWei"])
        self.assertEqual(int(row["reentryRounds"]), 1)
        self.assertEqual(len(row["transactionHashes"]), 5 if row["caseId"] == "13-etherstore" else 6)

    def test_etherstore_uses_one_week_gate_and_proves_withdrawable_value_extraction(self):
        row = run_case("13-etherstore")
        self.assertGreaterEqual(row["attackTimestamp"], 604800)
        self.assert_attack_evidence(row)

    def test_private_bank_deploys_log_and_proves_reentrant_extraction(self):
        row = run_case("16-simple_dao")
        self.assertTrue(row["logAddress"])
        self.assert_attack_evidence(row)


if __name__ == "__main__":
    unittest.main()
