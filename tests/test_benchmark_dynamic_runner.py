import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "benchmark_dynamic", ROOT / "scripts" / "benchmark-dynamic.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BenchmarkDynamicFailureReasonTests(unittest.TestCase):
    def test_prefers_structured_runner_reason(self):
        self.assertEqual(
            MODULE._runner_failure_reason({"reason": "target_credit_assertion_failed"},
                                          "Error: unrelated runner text"),
            "target_credit_assertion_failed")

    def test_uses_error_instead_of_later_compiler_runtime_warning(self):
        diagnostic = (
            "Error: original_source_compile_failed: pragma conflict\n"
            "    at compile (runner.cjs:10:2)\n"
            "(node:10) V8: soljson.cjs Invalid asm.js: Invalid member of stdlib\n"
            "(Use `node --trace-warnings ...` to show where the warning was created)\n"
        )
        self.assertEqual(
            MODULE._runner_failure_reason({}, diagnostic),
            "Error: original_source_compile_failed: pragma conflict")

    def test_falls_back_when_output_has_no_error_diagnostic(self):
        self.assertEqual(MODULE._runner_failure_reason({}, "V8 warning only"),
                         "poc_assertion_failed")

    def test_routes_new_samples_to_their_isolated_runners(self):
        self.assertIn("05-BECToken", MODULE.SUPPORTED_CASES)
        self.assertTrue(MODULE.CASE_ID_PATTERN.fullmatch("05-BECToken"))
        self.assertEqual(MODULE._runner_for_case("01-arbitrary_location_write_simple").name,
                         "benchmark-dynamic-storage-write.cjs")
        self.assertEqual(MODULE._runner_for_case("02-incorrect_constructor_name1").name,
                         "benchmark-dynamic-access-control.cjs")
        self.assertEqual(MODULE._runner_for_case("04-unprotected0").name,
                         "benchmark-dynamic-access-control.cjs")
        self.assertEqual(MODULE._runner_for_case("09-old_blockhash").name,
                         "benchmark-dynamic-old-blockhash.cjs")
        self.assertEqual(MODULE._runner_for_case("05-BECToken").name,
                         "benchmark-dynamic-bectoken-overflow.cjs")
        self.assertEqual(MODULE._runner_for_case("08-guess_the_random_number").name,
                         "benchmark-dynamic-predictable-randomness.cjs")
        self.assertEqual(MODULE._runner_for_case("13-etherstore").name,
                         "benchmark-dynamic-reentrancy-extra.cjs")
        self.assertEqual(MODULE._runner_for_case("16-simple_dao").name,
                         "benchmark-dynamic-reentrancy-extra.cjs")
        self.assertEqual(MODULE._runner_for_case("21-erc4626-donation").name,
                         "benchmark-dynamic-vault-lending.cjs")
        self.assertEqual(MODULE._runner_for_case("29-delegatecall").name,
                         "benchmark-dynamic-amm-calls.cjs")
        self.assertEqual(MODULE._runner_for_case("32-clean-lending").name,
                         "benchmark-dynamic-clean-controls.cjs")
        for case_id in (
                "10-dos_address", "11-dos_simple",
                "12-eth_tx_order_dependence_minimal", "17-timed_crowdsale",
                "18-lotto"):
            with self.subTest(case_id=case_id):
                self.assertEqual(MODULE._runner_for_case(case_id).name,
                                 "benchmark-dynamic-observation.cjs")

    def test_observation_cases_are_isolated_and_have_explicit_unconfirmed_contract(self):
        for case_id in sorted(MODULE.OBSERVATION_CASES):
            with self.subTest(case_id=case_id):
                self.assertIn(case_id, MODULE.SUPPORTED_CASES)
                self.assertEqual(MODULE._runner_for_case(case_id).name,
                                 "benchmark-dynamic-observation.cjs")
                self.assertEqual(MODULE._proof_scope(case_id, "unconfirmed"),
                                 "not_confirmed")
                state, confirmed, status = MODULE._classify_runner_result(0, {
                    "state": "unconfirmed",
                    "confirmedVulnerability": False,
                    "reason": "observation_only",
                })
                self.assertEqual((state, confirmed, status),
                                 ("unconfirmed", False, "poc_unconfirmed"))

    def test_observation_runner_source_contains_provenance_and_isolation_contract(self):
        runner = (ROOT / "scripts" / "benchmark-dynamic-observation.cjs").read_text(
            encoding="utf-8")
        for marker in (
                "sourceSha256", "compilerArtifactSha256", "executionBoundary",
                "confirmedVulnerability: false", "state: 'unconfirmed'",
                "isolated_in_process", "array_reset_branch_hit_local_gas_limit"):
            with self.subTest(marker=marker):
                self.assertIn(marker, runner)

    def test_timeout_output_accepts_bytes_and_text(self):
        error = __import__("subprocess").TimeoutExpired("node", 1, output=b"stdout", stderr="stderr")
        self.assertEqual(MODULE._timeout_output(error), b"stdout\nstderr")

    def test_observation_without_impact_remains_unconfirmed(self):
        state, confirmed, status = MODULE._classify_runner_result(0, {
            "state": "unconfirmed", "confirmedVulnerability": False,
            "reason": "false_return_observed_without_downstream_failure_or_asset_impact",
        })
        self.assertEqual(state, "unconfirmed")
        self.assertFalse(confirmed)
        self.assertEqual(status, "poc_unconfirmed")

    def test_negative_controls_never_become_vulnerability_confirmations(self):
        self.assertEqual(MODULE._classify_runner_result(0, {
            "state": "control_passed", "controlPassed": True, "confirmedVulnerability": False,
        }), ("control_passed", False, "negative_control_passed"))
        self.assertEqual(MODULE._classify_runner_result(1, {
            "state": "invalid_control", "invalidControl": True, "confirmedVulnerability": False,
        }), ("invalid_control", False, "invalid_control"))

    def test_cli_exit_code_distinguishes_valid_observations_from_runner_failures(self):
        for state in ("confirmed", "control_passed", "unconfirmed", "invalid_control"):
            with self.subTest(state=state):
                self.assertEqual(MODULE._run_exit_code({"pocState": state}), 0)
        for state in ("failed", "error", "unavailable"):
            with self.subTest(state=state):
                self.assertEqual(MODULE._run_exit_code({"pocState": state}), 1)

    def test_source_provenance_distinguishes_pinned_smartbugs_from_placeholders(self):
        pinned = MODULE._source_provenance({
            "source": "https://github.com/smartbugs/smartbugs-curated/blob/"
                      "230e649123477eff332742a59a1c7cc6dc286cab/dataset/reentrancy/reentrance.sol",
            "datasetCommit": "230e649123477eff332742a59a1c7cc6dc286cab",
        }, "a" * 64)
        placeholder = MODULE._source_provenance({
            "source": "https://github.com/example/defi-benchmarks", "datasetCommit": None,
        }, "b" * 64)
        self.assertEqual(pinned["status"], "pinned_reference_unverified_content")
        self.assertFalse(pinned["remoteContentVerified"])
        self.assertEqual(placeholder["status"], "placeholder_reference")

    def test_source_provenance_requires_case_url_and_hash_to_match_verification_record(self):
        truth = {
            "source": "https://github.com/smartbugs/smartbugs-curated/blob/"
                      "230e649123477eff332742a59a1c7cc6dc286cab/dataset/reentrancy/reentrance.sol",
            "datasetCommit": "230e649123477eff332742a59a1c7cc6dc286cab",
        }
        report = {"samples": [{"caseId": "14-reentrance", "source": truth["source"],
                               "state": "verified", "sourceSha256": "a" * 64,
                               "remoteContentSha256": "a" * 64}]}
        with patch.object(MODULE, "_read_source_verification", return_value=report):
            verified = MODULE._source_provenance(truth, "a" * 64, "14-reentrance")
            altered = MODULE._source_provenance(truth, "b" * 64, "14-reentrance")
        self.assertEqual(verified["status"], "pinned_commit_content_verified")
        self.assertTrue(verified["remoteContentVerified"])
        self.assertEqual(altered["status"], "pinned_reference_unverified_content")
        self.assertFalse(altered["remoteContentVerified"])

    def test_runner_identity_source_and_compiler_must_match_before_confirmation(self):
        expected = {"caseId": "14-reentrance", "sourceSha256": "a" * 64,
                    "compilerVersion": "0.4.18+commit.deadbeef", "compilerArtifactSha256": "0x" + "b" * 64,
                    "executionBoundary": {
                        "mode": "isolated_in_process", "requestedMode": "isolated_in_process",
                        "chainId": 31337, "forkState": "not_performed", "requestedFork": False,
                        "externalTransactions": False, "externalSigning": False, "networkWrites": "local_only",
                        "rpcEndpoint": {"state": "not_configured"},
                    }}
        self.assertIsNone(MODULE._binding_error(expected, "14-reentrance", "a" * 64,
                                                "0.4.18", "b" * 64))
        for key, value, reason in (
            ("caseId", "15-reentrancy_simple", "runner_case_id_mismatch"),
            ("sourceSha256", "c" * 64, "runner_source_hash_mismatch"),
            ("compilerVersion", "0.8.19+commit.deadbeef", "runner_compiler_version_mismatch"),
            ("compilerArtifactSha256", "d" * 64, "runner_compiler_hash_mismatch"),
        ):
            with self.subTest(key=key):
                altered = {**expected, key: value}
                self.assertEqual(MODULE._binding_error(altered, "14-reentrance", "a" * 64,
                                                       "0.4.18", "b" * 64), reason)
        forked = {**expected, "executionBoundary": {**expected["executionBoundary"],
                                                       "mode": "fixed_block_fork",
                                                       "requestedMode": "fixed_block_fork",
                                                       "requestedFork": True}}
        self.assertEqual(MODULE._binding_error(forked, "14-reentrance", "a" * 64,
                                               "0.4.18", "b" * 64),
                         "runner_execution_boundary_mismatch")

    def test_missing_runner_json_is_not_misclassified_as_case_id_mismatch(self):
        self.assertEqual(MODULE._binding_error({}, "21-erc4626-donation", "a" * 64,
                                               "0.8.19", "b" * 64), "runner_result_missing")
        reason = MODULE._runner_failure_reason({}, "Error: deployment_reverted\n")
        self.assertEqual(reason, "Error: deployment_reverted")

    def test_proof_scope_does_not_equate_state_invariant_with_asset_theft(self):
        self.assertEqual(MODULE._proof_scope("01-arbitrary_location_write_simple", "confirmed"),
                         "attacker_owner_takeover_and_contract_balance_drain")
        self.assertEqual(MODULE._proof_scope("05-BECToken", "confirmed"),
                         "token_supply_invariant_violation_and_transferability")
        self.assertEqual(MODULE._proof_scope("08-guess_the_random_number", "confirmed"),
                         "attacker_profit_and_contract_balance_depletion")
        self.assertEqual(MODULE._proof_scope("14-reentrance", "confirmed"),
                         "attacker_profit_and_victim_balance_change")
        self.assertEqual(MODULE._proof_scope("13-etherstore", "confirmed"),
                         "attacker_profit_and_victim_balance_change")
        self.assertEqual(MODULE._proof_scope("04-unprotected0", "confirmed"),
                         "unauthorized_owner_reassignment")
        self.assertEqual(MODULE._proof_scope("09-old_blockhash", "confirmed"),
                         "attacker_profit_and_contract_balance_depletion")
        self.assertEqual(MODULE._proof_scope("23-lending-health-factor", "confirmed"),
                         "lending_accounting_invariant")
        self.assertEqual(MODULE._proof_scope("21-erc4626-donation", "confirmed"),
                         "erc4626_donation_account_profit")
        self.assertEqual(MODULE._proof_scope("22-erc4626-rounding", "confirmed"),
                         "erc4626_rounding_account_profit")
        self.assertEqual(MODULE._proof_scope("24-lending-bad-debt", "confirmed"),
                         "lending_bad_debt_accounting")
        self.assertEqual(MODULE._proof_scope("30-reentrancy-withdraw", "confirmed"),
                         "attacker_profit_and_victim_balance_change")
        self.assertEqual(MODULE._proof_scope("32-clean-lending", "control_passed"),
                         "negative_control_passed")

    def test_batch_workers_defer_shared_manifest_aggregation_until_all_finish(self):
        case_ids = ["21-erc4626-donation", "23-lending-health-factor"]
        calls = []

        def fake_run(case_id, *, timeout, sync_training):
            calls.append((case_id, sync_training))
            return {"caseId": case_id, "pocState": "unconfirmed", "confirmedVulnerability": False}

        with patch.object(MODULE, "run_case", side_effect=fake_run), \
                patch.object(MODULE, "_sync_training_samples") as aggregate:
            results = MODULE.run_cases(case_ids, jobs=2)

        self.assertEqual([row["caseId"] for row in results], case_ids)
        self.assertCountEqual(calls, [(case_id, False) for case_id in case_ids])
        aggregate.assert_called_once()

    def test_unexpected_case_exception_is_saved_without_aborting_batch(self):
        case_ids = ["21-erc4626-donation", "23-lending-health-factor"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for case_id in case_ids:
                case_dir = root / "benchmark" / "contracts" / case_id
                case_dir.mkdir(parents=True)
                (case_dir / "sample.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")
                (case_dir / "ground-truth.json").write_text(json.dumps({
                    "sourceFile": "sample.sol", "knownIssues": ["test"], "clean": False,
                    "source": "https://github.com/example/repo/blob/commit/sample.sol",
                }), encoding="utf-8")
            with patch.object(MODULE, "ROOT", root), \
                    patch.object(MODULE, "run_case", side_effect=RuntimeError("simulated runner failure")):
                results = MODULE.run_cases(case_ids, jobs=2)
            self.assertEqual([row["pocState"] for row in results], ["error", "error"])
            for case_id, row in zip(case_ids, results):
                evidence_path = root / "benchmark" / "contracts" / case_id / "poc-result.json"
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                self.assertEqual(evidence["reason"], row["reason"])
                self.assertRegex(evidence["sourceSha256"], r"^[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
