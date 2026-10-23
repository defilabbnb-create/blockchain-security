#!/usr/bin/env python3
"""Run source-bound dynamic PoCs for benchmark cases."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard, provenance
FORGE = ROOT / "work" / "tools" / "forge"
GENERIC_DYNAMIC_CASES = {"06-integer_overflow_minimal", "07-overflow_simple_add", "19-mishandled"}
REENTRANCY_DYNAMIC_CASES = {"14-reentrance", "15-reentrancy_simple", "20-reentrancy_cross_function"}
VAULT_LENDING_CASES = {"21-erc4626-donation", "22-erc4626-rounding", "23-lending-health-factor", "24-lending-bad-debt"}
AMM_CALL_CASES = {"25-amm-k-decrease", "26-amm-fee", "27-oracle-stale", "28-cross-call",
                  "29-delegatecall", "30-reentrancy-withdraw"}
CLEAN_CONTROL_CASES = {"31-clean-vault", "32-clean-lending", "33-clean-amm"}
OBSERVATION_CASES = {"10-dos_address", "11-dos_simple", "12-eth_tx_order_dependence_minimal", "17-timed_crowdsale", "18-lotto"}
ACCESS_CONTROL_CASES = {"02-incorrect_constructor_name1", "03-simple_suicide", "04-unprotected0"}
OLD_BLOCKHASH_CASES = {"09-old_blockhash"}
EXTRA_REENTRANCY_CASES = {"13-etherstore", "16-simple_dao"}
STORAGE_WRITE_CASES = {"01-arbitrary_location_write_simple"}
BECTOKEN_OVERFLOW_CASES = {"05-BECToken"}
PREDICTABLE_RANDOMNESS_CASES = {"08-guess_the_random_number"}
CASE_ID_PATTERN = re.compile(r"[0-9]{2}-[A-Za-z0-9][A-Za-z0-9_-]{0,80}")
SUCCESSFUL_RUN_STATES = {"confirmed", "control_passed", "unconfirmed", "invalid_control"}
SUPPORTED_CASES = (STORAGE_WRITE_CASES | ACCESS_CONTROL_CASES | BECTOKEN_OVERFLOW_CASES
                   | PREDICTABLE_RANDOMNESS_CASES | OLD_BLOCKHASH_CASES | EXTRA_REENTRANCY_CASES
                   | GENERIC_DYNAMIC_CASES | REENTRANCY_DYNAMIC_CASES | VAULT_LENDING_CASES
                   | AMM_CALL_CASES | CLEAN_CONTROL_CASES | OBSERVATION_CASES)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return _sha256_bytes(encoded)


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_source_verification() -> dict:
    try:
        value = json.loads((ROOT / "benchmark" / "source-verification.json").read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _sync_training_samples(completed_rows: list[tuple[str, dict, str, dict, Path]]) -> None:
    if not completed_rows:
        return
    manifest_path = ROOT / "training-data" / "github-vulnerabilities" / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    changed = False
    for _case_id, ground_truth, source_sha256, result, evidence_path in completed_rows:
        identity = ("smartbugs/smartbugs-curated", ground_truth.get("datasetCommit"),
                    ground_truth.get("source", "").split("/blob/", 1)[-1].split("/", 1)[-1])
        sample = next((row for row in manifest.get("samples", [])
                       if (row.get("repo"), row.get("commit"), row.get("path")) == identity), None)
        if sample is None or sample.get("sha256") != source_sha256:
            continue
        try:
            evidence_bytes = evidence_path.read_bytes()
        except OSError:
            continue
        analysis = sample.setdefault("analysis", {})
        if result.get("confirmedVulnerability") is True:
            dynamic_state = "passed"
        elif result.get("pocState") in {"unconfirmed", "control_passed", "invalid_control"}:
            dynamic_state = "unconfirmed"
        else:
            dynamic_state = "failed"
        analysis["dynamic"] = dynamic_state
        analysis["dynamicReason"] = ("benchmark_local_poc_confirmed" if dynamic_state == "passed"
                                     else result.get("reason") or "benchmark_dynamic_poc_failed")
        analysis["dynamicEvidence"] = str(evidence_path.relative_to(ROOT))
        analysis["dynamicEvidenceSha256"] = _sha256_bytes(evidence_bytes)
        analysis["confirmedVulnerability"] = result.get("confirmedVulnerability") is True
        write_shard(sample, "dynamic", analysis, lane_id="0-benchmark-dynamic",
                    tool_versions={"runner": "benchmark-dynamic.py", "solc": result.get("compilerVersion", "unavailable")})
        changed = True
    if not changed:
        return
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   check=True, capture_output=True, text=True, timeout=60)
    subprocess.run(["python3", str(ROOT / "scripts" / "export-training-jsonl.py")], cwd=ROOT,
                   check=False, capture_output=True, text=True, timeout=60)


def _sync_training_sample(case_id: str, ground_truth: dict, source_sha256: str, result: dict, evidence_path: Path) -> None:
    _sync_training_samples([(case_id, ground_truth, source_sha256, result, evidence_path)])


def _runner_for_case(case_id: str) -> Path:
    if case_id in STORAGE_WRITE_CASES:
        name = "benchmark-dynamic-storage-write.cjs"
    elif case_id in ACCESS_CONTROL_CASES:
        name = "benchmark-dynamic-access-control.cjs"
    elif case_id in BECTOKEN_OVERFLOW_CASES:
        name = "benchmark-dynamic-bectoken-overflow.cjs"
    elif case_id in PREDICTABLE_RANDOMNESS_CASES:
        name = "benchmark-dynamic-predictable-randomness.cjs"
    elif case_id in OLD_BLOCKHASH_CASES:
        name = "benchmark-dynamic-old-blockhash.cjs"
    elif case_id in EXTRA_REENTRANCY_CASES:
        name = "benchmark-dynamic-reentrancy-extra.cjs"
    elif case_id in GENERIC_DYNAMIC_CASES:
        name = "benchmark-dynamic-case-runner.cjs"
    elif case_id in REENTRANCY_DYNAMIC_CASES:
        name = "benchmark-dynamic-runner.cjs"
    elif case_id in VAULT_LENDING_CASES:
        name = "benchmark-dynamic-vault-lending.cjs"
    elif case_id in AMM_CALL_CASES:
        name = "benchmark-dynamic-amm-calls.cjs"
    elif case_id in CLEAN_CONTROL_CASES:
        name = "benchmark-dynamic-clean-controls.cjs"
    elif case_id in OBSERVATION_CASES:
        name = "benchmark-dynamic-observation.cjs"
    else:
        raise ValueError("unsupported_dynamic_case")
    return ROOT / "scripts" / name


def _timeout_output(error: subprocess.TimeoutExpired) -> bytes:
    parts = []
    for value in (error.stdout, error.stderr):
        if isinstance(value, bytes):
            parts.append(value)
        elif value:
            parts.append(str(value).encode("utf-8", errors="replace"))
    return b"\n".join(parts)


def _source_provenance(ground_truth: dict, source_sha256: str, case_id: str | None = None) -> dict:
    source = ground_truth.get("source")
    parsed = urlparse(source) if isinstance(source, str) else None
    parts = [part for part in (parsed.path.split("/") if parsed else []) if part]
    commit = ground_truth.get("datasetCommit")
    pinned = (parsed is not None and parsed.scheme == "https" and parsed.netloc.lower() == "github.com"
              and len(parts) >= 5 and parts[2] == "blob" and isinstance(commit, str)
              and parts[3] == commit and bool(__import__("re").fullmatch(r"[a-f0-9]{40}", commit)))
    placeholder = bool(parsed and (parsed.netloc.lower() == "example.org"
                                   or parts[:1] == ["example"]))
    verified_content = None
    if pinned and case_id:
        report = _read_source_verification()
        samples = report.get("samples")
        samples = samples if isinstance(samples, list) else []
        verified_content = next((row for row in samples if isinstance(row, dict)
                                 if row.get("caseId") == case_id
                                 and row.get("source") == source
                                 and row.get("state") == "verified"
                                 and row.get("sourceSha256") == source_sha256
                                 and row.get("remoteContentSha256") == source_sha256), None)
    status = ("pinned_commit_content_verified" if verified_content else
              "pinned_reference_unverified_content" if pinned else
              "placeholder_reference" if placeholder else "unverified_reference")
    return {"url": source, "datasetCommit": commit if pinned else None,
            "status": status, "localSourceSha256": source_sha256,
            "remoteContentVerified": bool(verified_content),
            "remoteContentSha256": verified_content.get("remoteContentSha256") if verified_content else None,
            "verificationReport": "benchmark/source-verification.json" if verified_content else None}


def _classify_runner_result(return_code: int, row: dict) -> tuple[str, bool, str]:
    confirmed = return_code == 0 and row.get("state") == "passed" and row.get("confirmedVulnerability") is True
    control_passed = return_code == 0 and row.get("state") == "control_passed" and row.get("controlPassed") is True
    invalid_control = row.get("state") == "invalid_control" and row.get("invalidControl") is True
    was_unconfirmed = row.get("state") == "unconfirmed" and row.get("confirmedVulnerability") is False
    state = ("confirmed" if confirmed else "control_passed" if control_passed else
             "invalid_control" if invalid_control else "unconfirmed" if was_unconfirmed else
             "failed" if return_code != 0 else "unconfirmed")
    status = ("poc_confirmed" if confirmed else "negative_control_passed" if control_passed
              else "invalid_control" if invalid_control else "poc_unconfirmed" if was_unconfirmed
              else "poc_failed")
    return state, confirmed, status


def _binding_error(row: dict, case_id: str, source_sha256: str,
                   compiler_version: str, compiler_sha256: str) -> str | None:
    if not row:
        return "runner_result_missing"
    if row.get("caseId") != case_id:
        return "runner_case_id_mismatch"
    if row.get("sourceSha256") != source_sha256:
        return "runner_source_hash_mismatch"
    reported_version = row.get("compilerVersion")
    if not isinstance(reported_version, str) or reported_version.split("+", 1)[0] != compiler_version.split("+", 1)[0]:
        return "runner_compiler_version_mismatch"
    reported_sha256 = row.get("compilerArtifactSha256")
    if not isinstance(reported_sha256, str):
        reported_sha256 = row.get("compilerSha256")
    normalize = lambda value: value.lower().removeprefix("0x") if isinstance(value, str) else None
    if normalize(reported_sha256) != normalize(compiler_sha256):
        return "runner_compiler_hash_mismatch"
    boundary = row.get("executionBoundary")
    if not isinstance(boundary, dict):
        return "runner_execution_boundary_missing"
    if (boundary.get("mode") != "isolated_in_process"
            or boundary.get("requestedMode") != "isolated_in_process"
            or boundary.get("chainId") != 31337
            or boundary.get("forkState") != "not_performed"
            or boundary.get("requestedFork") is not False
            or boundary.get("externalTransactions") is not False
            or boundary.get("externalSigning") is not False
            or boundary.get("networkWrites") != "local_only"
            or boundary.get("rpcEndpoint") != {"state": "not_configured"}):
        return "runner_execution_boundary_mismatch"
    return None


def _proof_scope(case_id: str, state: str) -> str:
    if state == "control_passed":
        return "negative_control_passed"
    if state != "confirmed":
        return "not_confirmed"
    if case_id in STORAGE_WRITE_CASES:
        return "attacker_owner_takeover_and_contract_balance_drain"
    if case_id in BECTOKEN_OVERFLOW_CASES:
        return "token_supply_invariant_violation_and_transferability"
    if case_id in PREDICTABLE_RANDOMNESS_CASES:
        return "attacker_profit_and_contract_balance_depletion"
    if case_id in {"14-reentrance", "15-reentrancy_simple", "20-reentrancy_cross_function"}:
        return "attacker_profit_and_victim_balance_change"
    if case_id in EXTRA_REENTRANCY_CASES:
        return "attacker_profit_and_victim_balance_change"
    if case_id in {"02-incorrect_constructor_name1", "03-simple_suicide"}:
        return "unauthorized_ownership_takeover_and_asset_withdrawal"
    if case_id == "04-unprotected0":
        return "unauthorized_owner_reassignment"
    if case_id == "09-old_blockhash":
        return "attacker_profit_and_contract_balance_depletion"
    if case_id in {"06-integer_overflow_minimal", "07-overflow_simple_add"}:
        return "arithmetic_state_corruption"
    if case_id == "19-mishandled":
        return "unchecked_call_failure_handling"
    if case_id == "21-erc4626-donation":
        return "erc4626_donation_account_profit"
    if case_id == "22-erc4626-rounding":
        return "erc4626_rounding_account_profit"
    if case_id == "24-lending-bad-debt":
        return "lending_bad_debt_accounting"
    if case_id == "30-reentrancy-withdraw":
        return "attacker_profit_and_victim_balance_change"
    if case_id in {"10-dos_address", "11-dos_simple"}:
        return "denial_of_service_state_observation"
    if case_id == "12-eth_tx_order_dependence_minimal":
        return "front_running_ordering_observation"
    if case_id == "17-timed_crowdsale":
        return "timestamp_boundary_observation"
    if case_id == "18-lotto":
        return "unchecked_call_reachability_observation"
    return {
        "23-lending-health-factor": "lending_accounting_invariant",
        "25-amm-k-decrease": "amm_reserve_invariant",
        "26-amm-fee": "fee_accounting_state_change",
        "27-oracle-stale": "stale_oracle_value",
        "29-delegatecall": "delegatecall_storage_control",
    }.get(case_id, "synthetic_security_invariant_or_control_flow")


def _run_exit_code(result: dict) -> int:
    return 0 if result.get("pocState") in SUCCESSFUL_RUN_STATES else 1


def _runner_failure_reason(row: dict, diagnostic: str) -> str:
    reason = row.get("reason")
    if isinstance(reason, str) and reason:
        return reason
    for line in diagnostic.splitlines():
        candidate = line.strip()
        if candidate.startswith(("Error:", "TypeError:", "RangeError:", "ReferenceError:", "SyntaxError:")):
            return candidate[:500]
    return "poc_assertion_failed"


def run_case(case_id: str, *, timeout: float = 120.0, sync_training: bool = True) -> dict:
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.fullmatch(case_id):
        raise ValueError("invalid benchmark case id")
    case_dir = ROOT / "benchmark" / "contracts" / case_id
    ground_truth = json.loads((case_dir / "ground-truth.json").read_text(encoding="utf-8"))
    source_name = ground_truth.get("sourceFile")
    if not isinstance(source_name, str) or not source_name or Path(source_name).name != source_name:
        raise ValueError("benchmark sourceFile must be a safe file name")
    source_path = case_dir / source_name
    source_bytes = source_path.read_bytes()
    source_sha256 = _sha256_bytes(source_bytes)
    source_bundle_sha256 = _canonical_sha256({source_name: source_bytes.decode("utf-8")})
    source_provenance = _source_provenance(ground_truth, source_sha256, case_id)
    compiler_version = ground_truth.get("solcVersion")
    static_spec = importlib.util.spec_from_file_location("review_static_compiler", ROOT / "scripts" / "review-static.py")
    static_module = importlib.util.module_from_spec(static_spec)
    static_spec.loader.exec_module(static_module)
    try:
        compiler, compiler_metadata = static_module.compiler(compiler_version)
    except Exception as error:
        result = {"schemaVersion": 1, "caseId": case_id, "pocState": "unavailable",
                  "confirmedVulnerability": False, "reason": f"compiler_unavailable:{type(error).__name__}:{str(error)[:240]}",
                  "sourceSha256": source_sha256, "sourceBundleSha256": source_bundle_sha256,
                  "sourceProvenance": source_provenance,
                  "knownIssues": ground_truth.get("knownIssues", []),
                  "cleanControl": ground_truth.get("clean") is True}
        _atomic_json(case_dir / "poc-result.json", result)
        return result
    runner = _runner_for_case(case_id)
    command = ["node", str(runner), case_id, str(source_path)]
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(compiler), "BENCHMARK_SOLC_VERSION": compiler_version,
           "BENCHMARK_SOLC_SHA256": compiler_metadata["sha256"]}
    try:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                   timeout=timeout, check=False, env=env)
        output = (completed.stdout + completed.stderr).encode("utf-8", errors="replace")[:2_000_000]
        evidence_sha256 = _sha256_bytes(output)
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip().startswith("{")]
        row = rows[-1] if rows else {}
        diagnostic_text = output.decode("utf-8", errors="replace")[-12000:]
        binding_error = _binding_error(row, case_id, source_sha256, compiler_version,
                                       compiler_metadata.get("sha256", ""))
        if binding_error:
            state, confirmed, status = "failed", False, "poc_failed"
        else:
            state, confirmed, status = _classify_runner_result(completed.returncode, row)
        reason = None if state in {"confirmed", "control_passed"} else _runner_failure_reason(row, diagnostic_text)
        if binding_error:
            reason = (binding_error if binding_error != "runner_result_missing"
                      else f"runner_result_missing:{_runner_failure_reason({}, diagnostic_text)}")
        result = {**row, "schemaVersion": 1, "caseId": case_id, "pocState": state,
                  "confirmedVulnerability": confirmed,
                  "proofScope": _proof_scope(case_id, state),
                  "status": status,
                  "sourceSha256": source_sha256, "sourceBundleSha256": source_bundle_sha256,
                  "sourceProvenance": source_provenance,
                  "knownIssues": ground_truth.get("knownIssues", []),
                  "cleanControl": ground_truth.get("clean") is True,
                  "evidenceSha256": evidence_sha256, "testName": row.get("testName") or f"testPoC_{case_id}",
                  "compilerArtifact": compiler_metadata,
                  "reproduceCommand": f"python3 scripts/benchmark-dynamic.py --case {case_id}",
                  "reason": reason, "diagnostic": None if state in {"confirmed", "control_passed"} else diagnostic_text}
    except subprocess.TimeoutExpired as error:
        diagnostic = _timeout_output(error)
        result = {"schemaVersion": 1, "caseId": case_id, "pocState": "error",
                  "confirmedVulnerability": False, "reason": "poc_timeout",
                  "sourceSha256": source_sha256, "sourceBundleSha256": source_bundle_sha256,
                  "sourceProvenance": source_provenance,
                  "evidenceSha256": _sha256_bytes(diagnostic)}
    evidence_path = case_dir / "poc-result.json"
    result.update(provenance(source_sha256, "D", {"solc": compiler_version, "runner": runner.name}))
    _atomic_json(evidence_path, result)
    if sync_training:
        _sync_training_sample(case_id, ground_truth, source_sha256, result, evidence_path)
    return result


def run_cases(case_ids: list[str], *, jobs: int = 4, timeout: float = 120.0) -> list[dict]:
    if isinstance(jobs, bool) or not isinstance(jobs, int) or not 1 <= jobs <= 8:
        raise ValueError("jobs must be between 1 and 8")
    if not case_ids or len(set(case_ids)) != len(case_ids) or any(case_id not in SUPPORTED_CASES for case_id in case_ids):
        raise ValueError("cases must be a nonempty unique list of supported benchmark ids")
    completed = []
    with ThreadPoolExecutor(max_workers=min(jobs, len(case_ids)), thread_name_prefix="dynamic-case") as executor:
        futures = {executor.submit(run_case, case_id, timeout=timeout, sync_training=False): case_id
                   for case_id in case_ids}
        for future in as_completed(futures):
            case_id = futures[future]
            try:
                completed.append(future.result())
            except Exception as error:
                result = {"schemaVersion": 1, "caseId": case_id, "pocState": "error",
                          "confirmedVulnerability": False,
                          "reason": f"runner_error:{type(error).__name__}:{str(error)[:240]}"}
                try:
                    case_dir = ROOT / "benchmark" / "contracts" / case_id
                    ground_truth = json.loads((case_dir / "ground-truth.json").read_text(encoding="utf-8"))
                    source_path = case_dir / ground_truth["sourceFile"]
                    source_bytes = source_path.read_bytes()
                    source_sha256 = _sha256_bytes(source_bytes)
                    result.update(sourceSha256=source_sha256,
                                  sourceBundleSha256=_canonical_sha256({ground_truth["sourceFile"]:
                                                                       source_bytes.decode("utf-8")}),
                                  sourceProvenance=_source_provenance(ground_truth, source_sha256, case_id),
                                  knownIssues=ground_truth.get("knownIssues", []),
                                  cleanControl=ground_truth.get("clean") is True)
                    _atomic_json(case_dir / "poc-result.json", result)
                except Exception as evidence_error:
                    result["evidenceWriteError"] = f"{type(evidence_error).__name__}:{str(evidence_error)[:160]}"
                completed.append(result)
    by_case = {row.get("caseId"): row for row in completed}
    sync_rows = []
    for case_id in case_ids:
        result = by_case.get(case_id, {})
        try:
            case_dir = ROOT / "benchmark" / "contracts" / case_id
            ground_truth = json.loads((case_dir / "ground-truth.json").read_text(encoding="utf-8"))
            source_path = case_dir / ground_truth["sourceFile"]
            sync_rows.append((case_id, ground_truth, _sha256_bytes(source_path.read_bytes()), result,
                              case_dir / "poc-result.json"))
        except (OSError, KeyError, json.JSONDecodeError):
            continue
    _sync_training_samples(sync_rows)
    return [by_case.get(case_id, {"caseId": case_id, "pocState": "error"}) for case_id in case_ids]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--case")
    selection.add_argument("--cases", nargs="+")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--list-versions", action="store_true")
    parser.add_argument("--list-cases", action="store_true")
    args = parser.parse_args(argv)
    if args.list_cases:
        print(json.dumps(sorted(SUPPORTED_CASES), ensure_ascii=False, indent=2))
        return 0
    if args.list_versions:
        catalog = json.loads((ROOT / "work" / "compiler-cache" / "list.json").read_text(encoding="utf-8"))
        cached = {path.name for path in (ROOT / "work" / "compiler-cache").glob("soljson-*.cjs")}
        rows = [{"version": version, "cached": (Path(filename).stem + ".cjs") in cached}
                for version, filename in sorted(catalog.get("releases", {}).items(),
                                                key=lambda item: tuple(int(part) for part in item[0].split(".")))]
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    if args.all or args.cases:
        case_ids = sorted(SUPPORTED_CASES) if args.all else args.cases
        results = run_cases(case_ids, jobs=args.jobs, timeout=args.timeout)
        print(json.dumps([{key: value for key, value in result.items() if key not in {"diagnostic"}}
                          for result in results], ensure_ascii=False, indent=2))
        return 0 if all(_run_exit_code(result) == 0 for result in results) else 1
    result = run_case(args.case or "14-reentrance", timeout=args.timeout)
    print(json.dumps({key: value for key, value in result.items() if key not in {"diagnostic"}}, ensure_ascii=False, indent=2))
    return _run_exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())
