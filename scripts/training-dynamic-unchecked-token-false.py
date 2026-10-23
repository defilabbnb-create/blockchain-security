#!/usr/bin/env python3
"""Run a three-repeat source-bound false-return ERC20 bookkeeping check."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
HARNESS = ROOT / "scripts/training-dynamic-unchecked-token-false.cjs"
REPORT = ROOT / "work/lane-D4-report.json"
SHARD_DIR = ROOT / "work/corpus-shards/D4-unchecked-token"
SAMPLE = ("smartbugs/smartbugs-curated", "230e649123477eff332742a59a1c7cc6dc286cab",
          "dataset/unchecked_low_level_calls/0x19cf8481ea15427a98ba3cdd6d9e14690011ab10.sol")
EXPECTED_SHA256 = "fe2fb0a0e173f241ce33e07f3e01a4b0c8c2f8501e506c360af16648fa47b024"

sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import sample_id, validate_shard


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_compiler():
    spec = importlib.util.spec_from_file_location("review_static", ROOT / "scripts/review-static.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.compiler("0.4.26")


def signature(result: dict) -> str:
    return json.dumps({
        "state": result.get("state"), "confirmedVulnerability": result.get("confirmedVulnerability"),
        "impactDemonstrated": result.get("impactDemonstrated"), "sourceSha256": result.get("sourceSha256"),
        "compilerVersion": result.get("compilerVersion"),
        "storageObservation": result.get("storageObservation"),
        "tokenObservation": result.get("tokenObservation"),
        "transactionStatus": result.get("transaction", {}).get("status"),
        "assertions": result.get("assertions"), "reason": result.get("reason"),
    }, sort_keys=True, separators=(",", ":"))


def classify_runs(results: list[dict], failures: list[dict]) -> tuple[str, bool, bool]:
    if len(results) < 3:
        if not results and len(failures) == 3:
            return "harness_not_feasible", False, True
        return "flaky", False, False
    consistent = len({signature(result) for result in results}) == 1 and not failures
    if not consistent:
        return "flaky", False, False
    confirmed = all(
        result.get("state") == "confirmed"
        and result.get("confirmedVulnerability") is True
        and result.get("impactDemonstrated") is True
        and result.get("sourceSha256") == EXPECTED_SHA256
        and result.get("runnerExitCode") == 0
        and result.get("transaction", {}).get("status") == 1
        and bool(result.get("assertions"))
        and all(item.get("passed") is True for item in result["assertions"])
        for result in results
    )
    return ("confirmed" if confirmed else "unconfirmed"), confirmed, True


def manifest_context() -> tuple[dict, dict]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    unchecked = [row for row in manifest.get("samples", [])
                 if row.get("category") == "unchecked_low_level_calls"]
    not_run = [row for row in unchecked if row.get("analysis", {}).get("dynamic") == "not_run"]
    token_call_rows = []
    for row in not_run:
        try:
            source = (ROOT / row["objectPath"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if ("coinContract.transfer(" in source
                or "ERC20(_erc20Address).transfer(" in source
                or "ERC20Interface(tokenAddress).transfer(" in source):
            token_call_rows.append(row)
    row = next((item for item in not_run
                if (item.get("repo"), item.get("commit"), item.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_unchecked_token_manifest_identity_or_hash_mismatch")
    if not token_call_rows:
        raise ValueError("training_unchecked_token_screen_has_no_candidates")
    return row, {"uncheckedSampleCount": len(unchecked), "notRunSampleCount": len(not_run),
                 "tokenTransferCandidateCount": len(token_call_rows),
                 "tokenTransferCandidatePaths": [item.get("path") for item in token_call_rows]}


def run_once(source_path: Path, compiler_path: Path, compiler_meta: dict, timeout: float, run_index: int):
    environment = {**os.environ, "CAMPAIGN_SOLJSON": str(compiler_path),
                   "BENCHMARK_SOLC_VERSION": "0.4.26", "BENCHMARK_SOLC_SHA256": compiler_meta["sha256"],
                   "TRAINING_SOURCE_SHA256": EXPECTED_SHA256, "CORPUS_DEFER_MERGE": "1",
                   "PYTHONDONTWRITEBYTECODE": "1"}
    command = ["node", str(HARNESS), str(source_path)]
    try:
        completed = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True,
                                   timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        return None, {"runIndex": run_index, "failure": "timeout", "diagnostic": str(error)[:2400]}
    rows = [line for line in completed.stdout.splitlines() if line.lstrip().startswith("{")]
    if not rows:
        return None, {"runIndex": run_index, "returnCode": completed.returncode,
                      "failure": "missing_json_result",
                      "stdoutTail": completed.stdout[-1800:], "stderrTail": completed.stderr[-1800:]}
    try:
        result = json.loads(rows[-1])
    except json.JSONDecodeError as error:
        return None, {"runIndex": run_index, "failure": "invalid_json_result", "diagnostic": str(error)}
    if result.get("sourceSha256") != EXPECTED_SHA256:
        return None, {"runIndex": run_index, "failure": "source_hash_mismatch", "result": result}
    if result.get("compilerVersion", "").split("+", 1)[0] != "0.4.26":
        return None, {"runIndex": run_index, "failure": "compiler_version_mismatch", "result": result}
    if result.get("compilerArtifactSha256", "").removeprefix("0x") != compiler_meta["sha256"].removeprefix("0x"):
        return None, {"runIndex": run_index, "failure": "compiler_hash_mismatch", "result": result}
    result["runIndex"] = run_index
    result["runnerExitCode"] = completed.returncode
    result["diagnosticSha256"] = digest((completed.stdout + completed.stderr).encode("utf-8", errors="replace"))
    return result, (None if completed.returncode == 0 else {
        "runIndex": run_index, "failure": f"runner_exit_{completed.returncode}",
        "stdoutTail": completed.stdout[-1800:], "stderrTail": completed.stderr[-1800:]})


def run_sample(timeout: float = 180, runs: int = 3) -> dict:
    if runs != 3:
        raise ValueError("training_unchecked_token_requires_three_runs")
    row, screen = manifest_context()
    source_path = (ROOT / row["objectPath"]).resolve()
    if not source_path.is_relative_to(ROOT.resolve()) or digest(source_path.read_bytes()) != EXPECTED_SHA256:
        raise ValueError("training_unchecked_token_object_hash_mismatch")

    compiler_path, compiler_meta = load_compiler()
    results, failures = [], []
    for index in range(runs):
        result, failure = run_once(source_path, compiler_path, compiler_meta, timeout, index + 1)
        if result is not None:
            results.append(result)
        if failure is not None:
            failures.append(failure)
    state, confirmed, consistent = classify_runs(results, failures)
    reason = None if confirmed else ("three_run_result_inconsistent" if state == "flaky" else
                                    "all_three_harness_runs_failed" if state == "harness_not_feasible" else
                                    results[0].get("reason") if results else "dynamic_impact_not_demonstrated")
    evidence = {
        "schemaVersion": 1, "sampleId": "smartbugs-unchecked-token-transfer-bookkeeping",
        "sample": {"repo": row["repo"], "commit": row["commit"], "path": row["path"],
                   "sourceSha256": EXPECTED_SHA256, "objectPath": row["objectPath"]},
        "state": state, "confirmedVulnerability": confirmed, "impactDemonstrated": confirmed,
        "vulnerability": "unchecked_erc20_false_return_advances_transfer_bookkeeping",
        "reason": reason, "runCount": len(results), "attemptedRuns": runs, "consistent": consistent,
        "runs": results, "failures": failures,
        "harness": str(HARNESS.relative_to(ROOT)), "harnessSha256": digest(HARNESS.read_bytes()),
        "compilerArtifact": compiler_meta, "laneId": "D4-unchecked-token",
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "toolVersions": {"runner": HARNESS.name, "solc": "0.4.26", "runs": "3"},
    }

    shard_row = {"schemaVersion": 1, "sampleId": sample_id(row),
                 "identity": {key: row[key] for key in ("repo", "commit", "path")},
                 "sourceSha256": EXPECTED_SHA256, "layer": "dynamic",
                 "analysis": {"dynamic": state,
                              "dynamicReason": "source_bound_false_return_bookkeeping_effect_three_run_confirmed" if confirmed else reason,
                              "dynamicHarness": str(HARNESS.relative_to(ROOT)),
                              "dynamicHarnessSha256": evidence["harnessSha256"],
                              "confirmedVulnerability": confirmed},
                 "laneId": "D4-unchecked-token",
                 "toolVersions": {"runner": HARNESS.name, "solc": "0.4.26", "runs": "3"},
                 "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds")}
    validate_shard(shard_row)
    shard_path = SHARD_DIR / f"{shard_row['sampleId']}.dynamic.json"
    atomic_json(shard_path, shard_row)

    report = {
        "schemaVersion": 1, "laneId": "D4-unchecked-token",
        "generatedAt": evidence["generatedAt"], "state": state,
        "scope": "Offline triage of not_run unchecked_low_level_calls samples and one exact-source local-EVM ERC20 false-return bookkeeping test. No manifest edits or corpus merge.",
        "screening": {**screen, "samplePoolBefore": screen["notRunSampleCount"],
                      "reviewedNotRunSamples": screen["notRunSampleCount"],
                      "excludedPriorCases": ["0x2972 wrapper", "TokenBank/mishandled", "lotto", "King of the Ether Throne", "lane_a_fetch: 0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol"],
                      "selectionRationale": "Only five not_run sources matched the ERC20 transfer-call screen; the selected DAO Polska source has a direct unchecked return followed by a monotonic transfer-counter increment in the same owner-only function."},
        "sample": evidence["sample"], "proof": {
            "expectedImpact": "ERC20.transfer returns false without moving tokens, but exact-source sendTokenAw completes with receipt status 1 and increments numTransfers from 0 to 1.",
            "actualRunCount": len(results), "attemptedRunCount": runs, "consistent": consistent,
            "confirmedVulnerability": confirmed, "reason": reason,
            "runSummaries": [{"runIndex": item.get("runIndex"), "transactionStatus": item.get("transaction", {}).get("status"),
                              "transferCalls": item.get("tokenObservation", {}).get("transferCalls"),
                              "returnedFalse": item.get("tokenObservation", {}).get("returnedFalse"),
                              "daoBalanceBefore": item.get("tokenObservation", {}).get("daoBalanceBefore"),
                              "daoBalanceAfter": item.get("tokenObservation", {}).get("daoBalanceAfter"),
                              "recipientBalanceBefore": item.get("tokenObservation", {}).get("recipientBalanceBefore"),
                              "recipientBalanceAfter": item.get("tokenObservation", {}).get("recipientBalanceAfter"),
                              "numTransfersBefore": item.get("storageObservation", {}).get("before"),
                              "numTransfersAfter": item.get("storageObservation", {}).get("after"),
                              "assertions": item.get("assertions")} for item in results],
            "failures": failures,
        },
        "sourceAndToolHashes": {"sourceSha256": EXPECTED_SHA256,
                                 "harnessSha256": evidence["harnessSha256"],
                                 "compilerArtifactSha256": compiler_meta["sha256"]},
        "artifacts": {"harness": str(HARNESS.relative_to(ROOT)),
                      "shard": str(shard_path.relative_to(ROOT)),
                      "merge": "not_performed; CORPUS_DEFER_MERGE=1"},
        "limitations": [
            "The test proves the transfer counter advances while the mocked false-return ERC20 moves no tokens; it does not demonstrate token loss because assets remain in the source contract.",
            "The tested call is owner-only and represents an administrative token-recovery path; no unauthorized caller can invoke it.",
            "The mock behavior is explicit and local. This does not establish behavior of a deployed ERC20 or live contract.",
            "Dynamic PoC confirmation is separate from static scanner precision/recall.",
        ],
    }
    atomic_json(REPORT, report)
    return report


def main() -> int:
    report = run_sample()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("state") in {"confirmed", "unconfirmed", "flaky", "harness_not_feasible"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
