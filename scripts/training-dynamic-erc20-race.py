#!/usr/bin/env python3
"""Run a source-bound ERC20 allowance-ordering harness and write a D2-only shard."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
HARNESS = ROOT / "scripts/training-dynamic-erc20-race.cjs"
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
SHARDS = ROOT / "work/corpus-shards/D2-transaction-ordering"
SAMPLE = ("smartbugs/smartbugs-curated", "230e649123477eff332742a59a1c7cc6dc286cab",
          "dataset/front_running/ERC20.sol")
EXPECTED_SHA256 = "2945981f9e38addeee1e3936e18871cb4bd96a70ba84836dd48cd953a8d910f7"

sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import atomic_json, sample_id, validate_shard


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def compiler_loader():
    spec = importlib.util.spec_from_file_location("review_static", ROOT / "scripts/review-static.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signature(result: dict) -> str:
    normalized = {
        "state": result.get("state"), "confirmedVulnerability": result.get("confirmedVulnerability"),
        "sourceSha256": result.get("sourceSha256"), "vulnerability": result.get("vulnerability"),
        "additionalHolderTokenLoss": result.get("additionalHolderTokenLoss"),
        "assertions": result.get("assertions"),
    }
    for label in ("raced", "safeOrder"):
        row = result.get(label) or {}
        normalized[label] = {key: row.get(key) for key in
                             ("totalSpent", "allowanceAfter", "oldAllowanceSpendStatus",
                              "newAllowanceApprovalStatus", "remainingAllowanceSpendStatus",
                              "receiverBalanceGain")}
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def classify_runs(results: list[dict], failures: list[str], runs: int = 3) -> tuple[str, bool, bool]:
    if len(results) < runs:
        return ("harness_not_feasible", False, True) if not results else ("flaky", False, False)
    consistent = len({signature(result) for result in results}) == 1 and not failures
    if not consistent:
        return "flaky", False, False
    confirmed = all(result.get("state") == "confirmed"
                    and result.get("confirmedVulnerability") is True
                    and result.get("runnerExitCode") == 0 for result in results)
    return ("confirmed" if confirmed else "unconfirmed"), confirmed, True


def write_d2_shard(row: dict, analysis: dict) -> Path:
    lane_id = "D2-transaction-ordering"
    tool_versions = {"runner": "training-dynamic-erc20-race.cjs", "solc": "0.4.26", "runs": "3"}
    shard = {"schemaVersion": 1, "sampleId": sample_id(row),
             "identity": {key: row[key] for key in ("repo", "commit", "path")},
             "sourceSha256": row.get("sha256"), "layer": "dynamic",
             "analysis": {key: value for key, value in analysis.items()
                          if key.startswith("dynamic") or key == "confirmedVulnerability"},
             "laneId": lane_id, "toolVersions": tool_versions,
             "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds")}
    validate_shard(shard)
    SHARDS.mkdir(parents=True, exist_ok=True)
    path = SHARDS / f"{shard['sampleId']}.dynamic.json"
    lock_path = SHARDS / f"{shard['sampleId']}.lock"
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        history = SHARDS / "history" / shard["sampleId"]
        atomic_json(history / f"dynamic.{uuid.uuid4().hex}.json", shard)
        atomic_json(path, shard)
    return path


def run_sample(timeout: float = 120, runs: int = 3) -> dict:
    if os.environ.get("CORPUS_DEFER_MERGE", "1") != "1":
        raise RuntimeError("D2_requires_CORPUS_DEFER_MERGE=1")
    if runs != 3:
        raise ValueError("training_harness_requires_three_runs")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next((item for item in manifest.get("samples", [])
                if (item.get("repo"), item.get("commit"), item.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_sample_manifest_hash_mismatch")
    source_path = (ROOT / row["objectPath"]).resolve()
    if not source_path.is_relative_to(ROOT.resolve()) or digest(source_path.read_bytes()) != EXPECTED_SHA256:
        raise ValueError("training_sample_object_hash_mismatch")
    soljson, compiler_info = compiler_loader().compiler("0.4.26")
    compiler_sha = str(compiler_info.get("sha256", "")).removeprefix("0x")
    if compiler_info.get("version") and not str(compiler_info["version"]).startswith("0.4.26"):
        raise ValueError("training_compiler_version_mismatch")
    environment = {**os.environ, "CORPUS_DEFER_MERGE": "1", "CAMPAIGN_SOLJSON": str(soljson),
                   "BENCHMARK_SOLC_VERSION": "0.4.26", "BENCHMARK_SOLC_SHA256": compiler_sha,
                   "TRAINING_SOURCE_SHA256": EXPECTED_SHA256}
    results, failures = [], []
    for index in range(runs):
        try:
            completed = subprocess.run(["node", str(HARNESS), str(source_path)], cwd=ROOT,
                                       capture_output=True, text=True, timeout=timeout, check=False,
                                       env=environment)
        except subprocess.TimeoutExpired as error:
            failures.append(f"run_{index + 1}:timeout:{error}")
            continue
        lines = [line for line in completed.stdout.splitlines() if line.lstrip().startswith("{")]
        if not lines:
            failures.append(f"run_{index + 1}:exit_{completed.returncode}:"
                            f"{(completed.stdout + completed.stderr)[-2000:]}")
            continue
        try:
            result = json.loads(lines[-1])
        except json.JSONDecodeError as error:
            failures.append(f"run_{index + 1}:json:{error}")
            continue
        result["runIndex"] = index + 1
        result["runnerExitCode"] = completed.returncode
        if result.get("sourceSha256") != EXPECTED_SHA256:
            failures.append(f"run_{index + 1}:source_hash_mismatch")
        results.append(result)

    state, confirmed, consistent = classify_runs(results, failures, runs)
    record = dict(results[0]) if results else {"schemaVersion": 1,
                                                "sampleId": "smartbugs-erc20-approve-race",
                                                "vulnerability": "erc20_approve_allowance_transaction_ordering"}
    record.update({"state": state, "confirmedVulnerability": confirmed, "sourceSha256": EXPECTED_SHA256,
                   "runCount": len(results), "consistent": consistent, "runs": results,
                   "reason": None if confirmed else ";".join(failures) or "allowance_ordering_asset_assertion_failed",
                   "harnessSha256": digest(HARNESS.read_bytes()), "compilerArtifactSha256": compiler_sha,
                   "laneId": "D2-transaction-ordering",
                   "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "toolVersions": {"runner": "training-dynamic-erc20-race.cjs", "solc": "0.4.26", "runs": "3"}})
    evidence_path = EVIDENCE / f"{EXPECTED_SHA256}.dynamic-erc20-race.json"
    atomic_json(evidence_path, record)
    analysis = {"dynamic": "passed" if confirmed else state,
                "dynamicReason": "source_bound_three_run_allowance_ordering_impact_confirmed" if confirmed else record["reason"],
                "dynamicEvidence": str(evidence_path.relative_to(ROOT)),
                "dynamicEvidenceSha256": digest(evidence_path.read_bytes()),
                "dynamicHarness": str(HARNESS.relative_to(ROOT)),
                "dynamicHarnessSha256": record["harnessSha256"],
                "confirmedVulnerability": confirmed}
    record["shardPath"] = str(write_d2_shard(row, analysis).relative_to(ROOT))
    record["manifestMerged"] = False
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    record = run_sample(args.timeout, args.runs)
    print(json.dumps(record, ensure_ascii=False, indent=2))
    return 0 if record.get("state") in {"confirmed", "unconfirmed", "harness_not_feasible", "flaky"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
