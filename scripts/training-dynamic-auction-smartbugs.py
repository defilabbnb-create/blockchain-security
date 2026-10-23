#!/usr/bin/env python3
"""Run the source-hash-bound SmartBugs auction DoS harness three times."""
from __future__ import annotations

import argparse
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
HARNESS = ROOT / "scripts/training-dynamic-auction-smartbugs.cjs"
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
SAMPLE = ("smartbugs/smartbugs-curated", "230e649123477eff332742a59a1c7cc6dc286cab",
          "dataset/denial_of_service/auction.sol")
EXPECTED_SHA256 = "85952d4855d88d2870b14816dddd238c13f5b70bea0950564c1563e1a80f2438"

sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def compiler_loader():
    spec = importlib.util.spec_from_file_location("review_static", ROOT / "scripts/review-static.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signature(result: dict) -> str:
    vulnerable = result.get("vulnerableAuction", {})
    control = result.get("secureControl", {})
    fields = {
        "state": result.get("state"), "confirmedVulnerability": result.get("confirmedVulnerability"),
        "sourceSha256": result.get("sourceSha256"), "blockedTransaction": result.get("blockedTransaction", {}).get("status"),
        "vulnerable": {key: vulnerable.get(key) for key in ("bidBeforeWei", "bidAfterWei", "balanceBeforeWei", "balanceAfterWei")},
        "control": {key: control.get(key) for key in ("bidAfterWei", "balanceAfterWei", "priorBidderRefundWei")},
        "assertions": result.get("assertions"),
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def run_sample(timeout: float = 120, runs: int = 3) -> dict:
    if runs != 3:
        raise ValueError("smartbugs_auction_requires_three_runs")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next((item for item in manifest.get("samples", [])
                if (item.get("repo"), item.get("commit"), item.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_sample_manifest_hash_mismatch")
    source_path = ROOT / row["objectPath"]
    if digest(source_path.read_bytes()) != EXPECTED_SHA256:
        raise ValueError("training_sample_object_hash_mismatch")
    soljson, compiler_info = compiler_loader().compiler("0.4.26")
    compiler_sha = str(compiler_info.get("sha256", ""))
    environment = {**os.environ, "CAMPAIGN_SOLJSON": str(soljson),
                   "BENCHMARK_SOLC_VERSION": "0.4.26", "BENCHMARK_SOLC_SHA256": compiler_sha,
                   "TRAINING_SOURCE_SHA256": EXPECTED_SHA256, "CORPUS_DEFER_MERGE": "1"}
    results, failures = [], []
    for index in range(runs):
        try:
            completed = subprocess.run(["node", str(HARNESS), str(source_path)], cwd=ROOT,
                                       capture_output=True, text=True, timeout=timeout, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            failures.append(f"run_{index + 1}:timeout:{error}")
            continue
        lines = [line for line in completed.stdout.splitlines() if line.lstrip().startswith("{")]
        if not lines:
            failures.append(f"run_{index + 1}:exit_{completed.returncode}:{(completed.stdout + completed.stderr)[-1600:]}")
            continue
        try:
            result = json.loads(lines[-1])
        except json.JSONDecodeError as error:
            failures.append(f"run_{index + 1}:json:{error}")
            continue
        result["runIndex"] = index + 1
        result["runnerExitCode"] = completed.returncode
        results.append(result)
    consistent = len(results) == runs and not failures and len({signature(item) for item in results}) == 1
    confirmed = consistent and all(item.get("confirmedVulnerability") is True
                                   and item.get("sourceSha256") == EXPECTED_SHA256
                                   and item.get("runnerExitCode") == 0 for item in results)
    state = "confirmed" if confirmed else "flaky" if results and not consistent else "unconfirmed" if results else "harness_not_feasible"
    record = dict(results[-1]) if results else {
        "schemaVersion": 1, "sampleId": "smartbugs-dos-auction", "sourceSha256": EXPECTED_SHA256,
        "confirmedVulnerability": False,
    }
    record.update({"state": state, "confirmedVulnerability": confirmed, "runs": results,
                   "runCount": len(results), "consistent": consistent, "failures": failures,
                   "sourceSha256": EXPECTED_SHA256, "harnessSha256": digest(HARNESS.read_bytes()),
                   "compilerArtifactSha256": compiler_sha, "laneId": "D1-dos-auction",
                   "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "toolVersions": {"runner": HARNESS.name, "solc": compiler_info.get("version", "0.4.26"),
                                    "runs": str(runs)}, "manifestMergeDeferred": True})
    evidence_path = EVIDENCE / f"{EXPECTED_SHA256}.dynamic-auction-smartbugs.json"
    atomic_json(evidence_path, record)
    evidence_sha = digest(evidence_path.read_bytes())
    analysis = dict(row.get("analysis", {}))
    analysis.update({"dynamic": "passed" if confirmed else state,
                     "dynamicReason": "source_bound_three_run_victim_impact_confirmed" if confirmed else state,
                     "dynamicEvidence": str(evidence_path.relative_to(ROOT)),
                     "dynamicEvidenceSha256": evidence_sha,
                     "dynamicHarnessSha256": record["harnessSha256"],
                     "confirmedVulnerability": confirmed})
    shard_path = write_shard(row, "dynamic", analysis, lane_id="D1-dos-auction",
                             tool_versions={"runner": HARNESS.name, "solc": str(compiler_info.get("version", "0.4.26")),
                                            "runs": str(runs)})
    record["evidencePath"] = str(evidence_path.relative_to(ROOT))
    record["evidenceSha256"] = evidence_sha
    record["shardPath"] = str(shard_path.relative_to(ROOT))
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    result = run_sample(args.timeout, args.runs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["state"] in {"confirmed", "unconfirmed", "harness_not_feasible", "flaky"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
