#!/usr/bin/env python3
"""Run the source-bound DosAuction push-refund PoC three times in isolation."""
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
HARNESS = ROOT / "scripts/training-dynamic-auction.cjs"
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
SAMPLE = (
    "crytic/not-so-smart-contracts",
    "020dbdbde3e0c2e8de5f3944e7455e438b0995d5",
    "denial_of_service/auction.sol",
)
EXPECTED_SHA256 = "ba00c0f265d3830ea62584ae293b3f89224201a801968723d240703179fab86e"

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


def classify_runs(results: list[dict], failures: list[str], runs: int, expected_sha256: str) -> tuple[str, bool, bool]:
    """Return (state, confirmed, consistent) without mistaking runner failure for a PoC result."""
    if len(results) < runs:
        if not results:
            return "harness_not_feasible", False, True
        return "flaky", False, False
    def signature(result: dict) -> str:
        # Contract addresses and transaction hashes vary with deployment nonce; compare
        # the observed state/asset effects and each run's internal identity assertions.
        vulnerable = result.get("vulnerableAuction") or {}
        secure = result.get("secureControl") or {}
        normalized = {
            "confirmedVulnerability": result.get("confirmedVulnerability"),
            "state": result.get("state"), "vulnerability": result.get("vulnerability"),
            "checkedReverted": result.get("checkedReverted"),
            "transactionStatus": result.get("transactionStatus"),
            "runnerExitCode": result.get("runnerExitCode"),
            "sourceSha256": result.get("sourceSha256"),
            "vulnerableEffects": {key: vulnerable.get(key) for key in
                                  ("bidBeforeWei", "bidAfterWei", "balanceBeforeWei", "balanceAfterWei")},
            "secureEffects": {key: secure.get(key) for key in
                              ("bidAfterWei", "balanceAfterWei", "rejectingBidderRefundCreditWei")},
            "assertions": result.get("assertions"),
        }
        return json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    signatures = [signature(result) for result in results]
    consistent = len(set(signatures)) == 1 and not failures
    if not consistent:
        return "flaky", False, False
    confirmed = all(result.get("confirmedVulnerability") is True
                    and result.get("state") == "confirmed"
                    and result.get("sourceSha256") == expected_sha256
                    and result.get("runnerExitCode") == 0 for result in results)
    return ("confirmed" if confirmed else "unconfirmed"), confirmed, True


def run_sample(sample_id: str, timeout: float = 120, runs: int = 3) -> dict:
    if sample_id != "dos-auction":
        raise ValueError("unsupported_training_dynamic_sample")
    if runs != 3:
        raise ValueError("training_harness_requires_three_runs")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next((item for item in manifest.get("samples", [])
                if (item.get("repo"), item.get("commit"), item.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_sample_manifest_hash_mismatch")
    source_path = ROOT / row["objectPath"]
    source_bytes = source_path.read_bytes()
    if digest(source_bytes) != EXPECTED_SHA256:
        raise ValueError("training_sample_object_hash_mismatch")
    compiler = compiler_loader()
    soljson, compiler_info = compiler.compiler("0.4.26")
    compiler_sha = str(compiler_info.get("sha256", ""))
    if compiler_info.get("version") and not str(compiler_info["version"]).startswith("0.4.26"):
        raise ValueError("training_compiler_version_mismatch")
    environment = {
        **os.environ,
        "CAMPAIGN_SOLJSON": str(soljson),
        "BENCHMARK_SOLC_VERSION": "0.4.26",
        "BENCHMARK_SOLC_SHA256": compiler_sha,
        "TRAINING_SOURCE_SHA256": EXPECTED_SHA256,
    }
    results: list[dict] = []
    diagnostics: list[str] = []
    for index in range(runs):
        try:
            completed = subprocess.run(
                ["node", str(HARNESS), str(source_path)], cwd=ROOT,
                capture_output=True, text=True, timeout=timeout, check=False, env=environment,
            )
        except subprocess.TimeoutExpired as error:
            diagnostics.append(f"run_{index + 1}:timeout:{error}")
            continue
        lines = [line for line in completed.stdout.splitlines() if line.lstrip().startswith("{")]
        if not lines:
            diagnostics.append(f"run_{index + 1}:exit_{completed.returncode}:"
                               f"{(completed.stdout + completed.stderr)[-1600:]}")
            continue
        try:
            result = json.loads(lines[-1])
        except json.JSONDecodeError as error:
            diagnostics.append(f"run_{index + 1}:json:{error}")
            continue
        result["runIndex"] = index + 1
        result["runnerExitCode"] = completed.returncode
        results.append(result)

    state, confirmed, consistent = classify_runs(results, diagnostics, runs, EXPECTED_SHA256)
    if confirmed:
        record = dict(results[0])
        record["state"] = "confirmed"
        record["confirmedVulnerability"] = True
        record["runCount"] = runs
        record["consistent"] = True
        record["runs"] = results
        record["reason"] = None
    elif state == "flaky":
        record = {
            "schemaVersion": 1, "sampleId": "crytic-dos-auction", "state": "flaky",
            "confirmedVulnerability": False, "vulnerability": "denial_of_service_push_refund",
            "sourceSha256": EXPECTED_SHA256, "runCount": len(results), "consistent": False,
            "runs": results, "reason": "three_run_result_inconsistent", "diagnostic": diagnostics,
        }
    else:
        record = dict(results[-1]) if results else {
            "schemaVersion": 1, "sampleId": "crytic-dos-auction",
            "vulnerability": "denial_of_service_push_refund",
        }
        record.update({"state": state,
                       "confirmedVulnerability": False, "sourceSha256": EXPECTED_SHA256,
                       "runCount": len(results), "consistent": True, "runs": results,
                       "reason": ";".join(diagnostics) or "dynamic_assertion_failed"})
    record["harnessSha256"] = digest(HARNESS.read_bytes())
    record["compilerArtifactSha256"] = compiler_sha
    record.update({"sourceSha256": EXPECTED_SHA256, "laneId": "D-training-auction",
                   "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "toolVersions": {"runner": "training-dynamic-auction.cjs", "solc": "0.4.26", "runs": "3"}})
    evidence_path = EVIDENCE / f"{EXPECTED_SHA256}.dynamic-auction.json"
    atomic_json(evidence_path, record)
    analysis = row.setdefault("analysis", {})
    state = record["state"]
    analysis["dynamic"] = "passed" if confirmed else state
    analysis["dynamicReason"] = "source_bound_three_run_local_poc_confirmed" if confirmed else record.get("reason")
    analysis["dynamicEvidence"] = str(evidence_path.relative_to(ROOT))
    analysis["dynamicEvidenceSha256"] = digest(evidence_path.read_bytes())
    analysis["confirmedVulnerability"] = confirmed
    write_shard(row, "dynamic", analysis, lane_id="D-training-auction",
                tool_versions={"runner": "training-dynamic-auction.cjs", "solc": "0.4.26", "runs": "3"})
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=60)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, choices=("dos-auction",))
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    result = run_sample(args.sample, args.timeout, args.runs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("state") in {"confirmed", "unconfirmed", "harness_not_feasible", "flaky"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
