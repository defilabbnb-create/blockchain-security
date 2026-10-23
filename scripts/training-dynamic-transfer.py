#!/usr/bin/env python3
"""Run a three-pass source-bound false-return transferFrom training PoC."""
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
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
HARNESS = ROOT / "scripts/training-dynamic-unchecked-transfer.cjs"
SAMPLE = ("smartbugs/smartbugs-curated", "230e649123477eff332742a59a1c7cc6dc286cab",
          "dataset/unchecked_low_level_calls/0x2972d548497286d18e92b5fa1f8f9139e5653fd2.sol")
EXPECTED_SHA256 = "b9c32c34e06c5b84561b827738b0f4d4fe60d4292516714f6a08cbc8925ccac0"

sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def compiler_loader():
    spec = importlib.util.spec_from_file_location("review_static", ROOT / "scripts/review-static.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def proof_signature(result: dict) -> str:
    keys = ("state", "confirmedVulnerability", "sourceSha256", "falseReturn", "successfulControl", "assertions")
    return json.dumps({key: result.get(key) for key in keys}, sort_keys=True, separators=(",", ":"))


def classify_runs(results: list[dict], failures: list[str], runs: int = 3) -> tuple[str, bool, bool]:
    if len(results) < runs:
        return ("harness_not_feasible", False, True) if not results else ("flaky", False, False)
    consistent = len({proof_signature(result) for result in results}) == 1 and not failures
    if not consistent:
        return "flaky", False, False
    confirmed = all(result.get("state") == "confirmed"
                    and result.get("confirmedVulnerability") is True
                    and result.get("sourceSha256") == EXPECTED_SHA256
                    and result.get("runnerExitCode") == 0 for result in results)
    return ("confirmed" if confirmed else "unconfirmed"), confirmed, True


def run_sample(timeout: float = 120, runs: int = 3) -> dict:
    if runs != 3:
        raise ValueError("unchecked_transfer_harness_requires_three_runs")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next((item for item in manifest.get("samples", [])
                if (item.get("repo"), item.get("commit"), item.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_sample_manifest_hash_mismatch")
    source_path = (ROOT / row["objectPath"]).resolve()
    if not source_path.is_relative_to(ROOT.resolve()) or digest(source_path.read_bytes()) != EXPECTED_SHA256:
        raise ValueError("training_sample_object_hash_mismatch")
    compiler, compiler_metadata = compiler_loader().compiler("0.4.26")
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(compiler), "BENCHMARK_SOLC_VERSION": "0.4.26",
           "BENCHMARK_SOLC_SHA256": compiler_metadata["sha256"],
           "TRAINING_SOURCE_SHA256": EXPECTED_SHA256}
    results, failures, diagnostic_hashes = [], [], []
    for run_index in range(1, runs + 1):
        try:
            completed = subprocess.run(["node", str(HARNESS), str(source_path)], cwd=ROOT,
                                       capture_output=True, text=True, timeout=timeout, check=False, env=env)
        except subprocess.TimeoutExpired as error:
            failures.append(f"run_{run_index}:timeout:{error}")
            continue
        diagnostic = (completed.stdout + completed.stderr).encode("utf-8", errors="replace")
        diagnostic_hashes.append(digest(diagnostic))
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip().startswith("{")]
        if not rows:
            failures.append(f"run_{run_index}:runner_exit_{completed.returncode}:"
                            f"{diagnostic.decode('utf-8', errors='replace')[-1800:]}")
            continue
        result = rows[-1]
        if result.get("sourceSha256") != EXPECTED_SHA256:
            raise RuntimeError("training_harness_evidence_binding_mismatch")
        if result.get("compilerVersion", "").split("+", 1)[0] != "0.4.26":
            raise RuntimeError("training_harness_compiler_version_mismatch")
        result.update(runIndex=run_index, runnerExitCode=completed.returncode)
        results.append(result)

    state, confirmed, consistent = classify_runs(results, failures, runs)
    result = dict(results[0]) if results else {"schemaVersion": 1, "sampleId": "smartbugs-unchecked-transfer-demo"}
    result.update({"state": state, "confirmedVulnerability": confirmed, "consistent": consistent,
                   "runCount": len(results), "runs": results, "runnerFailures": failures,
                   "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "compilerArtifact": compiler_metadata,
                   "harnessSha256": digest(HARNESS.read_bytes()),
                   "diagnosticSha256": digest("".join(diagnostic_hashes).encode()) if diagnostic_hashes else None,
                   "laneId": "D-unchecked-transfer", "toolVersions": {
                       "runner": "training-dynamic-unchecked-transfer.cjs", "runs": str(runs),
                       "solc": "0.4.26", "node": subprocess.run(
                           ["node", "--version"], capture_output=True, text=True, check=True).stdout.strip()}})
    result["sourceSha256"] = EXPECTED_SHA256
    evidence_path = EVIDENCE / f"{EXPECTED_SHA256}.dynamic-transfer.json"
    atomic_json(evidence_path, result)
    analysis = {
        "dynamic": "passed" if confirmed else state,
        "dynamicReason": "source_bound_three_run_local_poc_confirmed" if confirmed else (
            "three_run_behavior_consistent_but_not_confirmed" if consistent and results else state),
        "dynamicEvidence": str(evidence_path.relative_to(ROOT)),
        "dynamicEvidenceSha256": digest(evidence_path.read_bytes()),
        "dynamicHarness": str(HARNESS.relative_to(ROOT)),
        "dynamicHarnessSha256": result["harnessSha256"],
        "confirmedVulnerability": confirmed,
    }
    write_shard(row, "dynamic", analysis, lane_id="D-unchecked-transfer", tool_versions=result["toolVersions"])
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=60)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    result = run_sample(args.timeout, args.runs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("state") in {"confirmed", "unconfirmed", "harness_not_feasible", "flaky"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
