#!/usr/bin/env python3
"""Run a three-run, source-hash-bound Lotto unchecked-send harness."""
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
HARNESS = ROOT / "scripts/training-dynamic-lotto-unchecked-send.cjs"
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
SAMPLE = ("smartbugs/smartbugs-curated", "230e649123477eff332742a59a1c7cc6dc286cab",
          "dataset/unchecked_low_level_calls/etherpot_lotto.sol")
EXPECTED_SHA256 = "42df68b79df9483a424dc0ce1aba6fd2382b20339ca23a62e881c52a52575b2f"

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
    rejecting, accepting = result.get("rejectingWinner") or {}, result.get("acceptingControl") or {}
    normalized = {
        "state": result.get("state"), "confirmedVulnerability": result.get("confirmedVulnerability"),
        "sourceSha256": result.get("sourceSha256"), "selectedSubpot": result.get("selectedSubpot"),
        "prizeWei": result.get("prizeWei"), "reason": result.get("reason"),
        "assertions": result.get("assertions"),
        "rejecting": {key: rejecting.get(key) for key in
                      ("sendStatus", "isCashed", "potBeforeWei", "balanceBeforeWei", "balanceAfterWei",
                       "recipientBalanceAfterWei", "balanceAfterRetryWei")},
        "accepting": {key: accepting.get(key) for key in
                      ("sendStatus", "isCashed", "potBeforeWei", "balanceBeforeWei", "balanceAfterWei",
                       "recipientBalanceAfterWei", "receivedWei")},
    }
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def classify_runs(results: list[dict], failures: list[str], runs: int = 3) -> tuple[str, bool, bool]:
    if len(results) < runs:
        return ("harness_not_feasible", False, True) if not results else ("flaky", False, False)
    consistent = len({signature(result) for result in results}) == 1 and not failures
    if not consistent:
        return "flaky", False, False
    if all(result.get("state") == "harness_not_feasible" for result in results):
        return "harness_not_feasible", False, True
    confirmed = all(result.get("state") == "confirmed"
                    and result.get("confirmedVulnerability") is True
                    and result.get("sourceSha256") == EXPECTED_SHA256
                    and result.get("runnerExitCode") == 0 for result in results)
    return ("confirmed" if confirmed else "unconfirmed"), confirmed, True


def run_sample(timeout: float = 180, runs: int = 3) -> dict:
    if runs != 3:
        raise ValueError("lotto_harness_requires_three_runs")
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
    environment = {**os.environ, "CAMPAIGN_SOLJSON": str(soljson), "BENCHMARK_SOLC_VERSION": "0.4.26",
                   "BENCHMARK_SOLC_SHA256": compiler_sha, "TRAINING_SOURCE_SHA256": EXPECTED_SHA256}
    results, failures = [], []
    for index in range(runs):
        try:
            completed = subprocess.run(["node", str(HARNESS), str(source_path)], cwd=ROOT,
                                       capture_output=True, text=True, timeout=timeout, check=False,
                                       env=environment)
        except subprocess.TimeoutExpired:
            failures.append(f"run_{index + 1}:timeout")
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
    record = dict(results[0]) if results else {
        "schemaVersion": 1, "sampleId": "etherpot-lotto-unchecked-winner-send",
        "vulnerability": "unchecked_winner_payout_permanently_marks_subpot_cashed",
    }
    if state == "harness_not_feasible" and results:
        reason = results[0].get("reason") or "harness_not_feasible"
    else:
        reason = None if confirmed else ";".join(failures) or "three_run_assertion_not_confirmed"
    record.update({"state": state, "confirmedVulnerability": confirmed, "consistent": consistent,
                   "sourceSha256": EXPECTED_SHA256, "runCount": len(results), "runs": results,
                   "reason": reason,
                   "harnessSha256": digest(HARNESS.read_bytes()), "compilerArtifactSha256": compiler_sha,
                   "laneId": "D-training-lotto-unchecked-send",
                   "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "toolVersions": {"runner": HARNESS.name, "solc": "0.4.26", "runs": "3"}})
    evidence_path = EVIDENCE / f"{EXPECTED_SHA256}.dynamic-lotto-unchecked-send.json"
    atomic_json(evidence_path, record)
    analysis = {"dynamic": "passed" if confirmed else state,
                "dynamicReason": "source_bound_three_run_local_lost_payout_confirmed" if confirmed else record["reason"],
                "dynamicEvidence": str(evidence_path.relative_to(ROOT)),
                "dynamicEvidenceSha256": digest(evidence_path.read_bytes()),
                "dynamicHarness": str(HARNESS.relative_to(ROOT)),
                "dynamicHarnessSha256": record["harnessSha256"],
                "confirmedVulnerability": confirmed}
    write_shard(row, "dynamic", analysis, lane_id="D-training-lotto-unchecked-send",
                tool_versions=record["toolVersions"])
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=60)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    result = run_sample(args.timeout, args.runs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("state") in {"confirmed", "unconfirmed", "harness_not_feasible", "flaky"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
