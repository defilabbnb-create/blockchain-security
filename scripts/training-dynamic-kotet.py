#!/usr/bin/env python3
"""Run the source-bound King of the Ether Throne unchecked-send harness three times."""
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
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
HARNESS = ROOT / "scripts/training-dynamic-kotet.cjs"
SAMPLE = (
    "crytic/not-so-smart-contracts", "020dbdbde3e0c2e8de5f3944e7455e438b0995d5",
    "unchecked_external_call/KotET_source_code/KingOfTheEtherThrone.sol",
)
EXPECTED_SHA256 = "f2aca13163e64595c86b30cda54a52b1b970fc75e9b38ccba0218ffc316b6619"

sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard


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


def classify_runs(results: list[dict], failures: list[str]) -> tuple[str, bool, bool]:
    if len(results) < 3:
        return ("harness_not_feasible", False, True) if not results else ("flaky", False, False)

    def signature(result: dict) -> str:
        return json.dumps({key: result.get(key) for key in
                           ("sourceSha256", "state", "confirmedVulnerability", "vulnerability",
                            "scenarios", "assertions", "reason")}, sort_keys=True, separators=(",", ":"))

    consistent = len({signature(row) for row in results}) == 1 and not failures
    if not consistent:
        return "flaky", False, False
    if all(row.get("state") == "harness_not_feasible" for row in results):
        return "harness_not_feasible", False, True
    confirmed = all(row.get("sourceSha256") == EXPECTED_SHA256 and row.get("state") == "confirmed"
                    and row.get("confirmedVulnerability") is True and row.get("runnerExitCode") == 0
                    for row in results)
    return ("confirmed" if confirmed else "unconfirmed"), confirmed, True


def run_sample(timeout: float = 180) -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next((sample for sample in manifest.get("samples", [])
                if (sample.get("repo"), sample.get("commit"), sample.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_sample_manifest_hash_mismatch")
    source = (ROOT / row["objectPath"]).resolve()
    if not source.is_relative_to(ROOT.resolve()) or digest(source.read_bytes()) != EXPECTED_SHA256:
        raise ValueError("training_sample_object_hash_mismatch")
    spec = importlib.util.spec_from_file_location("review_static", ROOT / "scripts/review-static.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    compiler, compiler_metadata = module.compiler("0.4.26")
    environment = {**os.environ, "CAMPAIGN_SOLJSON": str(compiler),
                   "BENCHMARK_SOLC_VERSION": "0.4.26",
                   "BENCHMARK_SOLC_SHA256": str(compiler_metadata["sha256"]),
                   "TRAINING_SOURCE_SHA256": EXPECTED_SHA256,
                   "PYTHONDONTWRITEBYTECODE": "1"}
    results: list[dict] = []
    diagnostics: list[str] = []
    for index in range(3):
        try:
            process = subprocess.run(["node", str(HARNESS), str(source)], cwd=ROOT, env=environment,
                                     capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            diagnostics.append(f"run_{index + 1}:timeout:{error}")
            continue
        rows = [line for line in process.stdout.splitlines() if line.lstrip().startswith("{")]
        if not rows:
            diagnostics.append(f"run_{index + 1}:exit_{process.returncode}:"
                               f"{(process.stdout + process.stderr)[-2000:]}")
            continue
        try:
            result = json.loads(rows[-1])
        except json.JSONDecodeError as error:
            diagnostics.append(f"run_{index + 1}:json:{error}")
            continue
        result["runIndex"] = index + 1
        result["runnerExitCode"] = process.returncode
        results.append(result)
    state, confirmed, consistent = classify_runs(results, diagnostics)
    record = dict(results[0]) if results else {
        "schemaVersion": 1, "sampleId": "crytic-kotet-unchecked-compensation",
        "vulnerability": "unchecked_compensation_send_with_state_advance",
    }
    record.update({"state": state, "confirmedVulnerability": confirmed,
                   "runCount": len(results), "consistent": consistent,
                   "runs": results, "diagnostics": diagnostics,
                   "sourceSha256": EXPECTED_SHA256,
                   "harnessSha256": digest(HARNESS.read_bytes()),
                   "reason": record.get("reason") or (diagnostics[-1] if diagnostics else None),
                   "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "laneId": "F-training-kotet", "toolVersions": {
                       "runner": "training-dynamic-kotet.cjs", "solc": "0.4.26", "runs": "3"}})
    evidence = EVIDENCE / f"{EXPECTED_SHA256}.dynamic-kotet.json"
    atomic_json(evidence, record)
    analysis = {
        "dynamic": "passed" if confirmed else state,
        "dynamicReason": "source_bound_three_run_unchecked_send_impact_confirmed" if confirmed
        else (record.get("reason") or "kotet_unchecked_send_assertions_unconfirmed"),
        "dynamicEvidence": str(evidence.relative_to(ROOT)),
        "dynamicEvidenceSha256": digest(evidence.read_bytes()),
        "dynamicHarness": str(HARNESS.relative_to(ROOT)),
        "dynamicHarnessSha256": record["harnessSha256"],
        "confirmedVulnerability": confirmed,
    }
    write_shard(row, "dynamic", analysis, lane_id="F-training-kotet",
                tool_versions={"runner": "training-dynamic-kotet.cjs", "solc": "0.4.26", "runs": "3"})
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=60)
    return record


def main() -> int:
    result = run_sample()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("state") in {"confirmed", "unconfirmed", "harness_not_feasible", "flaky"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
