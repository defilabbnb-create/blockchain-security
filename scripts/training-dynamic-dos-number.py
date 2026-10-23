#!/usr/bin/env python3
"""Run a three-repeat, source-bound local DoS impact check for DosNumber."""
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
HARNESS = ROOT / "scripts/training-dynamic-dos-number.cjs"
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
SAMPLE = ("smartbugs/smartbugs-curated", "230e649123477eff332742a59a1c7cc6dc286cab",
          "dataset/denial_of_service/dos_number.sol")
EXPECTED_SHA256 = "3ea414a7d2826634670730c75f983ee8cefc26a6a34fdda57844c0e897d362b0"

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


def load_compiler():
    spec = importlib.util.spec_from_file_location("review_static", ROOT / "scripts/review-static.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.compiler("0.4.25")


def run_once(source_path: Path, compiler_path: Path, compiler_meta: dict, timeout: float, run_index: int) -> dict:
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(compiler_path),
           "BENCHMARK_SOLC_VERSION": "0.4.25", "BENCHMARK_SOLC_SHA256": compiler_meta["sha256"],
           "TRAINING_SOURCE_SHA256": EXPECTED_SHA256, "PYTHONDONTWRITEBYTECODE": "1"}
    completed = subprocess.run(["node", str(HARNESS), str(source_path)], cwd=ROOT,
                               capture_output=True, text=True, timeout=timeout, check=False, env=env)
    rows = [line for line in completed.stdout.splitlines() if line.lstrip().startswith("{")]
    if not rows:
        raise RuntimeError(f"training_dos_number_harness_failed:{(completed.stdout + completed.stderr)[-2400:]}")
    result = json.loads(rows[-1])
    if result.get("sourceSha256") != EXPECTED_SHA256:
        raise RuntimeError("training_dos_number_evidence_hash_mismatch")
    if result.get("compilerVersion", "").split("+", 1)[0] != "0.4.25":
        raise RuntimeError("training_dos_number_compiler_version_mismatch")
    if result.get("compilerArtifactSha256", "").removeprefix("0x") != compiler_meta["sha256"].removeprefix("0x"):
        raise RuntimeError("training_dos_number_compiler_hash_mismatch")
    if completed.returncode != 0:
        raise RuntimeError(f"training_dos_number_runner_exit_{completed.returncode}")
    result["runIndex"] = run_index
    result["runnerExitCode"] = completed.returncode
    result["diagnosticSha256"] = digest((completed.stdout + completed.stderr).encode("utf-8", errors="replace"))
    return result


def signature(result: dict) -> str:
    observations = result.get("observations", {})
    return json.dumps({
        "state": result.get("state"),
        "confirmedVulnerability": result.get("confirmedVulnerability"),
        "impactDemonstrated": result.get("impactDemonstrated"),
        "sourceSha256": result.get("sourceSha256"),
        "blockGasLimit": result.get("blockGasLimit"),
        "population": result.get("population"),
        "clearDOSStatus": observations.get("clearDOS", {}).get("status"),
        "lengthAfterClearDOS": observations.get("logicalLengthAfterClearDOS"),
        "clearStatus": observations.get("clear", {}).get("status"),
        "lengthAfterClear": observations.get("logicalLengthAfterClear"),
        "insertAfterClearStatus": observations.get("insertAfterClear", {}).get("status"),
        "lengthAfterFollowupInsert": observations.get("logicalLengthAfterFollowupInsert"),
        "assertions": result.get("assertions"),
        "reason": result.get("reason"),
    }, sort_keys=True, separators=(",", ":"))


def classify_runs(results: list[dict]) -> tuple[str, bool, bool]:
    if len(results) < 3:
        return ("harness_not_feasible", False, True) if not results else ("flaky", False, False)
    consistent = len({signature(result) for result in results}) == 1
    if not consistent:
        return "flaky", False, False
    confirmed = all(result.get("state") == "confirmed"
                    and result.get("confirmedVulnerability") is True
                    and result.get("impactDemonstrated") is True
                    and result.get("sourceSha256") == EXPECTED_SHA256
                    and result.get("runnerExitCode") == 0
                    and all(assertion.get("passed") is True for assertion in result.get("assertions", []))
                    and bool(result.get("assertions")) for result in results)
    return ("confirmed" if confirmed else "unconfirmed"), confirmed, True


def run_sample(timeout: float = 180, runs: int = 3) -> dict:
    if runs != 3:
        raise ValueError("training_dos_number_harness_requires_three_runs")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next((item for item in manifest.get("samples", [])
                if (item.get("repo"), item.get("commit"), item.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_dos_number_manifest_hash_mismatch")
    source_path = (ROOT / row["objectPath"]).resolve()
    if not source_path.is_relative_to(ROOT.resolve()) or digest(source_path.read_bytes()) != EXPECTED_SHA256:
        raise ValueError("training_dos_number_object_hash_mismatch")

    compiler_path, compiler_meta = load_compiler()
    results = [run_once(source_path, compiler_path, compiler_meta, timeout, index + 1)
               for index in range(runs)]
    state, confirmed, consistent = classify_runs(results)
    record = dict(results[0])
    record.update({"state": state, "confirmedVulnerability": confirmed, "runCount": len(results),
                   "consistent": consistent, "runs": results,
                   "reason": None if confirmed else results[0].get("reason", "three_run_result_inconsistent"),
                   "compilerArtifact": compiler_meta, "harnessSha256": digest(HARNESS.read_bytes()),
                   "laneId": "F-training-dos-number",
                   "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "toolVersions": {"runner": HARNESS.name, "solc": "0.4.25", "runs": "3"}})
    evidence_path = EVIDENCE / f"{EXPECTED_SHA256}.dynamic-dos-number.json"
    atomic_json(evidence_path, record)
    analysis = {
        "dynamic": state,
        "dynamicReason": "source_bound_three_run_local_poc_confirmed" if confirmed else record["reason"],
        "dynamicEvidence": str(evidence_path.relative_to(ROOT)),
        "dynamicEvidenceSha256": digest(evidence_path.read_bytes()),
        "dynamicHarness": str(HARNESS.relative_to(ROOT)),
        "dynamicHarnessSha256": record["harnessSha256"],
        "confirmedVulnerability": confirmed,
    }
    write_shard(row, "dynamic", analysis, lane_id="F-training-dos-number",
                tool_versions={"runner": HARNESS.name, "solc": "0.4.25", "runs": "3"})
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=90)
    return record


def main() -> int:
    result = run_sample()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("state") in {"confirmed", "unconfirmed", "flaky"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
