#!/usr/bin/env python3
"""Record whether the pinned list_dos source can be dynamically executed as collected."""
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
HARNESS = ROOT / "scripts/training-dynamic-listdos.cjs"
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
SAMPLE = ("crytic/not-so-smart-contracts", "020dbdbde3e0c2e8de5f3944e7455e438b0995d5",
          "denial_of_service/list_dos.sol")
EXPECTED_SHA256 = "34dcd7cbad1f1cb261b3310e60fe0e8e7447ffd7aef3639df06a45a3c9e414dc"
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
    return module.compiler("0.4.15")


def run_sample(timeout: float = 90) -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next((item for item in manifest.get("samples", [])
                if (item.get("repo"), item.get("commit"), item.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_sample_manifest_hash_mismatch")
    source_path = (ROOT / row["objectPath"]).resolve()
    if not source_path.is_relative_to(ROOT.resolve()) or digest(source_path.read_bytes()) != EXPECTED_SHA256:
        raise ValueError("training_sample_object_hash_mismatch")
    compiler, metadata = load_compiler()
    loader = ROOT / "flare-scan/tools/solc-0819/node_modules/solc"
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(compiler), "BENCHMARK_SOLC_VERSION": "0.4.15",
           "BENCHMARK_SOLC_SHA256": metadata["sha256"], "TRAINING_SOURCE_SHA256": EXPECTED_SHA256,
           "TRAINING_SOLC_LOADER": str(loader), "PYTHONDONTWRITEBYTECODE": "1"}
    completed = subprocess.run(["node", str(HARNESS), str(source_path)], cwd=ROOT,
                               capture_output=True, text=True, timeout=timeout, check=False, env=env)
    lines = [line for line in completed.stdout.splitlines() if line.strip().startswith("{")]
    if not lines:
        raise RuntimeError(f"training_harness_failed:{(completed.stdout + completed.stderr)[-2500:]}")
    result = json.loads(lines[-1])
    if result.get("sourceSha256") != EXPECTED_SHA256:
        raise RuntimeError("training_harness_evidence_binding_mismatch")
    if result.get("compilerVersion", "").split("+", 1)[0] != "0.4.15":
        raise RuntimeError("training_harness_compiler_version_mismatch")
    if completed.returncode not in (0, 1):
        raise RuntimeError(f"training_harness_execution_error:{completed.returncode}")
    raw = (completed.stdout + completed.stderr).encode("utf-8", errors="replace")
    result.update({"compilerArtifact": metadata, "harnessSha256": digest(HARNESS.read_bytes()),
                   "diagnosticSha256": digest(raw), "laneId": "E-training-listdos",
                   "generatedAt": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "toolVersions": {"runner": HARNESS.name, "solc": "0.4.15"}})
    evidence_path = EVIDENCE / f"{EXPECTED_SHA256}.dynamic-listdos.json"
    atomic_json(evidence_path, result)
    analysis = {"dynamic": result["state"], "dynamicReason": result["reason"],
                "dynamicEvidence": str(evidence_path.relative_to(ROOT)),
                "dynamicEvidenceSha256": digest(evidence_path.read_bytes()),
                "dynamicHarness": str(HARNESS.relative_to(ROOT)),
                "dynamicHarnessSha256": result["harnessSha256"], "confirmedVulnerability": False}
    write_shard(row, "dynamic", analysis, lane_id="E-training-listdos",
                tool_versions={"runner": HARNESS.name, "solc": result["compilerVersion"]})
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=60)
    return result


def main() -> int:
    result = run_sample()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("state") in {"harness_not_feasible", "unconfirmed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
