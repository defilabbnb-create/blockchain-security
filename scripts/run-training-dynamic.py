#!/usr/bin/env python3
"""Run an allowlisted, source-hash-bound dynamic harness for training samples."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard
MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
EVIDENCE = ROOT / "training-data/github-vulnerabilities/evidence"
HARNESS = ROOT / "scripts/training-dynamic-king.cjs"
SAMPLE = ("smartbugs/smartbugs-curated", "230e649123477eff332742a59a1c7cc6dc286cab",
          "dataset/unchecked_low_level_calls/king_of_the_ether_throne.sol")
EXPECTED_SHA256 = "3d70aaab853a28761bcf53f1342619ccf256361b26468c4645c87e78d008ace2"


def sha256(data: bytes) -> str:
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
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def run_sample(sample_id: str, timeout: float = 120) -> dict:
    if sample_id != "king-of-the-ether-throne":
        raise ValueError("unsupported_training_dynamic_sample")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next((item for item in manifest.get("samples", [])
                if (item.get("repo"), item.get("commit"), item.get("path")) == SAMPLE), None)
    if row is None or row.get("sha256") != EXPECTED_SHA256:
        raise ValueError("training_sample_manifest_hash_mismatch")
    source_path = ROOT / row["objectPath"]
    source_bytes = source_path.read_bytes()
    if sha256(source_bytes) != EXPECTED_SHA256:
        raise ValueError("training_sample_object_hash_mismatch")
    compiler_loader = importlib_compiler_loader()
    compiler, compiler_metadata = compiler_loader.compiler("0.4.26")
    command = ["node", str(HARNESS), str(source_path)]
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(compiler), "BENCHMARK_SOLC_VERSION": "0.4.26",
           "BENCHMARK_SOLC_SHA256": compiler_metadata["sha256"]}
    try:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                   timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("training_harness_timeout") from error
    diagnostic = (completed.stdout + completed.stderr).encode("utf-8", errors="replace")
    result_rows = [json.loads(line) for line in completed.stdout.splitlines() if line.strip().startswith("{")]
    if not result_rows:
        raise RuntimeError(f"training_harness_failed:{diagnostic.decode('utf-8', errors='replace')[-2000:]}")
    result = result_rows[-1]
    if result.get("sourceSha256") != EXPECTED_SHA256 or result.get("compilerVersion", "").split("+", 1)[0] != "0.4.26":
        raise RuntimeError("training_harness_evidence_binding_mismatch")
    if result.get("compilerArtifactSha256") not in (None, compiler_metadata["sha256"]):
        raise RuntimeError("training_harness_compiler_hash_mismatch")
    result.update(compilerArtifact=compiler_metadata, harnessSha256=sha256(HARNESS.read_bytes()),
                  evidenceSha256=sha256(diagnostic), status="passed" if result.get("confirmedVulnerability") else "unconfirmed")
    result_path = EVIDENCE / f"{EXPECTED_SHA256}.dynamic.json"
    atomic_json(result_path, result)
    analysis = row.setdefault("analysis", {})
    analysis["dynamic"] = "passed" if result.get("confirmedVulnerability") else "unconfirmed"
    analysis["dynamicReason"] = "source_bound_local_poc_confirmed" if result.get("confirmedVulnerability") else "source_bound_poc_unconfirmed"
    analysis["dynamicEvidence"] = str(result_path.relative_to(ROOT))
    analysis["dynamicEvidenceSha256"] = sha256(result_path.read_bytes())
    analysis["confirmedVulnerability"] = result.get("confirmedVulnerability") is True
    summary = manifest.setdefault("analysisSummary", {})
    summary["dynamicPassed"] = sum(item.get("analysis", {}).get("dynamic") == "passed" for item in manifest["samples"])
    summary["dynamicUnconfirmed"] = sum(item.get("analysis", {}).get("dynamic") == "unconfirmed" for item in manifest["samples"])
    summary["dynamicNotRun"] = sum(item.get("analysis", {}).get("dynamic") == "not_run" for item in manifest["samples"])
    write_shard(row, "dynamic", analysis, lane_id="0-training-dynamic",
                tool_versions={"solc": result.get("compilerVersion", "0.4.26")})
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=60)
    return result


def importlib_compiler_loader():
    import importlib.util
    spec = importlib.util.spec_from_file_location("review_static", ROOT / "scripts/review-static.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, choices=("king-of-the-ether-throne",))
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    result = run_sample(args.sample, args.timeout)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("confirmedVulnerability") else 1


if __name__ == "__main__":
    raise SystemExit(main())
