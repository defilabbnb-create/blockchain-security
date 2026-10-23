#!/usr/bin/env python3
"""Run and bind the reviewed SmartBugs reentrancy-bonus PoC."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard
MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
RESULT = ROOT / "training-data/github-vulnerabilities/evidence/reentrancy-bonus-poc.json"
RUNNER = ROOT / "scripts/training-reentrancy-bonus-runner.cjs"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    sample = next(row for row in manifest["samples"] if row.get("path") == "dataset/reentrancy/reentrancy_bonus.sol")
    source_path = ROOT / sample["objectPath"]
    source_sha = sha256(source_path)
    spec = importlib.util.spec_from_file_location("review_static", ROOT / "scripts/review-static.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    compiler, metadata = module.compiler("0.4.24")
    process = subprocess.run(["node", str(RUNNER), str(source_path)], cwd=ROOT, capture_output=True, text=True,
                             timeout=180, check=False, env={**os.environ, "CAMPAIGN_SOLJSON": str(compiler),
                                                             "BENCHMARK_SOLC_SHA256": metadata["sha256"],
                                                             "PYTHONDONTWRITEBYTECODE": "1"})
    rows = [json.loads(line) for line in process.stdout.splitlines() if line.strip().startswith("{")]
    row = rows[-1] if rows else {}
    raw = (process.stdout + process.stderr).encode("utf-8", errors="replace")
    result = {**row, "sourceSha256": source_sha, "compilerArtifact": metadata,
              "evidenceSha256": hashlib.sha256(raw).hexdigest(),
              "reproduceCommand": "python3 scripts/training-reentrancy-bonus.py"}
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    analysis = sample.setdefault("analysis", {})
    if result.get("confirmedVulnerability") is True and source_sha == sample.get("sha256"):
        analysis["dynamic"] = "passed"
        analysis["dynamicReason"] = "training_reentrancy_bonus_poc_confirmed"
        analysis["dynamicEvidence"] = str(RESULT.relative_to(ROOT))
        analysis["confirmedVulnerability"] = True
    else:
        analysis["dynamic"] = "failed"
        analysis["dynamicReason"] = result.get("reason") or "training_reentrancy_bonus_poc_failed"
        analysis["dynamicEvidence"] = str(RESULT.relative_to(ROOT))
    analysis["dynamicEvidenceSha256"] = sha256(RESULT)
    summary = manifest.setdefault("analysisSummary", {})
    summary["dynamicPassed"] = sum(item.get("analysis", {}).get("dynamic") == "passed" for item in manifest["samples"])
    summary["dynamicNotRun"] = sum(item.get("analysis", {}).get("dynamic") == "not_run" for item in manifest["samples"])
    summary["dynamicConfirmed"] = sum(item.get("analysis", {}).get("confirmedVulnerability") is True for item in manifest["samples"])
    write_shard(sample, "dynamic", analysis, lane_id="0-training-bonus",
                tool_versions={"solc": metadata.get("longVersion", "0.4.24")})
    subprocess.run([sys.executable, str(ROOT / "scripts/corpus_merge.py")], cwd=ROOT,
                   capture_output=True, text=True, check=True, timeout=60)
    print(json.dumps({"state": result.get("state"), "confirmedVulnerability": result.get("confirmedVulnerability"),
                      "sourceSha256": source_sha, "evidence": str(RESULT)}, ensure_ascii=False))
    return 0 if process.returncode == 0 and result.get("confirmedVulnerability") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
