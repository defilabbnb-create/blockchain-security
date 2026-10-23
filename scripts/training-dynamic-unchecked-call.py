#!/usr/bin/env python3
"""Run the source-bound unchecked-call withdrawal PoC without merging the corpus."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard

MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
EVIDENCE_DIR = ROOT / "training-data/github-vulnerabilities/evidence"
RUNNER = ROOT / "scripts/training-dynamic-unchecked-call.cjs"
IDENTITY = ("smartbugs/smartbugs-curated", "230e649123477eff332742a59a1c7cc6dc286cab",
            "dataset/unchecked_low_level_calls/0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol")
EXPECTED_SOURCE_SHA256 = "649cc3600798f83d8ed12f181472a4b95938996a001e72025e65b57606f3f969"
COMPILER_VERSION = "0.4.26"
COMPILER_SHA256 = "357adb49bb74c9eabaa034db28f96b4105def2b052c7795db8e30ad9a34cc551"
SHARD_DIR = ROOT / "work/corpus-shards/D3-unchecked-call"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    manifest_bytes_before = MANIFEST.read_bytes()
    manifest = json.loads(manifest_bytes_before)
    sample = next((row for row in manifest.get("samples", [])
                   if (row.get("repo"), row.get("commit"), row.get("path")) == IDENTITY), None)
    if sample is None or sample.get("sha256") != EXPECTED_SOURCE_SHA256:
        raise SystemExit("training_unchecked_call_manifest_identity_or_hash_mismatch")
    analysis = sample.get("analysis") if isinstance(sample.get("analysis"), dict) else {}
    if analysis.get("dynamic") != "not_run":
        raise SystemExit("training_unchecked_call_sample_is_no_longer_not_run")

    source_path = ROOT / sample["objectPath"]
    source_bytes = source_path.read_bytes()
    source_sha256 = sha256(source_bytes)
    if source_sha256 != EXPECTED_SOURCE_SHA256:
        raise SystemExit("training_unchecked_call_object_hash_mismatch")
    compiler_path = ROOT / "work/compiler-cache/soljson-v0.4.26+commit.4563c3fc.cjs"
    if not compiler_path.is_file() or sha256(compiler_path.read_bytes()) != COMPILER_SHA256:
        raise SystemExit("training_unchecked_call_compiler_cache_missing_or_hash_mismatch")

    env = {**os.environ, "CAMPAIGN_SOLJSON": str(compiler_path),
           "BENCHMARK_SOLC_VERSION": COMPILER_VERSION,
           "BENCHMARK_SOLC_SHA256": COMPILER_SHA256,
           "CORPUS_DEFER_MERGE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    command = ["node", str(RUNNER), str(source_path)]
    try:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                   timeout=120, check=False, env=env)
    except subprocess.TimeoutExpired as error:
        diagnostic = b"\n".join(value if isinstance(value, bytes) else str(value or "").encode()
                                   for value in (error.stdout, error.stderr))
        _write_failure_shard(sample, source_sha256, diagnostic, "harness_timeout")
        raise SystemExit("training_unchecked_call_harness_timeout") from error

    diagnostic = (completed.stdout + completed.stderr).encode("utf-8", errors="replace")
    rows = []
    for line in completed.stdout.splitlines():
        if line.strip().startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    result = rows[-1] if rows else {}
    if result.get("sourceSha256") != source_sha256 or result.get("compilerArtifactSha256") != COMPILER_SHA256:
        _write_failure_shard(sample, source_sha256, diagnostic, "evidence_binding_mismatch")
        raise SystemExit("training_unchecked_call_evidence_binding_mismatch")

    evidence_path = EVIDENCE_DIR / f"{EXPECTED_SOURCE_SHA256}.unchecked-call.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence = {**result, "harnessSha256": sha256(RUNNER.read_bytes()),
                "diagnosticSha256": sha256(diagnostic),
                "reproduceCommand": "python3 scripts/training-dynamic-unchecked-call.py"}
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    evidence_sha256 = sha256(evidence_path.read_bytes())

    dynamic_state = "passed" if completed.returncode == 0 and evidence.get("confirmedVulnerability") is True else "unconfirmed"
    patch = {"dynamic": dynamic_state,
             "dynamicReason": "unchecked_withdraw_failure_cleared_reachable_credit" if dynamic_state == "passed"
             else "unchecked_withdraw_impact_not_fully_observed",
             "dynamicEvidence": str(evidence_path.relative_to(ROOT)),
             "dynamicEvidenceSha256": evidence_sha256,
             "confirmedVulnerability": dynamic_state == "passed"}
    shard_path = write_shard(sample, "dynamic", patch, lane_id="D3-unchecked-call",
                             tool_versions={"runner": "training-dynamic-unchecked-call.py",
                                            "solc": COMPILER_VERSION,
                                            "solcSha256": COMPILER_SHA256},
                             shard_dir=SHARD_DIR)
    manifest_bytes_after = MANIFEST.read_bytes()
    if manifest_bytes_after != manifest_bytes_before:
        raise SystemExit("manifest_changed_during_deferred_dynamic_run")
    print(json.dumps({"state": dynamic_state, "confirmedVulnerability": dynamic_state == "passed",
                      "sourceSha256": source_sha256, "evidenceSha256": evidence_sha256,
                      "shard": str(shard_path.relative_to(ROOT)),
                      "manifestModified": False, "command": " ".join(command)}, ensure_ascii=False))
    return 0 if dynamic_state == "passed" else 1


def _write_failure_shard(sample: dict, source_sha256: str, diagnostic: bytes, reason: str) -> None:
    evidence_path = EVIDENCE_DIR / f"{EXPECTED_SOURCE_SHA256}.unchecked-call.failed.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    failure = {"schemaVersion": 1, "state": "failed", "reason": reason,
               "sampleId": "smartbugs-keepmyether-unchecked-call", "sourceSha256": source_sha256,
               "harnessSha256": sha256(RUNNER.read_bytes()), "diagnosticSha256": sha256(diagnostic),
               "diagnosticTail": diagnostic.decode("utf-8", errors="replace")[-4000:]}
    evidence_path.write_text(json.dumps(failure, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_shard(sample, "dynamic", {"dynamic": "failed", "dynamicReason": reason,
                                    "dynamicEvidence": str(evidence_path.relative_to(ROOT)),
                                    "dynamicEvidenceSha256": sha256(evidence_path.read_bytes()),
                                    "confirmedVulnerability": False},
                lane_id="D3-unchecked-call",
                tool_versions={"runner": "training-dynamic-unchecked-call.py", "solc": COMPILER_VERSION},
                shard_dir=SHARD_DIR)


if __name__ == "__main__":
    raise SystemExit(main())
