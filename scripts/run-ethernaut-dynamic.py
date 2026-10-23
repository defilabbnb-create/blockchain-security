#!/usr/bin/env python3
"""Run the pinned Ethernaut subset with exact solc-js versions and local evidence."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "training-data" / "ethernaut"
MANIFEST = CORPUS / "manifest.json"
RUNNER = ROOT / "scripts" / "ethernaut-dynamic-runner.cjs"
COMPILER_VERSION = "0.8.29"
ALLOWED = {"fallback", "telephone", "coinflip", "force", "king"}


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def compiler() -> tuple[Path, dict]:
    spec = importlib.util.spec_from_file_location("review_static_compiler_ethernaut", ROOT / "scripts" / "review-static.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    path, metadata = module.compiler(COMPILER_VERSION)
    if metadata.get("version") != COMPILER_VERSION:
        raise ValueError("exact_solidity_0_8_29_not_selected")
    return path, metadata


def read_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("dataset") != "ethernaut" or manifest.get("commit") != "c6174bb3b68dde01ff15571e67ad5254cc6939a9":
        raise ValueError("ethernaut_manifest_is_not_pinned_commit")
    return manifest


def run_one(sample: dict, compiler_path: Path, compiler_metadata: dict, timeout: float) -> dict:
    challenge = sample.get("challenge")
    if challenge not in ALLOWED:
        raise ValueError("challenge_not_allowlisted")
    env = os.environ.copy()
    env.update({
        "CAMPAIGN_PROJECT_ROOT": str(ROOT),
        "CAMPAIGN_SOLJSON": str(compiler_path.resolve()),
        "ETHERNAUT_COMPILER_VERSION": compiler_metadata.get("longVersion") or COMPILER_VERSION,
        "ETHERNAUT_COMPILER_SHA256": compiler_metadata["sha256"],
        "DYNAMIC_EXECUTION_MODE": "isolated_in_process",
    })
    command = ["node", str(RUNNER), challenge]
    try:
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                                   timeout=timeout, check=False)
        lines = [line for line in completed.stdout.splitlines() if line.strip().startswith("{")]
        result = json.loads(lines[-1]) if lines else {}
        diagnostics = (completed.stdout + completed.stderr)[-16000:]
        confirmed = (completed.returncode == 0 and result.get("state") == "confirmed"
                     and result.get("confirmedVulnerability") is True
                     and result.get("executionBoundary", {}).get("mode") == "isolated_in_process"
                     and result.get("executionBoundary", {}).get("chainId") == 31337
                     and result.get("compilerArtifact", {}).get("sha256") == compiler_metadata.get("sha256"))
        return {**result, "challenge": challenge,
                "state": "confirmed" if confirmed else "failed",
                "confirmedVulnerability": confirmed,
                "runnerExitCode": completed.returncode,
                "runnerOutputSha256": sha256(diagnostics.encode("utf-8", errors="replace")),
                "diagnostic": None if confirmed else diagnostics or "runner_produced_no_output",
                "compilerArtifact": compiler_metadata}
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        diagnostic = ""
        if isinstance(error, subprocess.TimeoutExpired):
            output = error.stdout or ""
            stderr = error.stderr or ""
            diagnostic = (output.decode(errors="replace") if isinstance(output, bytes) else output)
            diagnostic += (stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr)
        return {"challenge": challenge, "state": "timeout" if isinstance(error, subprocess.TimeoutExpired) else "failed",
                "confirmedVulnerability": False, "reason": "dynamic_runner_timeout" if isinstance(error, subprocess.TimeoutExpired) else "runner_invalid_json",
                "runnerOutputSha256": sha256(diagnostic.encode("utf-8", errors="replace")),
                "diagnostic": diagnostic[-16000:], "compilerArtifact": compiler_metadata}


def run(*, challenges: list[str] | None = None, workers: int = 3, timeout: float = 180.0) -> dict:
    selected = list(challenges or sorted(ALLOWED))
    if not selected or len(set(selected)) != len(selected) or any(item not in ALLOWED for item in selected):
        raise ValueError("challenges_must_be_a_unique_nonempty_allowlist_subset")
    if isinstance(workers, bool) or not 1 <= workers <= len(selected):
        raise ValueError("workers_must_be_between_1_and_selected_count")
    if timeout <= 0:
        raise ValueError("timeout_must_be_positive")
    manifest = read_manifest()
    samples = {row.get("challenge"): row for row in manifest.get("samples", [])}
    if any(challenge not in samples for challenge in selected):
        raise ValueError("requested_challenge_missing_from_manifest")
    try:
        compiler_path, compiler_metadata = compiler()
    except Exception as error:
        compiler_path = None
        compiler_metadata = {"version": COMPILER_VERSION, "state": "unavailable",
                             "reason": f"{type(error).__name__}:{str(error)[:240]}"}
    if compiler_path is None:
        results = [{"challenge": challenge, "state": "unavailable", "confirmedVulnerability": False,
                    "reason": "exact_compiler_unavailable", "compilerArtifact": compiler_metadata}
                   for challenge in selected]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(selected)), thread_name_prefix="ethernaut-dynamic") as pool:
            futures = {pool.submit(run_one, samples[challenge], compiler_path, compiler_metadata, timeout): challenge for challenge in selected}
            results = [future.result() for future in as_completed(futures)]
    results.sort(key=lambda row: row["challenge"])

    evidence_root = CORPUS / "dynamic-evidence"
    generated = datetime.now(timezone.utc).isoformat()
    for result in results:
        challenge = result["challenge"]
        result["generatedAt"] = generated
        result["sourceCommit"] = manifest["commit"]
        result["sourceBundleSha256"] = samples[challenge].get("sourceBundleSha256")
        evidence_path = evidence_root / f"{challenge}.json"
        atomic_json(evidence_path, result)
        sample = samples[challenge]
        sample["dynamicState"] = "confirmed" if result["confirmedVulnerability"] else result["state"]
        sample["dynamicEvidence"] = str(evidence_path.relative_to(ROOT))
        sample["dynamicEvidenceSha256"] = sha256(evidence_path.read_bytes())
        sample["dynamicEvidenceGeneratedAt"] = generated
        sample["confirmedVulnerability"] = result["confirmedVulnerability"]
        sample["dynamicNotRunReason"] = None
        if result["confirmedVulnerability"]:
            sample.pop("dynamicFailureReason", None)
        else:
            sample["dynamicFailureReason"] = result.get("reason") or result.get("diagnostic") or result["state"]
    manifest["dynamicGeneratedAt"] = generated
    manifest["dynamicWorkers"] = min(workers, len(selected))
    manifest["dynamicSummary"] = {"requested": len(results), "confirmed": sum(row["confirmedVulnerability"] for row in results),
                                   "failed": sum(row["state"] == "failed" for row in results),
                                   "unavailable": sum(row["state"] == "unavailable" for row in results),
                                   "timeout": sum(row["state"] == "timeout" for row in results),
                                   "executionMode": "isolated_in_process", "compilerVersion": compiler_metadata.get("longVersion") or COMPILER_VERSION}
    atomic_json(MANIFEST, manifest)
    return {"manifest": str(MANIFEST), "results": results, "summary": manifest["dynamicSummary"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", action="append", choices=sorted(ALLOWED), dest="challenges")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=180.0)
    args = parser.parse_args(argv)
    try:
        result = run(challenges=args.challenges, workers=args.workers, timeout=args.timeout)
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as error:
        print(json.dumps({"state": "failed", "reason": f"{type(error).__name__}:{str(error)[:240]}"}, ensure_ascii=False))
        return 2
    print(json.dumps({"manifest": result["manifest"], "summary": result["summary"],
                      "results": [{"challenge": row["challenge"], "state": row["state"],
                                   "confirmedVulnerability": row["confirmedVulnerability"], "reason": row.get("reason")} for row in result["results"]]}, ensure_ascii=False))
    return 0 if result["summary"]["confirmed"] == result["summary"]["requested"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
