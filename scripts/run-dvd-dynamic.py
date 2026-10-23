#!/usr/bin/env python3
"""Run pinned Damn Vulnerable DeFi PoCs on isolated local EVM instances."""
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
import tempfile

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "training-data" / "damn-vulnerable-defi"
MANIFEST = CORPUS / "manifest.json"
RUNNER = ROOT / "scripts" / "dvd-dynamic-runner.cjs"
ALLOWED = {"side-entrance", "naive-receiver", "truster"}
COMPILER_VERSION = "0.8.25"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _compiler():
    spec = importlib.util.spec_from_file_location("review_static_compiler", ROOT / "scripts" / "review-static.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.compiler(COMPILER_VERSION)


def _read_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("dataset") != "damn-vulnerable-defi" or manifest.get("commit") != "64fddf9f96de2782f8868898d68673acb295119c":
        raise ValueError("dvd_manifest_is_not_pinned_commit")
    return manifest


def _run_one(sample: dict, compiler_path: Path, compiler_metadata: dict, timeout: float) -> dict:
    challenge = sample.get("challenge")
    if challenge not in ALLOWED:
        raise ValueError("challenge_not_allowlisted")
    if sample.get("compilerPragmas") != ["=0.8.25"]:
        return {"challenge": challenge, "state": "unavailable", "confirmedVulnerability": False,
                "reason": "unexpected_compiler_pragma", "compilerPragmas": sample.get("compilerPragmas")}
    bundle = CORPUS / "bundles" / challenge
    if not bundle.is_dir():
        return {"challenge": challenge, "state": "unavailable", "confirmedVulnerability": False,
                "reason": "pinned_dependency_bundle_missing"}
    environment = os.environ.copy()
    environment.update({
        "CAMPAIGN_PROJECT_ROOT": str(ROOT),
        "CAMPAIGN_SOLJSON": str(compiler_path.resolve()),
        "DVD_COMPILER_VERSION": compiler_metadata.get("longVersion") or COMPILER_VERSION,
        "DVD_COMPILER_SHA256": compiler_metadata["sha256"],
        "DYNAMIC_EXECUTION_MODE": "isolated_in_process",
    })
    command = ["node", str(RUNNER), challenge, str(bundle)]
    try:
        completed = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True,
                                   timeout=timeout, check=False)
        lines = [line for line in completed.stdout.splitlines() if line.strip().startswith("{")]
        try:
            result = json.loads(lines[-1]) if lines else {}
        except json.JSONDecodeError:
            result = {}
        diagnostics = (completed.stdout + completed.stderr)[-16000:]
        confirmed = (completed.returncode == 0 and result.get("state") == "confirmed"
                     and result.get("confirmedVulnerability") is True
                     and result.get("executionBoundary", {}).get("mode") == "isolated_in_process"
                     and result.get("executionBoundary", {}).get("chainId") == 31337)
        return {**result, "challenge": challenge,
                "state": "confirmed" if confirmed else "failed",
                "confirmedVulnerability": confirmed,
                "runnerExitCode": completed.returncode,
                "runnerOutputSha256": _sha256(diagnostics.encode("utf-8", errors="replace")),
                "diagnostic": None if confirmed else diagnostics or "runner_produced_no_output",
                "compilerArtifact": compiler_metadata}
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout.decode("utf-8", errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = error.stderr.decode("utf-8", errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
        diagnostic = (stdout + stderr)[-16000:]
        return {"challenge": challenge, "state": "timeout", "confirmedVulnerability": False,
                "reason": "dynamic_runner_timeout", "runnerOutputSha256": _sha256(diagnostic.encode()),
                "diagnostic": diagnostic, "compilerArtifact": compiler_metadata}


def run(*, challenges: list[str] | None = None, workers: int = 3, timeout: float = 180.0) -> dict:
    selected = list(challenges or sorted(ALLOWED))
    if not selected or len(set(selected)) != len(selected) or any(value not in ALLOWED for value in selected):
        raise ValueError("challenges_must_be_a_unique_nonempty_allowlist_subset")
    if isinstance(workers, bool) or not 1 <= workers <= 3:
        raise ValueError("workers_must_be_between_1_and_3")
    if timeout <= 0:
        raise ValueError("timeout_must_be_positive")
    manifest = _read_manifest()
    samples = {row.get("challenge"): row for row in manifest.get("samples", [])}
    if any(challenge not in samples for challenge in selected):
        raise ValueError("requested_challenge_missing_from_manifest")
    try:
        compiler_path, compiler_metadata = _compiler()
        if compiler_metadata.get("version") != COMPILER_VERSION:
            raise ValueError("exact_solidity_0_8_25_not_selected")
    except Exception as error:
        compiler_path = None
        compiler_metadata = {"version": COMPILER_VERSION, "state": "unavailable",
                             "reason": f"{type(error).__name__}:{str(error)[:240]}"}

    results = []
    if compiler_path is None:
        results = [{"challenge": challenge, "state": "unavailable", "confirmedVulnerability": False,
                    "reason": "exact_compiler_unavailable", "compilerArtifact": compiler_metadata}
                   for challenge in selected]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(selected)), thread_name_prefix="dvd-dynamic") as pool:
            pending = {pool.submit(_run_one, samples[challenge], compiler_path, compiler_metadata, timeout): challenge
                       for challenge in selected}
            for future in as_completed(pending):
                results.append(future.result())
    results.sort(key=lambda row: row["challenge"])

    evidence_root = CORPUS / "dynamic-evidence"
    now = datetime.now(timezone.utc).isoformat()
    for result in results:
        challenge = result["challenge"]
        result["generatedAt"] = now
        result["sourceCommit"] = manifest["commit"]
        result["sourceBundleSha256"] = samples[challenge].get("sourceBundleSha256")
        result["dependencyBundleSha256"] = samples[challenge].get("analysisBundle", {}).get("sourceBundleSha256")
        result["staticInputSha256"] = samples[challenge].get("analysisBundle", {}).get("inputSha256")
        result["targetSourceBundleSha256"] = _sha256("".join(
            f"{file['path']}:{file['sha256']}\n" for file in samples[challenge].get("sourceFiles", [])
        ).encode())
        evidence_path = evidence_root / f"{challenge}.json"
        _atomic_json(evidence_path, result)
        sample = samples[challenge]
        sample["dynamicState"] = "confirmed" if result["confirmedVulnerability"] else result["state"]
        sample["dynamicEvidence"] = str(evidence_path.relative_to(ROOT))
        sample["dynamicEvidenceSha256"] = _sha256(evidence_path.read_bytes())
        sample["dynamicEvidenceGeneratedAt"] = now
        sample["confirmedVulnerability"] = result["confirmedVulnerability"]
        sample["dynamicNotRunReason"] = None
        if not result["confirmedVulnerability"]:
            sample["dynamicFailureReason"] = result.get("reason") or result.get("diagnostic") or result["state"]
        else:
            sample.pop("dynamicFailureReason", None)

    manifest["dynamicGeneratedAt"] = now
    manifest["dynamicWorkers"] = min(workers, len(selected))
    manifest["dynamicSummary"] = {
        "requested": len(results),
        "confirmed": sum(row["confirmedVulnerability"] for row in results),
        "failed": sum(row["state"] == "failed" for row in results),
        "unavailable": sum(row["state"] == "unavailable" for row in results),
        "timeout": sum(row["state"] == "timeout" for row in results),
        "executionMode": "isolated_in_process",
        "compilerVersion": compiler_metadata.get("longVersion") or COMPILER_VERSION,
    }
    _atomic_json(MANIFEST, manifest)
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
                                   "confirmedVulnerability": row["confirmedVulnerability"],
                                   "reason": row.get("reason")} for row in result["results"]]}, ensure_ascii=False))
    return 0 if result["summary"]["confirmed"] == result["summary"]["requested"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
