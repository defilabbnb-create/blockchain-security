#!/usr/bin/env python3
"""Run and persist bounded static evidence for the pinned DvD sample set."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "training-data" / "damn-vulnerable-defi"
MANIFEST = CORPUS / "manifest.json"
ANALYZER = ROOT / "scripts" / "review-static.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside_root(path: Path) -> Path:
    resolved = path.resolve()
    project_root = ROOT.resolve()
    if resolved != project_root and project_root not in resolved.parents:
        raise ValueError("analysis_bundle_path_outside_project")
    return resolved


def verify_sample(sample: dict) -> tuple[Path, str]:
    bundle = sample.get("analysisBundle")
    if not isinstance(bundle, dict) or not isinstance(bundle.get("inputPath"), str):
        raise ValueError("analysis_bundle_missing")
    input_path = _inside_root(ROOT / bundle["inputPath"])
    if not input_path.is_file() or _sha256(input_path) != bundle.get("inputSha256"):
        raise ValueError("analysis_bundle_input_hash_mismatch")
    for row in bundle.get("files", []):
        path = _inside_root(ROOT / row["path"])
        if not path.is_file() or _sha256(path) != row.get("sha256"):
            raise ValueError("analysis_bundle_source_hash_mismatch:" + str(row.get("sourceUnit")))
    for row in sample.get("dependencyFiles", []):
        path = _inside_root(ROOT / row["objectPath"])
        if not path.is_file() or _sha256(path) != row.get("sha256"):
            raise ValueError("dependency_object_hash_mismatch:" + str(row.get("importPath")))
    return input_path, _sha256(input_path)


def _payload(stdout: str) -> dict:
    rows = [line for line in stdout.splitlines() if line.strip().startswith("{")]
    if not rows:
        return {}
    try:
        value = json.loads(rows[-1])
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def analyze_sample(sample: dict, *, timeout: int = 300, command_runner=subprocess.run) -> dict:
    name = sample.get("challenge")
    result = dict(sample)
    evidence_dir = _inside_root(CORPUS / "bundles" / str(name))
    evidence_path = evidence_dir / "static-result.json"
    stderr_path = evidence_dir / "static-result.stderr.log"
    try:
        input_path, input_sha256 = verify_sample(sample)
        completed = command_runner(
            ["python3", str(ANALYZER), str(input_path)], cwd=ROOT,
            capture_output=True, text=True, timeout=timeout, check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        payload = _payload(stdout)
        state = payload.get("state")
        if completed.returncode != 0:
            static_state = "failed"
            reason = f"analyzer_exit_{completed.returncode}"
            if payload.get("reason") and payload["reason"] != "completed":
                reason += ":" + str(payload["reason"])
            elif payload.get("staticError"):
                reason += ":" + str(payload["staticError"])
        elif state in {"completed", "partial", "unavailable", "failed"}:
            static_state = state
            reason = payload.get("reason") or payload.get("staticError")
            if not reason and state == "partial":
                stages = payload.get("staticStages") if isinstance(payload.get("staticStages"), dict) else {}
                reason = "partial_static_stages:" + ",".join(
                    sorted(key for key, value in stages.items() if value == "partial")
                )
        else:
            static_state = "failed"
            reason = "analyzer_payload_missing_state"
    except subprocess.TimeoutExpired as error:
        stdout_value = error.stdout or ""
        stderr_value = error.stderr or ""
        stdout = stdout_value.decode("utf-8", errors="replace") if isinstance(stdout_value, bytes) else stdout_value
        stderr = stderr_value.decode("utf-8", errors="replace") if isinstance(stderr_value, bytes) else stderr_value
        payload = _payload(stdout)
        input_sha256 = sample.get("analysisBundle", {}).get("inputSha256")
        static_state = "failed"
        reason = "analyzer_timeout"
    except (OSError, ValueError, KeyError, TypeError) as error:
        stdout = ""
        stderr = ""
        payload = {}
        input_sha256 = sample.get("analysisBundle", {}).get("inputSha256")
        static_state = "unavailable"
        reason = str(error)

    stdout_bytes = (stdout + ("\n" if stdout and not stdout.endswith("\n") else "")).encode("utf-8")
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(evidence_path, stdout_bytes)
    _atomic_write(stderr_path, stderr.encode("utf-8"))
    evidence_sha256 = _sha256(evidence_path)
    result.update({
        "staticState": static_state,
        "staticReason": reason,
        "staticFindingCount": payload.get("findingCount"),
        "staticEvidence": {
            "path": str(evidence_path.resolve().relative_to(ROOT.resolve())),
            "sha256": evidence_sha256,
            "stderrPath": str(stderr_path.resolve().relative_to(ROOT.resolve())),
            "stderrSha256": _sha256(stderr_path),
            "inputSha256": input_sha256,
            "sourceBundleSha256": sample.get("analysisBundle", {}).get("sourceBundleSha256"),
            "compiler": payload.get("compiler"),
            "compilerProvenance": payload.get("compilerProvenance"),
            "contracts": payload.get("contracts"),
            "detectors": payload.get("detectors"),
            "findingSemanticFingerprint": payload.get("findingSemanticFingerprint"),
            "staticStages": payload.get("staticStages"),
            "callGraphState": (payload.get("callGraph") or {}).get("state"),
            "unifiedIRState": (payload.get("unifiedIR") or {}).get("state"),
        },
    })
    return result


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _write_manifest(manifest: dict) -> None:
    lock_path = MANIFEST.with_suffix(".lock")
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Re-read while holding the lock and merge only static fields so a
        # concurrent dynamic evidence writer cannot lose its latest results.
        current = json.loads(MANIFEST.read_text(encoding="utf-8"))
        updated = {sample["challenge"]: sample for sample in manifest["samples"]}
        for sample in current.get("samples", []):
            replacement = updated.get(sample.get("challenge"))
            if replacement is None:
                continue
            for key in ("staticState", "staticReason", "staticFindingCount", "staticEvidence"):
                if key in replacement:
                    sample[key] = replacement[key]
        current["staticAnalysisUpdatedAt"] = datetime.now(timezone.utc).isoformat()
        _atomic_write(MANIFEST, (json.dumps(current, ensure_ascii=False, indent=2) + "\n").encode())
        fcntl.flock(lock, fcntl.LOCK_UN)


def analyze(*, challenges: list[str] | None = None, workers: int = 3, timeout: int = 300) -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    samples = manifest.get("samples")
    if not isinstance(samples, list):
        raise ValueError("manifest_samples_missing")
    selected = set(challenges or [sample["challenge"] for sample in samples])
    known = {sample.get("challenge") for sample in samples}
    if not selected or selected - known:
        raise ValueError("unknown_or_empty_challenge_selection")
    if not 1 <= workers <= 8 or not 1 <= timeout <= 1800:
        raise ValueError("workers_or_timeout_out_of_range")
    pending = [sample for sample in samples if sample.get("challenge") in selected]
    analyzed = {}
    with ThreadPoolExecutor(max_workers=min(workers, len(pending)), thread_name_prefix="dvd-static") as pool:
        futures = {pool.submit(analyze_sample, sample, timeout=timeout): sample["challenge"] for sample in pending}
        for future in as_completed(futures):
            challenge = futures[future]
            try:
                analyzed[challenge] = future.result()
            except Exception as error:
                analyzed[challenge] = {
                    **next(sample for sample in pending if sample["challenge"] == challenge),
                    "staticState": "failed", "staticReason": f"analysis_runner_error:{type(error).__name__}:{str(error)[:300]}",
                    "staticFindingCount": None,
                }
    manifest["samples"] = [analyzed.get(sample["challenge"], sample) for sample in samples]
    _write_manifest(manifest)
    return {"analyzedCount": len(analyzed), "states": {
        state: sum(sample.get("staticState") == state for sample in analyzed.values())
        for state in ("completed", "partial", "unavailable", "failed")
    }, "samples": [
        {"challenge": sample["challenge"], "staticState": sample.get("staticState"),
         "staticFindingCount": sample.get("staticFindingCount"), "staticReason": sample.get("staticReason"),
         "staticEvidence": sample.get("staticEvidence")}
        for sample in (analyzed[key] for key in sorted(analyzed))
    ]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", action="append", dest="challenges")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    try:
        result = analyze(challenges=args.challenges, workers=args.workers, timeout=args.timeout)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0 if not result["states"]["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
