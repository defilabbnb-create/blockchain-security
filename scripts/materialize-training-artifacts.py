#!/usr/bin/env python3
"""Compile corpus samples to source-bound bytecode and decompiler evidence."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard, provenance
MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
COMPILER = ROOT / "scripts/review-static.py"
SOLC_WRAPPER = ROOT / "scripts/campaign-solc.cjs"
BYTECODE_ANALYZER = ROOT / "scripts/bytecode_analysis.py"
ARTIFACT_ROOT = ROOT / "training-data/github-vulnerabilities/artifacts"
DECOMPILER_ROOT = ROOT / "training-data/github-vulnerabilities/decompiler"
EVIDENCE_ROOT = ROOT / "training-data/github-vulnerabilities/evidence"

def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)

def target_contracts(source: str) -> list[str]:
    return re.findall(r"\b(?:contract|library)\s+([A-Za-z_$][A-Za-z0-9_$]*)", source)

def load_compiler_module():
    spec = importlib.util.spec_from_file_location("training_compiler", COMPILER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compile_sample(sample: dict, timeout: float) -> dict:
    analysis = sample.get("analysis") if isinstance(sample.get("analysis"), dict) else {}
    if analysis.get("static") not in {"passed", "partial"}:
        return {"status": "not_run", "reason": "static_analysis_not_complete"}
    version = analysis.get("compilerVersion")
    if not isinstance(version, str) or not re.fullmatch(r"0\.\d+\.\d+", version):
        return {"status": "unavailable", "reason": "compiler_version_missing"}
    source_path = ROOT / sample["objectPath"]
    source_bytes = source_path.read_bytes()
    source_sha = sha256(source_bytes)
    if source_sha != sample.get("sha256"):
        return {"status": "failed", "reason": "source_hash_mismatch"}
    source = source_bytes.decode("utf-8")
    contracts = target_contracts(source)
    if not contracts:
        return {"status": "failed", "reason": "compilation_target_not_found"}
    existing = analysis.get("artifact")
    if analysis.get("decompiler") == "completed" and isinstance(existing, str):
        artifact_path = ROOT / existing
        report_path = ROOT / str(analysis.get("bytecodeReport", ""))
        evidence_path = ROOT / str(analysis.get("decompilerEvidence", ""))
        try:
            prior_artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            if (prior_artifact.get("sourceSha256") == source_sha
                    and prior_artifact.get("compilerVersion") == version
                    and report_path.is_file()
                    and evidence_path.is_file() and analysis.get("decompilerState") == "completed"):
                return {"status": "completed", "reason": None, "artifact": existing,
                        "artifactSha256": analysis.get("artifactSha256"),
                        "bytecodeReport": analysis.get("bytecodeReport"), "decompilerState": "completed",
                        "decompilerEvidence": analysis.get("decompilerEvidence")}
        except (OSError, json.JSONDecodeError):
            pass
    try:
        soljson, compiler_info = load_compiler_module().compiler(version)
    except Exception as error:
        return {"status": "unavailable", "reason": f"compiler_unavailable:{type(error).__name__}:{str(error)[:240]}"}
    compiler_input = {
        "language": "Solidity", "sources": {sample["path"]: {"content": source}},
        "settings": {"optimizer": {"enabled": False}, "outputSelection": {"*": {"*": [
            "abi", "metadata", "evm.bytecode.object", "evm.deployedBytecode.object"
        ]}}},
    }
    completed = subprocess.run(["node", str(SOLC_WRAPPER), "--standard-json"], cwd=ROOT,
        input=json.dumps(compiler_input, ensure_ascii=False), capture_output=True, text=True,
        timeout=timeout, check=False, env={**os.environ, "CAMPAIGN_SOLJSON": str(soljson)})
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError:
        output = {}
    diagnostics = [item for item in output.get("errors", []) if isinstance(item, dict)]
    errors = [item for item in diagnostics if item.get("severity") == "error"]
    contract_entries = (output.get("contracts") or {}).get(sample["path"], {})
    deployable = []
    for contract in contracts:
        entry = contract_entries.get(contract)
        evm = (entry or {}).get("evm") or {}
        runtime = (evm.get("deployedBytecode") or {}).get("object")
        if isinstance(runtime, str) and runtime:
            deployable.append((contract, entry, evm, runtime))
    if deployable:
        contract, entry, evm, runtime = deployable[0]
        creation = (evm.get("bytecode") or {}).get("object")
    else:
        contract, entry, runtime, creation = contracts[0], contract_entries.get(contracts[0]), None, None
    if completed.returncode != 0 or errors or not isinstance(runtime, str) or not runtime:
        reason = "compiler_error" if errors else f"solc_exit_{completed.returncode}" if completed.returncode else "no_deployable_contract"
        return {"status": "failed", "reason": reason, "compilerVersion": version,
                "diagnostics": diagnostics[:32], "diagnosticText": completed.stderr[-12000:]}
    artifact = {**provenance(source_sha, "E", {"solc": version}),
        "schemaVersion": 1, "sourceSha256": source_sha, "sourcePath": sample["path"],
        "repo": sample.get("repo"), "commit": sample.get("commit"), "contractName": contract,
        "targetSelection": "first_deployable_contract", "declaredContracts": contracts,
        "compiler": compiler_info, "compilerVersion": version,
        "creationBytecode": "0x" + creation if isinstance(creation, str) and creation else "0x",
        "runtimeBytecode": "0x" + runtime, "abi": (entry or {}).get("abi", []),
        "diagnostics": diagnostics[:32], "settings": compiler_input["settings"]}
    artifact_path = ARTIFACT_ROOT / f"{source_sha}.json"
    atomic_json(artifact_path, artifact)
    artifact_sha = sha256(artifact_path.read_bytes())
    return run_decompiler(sample, artifact, artifact_path, artifact_sha, timeout)


def run_decompiler(sample: dict, artifact: dict, artifact_path: Path, artifact_sha: str, timeout: float) -> dict:
    source_sha = artifact["sourceSha256"]
    input_dir = Path(tempfile.mkdtemp(prefix="training-bytecode-input-", dir=ROOT / "work"))
    input_path = input_dir / "runtime.json"
    report_path = EVIDENCE_ROOT / f"{source_sha}.bytecode.json"
    decompiler_path = DECOMPILER_ROOT / source_sha
    evidence_path = EVIDENCE_ROOT / f"{source_sha}.decompiler.json"
    attempt = 0
    while report_path.exists() or decompiler_path.exists() or evidence_path.exists():
        attempt += 1
        report_path = EVIDENCE_ROOT / f"{source_sha}.bytecode.retry-{attempt}.json"
        decompiler_path = DECOMPILER_ROOT / f"{source_sha}-retry-{attempt}"
        evidence_path = EVIDENCE_ROOT / f"{source_sha}.decompiler.retry-{attempt}.json"
    input_path.write_text(json.dumps({"runtimeBytecode": artifact["runtimeBytecode"],
                                      "compilation": {"compilerVersion": artifact["compilerVersion"]}}), encoding="utf-8")
    command = ["python3", str(BYTECODE_ANALYZER), str(input_path), "--output", str(report_path),
               "--decompiler", "heimdall", "--decompiler-output-dir", str(decompiler_path)]
    try:
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                                 check=False, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
    except subprocess.TimeoutExpired:
        process = None
        report = {"decompilation": {"state": "timeout", "error": "bytecode_analysis_timeout"}}
    except (OSError, json.JSONDecodeError) as error:
        process = None
        report = {"decompilation": {"state": "failed", "error": f"report_error:{type(error).__name__}:{error}"}}
    finally:
        try:
            input_path.unlink(); input_dir.rmdir()
        except OSError:
            pass
    decompilation = report.get("decompilation") if isinstance(report, dict) else {}
    state = decompilation.get("state") if isinstance(decompilation, dict) else "unavailable"
    atomic_json(evidence_path, {**provenance(source_sha, "E", {"bytecodeAnalyzer": "bytecode_analysis.py"}),
        "schemaVersion": 1, "sourceSha256": source_sha,
        "artifact": str(artifact_path.relative_to(ROOT)), "artifactSha256": artifact_sha,
        "bytecodeReport": str(report_path.relative_to(ROOT)), "decompilerDirectory": str(decompiler_path.relative_to(ROOT)),
        "decompilerState": state, "opcodeCrossCheckState": report.get("opcodePcCrossCheck", {}).get("state"),
        "processExitCode": process.returncode if process is not None else None,
        "diagnostic": ((process.stdout if process is not None else "") + (process.stderr if process is not None else ""))[-12000:]})
    status = "completed" if state == "completed" else "partial" if state in {"partial", "timeout"} else "failed"
    return {"status": status, "reason": decompilation.get("error") if isinstance(decompilation, dict) else "decompiler_report_missing",
        "artifact": str(artifact_path.relative_to(ROOT)), "artifactSha256": artifact_sha,
        "bytecodeReport": str(report_path.relative_to(ROOT)), "decompilerState": state,
        "decompilerEvidence": str(evidence_path.relative_to(ROOT))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= 8 or args.timeout <= 0:
        raise SystemExit("workers must be 1..8 and timeout must be positive")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    samples = manifest.get("samples", [])
    if args.limit:
        samples = samples[:args.limit]
    results = []
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="training-artifact") as pool:
        futures = {pool.submit(compile_sample, sample, args.timeout): sample for sample in samples}
        for future in as_completed(futures):
            sample = futures[future]
            try:
                result = future.result()
            except Exception as error:
                result = {"status": "failed", "reason": f"{type(error).__name__}:{str(error)[:240]}"}
            results.append((sample, result))
    by_id = {(sample.get("repo"), sample.get("commit"), sample.get("path")): result for sample, result in results}
    for sample in manifest.get("samples", []):
        result = by_id.get((sample.get("repo"), sample.get("commit"), sample.get("path")))
        if not result:
            continue
        analysis = sample.setdefault("analysis", {})
        if result["status"] == "not_run":
            analysis.setdefault("decompiler", "not_run")
            analysis.setdefault("decompilerReason", result["reason"])
        else:
            analysis["decompiler"] = result["status"]
            analysis["decompilerReason"] = result.get("reason")
            for key in ("artifact", "artifactSha256", "bytecodeReport", "decompilerState", "decompilerEvidence"):
                if key in result:
                    analysis[key] = result[key]
    # Bind only the already-confirmed, isolated benchmark PoC whose original
    # source hash exactly matches this corpus object. Labels from repository
    # paths are never promoted to dynamic confirmation.
    poc_path = ROOT / "benchmark/contracts/14-reentrance/poc-result.json"
    if poc_path.is_file():
        try:
            poc = json.loads(poc_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            poc = {}
        if poc.get("confirmedVulnerability") is True and poc.get("sourceSha256"):
            for sample in manifest.get("samples", []):
                if sample.get("sha256") != poc.get("sourceSha256"):
                    continue
                analysis = sample.setdefault("analysis", {})
                analysis["dynamic"] = "passed"
                analysis["dynamicReason"] = "benchmark_14_reentrance_poc_confirmed"
                analysis["dynamicEvidence"] = "benchmark/contracts/14-reentrance/poc-result.json"
                analysis["dynamicEvidenceSha256"] = sha256(poc_path.read_bytes())
                analysis["confirmedVulnerability"] = True
                write_shard(sample, "dynamic", analysis, lane_id="0-benchmark-binding",
                            tool_versions={"benchmark": "14-reentrance"})
    tool_versions = {"artifactCompiler": "campaign-solc.cjs", "bytecodeAnalyzer": "bytecode_analysis.py",
                     "python": sys.version.split()[0]}
    for sample in manifest.get("samples", []):
        if (sample.get("repo"), sample.get("commit"), sample.get("path")) not in by_id:
            continue
        analysis = sample.get("analysis") if isinstance(sample.get("analysis"), dict) else {}
        decompiler = {key: value for key, value in analysis.items()
                      if key.startswith("decompiler") or key in {"artifact", "artifactSha256", "bytecodeReport", "selectorComparison"}}
        if decompiler:
            write_shard(sample, "decompiler", decompiler, lane_id="0-decompiler", tool_versions=tool_versions)
    merger = ROOT / "scripts" / "corpus_merge.py"
    merged = subprocess.run([sys.executable, str(merger)], cwd=ROOT, capture_output=True, text=True,
                            check=True, timeout=60)
    print(merged.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
