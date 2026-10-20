#!/usr/bin/env python3
"""Local-safe pipeline adapters for dynamic checks, decompilation and PoCs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 2_000_000
ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = ROOT / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
FORGE = ROOT / "work" / "tools" / "forge"

from decompiler_semantics import write_semantics
from dynamic_runner import run_harness
from harness_gen import _source_digest, generate_harness
from invariant_gen import generate_invariants
from poc_generator import generate_poc
from deploy_adapter import generate_deployment, run_deployment


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _load_input(value: Any, *, json_path: bool = False) -> Any:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        raise ValueError("input path or object is required")
    if not json_path and value.startswith("0x") and len(value) % 2 == 0 and all(char in "0123456789abcdefABCDEFx" for char in value):
        return value
    candidate = Path(value)
    if not json_path and not candidate.is_file():
        return value
    path = candidate.resolve(strict=True)
    if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input must be a bounded regular file")
    raw = path.read_text(encoding="utf-8")
    if json_path or path.suffix.lower() == ".json":
        return json.loads(raw)
    return raw


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _dynamic(target: dict[str, Any], stage_dir: Path, mode: str) -> dict[str, Any]:
    if target.get("preferHarness") is not True and (target.get("unifiedIR") is not None or target.get("sourceBundle") is not None):
        return _dynamic_from_ir(target, stage_dir, mode)
    harness = target.get("harness")
    if not isinstance(harness, str) or not harness:
        return {"state": "unavailable", "reason": "harness_input_missing"}
    harness_dir = Path(harness).resolve(strict=True)
    if not harness_dir.is_dir() or not (harness_dir / "harness.json").is_file():
        return {"state": "unavailable", "reason": "harness_manifest_missing"}
    run_mode = mode if mode in {"local", "fixed_block_fork", "replay"} else "local"
    results = run_harness(
        harness_dir,
        mode=run_mode,
        forge=FORGE,
        timeout_seconds=min(float(target.get("timeoutSeconds", 120)), 600),
        rpc_url=target.get("rpcUrl") if run_mode == "fixed_block_fork" else None,
        block_number=target.get("block") if run_mode == "fixed_block_fork" else None,
        replay_enabled=target.get("enableReplay") is True,
    )
    manifest = json.loads((harness_dir / "harness.json").read_text(encoding="utf-8"))
    assertion_count = sum(1 for row in manifest.get("tests", [])
                          if isinstance(row, dict) and row.get("status") != "adapter_required")
    adapter_count = int(manifest.get("adapterRequiredCount", 0) or 0)
    artifact = {"schemaVersion": 1, "mode": run_mode, "results": results,
                "deployedTarget": target.get("deployedTarget"),
                "invariantAssertionsExecuted": assertion_count,
                "adapterRequiredCount": adapter_count,
                "evidenceSha256": _digest(json.dumps(results, sort_keys=True, separators=(",", ":")).encode())}
    _atomic_json(stage_dir / "dynamic-result.json", artifact)
    states = [row.get("state") for row in results]
    if states and all(state in {"passed", "violated"} for state in states):
        # A violated invariant is a completed experiment, never a vulnerability confirmation.
        return {"state": "completed", "outcome": "invariant_violated" if "violated" in states else "passed",
                "evidenceSha256": artifact["evidenceSha256"], "resultPath": "dynamic-result.json",
                "deployedTarget": target.get("deployedTarget"),
                "invariantAssertionsExecuted": assertion_count, "adapterRequiredCount": adapter_count}
    if states and all(state == "unavailable" for state in states):
        return {"state": "unavailable", "reason": "dynamic_runner_unavailable", "evidenceSha256": artifact["evidenceSha256"],
                "deployedTarget": target.get("deployedTarget"),
                "invariantAssertionsExecuted": assertion_count, "adapterRequiredCount": adapter_count}
    return {"state": "failed" if any(state == "timeout" for state in states) else "unavailable",
            "reason": "dynamic_result_incomplete", "evidenceSha256": artifact["evidenceSha256"]}


def _deploy(target: dict[str, Any], stage_dir: Path, mode: str) -> dict[str, Any]:
    """Prepare or run a local deployment adapter before dynamic execution.

    A deployment address is accepted only when supplied by a local runner or
    a real forge result. Constructor arguments are never guessed.
    """
    if mode != "local":
        return {"state": "unavailable", "reason": "deployment_is_local_only"}
    supplied = target.get("deployedTarget")
    if isinstance(supplied, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", supplied):
        return {"state": "completed", "deployedTarget": supplied.lower(),
                "invariantAssertionsExecuted": int(target.get("invariantAssertionsExecuted", 0) or 0),
                "adapterRequiredCount": int(target.get("adapterRequiredCount", 0) or 0),
                "deploymentState": "provided_local_target"}
    bundle_value = target.get("sourceBundle")
    if bundle_value is None:
        return {"state": "unavailable", "reason": "verified_source_bundle_missing",
                "deployedTarget": None, "invariantAssertionsExecuted": 0, "adapterRequiredCount": 0}
    try:
        bundle = _load_input(bundle_value, json_path=True)
        deployment_dir = stage_dir / "deployment"
        manifest = generate_deployment(bundle, deployment_dir,
                                       constructor_args=target.get("constructorArgs", target.get("deploymentArgs")))
        _atomic_json(stage_dir / "deployment.json", manifest)
        if manifest.get("state") == "adapter_required":
            manifest.update({"state": "unavailable", "reason": manifest.get("reason", "adapter_required"),
                             "deployedTarget": None, "invariantAssertionsExecuted": 0,
                             "adapterRequiredCount": len(manifest.get("missing", [])) or 1})
            _atomic_json(stage_dir / "deployment.json", manifest)
            return manifest
        if target.get("executeDeployment") is True:
            manifest = run_deployment(deployment_dir, forge=target.get("forge", "forge"),
                                      timeout=min(float(target.get("timeoutSeconds", 120)), 600))
        deployed = manifest.get("target")
        if not (isinstance(deployed, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", deployed)):
            return {"state": "unavailable", "reason": "deployment_target_not_observed",
                    "deploymentState": manifest.get("state"), "deploymentPath": "deployment.json",
                    "deployedTarget": None, "invariantAssertionsExecuted": 0, "adapterRequiredCount": 0}
        return {"state": "completed", "deploymentState": manifest.get("state"),
                "deploymentPath": "deployment.json", "deployedTarget": deployed.lower(),
                "invariantAssertionsExecuted": int(target.get("invariantAssertionsExecuted", 0) or 0),
                "adapterRequiredCount": int(target.get("adapterRequiredCount", 0) or 0)}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return {"state": "failed", "reason": f"deployment_error:{type(error).__name__}:{str(error)[:200]}",
                "deployedTarget": None, "invariantAssertionsExecuted": 0, "adapterRequiredCount": 0}


def _dynamic_from_ir(target: dict[str, Any], stage_dir: Path, mode: str) -> dict[str, Any]:
    ir_value, bundle_value = target.get("unifiedIR"), target.get("sourceBundle")
    if ir_value is None or bundle_value is None:
        return {"state": "unavailable", "reason": "unified_ir_or_verified_source_bundle_missing"}
    ir = _load_input(ir_value, json_path=True)
    bundle = _load_input(bundle_value, json_path=True)
    if not isinstance(ir, dict) or not isinstance(bundle, dict):
        return {"state": "unavailable", "reason": "unified_ir_or_verified_source_bundle_invalid"}
    sources = bundle.get("sources")
    if not isinstance(sources, dict) or not sources:
        return {"state": "unavailable", "reason": "verified_source_bundle_sources_missing"}
    source_sha256 = _source_digest(sources)
    invariants = generate_invariants(ir, source_sha256=source_sha256)
    _atomic_json(stage_dir / "invariants.json", invariants)
    if invariants.get("state") != "available":
        return {"state": "unavailable", "reason": "invariant_templates_unavailable",
                "invariantsPath": "invariants.json"}
    harness_dir = stage_dir / "harness"
    manifest = generate_harness(invariants, bundle, harness_dir)
    _atomic_json(stage_dir / "harness.json", manifest)
    run_mode = mode if mode in {"local", "fixed_block_fork", "replay"} else "local"
    rows = run_harness(harness_dir, mode=run_mode, forge=FORGE,
                       timeout_seconds=min(float(target.get("timeoutSeconds", 120)), 600),
                       rpc_url=target.get("rpcUrl") if run_mode == "fixed_block_fork" else None,
                       block_number=target.get("block") if run_mode == "fixed_block_fork" else None,
                       replay_enabled=target.get("enableReplay") is True)
    assertion_count = sum(1 for row in manifest.get("tests", [])
                          if isinstance(row, dict) and row.get("status") != "adapter_required")
    adapter_count = int(manifest.get("adapterRequiredCount", 0) or 0)
    artifact = {"schemaVersion": 1, "mode": run_mode, "results": rows,
                "deployedTarget": target.get("deployedTarget"),
                "invariantAssertionsExecuted": assertion_count,
                "adapterRequiredCount": adapter_count,
                "evidenceSha256": _digest(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())}
    _atomic_json(stage_dir / "dynamic-result.json", artifact)
    states = [row.get("state") for row in rows]
    if states and all(state in {"passed", "violated"} for state in states):
        return {"state": "completed", "outcome": "invariant_violated" if "violated" in states else "passed",
                "invariantsPath": "invariants.json", "harnessPath": "harness", "resultPath": "dynamic-result.json",
                "evidenceSha256": artifact["evidenceSha256"], "deployedTarget": target.get("deployedTarget"),
                "invariantAssertionsExecuted": assertion_count, "adapterRequiredCount": adapter_count}
    return {"state": "unavailable", "reason": "dynamic_adapter_or_invariant_execution_unavailable",
            "invariantsPath": "invariants.json", "harnessPath": "harness", "resultPath": "dynamic-result.json",
            "evidenceSha256": artifact["evidenceSha256"], "deployedTarget": target.get("deployedTarget"),
            "invariantAssertionsExecuted": assertion_count, "adapterRequiredCount": adapter_count}


def _decompile(target: dict[str, Any], stage_dir: Path) -> dict[str, Any]:
    source = target.get("decompilerInput") or target.get("bytecode")
    if source is None:
        return {"state": "unavailable", "reason": "decompiler_input_missing"}
    value = _load_input(source)
    result = write_semantics(stage_dir / "decompiled-semantics.json", value)
    return {"state": "completed", "inputSha256": result["inputSha256"],
            "riskHintCount": len(result["riskHints"]), "semanticsProven": False,
            "evidenceSha256": _digest((stage_dir / "decompiled-semantics.json").read_bytes()),
            "resultPath": "decompiled-semantics.json"}


def _run_poc(target: dict[str, Any], stage_dir: Path, *, forge_runner=None) -> dict[str, Any]:
    finding_value = target.get("finding")
    bundle_value = target.get("sourceBundle")
    if finding_value is None or bundle_value is None:
        return {"state": "unavailable", "reason": "finding_or_verified_source_bundle_missing"}
    finding = _load_input(finding_value, json_path=True)
    bundle = _load_input(bundle_value, json_path=True)
    test_source_value = target.get("pocTestSource")
    test_source = _load_input(test_source_value) if test_source_value is not None else None
    output_dir = stage_dir / "poc"
    manifest = generate_poc(finding, bundle, output_dir, test_source=test_source)
    attempts = []
    poc_state = "unconfirmed"
    if manifest["adapterState"] == "ready":
        if forge_runner is None and not FORGE.is_file():
            attempts.append({"mode": "local", "state": "unavailable", "reason": "bundled_forge_not_found"})
        else:
            environment = dict(os.environ)
            environment["FOUNDRY_OFFLINE"] = "true"
            for key in ("RPC_URL", "ETH_RPC_URL", "DYNAMIC_FORK_RPC_URL", "DYNAMIC_FORK_BLOCK_NUMBER", "FOUNDRY_ETH_RPC_URL"):
                environment.pop(key, None)
            command = [str(FORGE), "test", "--root", str(output_dir), "--offline", "--match-test", manifest["testName"]]
            try:
                run = forge_runner or subprocess.run
                completed = run(command, cwd=ROOT, env=environment, capture_output=True,
                                timeout=min(float(target.get("timeoutSeconds", 120)), 600), check=False)
                stdout = completed.stdout if isinstance(completed.stdout, bytes) else str(completed.stdout or "").encode()
                stderr = completed.stderr if isinstance(completed.stderr, bytes) else str(completed.stderr or "").encode()
                combined = (stdout + b"\n" + stderr)[:MAX_OUTPUT_BYTES]
                output_text = combined.decode("utf-8", errors="replace")
                test_path = (output_dir / manifest["testPath"]).resolve(strict=True)
                if test_path.parent != (output_dir / "test").resolve(strict=True):
                    raise ValueError("generated_poc_test_path_escaped")
                test_bytes = test_path.read_bytes()
                test_source_sha256 = _digest(test_bytes)
                manifest_path = output_dir / "poc.json"
                saved_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest_sha256 = _digest(manifest_path.read_bytes())
                test_name = manifest["testName"]
                passed = re.search(rf"(?m)^\[PASS\]\s+{re.escape(test_name)}(?:\b|(?=\())", output_text) is not None
                failed = re.search(rf"(?m)^\[FAIL\]\s+{re.escape(test_name)}(?:\b|(?=\())", output_text) is not None
                artifact_valid = (
                    saved_manifest == manifest and completed.returncode == 0 and passed and not failed and
                    manifest.get("adapterState") == "ready" and
                    len(re.findall(r"function\s+" + re.escape(test_name) + r"\s*\(", test_bytes.decode("utf-8"))) == 1
                )
                attempt = {"mode": "local", "returnCode": completed.returncode,
                           "state": "passed" if artifact_valid else "test_not_verified" if completed.returncode == 0 else "failed",
                           "testName": test_name, "matchedTestPassed": artifact_valid,
                           "pocManifestSha256": manifest_sha256,
                           "sourceBundleSha256": manifest["sourceBundleSha256"],
                           "testSourceSha256": test_source_sha256,
                           "evidenceSha256": _digest(combined)}
                attempts.append(attempt)
                if artifact_valid:
                    poc_state = "confirmed"
            except subprocess.TimeoutExpired as error:
                output = (error.stdout or b"") + (error.stderr or b"")
                attempts.append({"mode": "local", "state": "timeout", "evidenceSha256": _digest(output[:MAX_OUTPUT_BYTES])})
    else:
        attempts.append({"mode": "local", "state": "unavailable", "reason": "poc_test_adapter_required"})
    execution_evidence_sha256 = next((attempt.get("evidenceSha256") for attempt in attempts
                                      if attempt.get("state") == "passed" and attempt.get("matchedTestPassed") is True), None)
    payload = {"schemaVersion": 1, "findingId": manifest["findingId"], "pocState": poc_state,
               "confirmed_by_poc": poc_state == "confirmed", "attempts": attempts,
               "pocArtifactPath": "poc", "sourceBundleSha256": manifest["sourceBundleSha256"],
               "testName": manifest["testName"], "pocManifestSha256": _digest((output_dir / "poc.json").read_bytes()),
               "evidenceSha256": manifest["evidenceSha256"], "executionEvidenceSha256": execution_evidence_sha256,
               "severityScore": manifest["severityScore"],
               "minCapitalRequiredWei": None}
    _atomic_json(stage_dir / "poc-result.json", payload)
    return {"state": "completed", "pocState": poc_state, "evidenceSha256": payload["evidenceSha256"],
            "resultPath": "poc-result.json"}


def run_stage(stage: str, target: dict[str, Any], stage_dir: str | Path, mode: str = "local", *, forge_runner=None) -> dict[str, Any]:
    """Run one explicit verification stage without inferring missing evidence."""
    directory = Path(stage_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    try:
        if stage == "deploy":
            return _deploy(target, directory, mode)
        if stage == "dynamic":
            return _dynamic(target, directory, mode)
        if stage == "decompile":
            return _decompile(target, directory)
        if stage == "poc":
            return _run_poc(target, directory, forge_runner=forge_runner)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return {"state": "failed", "reason": f"{type(error).__name__}:{str(error)[:240]}"}
    return {"state": "unavailable", "reason": f"unsupported_stage:{stage}"}
