#!/usr/bin/env python3
"""Resumable, read-only orchestration for the contract analysis stages."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
STAGES = ("recon", "collect", "repr", "static", "deploy", "dynamic", "decompile", "review", "poc", "report")
SCRIPT_DIR = ROOT / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import pipeline_source_stages
import pipeline_verification_stages
import pipeline_review_stages
from recon import build_recon_profile, write_profile
from representation_pipeline import build_representations
from bytecode_analysis import analyze_bytecode, extract_runtime_bytecode
from unified_ir import from_bytecode_report


class PipelineError(ValueError):
    pass


def _atomic_json(path: Path, value: Any) -> None:
    path = Path(path)
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


def _load_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineError(f"无法读取 JSON: {path}") from error


def _write_pipeline_finding_index(stage_dir: Path, static_result: dict[str, Any], source_sha256: str | None) -> Path:
    """Persist static hypotheses for later review/report stages without confirming them."""
    rows = static_result.get("findings", []) if isinstance(static_result, dict) else []
    findings = []
    if isinstance(rows, list):
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            finding_id = row.get("id") or row.get("ruleId") or f"static-{index + 1}"
            evidence = row.get("evidence") if isinstance(row.get("evidence"), list) else []
            findings.append({
                "id": str(finding_id)[:160],
                "kind": str(row.get("check") or row.get("type") or row.get("ruleId") or "static_signal")[:120],
                "title": str(row.get("description") or row.get("check") or "静态分析观察")[:240],
                "severity": str(row.get("impact") or row.get("severity") or "info")[:40],
                "status": "static_signal",
                "confirmedVulnerability": False,
                "sourceSha256": source_sha256,
                "evidence": evidence,
            })
    destination = (stage_dir / "finding-index.json").resolve()
    _atomic_json(destination, {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "generatedByPipeline": True,
        "coverage": {"complete": False, "reason": "pipeline static hypotheses require dynamic and PoC evidence"},
        "findings": findings,
    })
    return destination


def _target_key(target: dict[str, Any], index: int) -> str:
    raw = target.get("id") or target.get("address") or f"target-{index + 1}"
    if not isinstance(raw, str) or not raw:
        raise PipelineError("target id/address 必须是非空字符串")
    key = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)[:96].strip("._")
    return key or f"target-{index + 1}"


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _targets(path: Path) -> list[dict[str, Any]]:
    payload = _load_json(path)
    rows = payload.get("targets") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        raise PipelineError("targets 必须是非空数组或包含 targets 数组的对象")
    result = []
    for index, target in enumerate(rows):
        if not isinstance(target, dict):
            raise PipelineError(f"targets[{index}] 必须是对象")
        result.append(dict(target))
    return result


def _validate_stages(stages: list[str]) -> list[str]:
    if not stages:
        raise PipelineError("至少需要一个 stage")
    if any(stage not in STAGES for stage in stages):
        raise PipelineError(f"未知 stage，可选值: {', '.join(STAGES)}")
    if len(set(stages)) != len(stages):
        raise PipelineError("stages 不得重复")
    return stages


def _resolve_target_concurrency(value: int | None, target_count: int) -> int:
    """Return a bounded worker count without allowing unbounded fan-out."""
    if value is None:
        raw = os.environ.get("PIPELINE_TARGET_CONCURRENCY", "4")
        try:
            value = int(raw)
        except (TypeError, ValueError) as error:
            raise PipelineError("target_concurrency 必须是正整数") from error
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 8:
        raise PipelineError("target_concurrency 必须是 1 到 8 的整数")
    return min(value, max(1, target_count))


def _default_runner(stage: str, target: dict[str, Any], stage_dir: Path, mode: str) -> dict[str, Any]:
    stage_dir.mkdir(parents=True, exist_ok=True)
    if stage in {"collect", "repr"}:
        if stage == "repr":
            target.setdefault("reprCacheRoot", str(ROOT / "work" / "repr-cache"))
        return pipeline_source_stages.run_stage(stage, target, stage_dir, mode)
    if stage in {"deploy", "dynamic", "decompile", "poc"}:
        return pipeline_verification_stages.run_stage(stage, target, stage_dir, mode)
    if stage in {"review", "report"}:
        return pipeline_review_stages.run_stage(stage, target, stage_dir, mode)
    if stage == "recon":
        fixture = target.get("rpcFixture")
        if isinstance(fixture, dict):
            responses = {key: list(value) if isinstance(value, list) else [value] for key, value in fixture.items()}
            def fixture_rpc(method, params):
                rows = responses.get(method)
                if not rows:
                    raise RuntimeError(f"rpc_fixture_missing:{method}")
                return rows.pop(0)
            try:
                profile = build_recon_profile(fixture_rpc, target["address"], chain_id=int(target["chainId"]),
                                               block=int(target["block"]), from_block=int(target.get("fromBlock", target["block"])),
                                               transaction_hashes=target.get("transactionHashes", []),
                                               dependencies=target.get("dependencies", []),
                                               reachable_assets_usd=float(target.get("reachableAssetsUsd", 0)))
                output_path = stage_dir / "recon-profile.json"
                write_profile(output_path, profile)
                return {"state": "completed", "resultPath": str(output_path),
                        "evidenceSha256": hashlib.sha256(output_path.read_bytes()).hexdigest()}
            except Exception as error:
                return {"state": "failed", "reason": f"recon_fixture_failed:{type(error).__name__}"}
        required = (target.get("rpcUrl"), target.get("address"), target.get("chainId"), target.get("block"))
        if not all(value is not None for value in required):
            return {"state": "unavailable", "reason": "stage_inputs_missing:recon"}
        command = [sys.executable, str(ROOT / "scripts" / "recon.py"), "--rpc-url", str(target["rpcUrl"]),
                   "--address", str(target["address"]), "--chain-id", str(target["chainId"]),
                   "--block", str(target["block"]), "--output", str(stage_dir / "recon.json")]
    elif stage == "static":
        source = target.get("sourcePath") or target.get("sourceBundlePath") or target.get("source")
        if not isinstance(source, str) or not source:
            return {"state": "unavailable", "reason": "stage_inputs_missing:static_source"}
        command = [sys.executable, str(ROOT / "scripts" / "review-static.py"), source]
    else:
        return {"state": "unavailable", "reason": f"stage_adapter_missing:{stage}", "evidence": None}
    started = time.monotonic()
    environment = dict(os.environ)
    if mode == "local":
        environment["DYNAMIC_EXECUTION_MODE"] = "local"
        for name in ("DYNAMIC_FORK_RPC_URL", "DYNAMIC_FORK_BLOCK_NUMBER", "RPC_URL", "ETH_RPC_URL"):
            environment.pop(name, None)
    try:
        completed = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True,
                                   timeout=target.get("timeoutSeconds", 300), check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"state": "failed", "reason": f"{type(error).__name__}", "durationMs": round((time.monotonic() - started) * 1000)}
    evidence = (completed.stdout + "\n" + completed.stderr).encode("utf-8", errors="replace")[:2_000_000]
    result = {"state": "completed" if completed.returncode == 0 else "failed",
              "returnCode": completed.returncode, "durationMs": round((time.monotonic() - started) * 1000),
              "evidenceSha256": hashlib.sha256(evidence).hexdigest()}
    if completed.returncode:
        result["reason"] = "stage_process_failed"
    elif stage == "static":
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {"state": "failed", "reason": "static_stage_returned_invalid_json",
                    "evidenceSha256": result["evidenceSha256"]}
        if (not isinstance(parsed, dict) or
                parsed.get("state") not in {"completed", "partial", "failed", "unavailable"}):
            return {"state": "failed", "reason": "static_stage_returned_invalid_schema",
                    "evidenceSha256": result["evidenceSha256"]}
        result["analysisState"] = parsed.get("state") if isinstance(parsed, dict) else "unknown"
        result["sourceSha256"] = parsed.get("sourceSha256") if isinstance(parsed, dict) else None
        if isinstance(parsed, dict):
            reason = parsed.get("reason") or parsed.get("error")
            if isinstance(reason, str) and reason:
                result["analysisReason"] = reason[:240]
            if parsed.get("state") == "failed":
                result["state"] = "failed"
            elif parsed.get("state") == "unavailable":
                result["state"] = "unavailable"
        output_path = stage_dir / "static.json"
        result["resultPath"] = str(output_path)
        result["findingIndex"] = str(_write_pipeline_finding_index(
            stage_dir, parsed,
            result.get("sourceSha256") or parsed.get("verifiedSourceFingerprint")
            if isinstance(parsed, dict) else result.get("sourceSha256")))
        # Link every representation available at this point. Static analysis
        # is the first stage that can provide source IR; bytecode and semantic
        # inputs remain explicitly unavailable when the target does not supply
        # them. The shared cache is the durable evidence boundary.
        try:
            source_bundle_path = Path(target.get("sourcePath", source)).resolve(strict=True)
            source_bundle = _load_json(source_bundle_path)
            unified = parsed.get("unifiedIR") if isinstance(parsed, dict) else None
            source_ir = None
            if isinstance(unified, dict):
                ir_ref = unified.get("report")
                if isinstance(ir_ref, str):
                    ir_path = (ROOT / ir_ref).resolve() if not Path(ir_ref).is_absolute() else Path(ir_ref).resolve()
                    if ir_path.is_file():
                        source_ir = _load_json(ir_path)
            bytecode_ir = None
            bytecode_report = None
            bytecode_value = target.get("bytecode") or target.get("runtimeBytecode")
            if bytecode_value is not None:
                decoded_bytecode = bytecode_value
                if isinstance(bytecode_value, str):
                    decoded_bytecode = pipeline_verification_stages._load_input(bytecode_value)
                runtime = extract_runtime_bytecode(decoded_bytecode)
                bytecode_report = analyze_bytecode(runtime, chain_id=target.get("chainId"), address=target.get("address"), block=target.get("block"))
                bytecode_ir = from_bytecode_report(bytecode_report)
                _atomic_json(stage_dir / "bytecode-report.json", bytecode_report)
                _atomic_json(stage_dir / "unified-ir-bytecode.json", bytecode_ir)
            decompiler_input = target.get("decompilerInput")
            representation = build_representations(
                source_bundle,
                source_ir=source_ir,
                bytecode_ir=bytecode_ir,
                decompiler_input=decompiler_input,
                cache_root=ROOT / "work" / "repr-cache",
                contract=target.get("contract") or target.get("address"),
            )
            result["representation"] = {
                "cacheKey": representation.get("cacheKey"),
                "cachePath": representation.get("cachePath"),
                "artifactSha256": representation.get("artifactSha256"),
                "artifacts": sorted(representation.get("artifacts", {}).keys()),
                "artifactPaths": {name: str(Path(representation.get("cachePath", "")) / name)
                                  for name in representation.get("artifacts", {})},
                "semanticsProven": False,
            }
            result["sourceBundle"] = str(source_bundle_path)
            if source_ir is not None:
                result["unifiedIR"] = str((ROOT / unified["report"]).resolve()) if isinstance(unified, dict) and isinstance(unified.get("report"), str) else source_ir
            if bytecode_ir is not None:
                result["bytecodeIR"] = str(stage_dir / "unified-ir-bytecode.json")
            if decompiler_input is not None:
                result["decompilerInput"] = decompiler_input
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            result["representation"] = {"state": "unavailable", "reason": f"representation_build_failed:{type(error).__name__}"}
        if isinstance(result.get("representation"), dict):
            parsed["representation"] = result["representation"]
        parsed["pipelineEvidence"] = {
            key: result.get(key) for key in ("sourceBundle", "unifiedIR", "bytecodeIR", "decompilerInput")
            if result.get(key) is not None
        }
        _atomic_json(output_path, parsed)
    return result


def _run_target(index: int, target: dict[str, Any], selected: list[str], root: Path, mode: str,
                budget_usd: float, runner: Callable[[str, dict[str, Any], Path, str], dict[str, Any]]) -> dict[str, Any]:
    """Run one target in an isolated directory; safe to execute in a worker."""
    key = _target_key(target, index)
    stage_dir = root / key
    state_path = stage_dir / "state.json"
    identity = {"targetSha256": _fingerprint(target), "mode": mode, "stages": selected}
    state = _load_json(state_path) if state_path.is_file() else {"target": key, "stages": {}, "spentUsd": 0.0}
    if state.get("identity") != identity:
        state = {"target": key, "stages": {}, "spentUsd": 0.0}
    state["identity"] = identity
    state.setdefault("stages", {})
    blocked = False
    for stage in selected:
        old = state["stages"].get(stage)
        if isinstance(old, dict) and old.get("state") == "completed":
            continue
        if blocked:
            state["stages"][stage] = {"state": "blocked", "reason": "upstream_stage_failed"}
            continue
        if float(state.get("spentUsd", 0.0)) >= float(budget_usd) and budget_usd > 0:
            state["stages"][stage] = {"state": "blocked", "reason": "budget_exhausted"}
            blocked = True
            continue
        try:
            stage_target = dict(target)
            for previous in state["stages"].values():
                if isinstance(previous, dict):
                    for field in (
                        "sourcePath", "sourceBundle", "sourceBundleSha256", "findingIndex", "cacheKey",
                        "artifactPath", "artifactPaths", "representation", "representationArtifactSha256",
                        "sourceIrSha256", "bytecodeIrSha256", "decompilerInputSha256", "resultPath",
                        "unifiedIR", "bytecodeIR", "decompilerInput", "invariantsPath", "harnessPath",
                        "deployedTarget", "deploymentPath", "invariantAssertionsExecuted", "adapterRequiredCount",
                    ):
                        if previous.get(field) is not None:
                            stage_target[field] = previous[field]
            result = runner(stage, stage_target, stage_dir, mode)
            if not isinstance(result, dict) or result.get("state") not in {"completed", "failed", "unavailable", "blocked"}:
                raise PipelineError("stage runner returned invalid state")
        except Exception as error:
            result = {"state": "failed", "reason": f"runner_error:{type(error).__name__}"}
        state["stages"][stage] = result
        state["spentUsd"] = float(state.get("spentUsd", 0.0)) + float(result.get("costUsd", 0.0) or 0.0)
        if result["state"] in {"failed", "blocked"}:
            blocked = True
    state["updatedAt"] = datetime.now(timezone.utc).isoformat()
    _atomic_json(state_path, state)
    return state


def run_pipeline(targets_path: str | Path, *, stages: list[str], mode: str = "local", budget_usd: float = 0.0,
                 output: str | Path, resume: str | Path | None = None,
                 runner: Callable[[str, dict[str, Any], Path, str], dict[str, Any]] | None = None,
                 target_concurrency: int | None = None) -> dict[str, Any]:
    if mode not in ("local", "fixed_block_fork", "replay"):
        raise PipelineError("mode 必须是 local、fixed_block_fork 或 replay")
    if isinstance(budget_usd, bool) or not isinstance(budget_usd, (int, float)) or budget_usd < 0:
        raise PipelineError("budget_usd 必须是非负数")
    selected = _validate_stages(list(stages))
    targets = _targets(Path(targets_path))
    target_keys = [_target_key(target, index) for index, target in enumerate(targets)]
    if len(set(target_keys)) != len(target_keys):
        raise PipelineError("targets 的 id/address 规范化后必须唯一")
    worker_count = _resolve_target_concurrency(target_concurrency, len(targets))
    root = Path(resume or output).resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_id = root.name
    runner = runner or _default_runner
    aggregate = {"schemaVersion": 1, "runId": run_id, "mode": mode, "budgetUsd": float(budget_usd),
                 "stages": selected, "targetConcurrency": worker_count, "targets": [], "state": "completed",
                 "generatedAt": datetime.now(timezone.utc).isoformat()}
    # Targets are independent; run them concurrently while retaining input order
    # in the aggregate for deterministic reports and resumable consumers.
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="pipeline-target") as executor:
        futures = [executor.submit(_run_target, index, target, selected, root, mode, float(budget_usd), runner)
                   for index, target in enumerate(targets)]
        states = [future.result() for future in futures]
    aggregate["targets"] = states
    for state in states:
        stage_states = [item.get("state") for item in state["stages"].values()]
        if any(value in {"failed", "blocked"} for value in stage_states):
            aggregate["state"] = "partial"
        elif any(value == "unavailable" for value in stage_states):
            aggregate["state"] = "partial"
        elif any(value != "completed" for value in stage_states):
            aggregate["state"] = "partial"
    _atomic_json(root / "run.json", aggregate)
    return aggregate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--targets", required=True)
    run.add_argument("--stages", required=True, help="逗号分隔的阶段")
    run.add_argument("--mode", default="local", choices=("local", "fixed_block_fork", "replay"))
    run.add_argument("--budget-usd", type=float, default=0.0)
    run.add_argument("--target-concurrency", type=int, default=None,
                     help="并行目标数（1-8，默认读取 PIPELINE_TARGET_CONCURRENCY 或 4）")
    run.add_argument("--output", required=True)
    run.add_argument("--resume")
    args = parser.parse_args(argv)
    try:
        result = run_pipeline(args.targets, stages=[item.strip() for item in args.stages.split(",") if item.strip()],
                              mode=args.mode, budget_usd=args.budget_usd, output=args.output, resume=args.resume,
                              target_concurrency=args.target_concurrency)
    except (PipelineError, OSError) as error:
        print(f"pipeline failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"runId": result["runId"], "state": result["state"], "output": str(Path(args.resume or args.output).resolve())}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
