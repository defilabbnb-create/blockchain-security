#!/usr/bin/env python3
"""Run the local static-analysis pipeline against explicitly labeled contracts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "benchmark" / "contracts"
RESULTS = ROOT / "benchmark" / "results"
ANALYZER = ROOT / "scripts" / "review-static.py"
DETECTOR_CATEGORIES = {
    "reentrancy-eth": "reentrancy", "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy", "reentrancy-events": "reentrancy",
    "arbitrary-send-eth": "access_control", "suicidal": "access_control",
    "unprotected-upgrade": "access_control", "tx-origin": "access_control",
    "unchecked-lowlevel": "unchecked_low_level_calls", "unchecked-send": "unchecked_low_level_calls",
    "incorrect-exp": "arithmetic", "divide-before-multiply": "arithmetic",
    "timestamp": "time_manipulation", "weak-prng": "bad_randomness",
    "tod": "front_running", "locked-ether": "denial_of_service",
}


class BenchmarkError(ValueError):
    pass


def _json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"无法读取 JSON: {path}") from error
    if not isinstance(value, dict):
        raise BenchmarkError(f"JSON 顶层必须是对象: {path}")
    return value


def _validate_truth(truth: dict[str, Any], path: Path) -> list[str]:
    known = truth.get("knownIssues")
    clean = truth.get("clean")
    source = truth.get("source")
    if not isinstance(known, list) or any(not isinstance(item, str) or not item for item in known):
        raise BenchmarkError(f"knownIssues 必须是非空字符串列表: {path}")
    if len(set(known)) != len(known):
        raise BenchmarkError(f"knownIssues 不得重复: {path}")
    if not isinstance(clean, bool) or not isinstance(source, str) or not source.startswith("https://"):
        raise BenchmarkError(f"ground-truth 必须包含 clean 布尔值和 HTTPS source: {path}")
    if clean and known:
        raise BenchmarkError(f"clean 样本不能同时声明 knownIssues: {path}")
    if not clean and not known:
        raise BenchmarkError(f"非 clean 样本必须声明已知问题: {path}")
    return known


def _bundle_path(case_dir: Path, truth: dict[str, Any]) -> Path:
    source_file = truth.get("sourceFile")
    if source_file is not None:
        if not isinstance(source_file, str) or not source_file:
            raise BenchmarkError(f"sourceFile 无效: {case_dir}")
        source = (case_dir / source_file).resolve()
        if case_dir.resolve() not in source.parents or not source.is_file():
            raise BenchmarkError(f"sourceFile 必须位于样本目录内: {case_dir}")
        version = truth.get("solcVersion")
        if not isinstance(version, str) or not version:
            raise BenchmarkError(f"solcVersion 缺失: {case_dir}")
        return source
    relative = truth.get("bundlePath", "verified-source.json")
    if not isinstance(relative, str) or not relative:
        raise BenchmarkError(f"bundlePath 无效: {case_dir}")
    candidate = (case_dir / relative).resolve()
    if case_dir.resolve() not in candidate.parents or not candidate.is_file():
        raise BenchmarkError(f"源码 bundle 必须是样本目录内的现有文件: {case_dir}")
    return candidate


def _source_hash(bundle: Path) -> str:
    if bundle.suffix == ".sol":
        return hashlib.sha256(bundle.read_bytes()).hexdigest()
    data = _json_file(bundle)
    sources = data.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise BenchmarkError(f"bundle 缺少 sources: {bundle}")
    for name, row in sorted(sources.items()):
        if not isinstance(name, str) or not isinstance(row, dict) or not isinstance(row.get("content"), str):
            raise BenchmarkError(f"bundle source 缺少文本内容: {bundle}")
    payload = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def score_case(known_issues: list[str], detected_issues: list[str]) -> dict[str, Any]:
    expected = set(known_issues)
    detected = set(detected_issues)
    true_positive = len(expected & detected)
    false_positive = len(detected - expected)
    false_negative = len(expected - detected)
    return {"truePositiveCount": true_positive, "falsePositiveCount": false_positive,
            "falseNegativeCount": false_negative}


def _analyze(bundle: Path, timeout: float) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["DYNAMIC_EXECUTION_MODE"] = "local"
    environment.pop("DYNAMIC_FORK_RPC_URL", None)
    environment.pop("DYNAMIC_FORK_BLOCK_NUMBER", None)
    try:
        analyzer_input = bundle
        temporary = None
        if bundle.suffix == ".sol":
            source = bundle.read_text(encoding="utf-8")
            version_match = __import__("re").search(r"pragma\s+solidity\s+[^;]*?(\d+\.\d+\.\d+)", source)
            if not version_match:
                raise BenchmarkError(f"Solidity pragma 缺少固定编译器版本: {bundle}")
            temporary = tempfile.TemporaryDirectory(prefix=".benchmark-bundle-", dir=bundle.parent)
            analyzer_input = Path(temporary.name) / "verified-source.json"
            source_name = bundle.name
            payload = {"sources": {source_name: {"content": source}},
                       "compilation": {"compilerVersion": version_match.group(1)},
                       "metadata": {"settings": {"compilationTarget": {source_name: source_name.removesuffix(".sol")}}}}
            analyzer_input.write_text(json.dumps(payload), encoding="utf-8")
        try:
            completed = subprocess.run([sys.executable, str(ANALYZER), str(analyzer_input)], cwd=ROOT,
                                       env=environment, capture_output=True, text=True,
                                       timeout=timeout, check=False)
        finally:
            if temporary:
                temporary.cleanup()
    except subprocess.TimeoutExpired as error:
        raise BenchmarkError("分析超时") from error
    if completed.returncode != 0:
        raise BenchmarkError(f"分析进程失败，退出码 {completed.returncode}")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BenchmarkError("分析器没有返回有效 JSON") from error
    if not isinstance(result, dict) or result.get("state") not in ("completed", "partial"):
        reason = result.get("staticError") or result.get("error") or result.get("state") if isinstance(result, dict) else "分析结果格式无效"
        raise BenchmarkError(f"分析结果不可评测: {str(reason)[:300]}")
    findings = result.get("findings")
    if not isinstance(findings, list):
        raise BenchmarkError("分析结果缺少 findings 列表")
    checks = []
    for finding in findings:
        if (isinstance(finding, dict) and isinstance(finding.get("check"), str)
                and str(finding.get("impact", "")).lower() in ("high", "medium", "low")):
            checks.append(DETECTOR_CATEGORIES.get(finding["check"], finding["check"]))
    return {"findings": checks, "analysisState": result["state"],
            "findingCount": len(findings), "sourceFingerprint": result.get("verifiedSourceFingerprint")}


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


EVAL_LAYERS = ("slither", "ir-reconcile", "invariants", "poc")


def _layer_observations(result: dict[str, Any], layer: str) -> list[str]:
    """Read a layer-specific result without promoting missing evidence."""
    if layer == "slither":
        return list(result.get("findings", [])) if isinstance(result.get("findings"), list) else []
    value = result.get(layer)
    if isinstance(value, dict):
        value = value.get("findings", value.get("issues", value.get("detected", [])))
    return list(value) if isinstance(value, list) else []


def _layer_metrics(rows: list[dict[str, Any]], layer: str) -> dict[str, Any]:
    tp = fp = fn = 0
    sample_count = 0
    for row in rows:
        if layer not in row.get("layers", {}):
            continue
        sample_count += 1
        counts = row["layers"][layer]
        tp += counts["truePositiveCount"]
        fp += counts["falsePositiveCount"]
        fn += counts["falseNegativeCount"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"sampleCount": sample_count, "truePositiveCount": tp,
            "falsePositiveCount": fp, "falseNegativeCount": fn,
            "precision": precision, "recall": recall,
            "no_incremental_value_detected": sample_count > 0 and tp == 0}


def run_evaluation(contracts_dir: Path = CONTRACTS, results_dir: Path = RESULTS,
                   timeout: float = 900, analyzer=None, layers=None) -> dict[str, Any]:
    selected_layers = list(layers or ("slither",))
    if not selected_layers or any(layer not in EVAL_LAYERS for layer in selected_layers):
        raise BenchmarkError(f"layers 必须来自: {', '.join(EVAL_LAYERS)}")
    started = time.monotonic()
    rows = []
    tp = fp = fn = 0
    case_dirs = contracts_dir.iterdir() if contracts_dir.is_dir() else ()
    for case_dir in sorted(path for path in case_dirs if path.is_dir()):
        truth_path = case_dir / "ground-truth.json"
        if not truth_path.is_file():
            continue
        truth = _json_file(truth_path)
        known = _validate_truth(truth, truth_path)
        bundle = _bundle_path(case_dir, truth)
        input_hash = _source_hash(bundle)
        try:
            result = (analyzer or _analyze)(bundle, timeout)
            detected = _layer_observations(result, "slither")
            counts = score_case(known, detected)
            tp += counts["truePositiveCount"]
            fp += counts["falsePositiveCount"]
            fn += counts["falseNegativeCount"]
            rows.append({"caseId": case_dir.name, "state": "scored", "clean": truth["clean"],
                         "knownIssues": known, "detectedIssues": sorted(set(detected)),
                         "inputSourceSha256": input_hash, "layers": {
                             layer: score_case(known, _layer_observations(result, layer))
                             | {"detectedIssues": sorted(set(_layer_observations(result, layer)))}
                             for layer in selected_layers
                         }, **counts})
        except BenchmarkError as error:
            rows.append({"caseId": case_dir.name, "state": "unscored", "reason": str(error),
                         "knownIssues": known, "inputSourceSha256": input_hash})
    scored = [row for row in rows if row["state"] == "scored"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    report = {"schemaVersion": 1, "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "sampleCount": len(rows), "scoredSampleCount": len(scored),
              "unscoredSampleCount": len(rows) - len(scored), "precision": precision, "recall": recall,
              "falsePositiveCount": fp, "truePositiveCount": tp, "falseNegativeCount": fn,
              "costUsd": 0.0, "costScope": "本地静态分析；未调用云端模型", "durationMs": round((time.monotonic() - started) * 1000),
              "layers": {layer: _layer_metrics(rows, layer) for layer in selected_layers},
              "selectedLayers": selected_layers,
              "metricsScope": "按显式层分别统计；缺少某层证据不计为通过，静态信号不代表确认漏洞",
              "samples": rows}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = results_dir / f"{stamp}.json"
    _atomic_json(output, report)
    report["resultPath"] = str(output)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="对有明确 ground-truth 的 Solidity 样本运行本地静态分析评测")
    parser.add_argument("--contracts", type=Path, default=CONTRACTS)
    parser.add_argument("--results", type=Path, default=RESULTS)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--layers", default="slither",
                        help="逗号分隔的评测层: slither,ir-reconcile,invariants,poc,all")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        print(json.dumps({"status": "invalid", "error": "timeout 无效"}, ensure_ascii=False))
        return 2
    try:
        selected = [item.strip() for item in args.layers.split(",") if item.strip()]
        if "all" in selected:
            selected = list(EVAL_LAYERS)
        result = run_evaluation(args.contracts, args.results, args.timeout, layers=selected)
    except (BenchmarkError, OSError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, ensure_ascii=False))
        return 1
    result["status"] = "completed" if result["scoredSampleCount"] else "no_scored_samples"
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["scoredSampleCount"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
