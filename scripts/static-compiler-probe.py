#!/usr/bin/env python3
"""编译器矩阵探针（修正版）。

用途：为静态层的 failed / partial 样本定性根因，而不是靠推测。
要点：
- 合约名提取必须先剥离注释，否则会命中注释里的英文单词。
- 编译器路径必须用绝对路径，否则 node require 解析失败。
- 只读源码，只调用本地缓存 soljson，不写语料、不改 manifest。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "work" / "compiler-cache"
SOLC_WRAPPER = ROOT / "scripts" / "campaign-solc.cjs"
sys.path.insert(0, str(ROOT / "scripts"))


def strip_comments(source: str) -> str:
    """剥离 Solidity 注释但保留字符串与行结构（与 analyze-training-corpus.py 同语义）。"""
    output: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char in ('"', "'"):
                state, quote = "string", char
                output.append(char)
            elif char == "/" and next_char == "/":
                state = "line_comment"
            elif char == "/" and next_char == "*":
                state = "block_comment"
                output.append(" ")
                output.append(" ")
                index += 1
            else:
                output.append(char)
        elif state == "string":
            output.append(char)
            if char == "\\" and next_char:
                output.append(next_char)
                index += 1
            elif char == quote:
                state = "code"
        elif state == "line_comment":
            if char == "\n":
                output.append(char)
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        index += 1
    return "".join(output)


def cached_versions() -> list[str]:
    versions = []
    for path in CACHE.glob("soljson-v*.cjs"):
        match = re.match(r"^soljson-v(\d+\.\d+\.\d+)", path.name)
        if match:
            versions.append(match.group(1))
    return sorted(set(versions), key=lambda value: tuple(int(part) for part in value.split(".")))


def soljson_path(version: str) -> Path | None:
    for path in CACHE.glob(f"soljson-v{version}*.cjs"):
        return path
    return None


def target_contract(source: str) -> str | None:
    """提取真实合约名：先剥离注释，避免命中注释里的英文单词。"""
    code = strip_comments(source)
    for keyword in ("contract", "library", "interface"):
        names = re.findall(r"\b" + keyword + r"\s+([A-Za-z_$][A-Za-z0-9_$]*)", code)
        if names:
            return names[0]
    return None


def compile_with(source: str, source_path: str, contract: str | None, version: str,
                 timeout: float = 120.0) -> dict:
    soljson = soljson_path(version)
    if soljson is None:
        return {"version": version, "available": False, "ok": False, "errorCode": "compiler_not_cached"}
    settings = {"outputSelection": {"*": {"*": ["evm.bytecode.object"]}}}
    if contract:
        settings["compilationTarget"] = {source_path: contract}
    bundle = {"language": "Solidity", "sources": {source_path: {"content": source}}, "settings": settings}
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(soljson)}
    try:
        completed = subprocess.run(
            ["node", str(SOLC_WRAPPER), "--standard-json"], input=json.dumps(bundle), cwd=ROOT,
            capture_output=True, text=True, timeout=timeout, check=False, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"version": version, "available": True, "ok": False, "errorCode": "timeout"}
    if not completed.stdout.strip():
        return {"version": version, "available": True, "ok": False, "errorCode": "no_stdout",
                "stderr": completed.stderr[-300:]}
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"version": version, "available": True, "ok": False, "errorCode": "stdout_not_json"}
    if not isinstance(output, dict):
        return {"version": version, "available": True, "ok": False,
                "errorCode": f"output_not_object:{type(output).__name__}"}
    raw_errors = output.get("errors")
    if not isinstance(raw_errors, list):
        raw_errors = []
    errors = [item for item in raw_errors if isinstance(item, dict) and item.get("severity") == "error"]
    warnings = [item for item in raw_errors if isinstance(item, dict) and item.get("severity") == "warning"]
    contracts = output.get("contracts")
    contracts = contracts.get(source_path, {}) if isinstance(contracts, dict) else {}
    if not isinstance(contracts, dict):
        contracts = {}
    bytecode = ""
    for entry in contracts.values():
        if not isinstance(entry, dict):
            continue
        code = entry.get("evm", {}).get("bytecode", {}).get("object", "")
        if isinstance(code, str) and len(code) > len(bytecode):
            bytecode = code
    return {
        "version": version, "available": True, "ok": not errors,
        "errorCount": len(errors), "warningCount": len(warnings),
        "contractCount": len(contracts), "bytecodeLength": len(bytecode) // 2,
        "errorCode": errors[0].get("errorCode") if errors else None,
        "firstError": (errors[0].get("formattedMessage") or errors[0].get("message") or "")[:400] if errors else None,
        "firstWarning": (warnings[0].get("formattedMessage") or warnings[0].get("message") or "")[:240] if warnings else None,
    }


def main() -> int:
    manifest = json.loads((ROOT / "training-data/github-vulnerabilities/manifest.json").read_text())
    wanted = sys.argv[1:] or None
    rows = []
    for sample in manifest["samples"]:
        path = sample["path"]
        if wanted and not any(key in path for key in wanted):
            continue
        analysis = sample.get("analysis", {})
        state = analysis.get("static")
        if state == "passed":
            continue
        source = (ROOT / sample["objectPath"]).read_text(encoding="utf-8", errors="replace")
        contract = target_contract(source)
        raw_names = re.findall(r"\bcontract\s+([A-Za-z_$][A-Za-z0-9_$]*)", source)
        attempts = [compile_with(source, path, contract, version) for version in cached_versions()]
        good = [item for item in attempts if item.get("ok") and item.get("bytecodeLength", 0) > 0]
        rows.append({
            "path": path, "sha256": sample["sha256"], "staticState": state,
            "staticReason": analysis.get("staticReason"),
            "currentCompiler": analysis.get("compilerVersion"),
            "recordedCandidates": analysis.get("compilerCandidates"),
            "targetContract": contract, "rawFirstContractMatch": raw_names[0] if raw_names else None,
            "attempts": attempts,
        })
        print(f"### {path}")
        print(f"    记录状态={state} 记录编译器={analysis.get('compilerVersion')}")
        print(f"    剥离注释后目标合约={contract!r} （原实现取到 {raw_names[0] if raw_names else None!r}）")
        print(f"    可编译且有字节码的版本数={len(good)} -> {[i['version'] for i in good][:12]}")
        classes: dict[str, list[str]] = {}
        for item in attempts:
            if item.get("ok") or item.get("bytecodeLength"):
                continue
            key = (item.get("firstError") or item.get("errorCode") or "unknown")[:90]
            classes.setdefault(key, []).append(item["version"])
        for key, versions in list(classes.items())[:6]:
            print(f"    失败类 {key!r} 出现于 {versions[:12]}")
        print()
    out = ROOT / "work" / "static-compiler-matrix-probe.json"
    out.write_text(json.dumps({"schemaVersion": 1, "generatedAt": "probe",
                               "cachedVersions": cached_versions(), "samples": rows},
                              ensure_ascii=False, indent=2) + "\n")
    print(f"写出 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
