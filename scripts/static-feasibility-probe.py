#!/usr/bin/env python3
"""静态层失败样本的编译器可行性与可部署合约探针。

对每个非 passed 样本：
- 不设 compilationTarget，编译一次并读取所有合约的字节码，
  据此确定哪些合约是真正可部署的（排除抽象/接口合约）。
- 遍历本地缓存的全部编译器，记录真实成功/失败与错误分类。
只读源码，不写语料、不改 manifest。
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
                output.extend((" ", " "))
                index += 1
            elif char == "*" and next_char == "/":
                state = "block_comment"
                output.extend((" ", " "))
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


def contract_names(source: str) -> list[str]:
    code = strip_comments(source)
    names = re.findall(r"\b(?:abstract\s+)?contract\s+([A-Za-z_$][A-Za-z0-9_$]*)", code)
    return names


def compile_all(source: str, source_path: str, version: str, timeout: float = 120.0) -> dict:
    soljson = soljson_path(version)
    if soljson is None:
        return {"version": version, "available": False, "ok": False, "errorCode": "compiler_not_cached"}
    bundle = {
        "language": "Solidity",
        "sources": {source_path: {"content": source}},
        "settings": {"outputSelection": {"*": {"*": ["evm.bytecode.object"]}}},
    }
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(soljson)}
    try:
        completed = subprocess.run(
            ["node", str(SOLC_WRAPPER), "--standard-json"], input=json.dumps(bundle), cwd=ROOT,
            capture_output=True, text=True, timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired:
        return {"version": version, "available": True, "ok": False, "errorCode": "timeout"}
    if not completed.stdout.strip():
        return {"version": version, "available": True, "ok": False, "errorCode": "no_stdout",
                "stderr": completed.stderr[-200:]}
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"version": version, "available": True, "ok": False, "errorCode": "stdout_not_json"}
    if not isinstance(output, dict):
        return {"version": version, "available": True, "ok": False, "errorCode": "output_not_object"}
    raw_errors = output.get("errors")
    raw_errors = raw_errors if isinstance(raw_errors, list) else []
    errors = [item for item in raw_errors if isinstance(item, dict) and item.get("severity") == "error"]
    contracts = output.get("contracts")
    contracts = contracts.get(source_path, {}) if isinstance(contracts, dict) else {}
    if not isinstance(contracts, dict):
        contracts = {}
    deployable = []
    for name, entry in contracts.items():
        if not isinstance(entry, dict):
            continue
        code = entry.get("evm", {}).get("bytecode", {}).get("object", "")
        if isinstance(code, str) and len(code) > 2:
            deployable.append({"name": name, "bytecodeLength": len(code) // 2})
    return {
        "version": version, "available": True, "ok": not errors,
        "errorCount": len(errors), "deployableContracts": deployable,
        "firstError": (errors[0].get("formattedMessage") or errors[0].get("message") or "")[:300] if errors else None,
    }


def main() -> int:
    manifest = json.loads((ROOT / "training-data/github-vulnerabilities/manifest.json").read_text())
    rows = []
    for sample in manifest["samples"]:
        analysis = sample.get("analysis", {})
        if analysis.get("static") == "passed":
            continue
        path = sample["path"]
        source = (ROOT / sample["objectPath"]).read_text(encoding="utf-8", errors="replace")
        names = contract_names(source)
        attempts = [compile_all(source, path, version) for version in cached_versions()]
        workable = [item for item in attempts if item.get("ok")]
        deployable = workable[-1]["deployableContracts"] if workable else []
        rows.append({
            "path": path, "sha256": sample["sha256"],
            "staticState": analysis.get("static"),
            "staticReason": analysis.get("staticReason"),
            "recordedCompiler": analysis.get("compilerVersion"),
            "recordedCandidates": analysis.get("compilerCandidates"),
            "declaredContracts": names,
            "workableCompilers": [item["version"] for item in workable],
            "deployableContracts": deployable,
            "attempts": attempts,
        })
        print(f"### {path}")
        print(f"    记录状态={analysis.get('static')} 记录编译器={analysis.get('compilerVersion')} 记录候选={analysis.get('compilerCandidates')}")
        print(f"    声明的合约={names}")
        print(f"    可编译成功的编译器={len(workable)} {[i['version'] for i in workable][:16]}")
        print(f"    可部署合约={[d['name'] for d in deployable][:8]}")
        classes: dict[str, list[str]] = {}
        for item in attempts:
            if item.get("ok"):
                continue
            key = (item.get("firstError") or item.get("errorCode") or "unknown")[:80]
            classes.setdefault(key, []).append(item["version"])
        for key, versions in list(classes.items())[:5]:
            print(f"    失败类 {key!r} -> {versions[:12]}")
        print()
    out = ROOT / "work" / "static-compiler-feasibility.json"
    out.write_text(json.dumps({"schemaVersion": 1, "cachedVersions": cached_versions(), "samples": rows},
                              ensure_ascii=False, indent=2) + "\n")
    print(f"写出 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
