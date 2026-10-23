#!/usr/bin/env python3
"""实测每个 solc 版本对同一份源码的真实产出能力。

逐版本检查（不看缓存状态、不看 pragma 推测）：
- 编译是否成功（severity=error 的条数）
- 产出合约数、是否含非空字节码
- AST 是否存在、是否含 nodes（旧版可能是 legacyAST 形态）
- evm.bytecode.sourceMap 是否存在（crytic-compile 硬依赖这个 key）
- outputSelection 里 "*"/"*" 与 "*"/"" 在旧版的行为差异
只读源码、只读编译器缓存，不改语料、不改 manifest。
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
WRAPPER = ROOT / "scripts" / "campaign-solc.cjs"


def soljson_path(version: str) -> Path | None:
    for path in CACHE.glob(f"soljson-v{version}+*.cjs"):
        return path
    return None


def cached_versions() -> list[str]:
    versions = []
    for path in CACHE.glob("soljson-v*.cjs"):
        match = re.match(r"^soljson-v(\d+\.\d+\.\d+)", path.name)
        if match:
            versions.append(match.group(1))
    return sorted(set(versions), key=lambda v: tuple(int(p) for p in v.split(".")))


def run_solc(soljson: Path, bundle: dict, timeout: float = 120.0) -> dict:
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(soljson)}
    try:
        completed = subprocess.run(
            ["node", str(WRAPPER), "--standard-json"],
            input=json.dumps(bundle), cwd=ROOT, capture_output=True,
            text=True, timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "errorCode": "timeout"}
    if not completed.stdout.strip():
        return {"ok": False, "errorCode": "no_stdout", "stderr": completed.stderr[-300:]}
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "errorCode": "stdout_not_json",
                "stderr": completed.stderr[-300:], "stdout": completed.stdout[:200]}
    if not isinstance(output, dict):
        return {"ok": False, "errorCode": "output_not_object"}
    raw = output.get("errors")
    raw = raw if isinstance(raw, list) else []
    errors = [e for e in raw if isinstance(e, dict) and e.get("severity") == "error"]
    warnings = [e for e in raw if isinstance(e, dict) and e.get("severity") == "warning"]
    contracts = output.get("contracts")
    contracts = contracts if isinstance(contracts, dict) else {}
    sources = output.get("sources")
    sources = sources if isinstance(sources, dict) else {}
    return {
        "ok": not errors,
        "errorCount": len(errors),
        "warningCount": len(warnings),
        "firstError": (errors[0].get("formattedMessage") or errors[0].get("message") or "")[:400] if errors else None,
        "errorCode": errors[0].get("errorCode") if errors else None,
        "contractCount": len(contracts),
        "contractNames": sorted(contracts.keys())[:12],
        "sourceUnitCount": len(sources),
        "output": output,
    }


def summarize_shapes(result: dict) -> dict:
    """检查 AST / sourceMap 在该版本下的真实形态。"""
    output = result.get("output") or {}
    summary: dict = {}
    sources = output.get("sources") if isinstance(output.get("sources"), dict) else {}
    ast_units = []
    for name, info in sources.items():
        if not isinstance(info, dict):
            continue
        ast_units.append({
            "name": name,
            "hasAst": isinstance(info.get("ast"), dict),
            "astHasNodes": bool((info.get("ast") or {}).get("nodes")) if isinstance(info.get("ast"), dict) else False,
            "hasLegacyAst": "legacyAST" in info,
        })
    summary["astUnits"] = ast_units[:4]
    contracts = output.get("contracts") if isinstance(output.get("contracts"), dict) else {}
    bytecode_with_srcmap = 0
    bytecode_without_srcmap = 0
    deployable = []
    for file_name, entries in contracts.items():
        if not isinstance(entries, dict):
            continue
        for name, entry in entries.items():
            if not isinstance(entry, dict):
                continue
            evm = entry.get("evm")
            if not isinstance(evm, dict):
                continue
            bytecode = evm.get("bytecode")
            if not isinstance(bytecode, dict):
                continue
            if "sourceMap" in bytecode:
                bytecode_with_srcmap += 1
            else:
                bytecode_without_srcmap += 1
            obj = bytecode.get("object")
            if isinstance(obj, str) and len(obj) > 2:
                deployable.append(name)
    summary["bytecodeWithSourceMap"] = bytecode_with_srcmap
    summary["bytecodeWithoutSourceMap"] = bytecode_without_srcmap
    summary["deployableContracts"] = sorted(deployable)[:12]
    summary["cryticCompatible"] = bytecode_without_srcmap == 0
    return summary


SELECTIONS = {
    "star_star": {"*": {"*": ["abi", "evm.bytecode", "evm.deployedBytecode"], "": ["ast"]}},
    "star_empty": {"*": {"": ["ast"]}},
}


def probe(source: str, source_path: str, version: str) -> dict:
    soljson = soljson_path(version)
    if soljson is None:
        return {"version": version, "available": False, "errorCode": "compiler_not_cached"}
    row: dict = {"version": version, "available": True}
    for label, selection in SELECTIONS.items():
        bundle = {
            "language": "Solidity",
            "sources": {source_path: {"content": source}},
            "settings": {"outputSelection": selection},
        }
        result = run_solc(soljson, bundle)
        entry = {k: v for k, v in result.items() if k != "output"}
        entry.update(summarize_shapes(result))
        row[label] = entry
    return row


def main() -> int:
    manifest_path = ROOT / "training-data/github-vulnerabilities/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    wanted = sys.argv[1:]
    versions = cached_versions()
    rows = []
    for sample in manifest["samples"]:
        analysis = sample.get("analysis", {})
        if analysis.get("static") == "passed":
            continue
        path = sample["path"]
        if wanted and not any(key in path for key in wanted):
            continue
        source = (ROOT / sample["objectPath"]).read_text(encoding="utf-8", errors="replace")
        attempts = [probe(source, path, version) for version in versions]
        row = {
            "path": path,
            "recordedCompiler": analysis.get("compilerVersion"),
            "recordedSelection": analysis.get("compilerSelection"),
            "recordedReason": (analysis.get("staticReason") or "")[:200],
            "attempts": attempts,
        }
        rows.append(row)
        print(f"### {path}")
        for attempt in attempts:
            star = attempt.get("star_star") or {}
            print(f"   {attempt['version']:>8} err={star.get('errorCount')} contracts={star.get('contractCount')} "
                  f"srcmap={star.get('bytecodeWithSourceMap')}/{star.get('bytecodeWithoutSourceMap')} "
                  f"ast={star.get('astUnits')} crytic_ok={star.get('cryticCompatible')}")
            if star.get("firstError"):
                print(f"            err: {star['firstError'][:150]!r}")
        print(flush=True)
    out = ROOT / "work" / "solc-version-capability-matrix.json"
    out.write_text(json.dumps({"schemaVersion": 1, "cachedVersions": versions, "samples": rows},
                              ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"写出 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
