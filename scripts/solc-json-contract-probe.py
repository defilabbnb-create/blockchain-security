#!/usr/bin/env python3
"""测定 solc 各版本在标准 JSON 下的产出契约差异（AST 键名、compilationTarget 支持、sourceMap）。

crytic-compile 的 parse_standard_json_output 硬依赖：
- sources[file]["ast"]（旧版本可能只给 legacyAST）
- contracts[file][name]["evm"]["bytecode"]["sourceMap"]
- contracts[file][name]["evm"]["deployedBytecode"]["sourceMap"]
并且 settings.compilationTarget 只在部分版本生效。
本脚本用一份最小合约逐版本实测这些键的真实存在性。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "work" / "compiler-cache"
WRAPPER = ROOT / "scripts" / "campaign-solc.cjs"

MINIMAL = """pragma solidity >=0.4.0;
contract Probe {
    uint public value;
    function setValue(uint v) public { value = v; }
}
"""


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


def run(soljson: Path, bundle: dict) -> dict:
    env = {**os.environ, "CAMPAIGN_SOLJSON": str(soljson)}
    try:
        completed = subprocess.run(
            ["node", str(WRAPPER), "--standard-json"], input=json.dumps(bundle),
            cwd=ROOT, capture_output=True, text=True, timeout=120, check=False, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "errorCode": "timeout"}
    if not completed.stdout.strip():
        return {"ok": False, "errorCode": "no_stdout", "stderr": completed.stderr[-200:]}
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "errorCode": "stdout_not_json", "stderr": completed.stderr[-200:]}
    if not isinstance(output, dict):
        return {"ok": False, "errorCode": "output_not_object"}
    raw = output.get("errors")
    raw = raw if isinstance(raw, list) else []
    errors = [e for e in raw if isinstance(e, dict) and e.get("severity") == "error"]
    return {"ok": not errors, "output": output,
            "firstError": (errors[0].get("formattedMessage") or "")[:220] if errors else None}


def inspect(output: dict) -> dict:
    sources = output.get("sources") if isinstance(output.get("sources"), dict) else {}
    contracts = output.get("contracts") if isinstance(output.get("contracts"), dict) else {}
    unit = next(iter(sources.values()), {}) if sources else {}
    unit = unit if isinstance(unit, dict) else {}
    ast = unit.get("ast")
    ast = ast if isinstance(ast, dict) else {}
    entry: dict = {}
    for file_entries in contracts.values():
        if isinstance(file_entries, dict):
            for candidate in file_entries.values():
                if isinstance(candidate, dict):
                    entry = candidate
                    break
        if entry:
            break
    bytecode = entry.get("evm", {}).get("bytecode", {}) if isinstance(entry.get("evm"), dict) else {}
    deployed = entry.get("evm", {}).get("deployedBytecode", {}) if isinstance(entry.get("evm"), dict) else {}
    return {
        "astKeyPresent": "ast" in unit,
        "legacyAstKeyPresent": "legacyAST" in unit,
        "astHasNodes": bool(ast.get("nodes")),
        "legacyAstHasNodes": bool((unit.get("legacyAST") or {}).get("nodes")),
        "bytecodeSourceMap": "sourceMap" in (bytecode or {}),
        "deployedSourceMap": "sourceMap" in (deployed or {}),
        "contractNames": sorted(contracts.get("Probe.sol", {}).keys()) if isinstance(contracts.get("Probe.sol"), dict) else [],
    }


def main() -> int:
    rows = []
    for version in cached_versions():
        soljson = soljson_path(version)
        if soljson is None:
            continue
        # 1) 只请求 ast（旧 crytic-compile 默认行为）
        plain = run(soljson, {
            "language": "Solidity", "sources": {"Probe.sol": {"content": MINIMAL}},
            "settings": {"outputSelection": {"*": {"*": ["abi", "evm.bytecode", "evm.deployedBytecode"], "": ["ast"]}}}})
        # 2) 同时请求 ast + legacyAST
        both = run(soljson, {
            "language": "Solidity", "sources": {"Probe.sol": {"content": MINIMAL}},
            "settings": {"outputSelection": {"*": {"*": ["abi", "evm.bytecode", "evm.deployedBytecode"], "": ["ast", "legacyAST"]}}}})
        # 3) 带 compilationTarget
        targeted = run(soljson, {
            "language": "Solidity", "sources": {"Probe.sol": {"content": MINIMAL}},
            "settings": {"compilationTarget": {"Probe.sol": "Probe"},
                         "outputSelection": {"*": {"*": ["abi", "evm.bytecode", "evm.deployedBytecode"], "": ["ast", "legacyAST"]}}}})
        row = {
            "version": version,
            "plain": {k: v for k, v in plain.items() if k != "output"},
            "both": {k: v for k, v in both.items() if k != "output"},
            "targeted": {k: v for k, v in targeted.items() if k != "output"},
        }
        if plain.get("output"):
            row["plain"].update(inspect(plain["output"]))
        if both.get("output"):
            row["both"].update(inspect(both["output"]))
        if targeted.get("output"):
            row["targeted"].update(inspect(targeted["output"]))
        rows.append(row)
        p = row["plain"]
        b = row["both"]
        t = row["targeted"]
        print(f"{version:>8} plain_ok={p.get('ok')} ast={p.get('astKeyPresent')} legacy={p.get('legacyAstKeyPresent')} "
              f"nodes={p.get('astHasNodes')}/{p.get('legacyAstHasNodes')} srcmap={p.get('bytecodeSourceMap')} "
              f"| both_ok={b.get('ok')} both_legacy_nodes={b.get('legacyAstHasNodes')} "
              f"| target_ok={t.get('ok')} target_names={t.get('contractNames')} target_err={(t.get('firstError') or '')[:80]!r}")
    out = ROOT / "work" / "solc-json-contract-compat.json"
    out.write_text(json.dumps({"schemaVersion": 1, "rows": rows}, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    print(f"\n写出 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
