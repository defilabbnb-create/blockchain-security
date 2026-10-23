#!/usr/bin/env python3
"""静态层目标矩阵：实测每个非 passed 样本在 (编译器, 目标合约) 组合下的真实分析结果。

目的：用实测结果替代推测，为每个失败样本确定真正可用的编译器与编译目标。
只读源码、只写 work/ 下的探针产物，不修改语料与 manifest。
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import importlib.util

_spec = importlib.util.spec_from_file_location("atc", ROOT / "scripts/analyze-training-corpus.py")
_atc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_atc)


def declared_contracts(source: str) -> list[str]:
    code = _atc.strip_solidity_comments(source)
    names = re.findall(r"\b(?:abstract\s+)?contract\s+([A-Za-z_$][A-Za-z0-9_$]*)", code)
    seen: list[str] = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen


def run_analyzer(source: str, source_path: str, contract: str | None, version: str) -> dict:
    directory = tempfile.mkdtemp(prefix="probe-m-", dir=ROOT / "work")
    bundle = Path(directory) / "verified-source.json"
    metadata: dict = {"settings": {}}
    if contract:
        metadata = {"settings": {"compilationTarget": {source_path: contract}}}
    bundle.write_text(json.dumps({
        "schemaVersion": 1,
        "sources": {source_path: {"content": source}},
        "metadata": metadata,
        "compilation": {"compilerVersion": version},
    }, ensure_ascii=False), encoding="utf-8")
    try:
        completed = subprocess.run(["python3", str(ROOT / "scripts/review-static.py"), str(bundle)],
                                   cwd=ROOT, capture_output=True, text=True, timeout=300, check=False)
    except subprocess.TimeoutExpired:
        return {"contract": contract, "version": version, "state": "timeout", "contracts": None,
                "findingCount": None, "staticError": "analyzer_timeout"}
    rows = [line for line in completed.stdout.splitlines() if line.strip().startswith("{")]
    payload: dict = {}
    if rows:
        try:
            payload = json.loads(rows[-1])
        except json.JSONDecodeError:
            payload = {}
    return {
        "contract": contract,
        "version": version,
        "state": payload.get("state"),
        "contracts": payload.get("contracts"),
        "findingCount": payload.get("findingCount"),
        "staticError": str(payload.get("staticError") or payload.get("reason") or "")[:300] or None,
        "exitCode": completed.returncode,
    }


def main() -> int:
    manifest = json.loads((ROOT / "training-data/github-vulnerabilities/manifest.json").read_text())
    feasibility = json.loads((ROOT / "work/static-compiler-feasibility.json").read_text())
    feasible = {row["path"]: row for row in feasibility["samples"]}
    cached = {path.name.removeprefix("soljson-v").split("+")[0]
              for path in (ROOT / "work/compiler-cache").glob("soljson-*.cjs")}
    catalog = json.loads((ROOT / "work/compiler-cache/list.json").read_text())
    released = set(catalog.get("releases", {}))

    jobs: list[tuple] = []
    plan: list[dict] = []
    for sample in manifest["samples"]:
        analysis = sample.get("analysis", {})
        if analysis.get("static") == "passed":
            continue
        path = sample["path"]
        source = (ROOT / sample["objectPath"]).read_text(encoding="utf-8", errors="replace")
        workable = feasible.get(path, {}).get("workableCompilers", [])
        pragma_versions = _atc.compiler_candidates(source, cached, released)[0]
        versions: list[str] = []
        for value in list(workable) + list(pragma_versions):
            if value in cached and value not in versions:
                versions.append(value)
        versions = versions[:6]
        contracts = declared_contracts(source)
        targets: list[str | None] = [None] + contracts[:3]
        for version in versions:
            for target in targets:
                jobs.append((source, path, target, version))
        plan.append({"path": path, "versions": versions, "targets": targets,
                     "contracts": contracts})

    print(f"待测组合数：{len(jobs)}", flush=True)
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(run_analyzer, *job): job for job in jobs}
        for future in as_completed(futures):
            job = futures[future]
            try:
                row = future.result()
            except Exception as error:  # noqa: BLE001
                row = {"contract": job[2], "version": job[3], "state": "probe_error",
                       "staticError": f"{type(error).__name__}: {error}"}
            results.append({**row, "path": job[1]})
            print(f"  {row['version']:>8} target={str(row['contract']):<28} "
                  f"state={row.get('state')} contracts={row.get('contracts')} "
                  f"findings={row.get('findingCount')}", flush=True)

    out = ROOT / "work/static-target-matrix.json"
    out.write_text(json.dumps({
        "schemaVersion": 1,
        "plan": plan,
        "results": results,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"写出 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
