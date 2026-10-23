#!/usr/bin/env python3
"""一键运行全部本地 Foundry PoC。

每个 PoC 项目都在 benchmark/dynamic/<case>/ 下，自带 foundry.toml 与 test/。
编译器统一从 work/compiler-cache 取已校验的 soljson，全程离线，不联网下载。

判据：PoC 必须断言攻击前后状态或余额确实发生变化。仅"跑通"不算复现。

用法：
  python3 scripts/run-local-pocs.py            # 跑全部
  python3 scripts/run-local-pocs.py --case 06-integer_overflow_minimal
  python3 scripts/run-local-pocs.py --table    # 打印扫读表格
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DYNAMIC = ROOT / "benchmark" / "dynamic"
BRIDGE = ROOT / "scripts" / "forge-with-solc.py"

# case_id -> 需要的编译器版本（PoC 内联的合约统一按此版本编译）
POC_PROJECTS = {
    "06-integer_overflow_minimal": "0.4.24",
    "16-simple_dao": "0.4.24",
    "19-mishandled": "0.4.25",
    "14-reentrance": "0.8.28",
}

PASS_LINE = re.compile(r"^\[PASS\]\s+(\S+)", re.M)
FAIL_LINE = re.compile(r"^\[FAIL\]\s+(\S+)", re.M)
SUITE_LINE = re.compile(r"Suite result:\s*(\w+)\.\s*(\d+) passed;\s*(\d+) failed")


def run_case(case_id: str, version: str) -> dict:
    """运行单个 PoC 项目，返回结构化结果。"""
    project = DYNAMIC / case_id
    if not (project / "foundry.toml").is_file():
        return {"caseId": case_id, "state": "no_project", "passed": 0, "failed": 0}

    completed = subprocess.run(
        [sys.executable, str(BRIDGE), "--compiler-version", version, "--",
         "test", "--root", str(project), "--offline"],
        cwd=ROOT, capture_output=True, text=True, timeout=300, check=False,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    passed_tests = PASS_LINE.findall(output)
    failed_tests = FAIL_LINE.findall(output)
    suite = SUITE_LINE.search(output)

    if completed.returncode != 0 and not suite:
        reason = "unknown"
        marker = re.search(r"Error: (.{0,120})", output)
        if marker:
            reason = marker.group(1).strip()
        return {"caseId": case_id, "state": "error", "passed": 0, "failed": 0,
                "reason": reason, "compilerVersion": version}

    passed = int(suite.group(2)) if suite else len(passed_tests)
    failed = int(suite.group(3)) if suite else len(failed_tests)
    state = "reproduced" if passed and not failed else "failed"
    return {
        "caseId": case_id, "state": state, "passed": passed, "failed": failed,
        "testNames": passed_tests, "compilerVersion": version,
        # 复现命令要能直接复制粘贴，这是"本地可复现"的关键
        "reproduceCommand": (
            f"python3 scripts/run-local-pocs.py --case {case_id}"),
    }


def render_table(results: list[dict]) -> str:
    lines = [f"{'样本':<32}{'状态':<13}{'通过':<6}{'失败':<6}编译器"]
    lines.append("-" * 76)
    for r in results:
        lines.append(f"{r['caseId']:<32}{r['state']:<13}{r.get('passed', 0):<6}"
                     f"{r.get('failed', 0):<6}{r.get('compilerVersion', '-')}")
    reproduced = [r for r in results if r["state"] == "reproduced"]
    lines.append("")
    lines.append(f"本地复现成功 {len(reproduced)}/{len(results)}；"
                 f"合计断言 {sum(r.get('passed', 0) for r in results)} 项。")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="一键运行本地 Foundry PoC")
    parser.add_argument("--case", help="只跑指定样本")
    parser.add_argument("--table", action="store_true", help="打印扫读表格")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args()

    if args.case:
        if args.case not in POC_PROJECTS:
            print(f"未知样本 {args.case}；可用：{', '.join(sorted(POC_PROJECTS))}")
            return 2
        targets = {args.case: POC_PROJECTS[args.case]}
    else:
        targets = POC_PROJECTS

    results = [run_case(case_id, version) for case_id, version in sorted(targets.items())]

    if args.json:
        print(json.dumps({"schemaVersion": 1, "results": results}, ensure_ascii=False, indent=2))
    elif args.table:
        print(render_table(results))
    else:
        for r in results:
            print(f"[{r['state']}] {r['caseId']}  "
                  f"通过 {r.get('passed', 0)} / 失败 {r.get('failed', 0)}"
                  + (f"  原因：{r['reason']}" if r.get("reason") else ""))

    return 0 if all(r["state"] in {"reproduced", "no_project"} for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())