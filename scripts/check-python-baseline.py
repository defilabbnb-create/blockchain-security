#!/usr/bin/env python3
"""把 python unittest 的失败分成「新回归」与「已知历史失败」。

背景：benchmark 泳道的动态 runner 依赖 solc-js 与 Hardhat 单进程 EVM，且
test_dynamic_runner 会扫描 work/corpus-shards/** 寻找 benchmark 分片。这些用例在
某些环境下会因为环境原因（缺 soljson、缺目录内容）而失败，与本次改动无关。为了不让
这些历史失败掩盖真实回归，本脚本把失败清单与基线文件比对：

- 基线文件里没有的失败  -> 判定为 new regression，exit 非 0
- 基线文件里有的失败    -> 判定为 known，标注出来，但不计入失败
- 基线文件里有、但这次没出现的失败 -> 判定为 stale，提示基线需要更新（不阻塞）

用法：
    python3 scripts/check-python-baseline.py            # 检查并打印分类
    python3 scripts/check-python-baseline.py --refresh  # 重新生成基线（需人工确认）
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "work" / "baselines" / "python-unittest.json"
TESTS_DIR = ROOT / "tests"

# unittest 的失败标题行形如： "FAIL: test_name (module.Class)"
CASE_PATTERN = re.compile(r"^(?:FAIL|ERROR): (\S+)")


def _classify(line: str) -> str | None:
    match = CASE_PATTERN.match(line)
    return match.group(1) if match else None


def run_tests() -> tuple[str, int]:
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout + completed.stderr, completed.returncode


def collect_failures(output: str) -> list[str]:
    return [
        case_id
        for case_id in (_classify(line) for line in output.splitlines())
        if case_id
    ]


def load_baseline() -> dict:
    if not BASELINE.is_file():
        return {}
    try:
        return json.loads(BASELINE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_baseline(failures: list[str], output: str) -> None:
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schemaVersion": 1,
        "generatedAt": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "generator": "scripts/check-python-baseline.py --refresh",
        "scope": "python3 -m unittest discover -s tests",
        "note": (
            "这些 case 在引入当前批次前就已失败，属于环境/依赖类历史失败；"
            "不在此列表中的失败会被判为新回归。"
        ),
        "knownFailures": sorted(set(failures)),
    }
    BASELINE.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="用本次失败清单覆盖基线（需人工确认后再使用）",
    )
    args = parser.parse_args()

    output, returncode = run_tests()
    failures = collect_failures(output)
    baseline = load_baseline()
    known = set(baseline.get("knownFailures", []))
    # flakyTests 收录间歇性失败：单轮不失败属正常，失败时不计为新回归，
    # 但会在报告里标注，避免把外部产物缺失导致的时绿时红误判成代码回归。
    flaky = {item.get("caseId") for item in baseline.get("flakyTests", []) if item.get("caseId")}

    if args.refresh:
        save_baseline(failures, output)
        print(f"基线已刷新：{len(set(failures))} 项 -> {BASELINE}")
        return 0

    regressions = sorted(set(failures) - known - flaky)
    stale = sorted(known - set(failures))
    observed_flaky = sorted(set(failures) & flaky)
    print(f"测试原始退出码：{returncode}")
    print(f"已知历史失败：{len(known & set(failures))}")
    print(f"已知间歇失败（本轮出现）：{len(observed_flaky)}")
    for case_id in observed_flaky:
        print(f"  [FLAKY] {case_id}")
    print(f"新回归：{len(regressions)}")
    for case_id in regressions:
        print(f"  [NEW] {case_id}")
    if stale:
        print(f"基线中已不存在的失败（可清理）：{len(stale)}")
        for case_id in stale:
            print(f"  [STALE] {case_id}")

    if regressions:
        print("\n检测到新回归，请修复后重跑。")
        return 1
    print("\n无新回归（历史失败与已知间歇失败已标注）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())