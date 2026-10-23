#!/usr/bin/env python3
"""按样本分级把 D/C 级样本移出评测分母。

原则：数据保留，只加 excludedReason 标记。评测侧读到该字段即跳过，
不删除任何文件，也不改写源码或 ground-truth 的既有内容。

剔除依据 benchmark/sample-adjudication.json 的分级：
  D 级 —— 标注与源码直接矛盾，题目本身错误
  C 级 —— 本地桩或合成样本，缺陷与标注不一致

用法：
  python3 scripts/exclude-unscored-samples.py           # 打标记
  python3 scripts/exclude-unscored-samples.py --dry-run  # 只看会改哪些
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "benchmark" / "contracts"
ADJUDICATION = ROOT / "benchmark" / "sample-adjudication.json"

# 只剔除 D 级与 C 级中的漏洞样本；A 级（真实项目、标注可信）与 B 级保留在分母内。
EXCLUDED_GRADES = {"D", "C"}

# 干净对照样本即使被判 C 级也必须留在分母内——它们是误报检测的唯一依据。
# 剔除对照等于让 precision 无法计算，得不偿失。
def _should_exclude(sample: dict) -> tuple[bool, str]:
    grade = sample.get("grade")
    if grade not in EXCLUDED_GRADES:
        return False, ""
    if sample.get("clean"):
        return False, "干净对照，保留用于误报检测"
    return True, f"{grade} 级，标注与源码不一致"


def main() -> int:
    parser = argparse.ArgumentParser(description="剔除 D/C 级样本出评测分母")
    parser.add_argument("--dry-run", action="store_true", help="只报告不写盘")
    args = parser.parse_args()

    if not ADJUDICATION.exists():
        print(f"缺少分级报告：{ADJUDICATION}")
        return 1

    data = json.loads(ADJUDICATION.read_text(encoding="utf-8"))
    samples = data.get("samples", [])

    changed: list[tuple[str, str]] = []
    kept: list[tuple[str, str]] = []
    for sample in samples:
        case_id = sample.get("caseId")
        if not case_id:
            continue
        exclude, why = _should_exclude(sample)
        if not exclude:
            if sample.get("grade") in EXCLUDED_GRADES:
                kept.append((case_id, why))
            continue

        gt_path = CONTRACTS / case_id / "ground-truth.json"
        if not gt_path.exists():
            continue
        gt = json.loads(gt_path.read_text(encoding="utf-8"))

        reason = {
            "grade": sample.get("grade"),
            "summary": why,
            "adjudication": sample.get("rationale", ""),
            "evidenceLines": [e.get("line") for e in sample.get("evidence", []) if e.get("line")],
        }
        if gt.get("excludedReason") == reason:
            continue

        changed.append((case_id, sample.get("grade")))
        if not args.dry_run:
            gt["excludedReason"] = reason
            gt_path.write_text(json.dumps(gt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    verb = "将标记" if args.dry_run else "已标记"
    print(f"{verb} {len(changed)} 个样本出评测分母：")
    for case_id, grade in changed:
        print(f"  {case_id:<34} {grade} 级")
    if kept:
        print(f"\n保留 {len(kept)} 个：")
        for case_id, why in kept:
            print(f"  {case_id:<34} {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())