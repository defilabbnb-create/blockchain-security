#!/usr/bin/env python3
"""证据矩阵：一眼扫读样本的分级、证据强度与本地复现状态。

把四份互不相干的证据叠到一张表上：
  1. 分级报告      benchmark/sample-adjudication.json   —— 标注本身可不可信
  2. 证据体检      benchmark/poc-evidence-audit.json     —— poc-result 有没有前后证据
  3. 覆盖率        benchmark/coverage-report.json         —— 检测器实际表现
  4. 本地 PoC      scripts/run-local-pocs.py --json       —— forge test 是否跑通

这四者不能混为一谈：分级说的是"题目对不对"，证据体检说的是"结论有没有依据"，
覆盖率说的是"检测器准不准"，PoC 说的是"能不能本地跑通"。

任一输入损坏或缺失时脚本显式降级：把该份输入标为不可用并写明原因，其余输入继续
参与对齐，最后打印「N/3 份输入缺失」。缺失的列保持空白，不推断为通过。降级口径与
`src/web-server.js` 的 `benchmarkEvidenceMatrix` 一致（逐份 readJson 失败即视为
该输入不可用）；差异在于脚本侧额外给出每一份的原因文字。

用法：
  python3 scripts/evidence-matrix.py            # 打印对齐表格
  python3 scripts/evidence-matrix.py --json     # 输出 JSON
  python3 scripts/evidence-matrix.py --matrix   # 额外打印类别×分级矩阵
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmark"

# 证据判定 -> 展示用的中文标签与排序权重
VERDICT_LABEL = {
    "reproduced": ("已复现", 0),
    "evidence_stale": ("证据失效", 1),
    "fabricated": ("伪确认", 2),
    "not_reproduced": ("未复现", 3),
}
VERDICT_TEXT = {"reproduced": "OK", "evidence_stale": "STALE", "fabricated": "BAD", "not_reproduced": "--"}


def _load(path: Path) -> tuple[dict | None, dict | None]:
    """Read one input report, reporting why it is unusable rather than raising.

    Returns `(data, status)`.  `status` is None when the file was read and
    parsed, or a reason string when it could not be used.  A truncated or
    hand-mangled report must not take the whole matrix down with it: the other
    inputs still carry evidence, and silently dropping one of them would let a
    broken file read as "nothing to report".  This mirrors
    `benchmarkEvidenceMatrix` in `src/web-server.js`, where readJson catches and
    returns null for each input independently.
    """
    try:
        if not path.is_file():
            return None, "文件不存在"
    except OSError as error:
        return None, f"路径不可访问：{error.__class__.__name__}"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return None, f"读取失败：{error.__class__.__name__}"
    if not text.strip():
        return None, "文件为空"
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        return None, f"JSON 解析失败（{path.name} 第 {error.lineno} 行第 {error.colno} 列：{error.msg}）"
    if not isinstance(data, dict):
        return None, f"顶层不是 JSON 对象（{path.name}）"
    return data, None


# 输入名 -> 相对路径，供缺失清单与 JSON 输出使用。
INPUTS = (
    ("adjudication", "sample-adjudication.json"),
    ("audit", "poc-evidence-audit.json"),
    ("coverage", "coverage-report.json"),
)


def collect() -> tuple[list[dict], list[dict]]:
    """把四份证据按 caseId 对齐成一行行。

    返回 `(rows, inputs)`，`inputs` 记录每份输入的可用状态，便于在报告里
    显式写出「N/3 份输入缺失」，而不是让读者以为表格已经覆盖全部证据。
    """
    loaded: dict[str, dict] = {}
    inputs: list[dict] = []
    for name, filename in INPUTS:
        data, reason = _load(BENCH / filename)
        inputs.append({
            "name": name,
            "file": filename,
            "available": data is not None,
            "reason": reason,
            "rowCount": _row_count(name, data) if data is not None else 0,
        })
        loaded[name] = data or {}

    adjudication = loaded["adjudication"]
    audit = loaded["audit"]
    coverage = loaded["coverage"]

    grades = {s["caseId"]: s for s in adjudication.get("samples", []) if isinstance(s, dict) and s.get("caseId")}
    verdicts = {c["caseId"]: c for c in audit.get("cases", []) if isinstance(c, dict) and c.get("caseId")}
    scored = {}
    split = coverage.get("pocEvidenceSplit") or {}
    if isinstance(split, dict):
        for bucket in ("withReproduction", "evidenceStale", "fabricated", "staticOnly"):
            group = split.get(bucket) or {}
            if not isinstance(group, dict):
                continue
            for case in (group.get("cases") or []):
                if not isinstance(case, dict):
                    continue
                cid = case.get("caseId")
                if cid:
                    scored[cid] = (bucket, case)

    rows: list[dict] = []
    for case_id, verdict_row in sorted(verdicts.items()):
        grade_row = grades.get(case_id, {})
        bucket, score_case = scored.get(case_id, (None, None))
        binding = verdict_row.get("sourceBinding")
        rows.append({
            "caseId": case_id,
            "grade": grade_row.get("grade", "-"),
            "clean": bool(verdict_row.get("clean")),
            "excluded": bool((grade_row.get("grade") in {"C", "D"}) and not grade_row.get("clean")),
            "verdict": verdict_row.get("verdict", "-"),
            "hasEvidence": verdict_row.get("hasEvidence", False),
            "issues": verdict_row.get("knownIssues") or [],
            "detectionBucket": bucket,
            "falseNegative": bool((score_case or {}).get("falseNegative")),
            "falsePositive": bool((score_case or {}).get("falsePositive")),
            "hit": bool((score_case or {}).get("hit")),
            "bindingOk": binding.get("matched") if isinstance(binding, dict) else None,
        })
    return rows, inputs


def _row_count(name: str, data: dict) -> int:
    """How many aligned rows an input actually contributed."""
    key = {"adjudication": "samples", "audit": "cases"}.get(name)
    if key is None:
        split = data.get("pocEvidenceSplit") or {}
        if not isinstance(split, dict):
            return 0
        return sum(len((split.get(bucket) or {}).get("cases") or [])
                   for bucket in ("withReproduction", "evidenceStale",
                                  "fabricated", "staticOnly")
                   if isinstance(split.get(bucket), dict))
    rows = data.get(key)
    return len(rows) if isinstance(rows, list) else 0


def render_inputs(inputs: list[dict]) -> list[str]:
    """The explicit availability line, so a missing input is never silent."""
    missing = [item for item in inputs if not item["available"]]
    total = len(inputs)
    head = f"输入可用性：{total - len(missing)}/{total} 份可读"
    if not missing:
        return [head]
    lines = [head + "，以下输入缺失，其列在本表中留空而非推断为通过："]
    for item in missing:
        lines.append(f"  - {item['file']}：{item['reason']}")
    return lines


def render(rows: list[dict], local_pocs: dict | None, inputs: list[dict] | None = None) -> str:
    lines: list[str] = list(render_inputs(inputs or []))
    if lines:
        lines.append("")
    if not rows:
        lines.append("没有任何可对齐的证据行：证据体检输入缺失或不含任何 caseId。"
                     "缺失不等于通过，不能据此声称样本已核对。")
        return "\n".join(lines)
    header = (f"{'样本':<32}{'级':<4}{'证据':<10}{'分类':<26}"
              f"{'检出':<8}{'本地PoC':<10}备注")
    lines.append(header)
    lines.append("-" * 110)

    for row in sorted(rows, key=lambda r: (
        VERDICT_LABEL.get(r["verdict"], ("?", 9))[1], r["grade"], r["caseId"])):
        label, _ = VERDICT_LABEL.get(row["verdict"], (row["verdict"], 9))
        detection = "命中" if row["hit"] else ("漏报" if row["falseNegative"] else
                                               ("误报" if row["falsePositive"] else "-"))
        poc = (local_pocs or {}).get(row["caseId"])
        poc_text = "已跑通" if poc and poc.get("state") == "reproduced" else (
            f"{poc.get('passed')}项" if poc else "-")
        notes: list[str] = []
        if row["clean"]:
            notes.append("干净对照")
        if row["excluded"]:
            notes.append("已剔出分母")
        if row["bindingOk"] is False:
            notes.append("绑定失效")
        if not row["hasEvidence"]:
            notes.append("无前后证据")
        lines.append(f"{row['caseId']:<32}{row['grade']:<4}{label:<10}"
                     f"{','.join(row['issues'])[:24]:<26}{detection:<8}{poc_text:<10}"
                     f"{' '.join(notes)}")

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    lines.append("")
    lines.append("证据判定：" + "  ".join(
        f"{VERDICT_LABEL.get(k, (k,))[0]}={v}" for k, v in sorted(counts.items())))
    excluded = sum(1 for r in rows if r["excluded"])
    lines.append(f"已剔出评测分母 {excluded} 个；干净对照保留用于误报检测。")
    lines.append("检出列来自静态角色识别，是观察到的类别，不等于确认漏洞。")
    return "\n".join(lines)


def render_matrix(rows: list[dict]) -> str:
    """类别 × 分级矩阵，用于一眼看出哪个类别有缺口。"""
    by_issue: dict[str, dict[str, list[str]]] = {}
    for row in rows:
        key = ",".join(row["issues"]) or "clean_control"
        by_issue.setdefault(key, {}).setdefault(row["grade"], []).append(row["caseId"])

    grades = sorted({r["grade"] for r in rows})
    lines = [f"{'类别':<28}" + "".join(f"{g:<8}" for g in grades)]
    lines.append("-" * (28 + 8 * len(grades)))
    for issue in sorted(by_issue):
        cells = []
        for g in grades:
            items = by_issue[issue].get(g, [])
            cells.append(f"{len(items)}".ljust(8))
        lines.append(f"{issue[:26]:<28}" + "".join(cells))
    lines.append("")
    lines.append("数字为该类别在该分级下的样本数；空白表示无样本。")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="证据矩阵扫读")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--matrix", action="store_true", help="额外打印类别×分级矩阵")
    args = parser.parse_args()

    rows, inputs = collect()

    local_pocs = None
    try:
        import subprocess
        import sys
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "run-local-pocs.py"), "--json"],
            cwd=ROOT, capture_output=True, text=True, timeout=600, check=False)
        payload = json.loads(completed.stdout)
        local_pocs = {r["caseId"]: r for r in payload.get("results", [])}
    except Exception:
        local_pocs = None

    if args.json:
        # `available` mirrors src/web-server.js: when no input at all could be
        # read the API answers available:false with a reason; here the reason is
        # carried per input so a partial degradation stays visible to callers.
        missing = [item for item in inputs if not item["available"]]
        print(json.dumps({
            "schemaVersion": 1,
            "available": not missing,
            "reason": None if not missing else
                       f"{len(missing)}/{len(inputs)} 份输入不可用",
            "inputs": inputs,
            "rows": rows,
            "localPocs": local_pocs,
        }, ensure_ascii=False, indent=2))
        return 0

    print(render(rows, local_pocs, inputs))
    if args.matrix:
        print()
        print(render_matrix(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())