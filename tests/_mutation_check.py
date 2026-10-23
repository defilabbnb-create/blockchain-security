#!/usr/bin/env python3
# ⚠️ 手动变异测试工具 —— 不进 CI，不在并发跑测试时使用。
#
# 本工具会**原地改写 scripts/ 下的生产源文件**（见 main() 中的 path.write_text，
# 每个变异用完在 finally 里还原），并为每个变异单独跑一次 unittest。
# 因此：期间任何并行运行的测试都会读到被故意改坏的源码，结论不可信；
# 中途被 Ctrl-C 或崩溃中断可能留下未还原的源文件（还原只保证在正常流程内发生）。
# 只有在确认没有其他测试/采集/评测进程在跑时，手动执行：
#     python3 tests/_mutation_check.py
# 文件名以 _ 开头，不匹配 tests/test_*.py，unittest discover 不会收集它。
"""Mutation harness: revert one fix at a time and record what fails.

A new test that stays green after its guard is removed is decoration, not
evidence.  Each mutation below is a literal revert of one decision in the
source; the harness applies it, runs the test module that claims to cover that
decision, and restores the original file afterwards.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INV = ROOT / "scripts" / "vulnerability_inventory.py"
MATRIX = ROOT / "scripts" / "evidence-matrix.py"
AUDIT = ROOT / "scripts" / "audit-poc-evidence.py"

T_INV = "tests.test_inventory_cache_trust"
T_MATRIX = "tests.test_evidence_matrix_robustness"
T_AUDIT = "tests.test_poc_evidence_robustness"

# (label, file, original snippet, mutated snippet, test module)
MUTATIONS = [
    (
        "P0-3 取消条目文档内容校验（回到无条件 verified=True）",
        INV,
        '    if text is None:\n        return "条目在固定提交上读取失败"',
        '    if text is not None:\n        return None\n    if text is None:\n        return "条目在固定提交上读取失败"',
        T_INV,
    ),
    (
        "P0-3 去掉必需章节校验",
        INV,
        '    missing = [section for section in REQUIRED_ENTRY_SECTIONS\n               if f"## {section}" not in text]\n    if missing:\n        return f"条目缺少必需章节 {\'/\'.join(missing)}：疑似截断"',
        '    missing = []\n    if missing:\n        return f"条目缺少必需章节 {\'/\'.join(missing)}：疑似截断"',
        T_INV,
    ),
    (
        "P0-3 去掉代码围栏配平校验",
        INV,
        "    if text.count(\"```\") % 2:\n        return \"条目内代码块围栏不成对：文件在写入中途被截断\"",
        "    if False:\n        return \"条目内代码块围栏不成对：文件在写入中途被截断\"",
        T_INV,
    ),
    (
        "P0-3 去掉字节下限校验",
        INV,
        "    if len(raw) < MIN_ENTRY_BYTES:",
        "    if False:",
        T_INV,
    ),
    (
        "P0-3 去掉标题长度校验",
        INV,
        "    if len(title) < MIN_TITLE_LENGTH:",
        "    if False:",
        T_INV,
    ),
    (
        "P0-3 去掉 index 交叉核对（缺失条目不再上报）",
        INV,
        "    for number in sorted(index_ids - seen):",
        "    for number in sorted(set()):",
        T_INV,
    ),
    (
        "P0-3 把损坏条目重复计为缺失（double-count 回归）",
        INV,
        "        seen.add(number)\n        try:\n            text = path.read_text(encoding=\"utf-8\")",
        "        try:\n            text = path.read_text(encoding=\"utf-8\")",
        T_INV,
    ),
    (
        "P0-3 恢复按 int() 排序（文件名不可解析时崩溃）",
        INV,
        "    def sort_key(item: dict) -> tuple[int, str]:\n        number = _cache_entry_number(Path(item[\"id\"] if item[\"id\"].startswith(\"SWC-\")\n                                          else f\"x-SWC-{item['id']}\"))\n        return (number if number is not None else 1 << 30, item[\"id\"])\n\n    return sorted(entries, key=sort_key)",
        "    return sorted(entries, key=lambda item: int(item[\"id\"].split(\"-\")[1]))",
        T_INV,
    ),
    (
        "P0-3b 恢复写死的「37 个条目」文案",
        INV,
        '    if entry_count == 0:\n        return ("本次未取得任何 SWC 条目（缓存为空、提交不可达或索引缺失），"',
        '    if False:\n        return ("本次未取得任何 SWC 条目（缓存为空、提交不可达或索引缺失），"',
        T_INV,
    ),
    (
        "P0-3b 恢复写死的编号范围文案",
        INV,
        '    if isinstance(index_count, int) and index_count:\n        return (f"该提交 entries/index.md 列出 {index_count} 个条目；"',
        '    if True:\n        return (f"该提交 entries/index.md 列出 {index_count} 个条目；"',
        T_INV,
    ),
    (
        "P0-3 verifiedCount 直接等于 entryCount（把损坏条目也算成已验证）",
        INV,
        '            "verifiedCount": len(verified_entries),',
        '            "verifiedCount": len(entries),',
        T_INV,
    ),
    (
        "P0-4 _load 去掉 JSON 异常保护（回到直接 json.loads）",
        MATRIX,
        "    try:\n        data = json.loads(text)\n    except json.JSONDecodeError as error:\n        return None, f\"JSON 解析失败（{path.name} 第 {error.lineno} 行第 {error.colno} 列：{error.msg}）\"",
        "    data = json.loads(text)",
        T_MATRIX,
    ),
    (
        "P0-4 _load 接受空文件与顶层数组（不再显式降级）",
        MATRIX,
        "    if not text.strip():\n        return None, \"文件为空\"",
        "    if False:\n        return None, \"文件为空\"",
        T_MATRIX,
    ),
    (
        "P0-4 丢失样本adjudication 后把缺失分级推断成具体等级",
        MATRIX,
        '            "grade": grade_row.get("grade", "-"),',
        '            "grade": grade_row.get("grade") or "A",',
        T_MATRIX,
    ),
    (
        "P0-4 不再输出输入可用性（N/3）",
        MATRIX,
        '    lines: list[str] = list(render_inputs(inputs or []))\n    if lines:\n        lines.append("")',
        '    lines: list[str] = []',
        T_MATRIX,
    ),
    (
        "AUDIT ground-truth 损坏时抛错（回到裸 json.loads）",
        AUDIT,
        "    try:\n        value = json.loads(raw)\n    except json.JSONDecodeError as error:\n        return {}, f\"JSON 解析失败（第 {error.lineno} 行第 {error.colno} 列：{error.msg}）\"",
        "    value = json.loads(raw)",
        T_AUDIT,
    ),
    (
        "AUDIT 顶层数组不再判为不可读",
        AUDIT,
        "    if not isinstance(value, dict):\n        return {}, f\"顶层不是 JSON 对象（实际为 {type(value).__name__}）\"",
        "    if False:\n        return {}, f\"顶层不是 JSON 对象（实际为 {type(value).__name__}）\"",
        T_AUDIT,
    ),
    (
        "AUDIT 跳过没有 ground-truth.json 的样本（分母静默缩小）",
        AUDIT,
        "    cases = [audit_case(d) for d in sorted(CONTRACTS.iterdir()) if d.is_dir()]",
        "    cases = [audit_case(d) for d in sorted(CONTRACTS.iterdir())\n             if d.is_dir() and (d / \"ground-truth.json\").exists()\n             and json.loads((d / \"ground-truth.json\").read_text(encoding=\"utf-8\"))]",
        T_AUDIT,
    ),
    (
        "AUDIT 损坏样本被算进干净对照分母",
        AUDIT,
        "    controls = [c for c in cases if c[\"clean\"]]",
        "    controls = [c for c in cases if c[\"clean\"] or c[\"verdict\"] == \"unreadable\"]",
        T_AUDIT,
    ),
    (
        "AUDIT 分级报告损坏时抛错（回到裸 json.loads）",
        AUDIT,
        "    data, reason = _read_json_object(adjudication)\n    if reason:",
        "    data = json.loads(adjudication.read_text(encoding=\"utf-8\"))\n    if False:",
        T_AUDIT,
    ),
]


def run_tests(module: str) -> tuple[int, int, int]:
    """Return (ran, failures, errors) for one test module.

    unittest writes its summary to stderr, and the counts appear on the
    ``FAILED (failures=N, errors=M)`` line -- not on the ``Ran N tests`` line.
    Parsing only ``Ran`` silently reports every mutation as surviving, which is
    the one failure mode this harness must not have.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", module],
        cwd=ROOT, capture_output=True, text=True)
    ran = failures = errors = 0
    for line in proc.stderr.splitlines():
        if line.startswith("Ran ") and " test" in line:
            ran = int(line.split()[1])
        if line.startswith("FAILED"):
            for item in line[line.find("("):].strip("()").split(","):
                item = item.strip()
                if item.startswith("failures="):
                    failures += int(item.split("=")[1])
                elif item.startswith("errors="):
                    errors += int(item.split("=")[1])
        elif line.startswith("OK"):
            failures = errors = 0
    return ran, failures, errors


def failing_test_names(module: str) -> list[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "-v", module],
        cwd=ROOT, capture_output=True, text=True)
    names = []
    for line in proc.stderr.splitlines():
        line = line.strip()
        if line.startswith(("FAIL: ", "ERROR: ")):
            names.append(line.split(" (")[0].replace("FAIL: ", "").replace("ERROR: ", ""))
    return names


def main() -> int:
    print("=" * 78)
    print("变异测试：逐个还原修复，确认新测试真的失败")
    print("=" * 78)
    # Control run: everything green before any mutation.
    baseline = {}
    for module in (T_INV, T_MATRIX, T_AUDIT):
        ran, failed, errors = run_tests(module)
        baseline[module] = ran
        print(f"[对照] {module}: ran={ran} failed={failed} errors={errors}")
    if any(run_tests(m)[1] or run_tests(m)[2] for m in baseline):
        print("对照就不是绿的，无法做变异测试。")
        return 1
    print()

    survivors = []
    for label, path, original, mutated, module in MUTATIONS:
        source = path.read_text(encoding="utf-8")
        if original not in source:
            print(f"[!!] 定位不到变异点，跳过：{label}")
            survivors.append((label, "SNIPPET-NOT-FOUND"))
            continue
        path.write_text(source.replace(original, mutated, 1), encoding="utf-8")
        try:
            ran, failed, errors = run_tests(module)
            names = failing_test_names(module)
        finally:
            path.write_text(source, encoding="utf-8")
        broken = failed + errors
        status = "捕获" if broken else "存活(!!)"
        if not broken:
            survivors.append((label, "NOT-CAUGHT"))
        print(f"[{status}] {label}")
        print(f"        module={module} ran={ran} failures={failed} errors={errors}")
        for name in names[:6]:
            print(f"          - {name}")
        if len(names) > 6:
            print(f"          ... 另 {len(names) - 6} 个")

    print()
    print("=" * 78)
    if survivors:
        print(f"结论：{len(survivors)}/{len(MUTATIONS)} 个变异存活（断言是摆设）")
        for label, why in survivors:
            print(f"  - {label}: {why}")
        return 1
    print(f"结论：{len(MUTATIONS)}/{len(MUTATIONS)} 个变异全部被测试捕获")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())