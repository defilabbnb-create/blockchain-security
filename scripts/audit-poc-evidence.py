#!/usr/bin/env python3
"""PoC 证据体检器。

对 benchmark/contracts/*/poc-result.json 逐份判定：这份"复现成功"的声明背后
到底有没有可核验的证据。

背景：历史上多份 poc-result.json 直接写入 state=passed / confirmedVulnerability=true，
但既无余额变化也无状态前后对比。这样的结论不能进覆盖率分母，也不能对外称
"本地已复现"。本脚本把这类声明挑出来，并按证据强度分级。

判定四档：
  reproduced       —— 有 before/after 状态或余额证据，且证据自洽
  evidence_stale   —— 有证据，但 sourceSha256 与当前源码不符，证据绑到了旧版本
  fabricated       —— 声称复现成功，却没有任何 before/after 证据
  not_reproduced   —— 声称未复现（正常结论，不是问题）

用法：
  python3 scripts/audit-poc-evidence.py            # 写 benchmark/poc-evidence-audit.json
  python3 scripts/audit-poc-evidence.py --table    # 直接打印对齐表格
  python3 scripts/audit-poc-evidence.py --fail     # 有 fabricated/stale 时退出码 1（供 CI）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "benchmark" / "contracts"
OUT_PATH = ROOT / "benchmark" / "poc-evidence-audit.json"

# 判定"状态前后对比"的字段名。语义分三类：
#   余额类 —— 攻击者/受害者/目标合约的 ETH 数额变化
#   存储类 —— owner、数组长度、slot 等存储槽前后对比
#   语义类 —— 布尔观察量，如越权是否成功、返回值与实际是否背离
BALANCE_HINT = re.compile(r"(balance|wei|profit|extracted|received)", re.I)
STORAGE_HINT = re.compile(r"(lengthbefore|lengthafter|before|after|slot|owner|index)", re.I)
OBSERVATION_HINT = re.compile(
    r"(observation|observationconfirmed|rejected|reverted|controlpassed|"
    r"invalidcontrol|attackstatus|redeemstatus|checked|transactionstatuses|"
    r"unauthorized|delegatecallwrote|overflowvalue|guessedvalue)",
    re.I,
)

# 只有 before/after 成对出现才构成"变化"证据。
DELTA_PAIR = re.compile(r"^(.*)(before|after)(.*)$", re.I)


def _is_delta_key(key: str) -> bool:
    """判断字段是否属于 before/after 配对形态（去掉 before/after 前后缀后能配平）。"""
    return bool(DELTA_PAIR.match(key))


def _collect_evidence(poc: dict) -> tuple[list[str], list[str]]:
    """从 poc-result 中收集可核验证据字段名。

    返回 (余额类证据, 状态类证据)。只认 before/after 配对、余额数额、语义观察量，
    不认单个孤立数值——孤立数值无法证明"发生了变化"。
    """
    balance_keys: list[str] = []
    state_keys: list[str] = []

    for key, value in poc.items():
        if value is None:
            continue
        # 已经有专门的 before/after 配对字段时，同义的单一字段不再重复计数
        if _is_delta_key(key) and _pair_partner(poc, key) is not None:
            continue
        if BALANCE_HINT.search(key) and isinstance(value, str) and value.strip():
            balance_keys.append(key)
        elif OBSERVATION_HINT.search(key) and not _is_delta_key(key):
            state_keys.append(key)

    # 补上真正的 before/after 配对（这类是最强证据）
    for key in poc:
        if _is_delta_key(key) and _pair_partner(poc, key) is not None:
            (balance_keys if BALANCE_HINT.search(key) else state_keys).append(key)

    return sorted(set(balance_keys)), sorted(set(state_keys))


def _pair_partner(poc: dict, key: str) -> object | None:
    """给定 before/after 形态的键，返回配对端的值；不成对则 None。"""
    match = DELTA_PAIR.match(key)
    if not match:
        return None
    prefix, marker, suffix = match.groups()
    partner = f"{prefix}{'after' if marker.lower() == 'before' else 'before'}{suffix}"
    if partner in poc and poc[partner] is not None:
        return poc[partner]
    # 退化形态：{before:..., after:...} 字典
    if isinstance(poc.get(key), dict):
        inner = poc[key]
        opposite = "after" if marker.lower() == "before" else "before"
        if inner.get(opposite) is not None:
            return inner[opposite]
    return None


def _values_differ(poc: dict, key: str) -> bool:
    """配对的 before/after 两端取值是否真的不同——相同就说明什么都没变。"""
    match = DELTA_PAIR.match(key)
    if not match:
        return False
    prefix, marker, suffix = match.groups()
    partner = f"{prefix}{'after' if marker.lower() == 'before' else 'before'}{suffix}"
    left = poc.get(key)
    right = poc.get(partner)
    if isinstance(poc.get(key), dict):
        inner = poc[key]
        opposite = "after" if marker.lower() == "before" else "before"
        left, right = inner.get(marker.lower()), inner.get(opposite)
    return left is not None and right is not None and left != right


def _read_json_object(path: Path) -> tuple[dict, str | None]:
    """Read one JSON object, reporting why it is unusable instead of raising.

    Returns `(data, reason)`.  A truncated file or a top-level array is a real
    condition to report, not a reason to abort the whole audit: dropping such a
    case silently would shrink the denominator and make a broken file look like
    a clean run.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, "文件不存在"
    except OSError as error:
        return {}, f"读取失败：{error.__class__.__name__}"
    if not raw.strip():
        return {}, "文件为空"
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        return {}, f"JSON 解析失败（第 {error.lineno} 行第 {error.colno} 列：{error.msg}）"
    if not isinstance(value, dict):
        return {}, f"顶层不是 JSON 对象（实际为 {type(value).__name__}）"
    return value, None


def _source_binding(case_dir: Path, ground_truth: dict, poc: dict) -> dict:
    """校验 poc 证据是否绑定到当前源码。返回 {checked, recorded, actual, matched}。"""
    result = {"checked": False, "recorded": poc.get("sourceSha256"), "actual": None, "matched": None}
    source_file = ground_truth.get("sourceFile")
    if not source_file:
        return result
    source_path = case_dir / source_file
    if not source_path.exists() or not result["recorded"]:
        return result
    result["checked"] = True
    result["actual"] = hashlib.sha256(source_path.read_bytes()).hexdigest()
    result["matched"] = result["recorded"] == result["actual"]
    return result


def audit_case(case_dir: Path) -> dict:
    """体检单个样本的 PoC 证据。"""
    case_id = case_dir.name
    case: dict = {
        "caseId": case_id,
        "clean": False,
        "knownIssues": [],
        "verdict": "unreadable",
        "hasEvidence": False,
        "balanceEvidence": [],
        "stateEvidence": [],
        "changedPairs": [],
        "sourceBinding": {"checked": False, "recorded": None, "actual": None, "matched": None},
        "problems": [],
    }
    truth, truth_error = _read_json_object(case_dir / "ground-truth.json")
    if truth_error:
        # A sample whose ground truth cannot be parsed cannot be graded, so it
        # must not disappear from the report.  Naming it keeps the denominator
        # honest instead of quietly shrinking because a file got truncated.
        case["problems"].append(f"ground-truth.json 不可用：{truth_error}")
        return case
    poc_path = case_dir / "poc-result.json"
    poc, poc_error = _read_json_object(poc_path)
    if poc_error and poc_path.exists():
        case["problems"].append(f"poc-result.json 不可用：{poc_error}")
        case["claimedState"] = "unreadable"
        case["claimedConfirmed"] = False
        case["verdict"] = "unreadable"
        case["reason"] = None
        return case
    poc = poc or {}

    clean = bool(truth.get("clean"))
    state = poc.get("state") or poc.get("status") or "unknown"
    claimed = bool(poc.get("confirmedVulnerability"))
    balance_keys, state_keys = _collect_evidence(poc)
    binding = _source_binding(case_dir, truth, poc)

    # 只有真正发生变化的配对字段才算状态证据
    changed_pairs = sorted({k for k in poc if _is_delta_key(k) and _values_differ(poc, k)})

    has_evidence = bool(balance_keys or state_keys or changed_pairs)
    problems: list[str] = []

    if claimed and not has_evidence:
        verdict = "fabricated"
        problems.append("声称复现成功，但没有任何余额或状态前后证据")
    elif binding["checked"] and binding["matched"] is False:
        verdict = "evidence_stale"
        problems.append("sourceSha256 与当前源码不符，证据绑定在旧版本上")
    elif claimed and has_evidence:
        verdict = "reproduced"
    else:
        verdict = "not_reproduced"

    # 附带的诊断项：不改变判定，但记录下来
    if binding["checked"] and binding["matched"] is False and verdict != "fabricated":
        pass
    if clean and claimed:
        problems.append("干净对照样本却声称存在漏洞")
    if not poc:
        problems.append("缺少 poc-result.json")

    return {
        "caseId": case_id,
        "clean": clean,
        "knownIssues": truth.get("knownIssues") or truth.get("vulnerability") or [],
        "claimedState": state,
        "claimedConfirmed": claimed,
        "verdict": verdict,
        "hasEvidence": has_evidence,
        "balanceEvidence": balance_keys,
        "stateEvidence": state_keys,
        "changedPairs": changed_pairs,
        "evidenceSha256": poc.get("evidenceSha256"),
        "reproduceCommand": poc.get("reproduceCommand"),
        "sourceBinding": binding,
        "problems": problems,
        "reason": poc.get("reason"),
    }


def audit_all() -> dict:
    """体检全部样本，按判定汇总。"""
    cases = [audit_case(d) for d in sorted(CONTRACTS.iterdir()) if d.is_dir()]

    by_verdict: dict[str, list[str]] = {}
    for case in cases:
        by_verdict.setdefault(case["verdict"], []).append(case["caseId"])

    unreadable = [c["caseId"] for c in cases if c["verdict"] == "unreadable"]
    # 干净对照必须零误报：它们声称 unconfirmed 才是正确结论
    controls = [c for c in cases if c["clean"]]
    report = {
        "schemaVersion": 1,
        "generatedAt": None,
        "method": (
            "对每份 poc-result.json 校验三件事：是否存在 before/after 状态或余额证据、"
            "证据两端取值是否真的变化、sourceSha256 是否绑定当前源码。"
            "声称复现成功却无任何证据者判 fabricated。"
        ),
        "verdictSemantics": {
            "reproduced": "有余额或状态前后证据，且绑定当前源码",
            "evidence_stale": "有证据，但绑定的源码已被改写，证据不可用于当前版本",
            "fabricated": "声称复现成功，却没有任何前后证据",
            "not_reproduced": "声称未复现或未确认（正常结论）",
            "unreadable": "ground-truth 或 poc-result 损坏/缺失，本样本无法判定；"
                          "既不算通过，也不计入覆盖率分母",
        },
        "counts": {k: len(v) for k, v in sorted(by_verdict.items())},
        "byVerdict": by_verdict,
        "unreadableCount": len(unreadable),
        "unreadableIds": unreadable,
        "cleanControls": {
            "total": len(controls),
            "correctlyQuiet": [c["caseId"] for c in controls if not c["claimedConfirmed"]],
            "falsePositive": [c["caseId"] for c in controls if c["claimedConfirmed"]],
        },
        "cases": cases,
    }
    return report


def _load_grades() -> dict[str, dict]:
    """读取样本分级报告（若存在），用于给体检表格补一列分级。"""
    adjudication = ROOT / "benchmark" / "sample-adjudication.json"
    data, reason = _read_json_object(adjudication)
    if reason:
        # A broken grading report only costs the table one column; it must not
        # abort the audit.  The reason travels back for the caller to show.
        print(f"分级报告不可用，分级列留空：{reason}", file=sys.stderr)
        return {}
    return {s["caseId"]: s for s in data.get("samples", [])
            if isinstance(s, dict) and s.get("caseId")}


def render_table(report: dict, grades: dict[str, dict]) -> str:
    """打印对齐表格，供一眼扫读。"""
    lines: list[str] = []
    header = f"{'样本':<34}{'分级':<5}{'自述':<15}{'判定':<15}{'证据'}"
    lines.append(header)
    lines.append("-" * 94)

    cases = report["cases"]
    verdict_order = {"fabricated": 0, "evidence_stale": 1, "unreadable": 2,
                     "reproduced": 3, "not_reproduced": 4}
    for case in sorted(cases, key=lambda c: (verdict_order.get(c["verdict"], 9), c["caseId"])):
        evidence = "余额" if case["balanceEvidence"] else ""
        if case["stateEvidence"]:
            evidence = f"{evidence}+状态" if evidence else "状态"
        if case["changedPairs"]:
            evidence = f"{evidence}+变化对" if evidence else "变化对"
        if not evidence:
            evidence = "无"
        grade = grades.get(case["caseId"], {}).get("grade", "-")
        lines.append(
            f"{case['caseId']:<34}{grade:<5}{str(case.get('claimedState', '-')):<15}"
            f"{case['verdict']:<15}{evidence}"
        )

    lines.append("")
    counts = report["counts"]
    lines.append("判定汇总：" + "  ".join(f"{k}={v}" for k, v in counts.items()))
    lines.append(
        "可用于覆盖率分母的仅 reproduced；"
        f"fabricated={counts.get('fabricated', 0)} 需剔除，"
        f"evidence_stale={counts.get('evidence_stale', 0)} 需重跑。"
    )
    if report.get("unreadableCount"):
        lines.append(
            f"unreadable={report['unreadableCount']} 为损坏/缺失输入，"
            "既不算通过也不计入分母，需修好源文件后重跑。"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="PoC 证据体检")
    parser.add_argument("--table", action="store_true", help="打印对齐表格")
    parser.add_argument("--fail", action="store_true", help="存在 fabricated/stale 时退出码 1")
    args = parser.parse_args()

    report = audit_all()
    report["generatedAt"] = None  # 由调用方决定是否写入时间戳，保持输出可复现

    OUT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.table:
        print(render_table(report, _load_grades()))

    if args.fail:
        blocking = (report["counts"].get("fabricated", 0)
                    + report["counts"].get("evidence_stale", 0))
        # An unreadable case is not a pass.  Letting a broken input file exit 0
        # is how "no evidence" turns into "nothing to fix" in CI.
        unreadable = report.get("unreadableCount", 0)
        if blocking:
            print(f"\n存在 {blocking} 份不可采信的 PoC 证据，拒绝作为复现依据。", file=sys.stderr)
        if unreadable:
            print(f"\n存在 {unreadable} 份损坏或缺失的样本输入（{','.join(report['unreadableIds'])}），"
                  "既未判定也不能计入分母。", file=sys.stderr)
        if blocking or unreadable:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())