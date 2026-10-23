#!/usr/bin/env python3
"""Measure vulnerability-class coverage of the deep-layers role detector.

The unit of comparison is one vulnerability class name.  For every benchmark
case the expected set comes from `ground-truth.json`'s `knownIssues`; the
detected set comes from `invariants.json`'s `detectedRoles`.  Both are read from
files that were produced by a real run, so this script never re-derives a
detection and can only report what the pipeline recorded.

The script also groups cases into protocol families, because samples of the
same family are variants of one defect rather than independent evidence.  A
coverage number computed over all samples as if they were independent would
overstate the result, so the family-aware view is printed alongside the naive
one and both are labelled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "benchmark" / "contracts"

# Protocol families and clean controls, derived from the sample contracts
# themselves (see scripts/benchmark-family-map.json for the machine readable
# copy).  A family groups samples that exercise the same protocol role, so two
# samples in one family are variants of one defect rather than two findings.
FAMILY_MAP_PATH = Path(__file__).resolve().parent / "benchmark-family-map.json"


def _load_family_map() -> dict:
    if not FAMILY_MAP_PATH.is_file():
        return {"families": [], "controls": [], "rationale": "unavailable"}
    return json.loads(FAMILY_MAP_PATH.read_text(encoding="utf-8"))


def _canonical_class(name: str) -> str:
    """Normalise a vulnerability class label to a single spelling.

    The corpus annotations and the detector do not agree on pluralisation: the
    ground truth writes `unchecked_low_level_calls` while the detector emits
    `unchecked_low_level_call`.  Comparing the raw strings scored that sample as
    a miss *and* a false positive at the same time, which is worse than either
    error alone -- it hid a real detection behind a spelling artefact.

    Only a trailing plural `s` is normalised, and only when the label ends in a
    noun the detector also uses in the singular.  Genuinely different class names
    are left alone, so this cannot merge two distinct classes into one.
    """
    text = str(name).strip().lower()
    # Only the specific label the corpus spells in the plural is normalised.
    # Anything else keeps its own spelling, so two genuinely different classes
    # can never be merged into one by this function.
    if text in PLURAL_LABELS:
        return text[:-1]
    return text


# Ground truth writes these in the plural; the detector emits the singular.
PLURAL_LABELS = ("unchecked_low_level_calls",)


def _canonical_set(names) -> set:
    return {_canonical_class(item) for item in names or []}


def _canonical_sorted(names) -> list:
    return sorted(_canonical_set(names))


def _case_rows(contracts: Path) -> list[dict]:
    rows = []
    for case_dir in sorted(contracts.iterdir()):
        if not case_dir.is_dir():
            continue
        truth_path = case_dir / "ground-truth.json"
        if not truth_path.is_file():
            rows.append({"caseId": case_dir.name, "state": "no_ground_truth",
                         "expected": [], "detected": [], "reason": "ground-truth.json 缺失"})
            continue
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        expected = _canonical_sorted(truth.get("knownIssues") or [])
        invariants_path = case_dir / "invariants.json"
        row = {"caseId": case_dir.name, "expected": expected,
               "source": truth.get("source"), "clean": bool(truth.get("clean"))}
        # ground-truth 里的 excludedReason 由 scripts/exclude-unscored-samples.py
        # 写入，标记那些标注与源码矛盾、不能拿来当分母的样本。数据保留在仓库里，
        # 但评测侧直接跳过——否则是在用错误标注当标准答案。
        if truth.get("excludedReason"):
            row.update(state="excluded_by_adjudication", detected=[],
                       reason=f"{truth['excludedReason'].get('summary', '标注与源码不一致')}"
                              f"（{truth['excludedReason'].get('grade', '?')} 级）")
            rows.append(row)
            continue
        if not invariants_path.is_file():
            row.update(state="no_evidence", detected=[], reason="invariants.json 缺失")
            rows.append(row)
            continue
        evidence = json.loads(invariants_path.read_text(encoding="utf-8"))
        row["pipelineState"] = evidence.get("state")
        row["pipelineReason"] = evidence.get("reason")
        # An evidence file is only evidence about the source that is on disk now.
        # If the source was edited after the run, the recorded digest no longer
        # matches and every role in the file describes a different contract, so it
        # is excluded rather than scored: silently reusing it would report coverage
        # for code that no longer exists.
        source_file = next(iter(sorted(case_dir.glob("*.sol"))), None)
        if source_file is not None:
            current = hashlib.sha256(source_file.read_bytes()).hexdigest()
            recorded = evidence.get("sourceSha256")
            if isinstance(recorded, str) and recorded and recorded != current:
                row.update(state="evidence_not_bound", detected=[],
                           reason=f"evidence_describes_other_source:recorded={recorded[:12]}"
                                  f":current={current[:12]}")
                rows.append(row)
                continue
        # The role set is recorded before the harness runs, so a sample whose
        # deployment failed still carries its detection result.  Scoring reads the
        # roles that exist rather than only the cases whose invariant assertions
        # happened to execute: treating a deployment failure as a detection miss
        # would inflate the false-negative column with harness problems.
        detected = _canonical_sorted(evidence.get("detectedRoles") or [])
        if not detected:
            # Silence is only a correct result for a sample that declares no
            # issue.  For a sample with a known issue, an empty role set is a
            # miss, not a pass, so it stays in the denominator as a miss.  A
            # clean sample with no roles is scored as a true negative.
            row.update(state="scored_clean_silence" if not expected else "scored",
                       detected=[], reason=str(evidence.get("reason") or evidence.get("state")
                                               or "detectedRoles 为空"),
                       reasons=sorted(evidence.get("unresolved") or []))
            rows.append(row)
            continue
        row.update(state="scored", detected=detected,
                   reasons=sorted(evidence.get("unresolved") or []))
        rows.append(row)
    return rows


def _score(rows: list[dict]) -> dict:
    """Count per-sample class hits, and per-class which samples produced them."""
    scored = [row for row in rows if row.get("state") in {"scored", "scored_clean_silence"}]
    per_case = []
    tp = fp = fn = 0
    per_class_hit: dict[str, list[str]] = defaultdict(list)
    per_class_expected: dict[str, list[str]] = defaultdict(list)
    per_class_false: dict[str, list[str]] = defaultdict(list)
    for row in scored:
        expected = set(row["expected"])
        detected = set(row["detected"])
        case_tp = sorted(expected & detected)
        case_fp = sorted(detected - expected)
        case_fn = sorted(expected - detected)
        tp += len(case_tp)
        fp += len(case_fp)
        fn += len(case_fn)
        for item in case_tp:
            per_class_hit[item].append(row["caseId"])
        for item in case_fp:
            per_class_false[item].append(row["caseId"])
        for item in expected:
            per_class_expected[item].append(row["caseId"])
        per_case.append({
            "caseId": row["caseId"], "expected": sorted(expected),
            "detected": sorted(detected), "hit": case_tp,
            "falsePositive": case_fp, "falseNegative": case_fn,
            "exact": not case_fp and not case_fn,
        })
    return {
        "scoredSampleCount": len(scored),
        "unscoredSampleCount": len(rows) - len(scored),
        "truePositiveCount": tp, "falsePositiveCount": fp, "falseNegativeCount": fn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "exactMatchCount": sum(1 for row in per_case if row["exact"]),
        "caseCoveredCount": sum(1 for row in per_case if row["hit"]),
        "casesWithFalsePositive": sum(1 for row in per_case if row["falsePositive"]),
        "perClass": {
            item: {"expectedIn": sorted(per_class_expected[item]),
                   "hitIn": sorted(per_class_hit[item]),
                   "falsePositiveIn": sorted(per_class_false[item]),
                   "hitCount": len(per_class_hit[item]),
                   "falsePositiveCount": len(per_class_false[item]),
                   "expectedCount": len(per_class_expected[item])}
            for item in sorted(per_class_expected)
        },
        "cases": per_case,
    }


def _load_policy(contracts: Path) -> dict:
    """Load the analysis policy that constrains how coverage may be reported.

    The policy records three constraints that change what a coverage number is
    allowed to claim: majority voting may not resolve disagreements, the
    decompiler's pseudocode may not be an analysis input, and the raw count has
    to be quoted next to the post-triage count.  They are read here so the report
    carries them rather than leaving them in a document nobody reads.
    """
    path = contracts.parent / "analysis-policy.json"
    if not path.is_file():
        return {"available": False,
                "note": "缺少 benchmark/analysis-policy.json，无法附带分析口径约束"}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"available": False, "note": f"analysis-policy.json 无法读取：{error}"}
    return {
        "available": True,
        "source": str(path),
        "taxonomy": data.get("taxonomy") or {},
        "majorityVoteAllowed": (data.get("consensus") or {}).get("majorityVoteAllowed"),
        "decompilerAnalysisInput": (data.get("decompiler") or {}).get("analysisInput"),
        "triageReportingRule": (data.get("triage") or {}).get("reportingRule"),
    }


def _load_triage_baseline(contracts: Path) -> dict:
    """读取误报基线；缺失时返回不可用结构，绝不静默当作空基线。

    基线的作用是把"人工确认过的误报"和"尚未审过的告警"分开。没有基线时，
    precision 只反映原始告警量；有了基线，才能同时看到审前与审后两个数，
    并知道差额是被人审掉的而不是被静默丢弃的。
    """
    path = contracts.parent / "fp-triage-baseline.json"
    if not path.is_file():
        return {"available": False,
                "note": "缺少 benchmark/fp-triage-baseline.json，未记录任何误审判据"}
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("acknowledged") or []
    # 一条没有理由的条目不算已审：它无法复核，也会在基线腐化时静默吞掉真实告警。
    reviewed = [item for item in entries
                if isinstance(item, dict) and isinstance(item.get("reason"), str)
                and item["reason"].strip() and isinstance(item.get("caseId"), str)
                and isinstance(item.get("role"), str)]
    key = {(item["caseId"], _canonical_class(item["role"])) for item in reviewed}
    return {
        "available": True,
        "source": str(path),
        "declaredCount": len(entries),
        "reviewedCount": len(reviewed),
        "unreviewedDropped": len(entries) - len(reviewed),
        "note": data.get("说明") or data.get("note") or None,
        "keys": key,
        "entries": reviewed,
    }


def _score_with_baseline(rows: list[dict], baseline: dict) -> dict:
    """在保留原始计数的前提下，给出扣除已确认误报后的计数。

    原始 `naive` 数字一个都不改：基线是审查记录，不是检测结果。基线里被
    确认的条目只是不再计入"未审告警"这一列，并且逐条可追溯。
    """
    if not baseline.get("available"):
        return {"available": False, "note": baseline.get("note")}
    keys = baseline["keys"]
    scored = [row for row in rows if row.get("state") in {"scored", "scored_clean_silence"}]
    kept_fp = 0
    suppressed = []
    by_category: dict[str, int] = defaultdict(int)
    for row in scored:
        expected = set(row["expected"])
        for role in sorted(set(row["detected"]) - expected):
            if (row["caseId"], _canonical_class(role)) in keys:
                suppressed.append({"caseId": row["caseId"], "role": role})
                by_category[role] += 1
            else:
                kept_fp += 1
    tp = 0
    fn = 0
    for row in scored:
        expected = set(row["expected"])
        detected = set(row["detected"])
        tp += len(expected & detected)
        fn += len(expected - detected)
    return {
        "available": True,
        "reviewedSuppressedCount": len(suppressed),
        "reviewedSuppressedByCategory": dict(sorted(by_category.items())),
        "unreviewedFalsePositiveCount": kept_fp,
        "truePositiveCount": tp,
        "falseNegativeCount": fn,
        "precision": round(tp / (tp + kept_fp), 4) if tp + kept_fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "note": "扣除的是基线中人工确认的误报；原始计数见 naive，两者必须一起引用。",
        "suppressed": sorted(suppressed, key=lambda item: (item["caseId"], item["role"])),
    }


def _family_aware(rows: list[dict], family_map: dict) -> dict:
    """Recount with each family counted once, so variants do not inflate hits."""
    families = {item["id"]: item for item in family_map.get("families", [])}
    member_of = {}
    for family_id, family in families.items():
        for case_id in family.get("cases", []):
            member_of[case_id] = family_id
    scored = [row for row in rows if row.get("state") == "scored"]
    # A class is "recovered" for a family when at least one member detected it.
    family_class = defaultdict(lambda: {"expected": False, "hit": False,
                                        "falsePositive": False, "cases": []})
    for row in scored:
        expected = set(row["expected"])
        detected = set(row["detected"])
        family_id = member_of.get(row["caseId"], f"solo:{row['caseId']}")
        bucket = family_class[family_id]
        bucket["cases"].append(row["caseId"])
        bucket["expected"] = bucket["expected"] or bool(expected)
        bucket["hit"] = bucket["hit"] or bool(expected & detected)
        bucket["falsePositive"] = bucket["falsePositive"] or bool(detected - expected)
    groups = []
    tp = fp = fn = 0
    for family_id in sorted(family_class):
        bucket = family_class[family_id]
        groups.append({
            "familyId": family_id,
            "cases": sorted(bucket["cases"]),
            "expected": bucket["expected"], "hit": bucket["hit"],
            "falsePositive": bucket["falsePositive"],
        })
        if bucket["expected"] and bucket["hit"]:
            tp += 1
        if bucket["falsePositive"]:
            fp += 1
        if bucket["expected"] and not bucket["hit"]:
            fn += 1
    return {"groupCount": len(groups), "recoveredGroupCount": tp,
            "falsePositiveGroupCount": fp, "missedGroupCount": fn, "groups": groups}


def _load_adjudication(contracts: Path) -> dict:
    """Load the sample adjudication, if it has been produced.

    The report normally sits beside the `contracts/` directory, but the path is
    also checked directly so the function can be pointed at an arbitrary
    contracts root without that assumption.
    """
    for candidate in (contracts.parent / "sample-adjudication.json",
                      contracts / "sample-adjudication.json"):
        if candidate.is_file():
            data = json.loads(candidate.read_text(encoding="utf-8"))
            return {row["caseId"]: row for row in data.get("samples", [])
                    if isinstance(row, dict)}
    return {}


def _grade_of(adjudication: dict, case_id: str) -> str | None:
    row = adjudication.get(case_id)
    return row.get("grade") if row else None


def _grade_split(rows: list[dict], adjudication: dict) -> dict:
    """Recount with an explicit grade filter as the denominator.

    Coverage over all 33 samples counts a sample whose label contradicts its own
    source as a miss, which attributes the label's error to the detector.  Splitting
    by grade separates that: A-only counts only labels that are known-good, while
    B+C also admits the self-consistent synthetic fixtures.  A grade-D sample is
    never scored as a miss -- its label is wrong, so a miss would be measuring the
    label, not the scanner.
    """
    def recount(wanted: set[str], label: str) -> dict:
        scoped = []
        excluded = []
        mislabeled = []
        for row in rows:
            grade = _grade_of(adjudication, row["caseId"])
            if grade in wanted:
                scoped.append(row)
            else:
                excluded.append({"caseId": row["caseId"], "grade": grade,
                                 "state": row.get("state")})
                if grade == "D":
                    mislabeled.append(row["caseId"])
        score = _score(scoped)
        score["denominatorLabel"] = label
        score["excludedCaseCount"] = len(excluded)
        score["excluded"] = sorted(item["caseId"] for item in excluded)
        score["excludedBecauseLabelContradictsSource"] = sorted(mislabeled)
        return score

    a_only = recount({"A"}, "A 级：真实项目 + 标注可信")
    b_plus_c = recount({"B", "C"}, "B+C 级：标注存疑 + 自洽桩（排除 D）")
    both = {**a_only}
    both.update({key: value for key, value in b_plus_c.items() if key == "excludedBecauseLabelContradictsSource"})
    return {"A_only": a_only, "B_plus_C": b_plus_c,
            "trueFalseNegativeCases": sorted(
                item["caseId"] for item in a_only["cases"] if item["falseNegative"]),
            "labelErrorCases": a_only["excludedBecauseLabelContradictsSource"]}


def _poc_audit(contracts: Path) -> dict:
    """读取 PoC 证据体检结果（若存在），用于区分"本地复现"与"仅静态告警"。"""
    audit_path = contracts.parent / "poc-evidence-audit.json"
    if not audit_path.is_file():
        return {"available": False}
    data = json.loads(audit_path.read_text(encoding="utf-8"))
    return {"available": True,
            "verdicts": {c["caseId"]: c["verdict"] for c in data.get("cases", [])},
            "counts": data.get("counts", {})}


def _split_by_poc_evidence(rows: list[dict], poc: dict) -> dict:
    """按 PoC 证据强度再分一层。

    静态告警、PoC 复现、动态确认是三件事，不能合并成一个"检测成功"。这里把
    "有可核验复现证据"和"只有静态结论"分开，避免用一个数字同时描述两种能力。
    """
    if not poc.get("available"):
        return {"available": False,
                "note": "缺少 benchmark/poc-evidence-audit.json，无法区分复现证据与静态告警"}
    verdicts = poc["verdicts"]

    def collect(wanted: set[str], label: str) -> dict:
        scoped = [r for r in rows if verdicts.get(r["caseId"]) in wanted]
        score = _score(scoped)
        score["denominatorLabel"] = label
        score["caseIds"] = sorted(r["caseId"] for r in scoped)
        return score

    return {
        "available": True,
        "withReproduction": collect({"reproduced"}, "有余额/状态前后证据，可称本地复现"),
        "evidenceStale": collect({"evidence_stale"}, "证据绑定旧源码，需重跑后才能采信"),
        "fabricated": collect({"fabricated"}, "声称复现但无证据，不可采信"),
        "staticOnly": collect({"not_reproduced"}, "仅静态结论，未复现"),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts", type=Path, default=CONTRACTS)
    parser.add_argument("--json", action="store_true", help="输出完整 JSON")
    parser.add_argument("--output", type=Path, default=None,
                        help="覆盖率报告写入路径，默认写到语料目录旁的 coverage-report.json")
    args = parser.parse_args(argv)
    rows = _case_rows(args.contracts)
    family_map = _load_family_map()
    adjudication = _load_adjudication(args.contracts)
    poc = _poc_audit(args.contracts)
    naive = _score(rows)
    baseline = _load_triage_baseline(args.contracts)
    policy = _load_policy(args.contracts)
    report = {
        "schemaVersion": 1,
        "comparison": "ground-truth.knownIssues vs invariants.detectedRoles",
        "scope": "静态角色识别对照；detectedRoles 是观察到的类别，不是确认漏洞",
        "analysisPolicy": policy,
        "naive": naive,
        "triageBaseline": {
            "available": baseline.get("available"),
            "source": baseline.get("source"),
            "reviewedCount": baseline.get("reviewedCount"),
            "unreviewedDropped": baseline.get("unreviewedDropped"),
            "note": baseline.get("note"),
        },
        "afterReviewedBaseline": _score_with_baseline(rows, baseline),
        "gradeSplit": _grade_split(rows, adjudication) if adjudication else None,
        "pocEvidenceSplit": _split_by_poc_evidence(rows, poc),
        "familyAware": _family_aware(rows, family_map),
        "familyMapAvailable": bool(family_map.get("families")),
        "adjudicationAvailable": bool(adjudication),
        "unscored": [{"caseId": row["caseId"], "state": row["state"],
                      "reason": row.get("reason")} for row in rows if row.get("state") != "scored"],
    }
    # The evidence matrix and the web overview both read this file, and neither
    # of them can recompute it: they consume the scored report.  Nothing wrote it,
    # so both showed whatever had been left there by hand while the detectors
    # moved on -- which is how a matrix kept reporting "miss" for samples the
    # scanner was already detecting.  Writing it here makes the report a product
    # of the run rather than a separate artefact someone has to remember to
    # refresh.
    output_path = args.output
    if output_path is None:
        output_path = args.contracts.parent / "coverage-report.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(output_path)
    report["writtenTo"] = str(output_path)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    naive_score = report["naive"]
    print(f"样本 {len(rows)}，可评分 {naive_score['scoredSampleCount']}，"
          f"不可评分 {naive_score['unscoredSampleCount']}")
    print(f"命中 {naive_score['truePositiveCount']} / 误报 {naive_score['falsePositiveCount']} "
          f"/ 漏报 {naive_score['falseNegativeCount']}")
    print(f"precision={naive_score['precision']} recall={naive_score['recall']} "
          f"完全一致样本 {naive_score['exactMatchCount']} "
          f"至少命中一类的样本 {naive_score['caseCoveredCount']}")
    reviewed = report.get("afterReviewedBaseline") or {}
    if reviewed.get("available"):
        print(f"\n误报基线：已审确认 {reviewed['reviewedSuppressedCount']} 条，"
              f"剩余未审告警 {reviewed['unreviewedFalsePositiveCount']} 条，"
              f"precision={reviewed['precision']} recall={reviewed['recall']}")
        for item, count in (reviewed.get("reviewedSuppressedByCategory") or {}).items():
            print(f"  已审 {item}: {count}")
        print(f"  {reviewed.get('note')}")
    if report["gradeSplit"]:
        print("\n按分级分母：")
        for key in ("A_only", "B_plus_C"):
            part = report["gradeSplit"][key]
            print(f"  [{part['denominatorLabel']}] 可评分 {part['scoredSampleCount']}，"
                  f"命中 {part['truePositiveCount']} / 误报 {part['falsePositiveCount']} "
                  f"/ 漏报 {part['falseNegativeCount']}，precision={part['precision']} "
                  f"recall={part['recall']}（排除 {part['excludedCaseCount']} 个样本）")
    family = report["familyAware"]
    print(f"\n按协议族去重：{family['groupCount']} 组，命中 {family['recoveredGroupCount']}，"
          f"含误报 {family['falsePositiveGroupCount']}，漏 {family['missedGroupCount']}")
    for group in family["groups"]:
        mark = "命中" if group["hit"] and not group["expected"] is False else (
            "命中" if group["hit"] else ("漏" if group["expected"] else "clean"))
        extra = " 误报" if group["falsePositive"] else ""
        print(f"  [{mark}{extra}] {group['familyId']}: {','.join(group['cases'])}")
    print("\n分类别：")
    for item, detail in naive_score["perClass"].items():
        print(f"  {item}: 命中 {detail['hitCount']}/{detail['expectedCount']} "
              f"误报样本 {detail['falsePositiveCount']}")
        if detail["hitIn"]:
            print(f"      命中: {','.join(detail['hitIn'])}")
        if detail["falsePositiveIn"]:
            print(f"      误报: {','.join(detail['falsePositiveIn'])}")
    if report["unscored"]:
        print("\n未评分样本：")
        for row in report["unscored"]:
            print(f"  {row['caseId']}: {row['state']} {row.get('reason') or ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())