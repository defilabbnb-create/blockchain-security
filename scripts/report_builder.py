#!/usr/bin/env python3
"""Build provenance-aware Markdown, HTML and SARIF security reports."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SEVERITIES = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note", "informational": "note"}


def _load(path: Path) -> tuple[Any, str]:
    if not path.is_file():
        return None, "not_available"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "available"
    except (OSError, json.JSONDecodeError):
        return None, "unavailable"


def _findings(value: Any) -> list[dict[str, Any]]:
    rows = value.get("findings", []) if isinstance(value, dict) else []
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _confirmed_poc_ids(value: Any, findings: list[dict[str, Any]], evidence_dir: Path | None = None) -> set[str]:
    """Accept confirmation only when a successful PoC is bound to this finding."""
    if not isinstance(value, dict) or value.get("pocState") != "confirmed" or value.get("confirmed_by_poc") is not True:
        return set()
    finding_id = value.get("findingId")
    evidence_hash = value.get("evidenceSha256")
    execution_hash = value.get("executionEvidenceSha256")
    bundle_hash = value.get("sourceBundleSha256")
    test_name = value.get("testName")
    manifest_hash = value.get("pocManifestSha256")
    attempts = value.get("attempts")
    if (not isinstance(finding_id, str) or not finding_id or not _valid_sha256(bundle_hash) or
            not isinstance(test_name, str) or not test_name or not _valid_sha256(manifest_hash)):
        return set()
    if not _valid_sha256(evidence_hash) or not isinstance(attempts, list):
        return set()
    if value.get("pocArtifactPath") is not None and not _valid_sha256(execution_hash):
        return set()
    if not any(isinstance(attempt, dict) and attempt.get("state") == "passed" and
               attempt.get("matchedTestPassed") is True and attempt.get("testName") == test_name and
               attempt.get("pocManifestSha256") == manifest_hash and
               attempt.get("sourceBundleSha256") == bundle_hash and
               _valid_sha256(attempt.get("testSourceSha256")) and
               _valid_sha256(attempt.get("evidenceSha256")) and
               (execution_hash is None or attempt.get("evidenceSha256") == execution_hash)
               for attempt in attempts):
        return set()
    matches = [row for row in findings if str(row.get("id", "")) == finding_id]
    if len(matches) != 1:
        return set()
    declared_bundle_hash = matches[0].get("sourceBundleSha256")
    if declared_bundle_hash is not None and declared_bundle_hash != bundle_hash:
        return set()
    if evidence_dir is not None and value.get("pocArtifactPath") is not None:
        try:
            artifact_root = (evidence_dir / str(value["pocArtifactPath"])).resolve(strict=True)
            evidence_root = evidence_dir.resolve(strict=True)
            artifact_root.relative_to(evidence_root)
            manifest_path = (artifact_root / "poc.json").resolve(strict=True)
            manifest_path.relative_to(artifact_root)
            if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != manifest_hash:
                return set()
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (manifest.get("findingId") != finding_id or manifest.get("testName") != test_name or
                    manifest.get("sourceBundleSha256") != bundle_hash):
                return set()
            passed_attempt = next(attempt for attempt in attempts
                                  if isinstance(attempt, dict) and attempt.get("state") == "passed" and
                                  attempt.get("matchedTestPassed") is True and attempt.get("testName") == test_name)
            test_path = (artifact_root / str(manifest.get("testPath", ""))).resolve(strict=True)
            test_path.relative_to(artifact_root / "test")
            if hashlib.sha256(test_path.read_bytes()).hexdigest() != passed_attempt.get("testSourceSha256"):
                return set()
        except (OSError, ValueError, TypeError, json.JSONDecodeError, StopIteration):
            return set()
    return {finding_id}


def _status(row: dict[str, Any], confirmed_poc_ids: set[str] | None = None) -> str:
    status = str(row.get("status") or "unconfirmed_observation")
    if str(row.get("id", "")) in (confirmed_poc_ids or set()):
        return "已证实"
    if status in {"poc_failed", "excluded", "rejected"}:
        return "已排除"
    return "未证实"


def _severity(row: dict[str, Any]) -> str:
    value = str(row.get("severity") or row.get("impact") or "info").lower()
    return value if value in SEVERITIES else "info"


def _safe_id(row: dict[str, Any], index: int) -> str:
    value = row.get("id") or row.get("ruleId") or f"finding-{index + 1}"
    return str(value)[:160]


def _evidence(row: dict[str, Any]) -> list[dict[str, Any]]:
    value = row.get("evidence", [])
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def build_report(input_path: str | Path, *, output_dir: str | Path | None = None,
                 evidence_dir: str | Path | None = None, generated_at: str | None = None) -> dict[str, Any]:
    """Load a run directory or finding-index and return all report formats."""
    root = Path(input_path)
    if root.is_file():
        root_dir = root.parent
        index_path = root
    else:
        root_dir = root
        index_path = root / "finding-index.json"
    index, index_state = _load(index_path)
    rows = _findings(index)
    evidence_root = Path(evidence_dir) if evidence_dir is not None else root_dir
    optional: dict[str, dict[str, Any]] = {}
    for name in ("invariants", "dynamic-result", "poc-result", "ir-reconciliation"):
        value, state = _load(evidence_root / f"{name}.json")
        optional[name] = {"state": state, "value": value}
    confirmed_poc_ids = _confirmed_poc_ids(optional["poc-result"]["value"], rows, evidence_root)
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    ir_value = optional["ir-reconciliation"]["value"]
    ir_score = ir_value.get("sourceFaithfulnessScore") if isinstance(ir_value, dict) else None
    index_value = index if isinstance(index, dict) else {}
    recorded_coverage = index_value.get("coverage")
    coverage_complete = recorded_coverage.get("complete") is True if isinstance(recorded_coverage, dict) else False
    coverage_reason = recorded_coverage.get("reason") if isinstance(recorded_coverage, dict) else "finding index does not establish full analysis coverage"
    payload = {
        "schemaVersion": 1,
        "generatedAt": generated,
        "coverage": {"complete": coverage_complete, "state": index_state, "reason": coverage_reason if index_state == "available" else "finding-index.json unavailable"},
        "findingCount": len(rows),
        "findings": [{**row, "reportStatus": _status(row, confirmed_poc_ids)} for row in rows],
        "sources": optional,
        "sourceFaithfulnessScore": ir_score,
        "cost": {"state": "not_available", "amountUsd": None, "reason": "input evidence does not include a complete cost record"},
        "reproduction": {"state": "not_available", "instructions": "Use the recorded local test plan and evidence paths; no executable reproduction was supplied."},
        "methodology": {"static": "available" if rows else "not_performed", "dynamic": optional["dynamic-result"]["state"], "poc": optional["poc-result"]["state"], "irReconciliation": optional["ir-reconciliation"]["state"]},
    }
    payload["markdown"] = render_markdown(payload)
    payload["html"] = render_html(payload)
    payload["sarif"] = render_sarif(payload)
    if output_dir is not None:
        write_reports(output_dir, payload)
    return payload


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# 区块链分析报告", "", f"生成时间：{report.get('generatedAt', '未记录')}", "", "## 执行摘要", "", f"记录数量：{report.get('findingCount', 0)}。结论仅适用于已保存且可追溯的证据。", "", "## 方法论", ""]
    for key, value in report.get("methodology", {}).items():
        lines.append(f"- {key}：{value}")
    lines += ["", "## 覆盖范围", "", f"覆盖状态：{report.get('coverage', {}).get('state', 'not_available')}"]
    if report.get("coverage", {}).get("reason"):
        lines.append(f"缺失原因：{report['coverage']['reason']}")
    score = report.get("sourceFaithfulnessScore")
    if isinstance(score, (int, float)) and score < 0.8:
        lines += ["", "警示：源码与字节码对账可信度低于 0.8，源码结论仅供参考。"]
    lines += ["", "## 发现列表", ""]
    rows = report.get("findings", [])
    if not rows:
        lines.append("当前输入没有可列出的发现记录；这不表示目标不存在风险。")
    for index, row in enumerate(rows):
        title = str(row.get("title") or row.get("kind") or "未命名记录").replace("\n", " ")
        lines += [f"### {_safe_id(row, index)}：{title}", "", f"- 严重度：{_severity(row)}", f"- 结论：{row.get('reportStatus', _status(row))}", f"- 来源指纹：{row.get('sourceSha256') or '未记录'}"]
        evidence = _evidence(row)
        if evidence:
            lines.append("- 证据：")
            for item in evidence:
                quote = str(item.get("quote") or "").replace("\n", " ")[:400]
                lines.append(f"  - `{item.get('file', '未记录')}`:{item.get('lineStart', '?')}-{item.get('lineEnd', '?')} {quote}")
        else:
            lines.append("- 证据：未记录")
    lines += ["", "## 成本披露", "", f"状态：{report.get('cost', {}).get('state', 'not_available')}；金额：{report.get('cost', {}).get('amountUsd', '未记录')}。", "", "## 复现指引", "", report.get("reproduction", {}).get("instructions", "未提供可执行复现步骤。"), "", "## 附录证据路径", "", "缺失的动态、PoC 或 IR 输入均保留为 `not_available`，不会被解释为通过或失败。"]
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""), quote=True)
    rows = []
    for index, row in enumerate(report.get("findings", [])):
        rows.append(f"<tr><td>{esc(_severity(row))}</td><td>{esc(_safe_id(row, index))}</td><td>{esc(row.get('title') or row.get('kind') or '未命名记录')}</td><td>{esc(row.get('reportStatus', _status(row)))}</td><td>{esc(row.get('sourceSha256') or '未记录')}</td></tr>")
    if not rows:
        rows.append('<tr><td colspan="5">当前输入没有可列出的发现记录；这不表示目标不存在风险。</td></tr>')
    warning = ""
    score = report.get("sourceFaithfulnessScore")
    if isinstance(score, (int, float)) and score < 0.8:
        warning = '<p class="notice">源码与字节码对账可信度低于 0.8，源码结论仅供参考。</p>'
    return "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>区块链分析报告</title><style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#18212b}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d6dce3;padding:.5rem;text-align:left}th{background:#f3f6f8}.notice{padding:.8rem;background:#fff6df;border-left:4px solid #d49a26}</style></head><body><h1>区块链分析报告</h1><p>生成时间：" + esc(report.get("generatedAt")) + "</p><p class=\"notice\">结果来自已保存证据。未证实记录需要进一步验证。</p>" + warning + "<h2>发现列表</h2><table><thead><tr><th>严重度</th><th>ID</th><th>标题</th><th>结论</th><th>来源指纹</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table><h2>覆盖范围</h2><p>完整：" + esc(report.get("coverage", {}).get("complete")) + "；" + esc(report.get("coverage", {}).get("reason")) + "</p><h2>成本披露</h2><p>not_available：未记录完整成本。</p><h2>复现指引</h2><p>使用记录的本地测试计划和证据路径；没有提供可执行复现。</p></body></html>"


def render_sarif(report: dict[str, Any]) -> dict[str, Any]:
    results = []
    rules = []
    seen = set()
    for index, row in enumerate(report.get("findings", [])):
        rule_id = _safe_id(row, index)
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({"id": rule_id, "name": str(row.get("title") or row.get("kind") or rule_id), "shortDescription": {"text": str(row.get("title") or row.get("kind") or rule_id)}})
        result = {"ruleId": rule_id, "level": SEVERITIES[_severity(row)], "message": {"text": str(row.get("title") or row.get("kind") or "未命名记录")}, "properties": {"status": row.get("reportStatus", _status(row)), "sourceSha256": row.get("sourceSha256")}}
        evidence = _evidence(row)
        if evidence and isinstance(evidence[0].get("file"), str):
            location = {"physicalLocation": {"artifactLocation": {"uri": evidence[0]["file"]}}}
            if isinstance(evidence[0].get("lineStart"), int):
                location["physicalLocation"]["region"] = {"startLine": evidence[0]["lineStart"]}
            result["locations"] = [location]
        results.append(result)
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "defi-scan", "rules": rules}}, "results": results, "properties": {"coverage": report.get("coverage"), "interpretation": "候选记录不等于已证实漏洞。"}}]}


def write_reports(output_dir: str | Path, report: dict[str, Any]) -> None:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "report.md": report["markdown"],
        "report.html": report["html"],
        "report.sarif.json": json.dumps(report["sarif"], ensure_ascii=False, indent=2) + "\n",
    }
    for name, content in artifacts.items():
        destination = directory / name
        fd, temporary = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="run directory or finding-index.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    build_report(args.input, output_dir=args.output)
    print(json.dumps({"output": args.output, "formats": ["markdown", "html", "sarif"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
