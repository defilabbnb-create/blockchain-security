#!/usr/bin/env python3
"""Local evidence adapters for the pipeline review and report stages."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from report_builder import build_report
from repr_cache import source_bundle_sha256


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _finding_index(target: dict[str, Any], stage_dir: Path) -> Path | None:
    configured = target.get("findingIndex")
    candidates = []
    if isinstance(configured, str) and configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend((stage_dir / "finding-index.json", stage_dir.parent / "finding-index.json"))
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file() and resolved.name == "finding-index.json":
            if resolved == (stage_dir / "finding-index.json").resolve():
                try:
                    existing = json.loads(resolved.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    existing = None
                if isinstance(existing, dict) and existing.get("generatedByPipeline") is True:
                    return _write_run_finding_index(target, stage_dir)
            return resolved
    evidence_files = ("static.json", "dynamic-result.json", "poc-result.json", "ir-reconciliation.json")
    if not any((stage_dir / name).is_file() for name in evidence_files):
        return None
    return _write_run_finding_index(target, stage_dir)


def _write_run_finding_index(target: dict[str, Any], stage_dir: Path) -> Path:
    """Normalize evidence produced by this pipeline run without confirming risks."""
    static_path = stage_dir / "static.json"
    static, static_state = ({}, "not_available")
    if static_path.is_file():
        try:
            static = json.loads(static_path.read_text(encoding="utf-8"))
            static_state = "available"
        except (OSError, json.JSONDecodeError):
            static_state = "unavailable"
    source_hash = static.get("verifiedSourceFingerprint") or static.get("sourceSha256")
    source_bundle_path = target.get("sourceBundle") or target.get("sourcePath")
    if isinstance(source_bundle_path, str):
        try:
            bundle = json.loads(Path(source_bundle_path).read_text(encoding="utf-8"))
            source_hash = source_bundle_sha256(bundle)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
    source_hash = source_hash if isinstance(source_hash, str) and len(source_hash) == 64 else None
    static_hash = _sha256(static_path) if static_path.is_file() else None
    rows: list[dict[str, Any]] = []

    def add(kind: str, title: str, severity: str, status: str, evidence: dict[str, Any], identity: Any) -> None:
        digest_source = source_hash or static_hash or hashlib.sha256(b"missing-source").hexdigest()
        identity_json = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        finding_id = hashlib.sha256(f"{digest_source}\0{kind}\0{identity_json}".encode("utf-8")).hexdigest()
        rows.append({"id": finding_id, "kind": kind, "title": title[:300], "severity": severity,
                     "status": status, "sourceSha256": source_hash, "confirmedVulnerability": False,
                     "evidence": [evidence], "origin": "pipeline_run"})

    findings = static.get("findings", []) if isinstance(static, dict) else []
    if isinstance(findings, list):
        for index, finding in enumerate(findings[:2000]):
            if not isinstance(finding, dict):
                continue
            check = str(finding.get("check") or finding.get("id") or "static_signal")[:160]
            impact = str(finding.get("impact") or "info").lower()
            severity = impact if impact in {"critical", "high", "medium", "low", "info"} else "info"
            elements = finding.get("elements") if isinstance(finding.get("elements"), list) else []
            element = next((item for item in elements if isinstance(item, dict)), {})
            mapping = element.get("source_mapping") if isinstance(element.get("source_mapping"), dict) else {}
            filename = mapping.get("filename_relative") or mapping.get("filename_short") or "static.json"
            if not isinstance(filename, str) or filename.startswith("/") or ".." in Path(filename).parts or "\\" in filename:
                filename = "static.json"
            lines = mapping.get("lines") if isinstance(mapping.get("lines"), list) else []
            line = next((value for value in lines if isinstance(value, int) and not isinstance(value, bool) and value > 0), 0)
            evidence = {"file": filename, "lineStart": line, "lineEnd": line,
                        "quote": str(finding.get("description") or finding.get("markdown") or check)[:800],
                        "sourceSha256": source_hash, "evidenceSha256": static_hash}
            add("static_signal", check, severity, "unconfirmed_observation", evidence,
                {"check": check, "impact": impact, "file": filename, "line": line, "ordinal": index})

    representation = static.get("representation") if isinstance(static, dict) else None
    cache_path = representation.get("cachePath") if isinstance(representation, dict) else None
    if isinstance(cache_path, str):
        ir_path = Path(cache_path) / "ir-reconciliation.json"
        try:
            ir = json.loads(ir_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            ir = None
        divergent = ir.get("bytecodeOnlyFunctions", []) if isinstance(ir, dict) else []
        if isinstance(divergent, list) and divergent:
            evidence = {"file": "ir-reconciliation.json", "lineStart": 0, "lineEnd": 0,
                        "quote": f"bytecodeOnlyFunctions={len(divergent)}; sourceFaithfulnessScore={ir.get('sourceFaithfulnessScore')}",
                        "evidenceSha256": _sha256(ir_path)}
            add("source_bytecode_divergence", "源码与字节码存在未对齐函数候选", "info", "static_signal",
                evidence, {"bytecodeOnlyFunctions": divergent[:40]})

    dynamic_path = stage_dir / "dynamic-result.json"
    try:
        dynamic = json.loads(dynamic_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        dynamic = None
    dynamic_rows = dynamic.get("results", []) if isinstance(dynamic, dict) else []
    if isinstance(dynamic_rows, list):
        for item in dynamic_rows[:500]:
            if not isinstance(item, dict) or item.get("state") not in {"violated", "passed"}:
                continue
            state = item["state"]
            evidence = {"file": "dynamic-result.json", "lineStart": 0, "lineEnd": 0,
                        "quote": f"invariantId={str(item.get('invariantId', 'unknown'))[:80]}; state={state}",
                        "evidenceSha256": dynamic.get("evidenceSha256")}
            add("invariant_observation", "动态不变量执行观察", "info", "unconfirmed_observation",
                evidence, {"invariantId": item.get("invariantId"), "state": state})

    index = {"schemaVersion": 1, "generatedAt": datetime.now(timezone.utc).isoformat(),
             "findings": rows, "coverage": {"complete": False, "state": static_state,
                                              "reason": "本索引仅汇总当前流水线已落盘证据；未覆盖不代表不存在风险。"},
             "sourceSha256": source_hash, "staticEvidenceSha256": static_hash,
             "confirmedVulnerability": False, "semanticsProven": False, "generatedByPipeline": True}
    path = stage_dir / "finding-index.json"
    _atomic_json(path, index)
    return path


def _local_review(index_path: Path, stage_dir: Path) -> dict[str, Any]:
    raw = index_path.read_bytes()
    try:
        index = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("finding-index.json is not valid UTF-8 JSON")
    if not isinstance(index, dict) or not isinstance(index.get("findings"), list):
        raise ValueError("finding-index.json must contain a findings array")
    findings = [row for row in index["findings"] if isinstance(row, dict)]
    evidence = {
        "schemaVersion": 1,
        "provider": "local_structured_evidence",
        "state": "available",
        "source": {"file": "finding-index.json", "sha256": hashlib.sha256(raw).hexdigest()},
        "findingCount": len(findings),
        "observations": [
            {
                "findingId": str(row.get("id", ""))[:160],
                "kind": str(row.get("kind", "unknown"))[:120],
                "status": str(row.get("status", "unconfirmed_observation"))[:80],
                "severity": str(row.get("severity", "info"))[:40],
                "confirmedVulnerability": False,
            }
            for row in findings
        ],
        "securityConclusion": "unconfirmed_observations_only",
        "semanticsProven": False,
    }
    output = stage_dir / "review-local.json"
    _atomic_json(output, evidence)
    return {"state": "unavailable", "reason": "cloud_review_not_configured",
            "localEvidencePath": str(output), "localEvidenceSha256": _sha256(output),
            "provider": "local_structured_evidence", "findingCount": len(findings)}


def _configured_cloud_review(target: dict[str, Any], stage_dir: Path) -> dict[str, Any]:
    endpoint = os.environ.get("DEFI_CLOUD_AI_BASE_URL", "").strip()
    api_key = os.environ.get("DEFI_CLOUD_AI_API_KEY", "").strip()
    model = os.environ.get("DEFI_CLOUD_AI_MODEL", "").strip()
    if target.get("allowCloudReview") is not True or not endpoint or not api_key or not model:
        return {"state": "unavailable", "reason": "cloud_review_not_configured"}
    sources = target.get("sources")
    record = target.get("reviewRecord")
    target_files = target.get("reviewTargets")
    if (not isinstance(sources, dict) or not sources or
            any(not isinstance(name, str) or not isinstance(text, str) for name, text in sources.items()) or
            not isinstance(record, dict) or not all(isinstance(record.get(key), str) and record[key] for key in ("protocol", "chain", "address")) or
            not isinstance(target_files, list) or any(not isinstance(name, str) for name in target_files)):
        return {"state": "unavailable", "reason": "cloud_review_inputs_missing"}
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    campaign_path = SCRIPT_DIR / "defi-campaign.py"
    spec = importlib.util.spec_from_file_location("pipeline_campaign_review", campaign_path)
    if spec is None or spec.loader is None:
        return {"state": "unavailable", "reason": "campaign_review_helpers_unavailable"}
    campaign = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(campaign)
    from cloud_review import run_staged_review

    result = run_staged_review(
        data={"sources": sources}, record=record, sources=sources, targets=target_files,
        validate_review=campaign.validate_review, build_excerpts=campaign.build_excerpts,
        unified_ir=target.get("unifiedIR"), invariants=target.get("invariants"),
        dependency_signatures=target.get("dependencySignatures"), endpoint=endpoint,
        api_key=api_key, model=model,
        summary_model=os.environ.get("DEFI_CLOUD_AI_SUMMARY_MODEL", "").strip() or None,
        adversarial_model=os.environ.get("DEFI_CLOUD_AI_ADVERSARIAL_MODEL", "").strip() or None,
        budget_usd=target.get("reviewBudgetUsd"),
    )
    output = stage_dir / "review-cloud.json"
    _atomic_json(output, result)
    return {"state": "completed", "provider": "external_cloud_ai", "model": model,
            "manifestSha256": result["manifestSha256"], "responseSha256": result.get("responseSha256"),
            "outputPath": str(output), "outputSha256": _sha256(output),
            "findingCount": len(result.get("observations", [])), "semanticsProven": False}


def run_stage(stage: str, target: dict[str, Any], stage_dir: str | Path, mode: str) -> dict[str, Any]:
    """Run review/report adapters without implicit network access."""
    directory = Path(stage_dir).resolve()
    if stage == "review":
        if target.get("mockCloudReview") is True:
            index_path = _finding_index(target, directory)
            if index_path is None:
                return {"state": "unavailable", "reason": "finding_index_missing"}
            local = _local_review(index_path, directory)
            local_payload = json.loads((directory / "review-local.json").read_text(encoding="utf-8"))
            local_payload["provider"] = "mock_cloud_ai"
            local_payload["state"] = "completed"
            local_payload["mock"] = True
            _atomic_json(directory / "review-mock.json", local_payload)
            return {"state": "completed", "provider": "mock_cloud_ai", "mock": True,
                    "manifestSha256": local_payload["source"]["sha256"],
                    "outputPath": str(directory / "review-mock.json"),
                    "outputSha256": _sha256(directory / "review-mock.json"),
                    "findingCount": local_payload["findingCount"], "semanticsProven": False}
        configured = all(os.environ.get(key, "").strip() for key in (
            "DEFI_CLOUD_AI_BASE_URL", "DEFI_CLOUD_AI_API_KEY", "DEFI_CLOUD_AI_MODEL"))
        if configured and target.get("allowCloudReview") is True:
            try:
                return _configured_cloud_review(target, directory)
            except Exception as error:
                return {"state": "failed", "reason": f"cloud_review_failed:{type(error).__name__}"}
        index_path = _finding_index(target, directory)
        if index_path is None:
            return {"state": "unavailable", "reason": "finding_index_missing"}
        return _local_review(index_path, directory)
    if stage == "report":
        index_path = _finding_index(target, directory)
        if index_path is None:
            return {"state": "unavailable", "reason": "finding_index_missing"}
        report_dir = directory / "reports"
        try:
            report = build_report(index_path, output_dir=report_dir, evidence_dir=directory)
        except (OSError, ValueError, TypeError) as error:
            return {"state": "failed", "reason": f"report_build_failed:{type(error).__name__}"}
        output_names = ("report.md", "report.html", "report.sarif.json")
        output_hashes = {name: _sha256(report_dir / name) for name in output_names}
        return {"state": "completed", "provider": "local_report_builder",
                "findingIndexSha256": _sha256(index_path), "findingCount": report["findingCount"],
                "coverageComplete": report["coverage"]["complete"], "outputs": output_hashes,
                "semanticsProven": False}
    return {"state": "unavailable", "reason": f"unsupported_review_report_stage:{stage}"}

