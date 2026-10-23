#!/usr/bin/env python3
"""Export provenance-bound examples from all local Solidity corpora."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
DEFAULT_OUTPUT = ROOT / "training-data/training.jsonl"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rooted_path(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("unsafe_path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("unsafe_path")
    path = (root / Path(*relative.parts)).resolve()
    root_resolved = root.resolve()
    if path != root_resolved and root_resolved not in path.parents:
        raise ValueError("path_outside_corpus")
    return path


def _source_entry(root: Path, file_entry: dict[str, Any], *, primary: bool) -> dict[str, Any]:
    object_path = file_entry.get("objectPath")
    declared = file_entry.get("sha256")
    if not isinstance(object_path, str) or not isinstance(declared, str):
        raise ValueError("source_object_metadata_missing")
    path = _rooted_path(root, object_path)
    content = path.read_bytes()
    observed = _sha256(content)
    if observed != declared:
        raise ValueError(f"source_hash_mismatch:{object_path}")
    return {**file_entry, "sha256": observed,
            "source": content.decode("utf-8", errors="replace"), "primary": primary}


def _validate_sources(root: Path, sample: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    declared_sources = sample.get("sourceFiles")
    if isinstance(declared_sources, list):
        sources = [_source_entry(root, value, primary=True) for value in declared_sources
                   if isinstance(value, dict)]
    else:
        sources = [_source_entry(root, {
            "path": sample.get("path"), "objectPath": sample.get("objectPath"),
            "sha256": sample.get("sha256"),
        }, primary=True)]
    if not sources:
        raise ValueError("source_files_empty")
    declared_dependencies = sample.get("dependencyFiles")
    dependencies = []
    if isinstance(declared_dependencies, list):
        if any(not isinstance(value, dict) for value in declared_dependencies):
            raise ValueError("dependency_file_metadata_invalid")
        dependencies = [_source_entry(root, value, primary=False) for value in declared_dependencies]
    return sources, dependencies


def _bundle_sha256(entries: list[dict[str, Any]], *, preserve_order: bool = False) -> str:
    units = []
    for entry in entries:
        unit = entry.get("compilerSourceUnit") or entry.get("path")
        if not isinstance(unit, str) or not unit:
            raise ValueError("source_unit_missing")
        units.append((unit, entry["sha256"]))
    ordered_units = units if preserve_order else sorted(units)
    payload = "".join(f"{unit}:{digest}\n" for unit, digest in ordered_units)
    return _sha256(payload.encode())


def _load_evidence(root: Path, value: object, declared_digest: object) -> dict[str, Any]:
    result: dict[str, Any] = {"path": value if isinstance(value, str) else None,
                              "declaredSha256": declared_digest if isinstance(declared_digest, str) else None,
                              "observedSha256": None, "valid": False, "record": None, "reason": None}
    if not isinstance(value, str):
        result["reason"] = "evidence_path_missing"
        return result
    try:
        raw = _rooted_path(root, value).read_bytes()
        observed = _sha256(raw)
        result["observedSha256"] = observed
        record = json.loads(raw.decode("utf-8"))
        result["record"] = record if isinstance(record, dict) else None
        if not isinstance(declared_digest, str):
            result["reason"] = "evidence_digest_missing"
        elif declared_digest != observed:
            result["reason"] = "evidence_hash_mismatch"
        elif not isinstance(record, dict):
            result["reason"] = "evidence_not_object"
        else:
            result["valid"] = True
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        result["reason"] = f"evidence_unreadable:{type(error).__name__}"
    return result


def _reentrancy_profit_assertion(record: dict[str, Any]) -> bool:
    def amount(key: str) -> int | None:
        value = record.get(key)
        if isinstance(value, bool):
            return None
        if isinstance(value, int) and value >= 0:
            return value
        if isinstance(value, str) and value.isdecimal():
            return int(value)
        return None

    extracted = amount("extractedWei")
    seeded = amount("seededBalanceWei")
    profit = amount("profitWei")
    victim_before = amount("victimCreditBeforeWei")
    victim_after = amount("victimCreditAfterWei")
    target_before = amount("beforeTargetBalanceWei")
    target_after = amount("afterTargetBalanceWei")
    attacker_before = amount("attackerBalanceBeforeAttackWei")
    attacker_after = amount("attackerBalanceWei")
    return (
        record.get("attackStatus") == 1
        and all(value is not None for value in (
            extracted, seeded, profit, victim_before, victim_after,
            target_before, target_after, attacker_before, attacker_after))
        and profit > 0
        and extracted > seeded
        and profit == extracted - seeded
        and victim_before > 0
        and victim_after == victim_before
        and target_before > target_after
        and attacker_after - attacker_before == extracted
    )


def _dynamic_evidence(root: Path, sample: dict[str, Any], analysis: dict[str, Any],
                      source_bundle: object, source_sha: str) -> tuple[dict[str, Any], bool]:
    evidence = _load_evidence(root, analysis.get("dynamicEvidence"), analysis.get("dynamicEvidenceSha256"))
    record = evidence.get("record")
    state = analysis.get("dynamicState", analysis.get("dynamic", sample.get("dynamicState", "not_run")))
    assertions = record.get("assertions") if isinstance(record, dict) else None
    assertions_valid = (isinstance(assertions, list) and bool(assertions)
                        and all(isinstance(assertion, dict) and assertion.get("passed") is True
                                for assertion in assertions))
    if not assertions_valid and isinstance(record, dict):
        assertion = record.get("assertion")
        assertions_valid = isinstance(assertion, dict) and assertion.get("passed") is True
        if not assertions_valid:
            assertions_valid = (_reentrancy_profit_assertion(record)
                                or record.get("checkedReverted") is True
                                or record.get("transactionStatus") == 1
                                or (record.get("attackStatus") == 1
                                    and record.get("beforeTargetBalanceWei") is not None
                                    and record.get("afterTargetBalanceWei") == "0")
                                or (record.get("beforeValue") is not None
                                    and record.get("afterValue") is not None
                                    and record.get("beforeValue") != record.get("afterValue")))
    transactions = record.get("transactions") if isinstance(record, dict) else None
    transactions_valid = (isinstance(transactions, list) and bool(transactions)
                          and all(isinstance(transaction, dict) and transaction.get("status") == 1
                                  for transaction in transactions))
    if not transactions_valid and isinstance(record, dict):
        transactions_valid = (record.get("transactionStatus") == 1
                              or isinstance(record.get("transactionHash"), str)
                              or (record.get("attackStatus") == 1 and isinstance(record.get("callTrace"), list)
                                  and bool(record.get("callTrace")))
                              or (record.get("checkedReverted") is True
                                  and isinstance(record.get("blockedTransaction"), dict)
                                  and record["blockedTransaction"].get("status") == 0))
    boundary = record.get("executionBoundary") if isinstance(record, dict) else None
    confirmed = (
        state in {"confirmed", "passed"}
        and evidence.get("valid") is True
        and isinstance(record, dict)
        and record.get("confirmedVulnerability") is True
        and record.get("state") in {"confirmed", "passed"}
        and ((source_bundle is not None and record.get("sourceBundleSha256") == source_bundle)
             or (source_bundle is None and record.get("sourceSha256") == source_sha))
        and record.get("runnerExitCode", 0) == 0
        and assertions_valid
        and transactions_valid
        and isinstance(boundary, dict)
        and boundary.get("mode") == "isolated_in_process"
        and boundary.get("externalTransactions") is False
        and boundary.get("externalSigning") is False
    )
    if state in {"confirmed", "passed"} and not confirmed:
        effective_state = "unverified"
        reason = evidence.get("reason") or "dynamic_evidence_confirmation_mismatch"
    else:
        effective_state = state
        reason = analysis.get("dynamicReason", sample.get("dynamicNotRunReason"))
    return ({"state": effective_state, "reason": reason, "path": evidence.get("path"),
             "declaredSha256": evidence.get("declaredSha256"),
             "observedSha256": evidence.get("observedSha256"),
             "valid": evidence.get("valid", False)}, confirmed)


def _static_findings(root: Path, analysis: dict[str, Any]) -> list[dict[str, Any]]:
    evidence_path = analysis.get("analysisEvidence")
    if not isinstance(evidence_path, str):
        return []
    try:
        evidence = json.loads(_rooted_path(root, evidence_path).read_text(encoding="utf-8"))
        attempts = evidence.get("attempts", []) if isinstance(evidence, dict) else []
        selected = next((attempt for attempt in attempts
                         if isinstance(attempt, dict)
                         and attempt.get("compilerVersion") == analysis.get("compilerVersion")
                         and attempt.get("status") in {"passed", "partial"}), None)
        payload = selected.get("payload", {}) if isinstance(selected, dict) else {}
        findings = payload.get("findings", []) if isinstance(payload, dict) else []
        output = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            locations = []
            for element in (finding.get("elements") if isinstance(finding.get("elements"), list) else [])[:8]:
                mapping = element.get("source_mapping") if isinstance(element, dict) else None
                if isinstance(mapping, dict):
                    locations.append({"file": mapping.get("filename_relative") or mapping.get("filename_short"),
                                      "lines": mapping.get("lines", [])[:4]})
            output.append({"check": finding.get("check"), "impact": finding.get("impact"),
                           "confidence": finding.get("confidence"),
                           "description": str(finding.get("description", ""))[:1000],
                           "locations": locations})
        return output
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return []


def _compiler_sha(analysis: dict[str, Any]) -> str | None:
    attempts = analysis.get("compilerAttempts")
    if not isinstance(attempts, list):
        return None
    return next((row.get("compilerSha256") for row in attempts
                 if isinstance(row, dict)
                 and row.get("compilerVersion") == analysis.get("compilerVersion")
                 and row.get("status") in {"passed", "partial"}), None)


def _row_for_sample(root: Path, manifest: dict[str, Any], sample: dict[str, Any]) -> dict[str, Any]:
    sources, dependencies = _validate_sources(root, sample)
    analysis = sample.get("analysis") if isinstance(sample.get("analysis"), dict) else {}
    if not analysis:
        analysis = {"static": sample.get("staticState"), "dynamic": sample.get("dynamicState"),
                    "dynamicEvidence": sample.get("dynamicEvidence"),
                    "dynamicEvidenceSha256": sample.get("dynamicEvidenceSha256"),
                    "dynamicReason": sample.get("dynamicNotRunReason"),
                    "confirmedVulnerability": sample.get("confirmedVulnerability", False)}
    source_bundle = sample.get("sourceBundleSha256")
    if source_bundle is not None and _bundle_sha256(
            sources + dependencies, preserve_order=sample.get("dataset", manifest.get("dataset", "github-vulnerabilities")) == "ethernaut") != source_bundle:
        raise ValueError("source_bundle_hash_mismatch")
    dynamic, confirmed = _dynamic_evidence(root, sample, analysis, source_bundle, sources[0]["sha256"])
    primary = sources[0]
    all_files = sources + dependencies
    source_hashes = sorted({entry["sha256"] for entry in all_files})
    source_payload = [{key: value for key, value in entry.items() if key != "primary"} for entry in all_files]
    return {
        "schemaVersion": 1,
        "dataset": sample.get("dataset", manifest.get("dataset", "github-vulnerabilities")),
        "repo": sample.get("repo", manifest.get("repo")),
        "commit": sample.get("commit", manifest.get("commit")),
        "challenge": sample.get("challenge"),
        "path": sample.get("path", primary.get("path")),
        "category": sample.get("category", sample.get("vulnerabilityType")),
        "vulnerabilityType": sample.get("vulnerabilityType", sample.get("category")),
        "attack": sample.get("attack"),
        "source": primary["source"],
        "sourceSha256": primary["sha256"],
        "sourceBundleSha256": source_bundle,
        "sourceFiles": source_payload,
        "sources": [{"path": entry.get("path", entry.get("compilerSourceUnit")),
                     "sha256": entry["sha256"], "source": entry["source"],
                     "primary": entry.get("primary", False)} for entry in all_files],
        "sourceFileCount": len(sources),
        "dependencyFiles": [{key: value for key, value in entry.items() if key != "primary"}
                            for entry in dependencies],
        "dependencyLicenses": sample.get("dependencyLicenses", []),
        "sourceLicense": sample.get("sourceLicense", manifest.get("sourceLicense")),
        "license": sample.get("license"),
        "prompt": sample.get("prompt"),
        "harness": sample.get("harness"),
        "compilerPragmas": sample.get("compilerPragmas"),
        "compilerVersion": analysis.get("compilerVersion"),
        "compilerSelection": analysis.get("compilerSelection"),
        "compilerPinnedVersion": analysis.get("compilerPinnedVersion"),
        "compilerSha256": _compiler_sha(analysis),
        "staticState": analysis.get("static", analysis.get("staticState")),
        "staticReason": analysis.get("staticReason"),
        "staticEvidence": analysis.get("analysisEvidence"),
        "findingCount": analysis.get("findingCount", analysis.get("staticFindingCount")),
        "staticFindings": _static_findings(root, analysis),
        "dynamicState": dynamic["state"],
        "dynamicReason": dynamic["reason"],
        "dynamicEvidence": dynamic["path"],
        "dynamicEvidenceSha256": dynamic["declaredSha256"],
        "dynamicEvidenceObservedSha256": dynamic["observedSha256"],
        "dynamicEvidenceValid": dynamic["valid"],
        "confirmedVulnerability": confirmed,
        "decompilerState": analysis.get("decompiler", analysis.get("decompilerState")),
        "decompilerReason": analysis.get("decompilerReason"),
        "bytecodeArtifact": analysis.get("artifact"),
        "bytecodeReport": analysis.get("bytecodeReport"),
        "decompilerEvidence": analysis.get("decompilerEvidence"),
        "decompiledPseudocode": None,
        "_sourceHashes": source_hashes,
        "trainingNote": "Repository labels and static/decompiler outputs are signals; dynamic confirmation requires a valid referenced local EVM evidence record.",
    }


def _manifest_paths(explicit: list[Path] | None) -> list[Path]:
    return explicit if explicit else [MANIFEST,
                                      ROOT / "training-data/damn-vulnerable-defi/manifest.json",
                                      ROOT / "training-data/ethernaut/manifest.json"]


def _assign_splits(rows: list[dict[str, Any]]) -> None:
    parent: dict[str, str] = {}

    def find(value: str) -> str:
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for row in rows:
        hashes = row.get("_sourceHashes", [])
        for digest in hashes:
            find(digest)
        for digest in hashes[1:]:
            union(hashes[0], digest)
    components: dict[str, set[str]] = {}
    for row in rows:
        roots = {find(digest) for digest in row.get("_sourceHashes", [])}
        component = min(roots) if roots else "empty"
        components.setdefault(component, set()).update(row.get("_sourceHashes", []))
    component_keys = {key: (next(iter(hashes)) if len(hashes) == 1
                            else _sha256("\n".join(sorted(hashes)).encode()))
                      for key, hashes in components.items()}
    for row in rows:
        roots = {find(digest) for digest in row.get("_sourceHashes", [])}
        key = component_keys[min(roots)] if roots else _sha256(b"empty")
        bucket = int(key[:8], 16) % 100
        row["split"] = "train" if bucket < 80 else "validation" if bucket < 90 else "test"
        row.pop("_sourceHashes", None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, action="append", help="manifest to include; repeatable")
    args = parser.parse_args(argv)
    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for manifest_path in _manifest_paths(args.manifest):
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            skipped.append({"manifest": str(manifest_path), "reason": f"manifest_unreadable:{type(error).__name__}"})
            continue
        if not isinstance(manifest, dict):
            skipped.append({"manifest": str(manifest_path), "reason": "manifest_not_object"})
            continue
        for sample in manifest.get("samples", []):
            if not isinstance(sample, dict):
                continue
            try:
                rows.append(_row_for_sample(ROOT, manifest, sample))
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                skipped.append({"manifest": str(manifest_path), "challenge": str(sample.get("challenge", "")),
                                "path": str(sample.get("path", "")), "reason": str(error)[:240]})
    _assign_splits(rows)
    rows.sort(key=lambda item: (item.get("dataset") or "", item.get("repo") or "",
                               item.get("path") or item.get("challenge") or ""))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    temporary.replace(args.output)
    print(json.dumps({"output": str(args.output), "rows": len(rows), "skipped": len(skipped),
                      "skippedSamples": skipped}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
