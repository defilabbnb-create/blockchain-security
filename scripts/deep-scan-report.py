#!/usr/bin/env python3
"""Summarise the ir-reconcile and invariants evidence layers for the benchmark.

Reads the evidence files written by ``benchmark-deep-layers.py`` and the matching
eval report, and prints one table per layer plus the reasons each unavailable
sample is unavailable.  The script reports what was measured; it never edits
evidence and never treats a missing layer as a pass.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "benchmark" / "contracts"
RESULTS = ROOT / "benchmark" / "results"
LAYER_FILES = {"ir-reconcile": ("ir-reconcile.json", "ir-reconcile-result.json"),
               "invariants": ("invariants.json", "invariant-result.json")}
CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")

# Reasons that describe the sample or its ground truth rather than a defect in the
# evidence pipeline.  They are grouped so a reviewer can see at a glance which
# samples are structurally out of reach for a layer.
STRUCTURAL_REASONS = {
    "invariant_templates_unavailable": "role not recognised from the source",
    "local_deployment_unavailable": "constructor arguments required",
    "invariant_inputs_unavailable": "inputs unavailable",
    "ir_reconcile_inputs_unavailable": "IR inputs unavailable",
}


def _case_ids() -> list[str]:
    if not CONTRACTS.is_dir():
        return []
    return sorted(entry.name for entry in CONTRACTS.iterdir()
                  if entry.is_dir() and CASE_ID_PATTERN.fullmatch(entry.name)
                  and (entry / "ground-truth.json").is_file())


def _layer_document(case_dir: Path, names: tuple[str, ...]) -> dict[str, Any] | None:
    for name in names:
        path = case_dir / name
        if path.is_file():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
            return value if isinstance(value, dict) else None
    return None


def _category(reason: Any) -> str:
    text = str(reason or "unknown")
    for prefix, label in STRUCTURAL_REASONS.items():
        if text.startswith(prefix):
            return label
    return text.split(":")[0]


def _collect(layers: tuple[str, ...]) -> dict[str, Any]:
    report: dict[str, Any] = {"cases": [], "generatedAt": None}
    for case_id in _case_ids():
        row: dict[str, Any] = {"caseId": case_id}
        for layer in layers:
            document = _layer_document(CONTRACTS / case_id, LAYER_FILES[layer])
            if document is None:
                row[layer] = {"state": "missing", "reason": "evidence_file_absent",
                              "outcome": None, "issues": 0, "executed": 0}
                continue
            row[layer] = {
                "state": document.get("state"),
                "reason": document.get("reason"),
                "outcome": document.get("outcome"),
                "issues": len(document.get("detectedIssues") or []),
                "executed": int(document.get("executedAssertionCount") or 0),
                "roles": document.get("detectedRoles"),
                "divergences": document.get("divergenceCount"),
                "faithfulness": document.get("sourceFaithfulnessScore"),
                "categories": _category(document.get("reason")),
            }
        report["cases"].append(row)
    return report


def _latest_eval() -> dict[str, Any] | None:
    if not RESULTS.is_dir():
        return None
    files = sorted(RESULTS.glob("*.json"), key=lambda path: path.name, reverse=True)
    for path in files:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and isinstance(value.get("layers"), dict):
            return value
    return None


def _print_table(title: str, rows: list[dict[str, Any]], layer: str) -> None:
    print(f"\n{title}")
    print(f"{'case':<34}{'state':<14}{'outcome':<20}{'exec':>5}  detail")
    print("-" * 108)
    for row in rows:
        cell = row.get(layer) or {}
        outcome = cell.get("outcome") or "-"
        completed = cell.get("state") == "completed"
        detail = "" if completed else (cell.get("categories") or "")
        if cell.get("roles"):
            roles = f"roles={','.join(cell['roles'])}"
            detail = f"{detail}; {roles}" if detail else roles
        if completed and layer == "ir-reconcile":
            faithfulness = cell.get("faithfulness")
            measured = f"faithfulness={faithfulness}" if faithfulness is not None else ""
            divergences = cell.get("divergences")
            if divergences is not None:
                measured = f"{measured}; divergences={divergences}".strip("; ")
            detail = f"{detail}; {measured}" if detail else measured
        print(f"{row['caseId']:<34}{str(cell.get('state')):<14}{str(outcome):<20}"
              f"{cell.get('executed', 0):>5}  {detail}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layers", default="ir-reconcile,invariants",
                        help="comma separated layers to summarise")
    parser.add_argument("--json", action="store_true", help="emit the raw report")
    args = parser.parse_args(argv)
    layers = tuple(part.strip() for part in args.layers.split(",") if part.strip())
    unknown = set(layers) - set(LAYER_FILES)
    if unknown:
        parser.error(f"unknown layer: {','.join(sorted(unknown))}")

    report = _collect(layers)
    evaluation = _latest_eval()
    if args.json:
        report["evalMetrics"] = (evaluation or {}).get("layers")
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    print(f"deep layer evidence: {len(report['cases'])} benchmark cases")
    for layer in layers:
        rows = report["cases"]
        states: dict[str, int] = {}
        for row in rows:
            state = str((row.get(layer) or {}).get("state"))
            states[state] = states.get(state, 0) + 1
        _print_table(f"layer: {layer}  {states}", rows, layer)

    if evaluation:
        print("\neval_pipeline metrics for the same layers")
        print(f"{'layer':<16}{'sampleCount':>12}{'unavailable':>13}{'tp':>5}{'fp':>5}{'fn':>5}")
        print("-" * 56)
        for layer, metrics in (evaluation.get("layers") or {}).items():
            if layer not in layers:
                continue
            print(f"{layer:<16}{metrics.get('sampleCount', 0):>12}"
                  f"{metrics.get('unavailableSampleCount', 0):>13}"
                  f"{metrics.get('truePositiveCount', 0):>5}"
                  f"{metrics.get('falsePositiveCount', 0):>5}"
                  f"{metrics.get('falseNegativeCount', 0):>5}")

    print("\nunavailable reasons by cause")
    for layer in layers:
        causes: dict[str, int] = {}
        for row in report["cases"]:
            cell = row.get(layer) or {}
            if cell.get("state") in {"missing", "unavailable", "failed"}:
                causes[str(cell.get("categories"))] = causes.get(str(cell.get("categories")), 0) + 1
        for cause, count in sorted(causes.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {layer:<14}{count:>4}  {cause}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())