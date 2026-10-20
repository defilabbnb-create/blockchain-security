#!/usr/bin/env python3
"""Run the complete pipeline against saved real-contract evidence.

The command is deliberately replay-only when network evidence is unavailable. It
never invents a target from the assertion fixtures and never signs or broadcasts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import pipeline


def _load_targets(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"无法读取 targets: {path}") from error
    rows = payload.get("targets") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        raise ValueError("targets 必须是非空数组")
    for index, target in enumerate(rows):
        if not isinstance(target, dict) or not isinstance(target.get("address"), str):
            raise ValueError(f"targets[{index}] 缺少 address")
        # A replay target must identify saved evidence. This prevents an empty
        # live scan from being reported as an offline end-to-end result.
        has_fixture = isinstance(target.get("rpcFixture"), dict) and bool(target["rpcFixture"])
        if not (has_fixture or any(isinstance(target.get(name), str) and target.get(name) for name in
                                    ("sourceBundle", "sourcePath", "bytecode", "runtimeBytecode"))):
            raise ValueError(f"targets[{index}] 缺少已保存证据路径")
    return {"targets": rows}


def run_e2e(targets_path: str | Path, output: str | Path, *, mode: str = "offline_replay",
            budget_usd: float = 0.0) -> dict[str, Any]:
    """Execute all ten pipeline stages and write a compact review summary."""
    target_path = Path(targets_path).resolve(strict=True)
    payload = _load_targets(target_path)
    output_path = Path(output).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    # Offline replay still reruns local analysis stages against archived inputs;
    # "replay" would skip those stages and is reserved for prebuilt evidence.
    pipeline_mode = "local" if mode == "offline_replay" else mode
    if pipeline_mode not in ("replay", "local", "fixed_block_fork"):
        raise ValueError("mode 必须是 offline_replay、replay、local 或 fixed_block_fork")
    run = pipeline.run_pipeline(
        target_path,
        stages=list(pipeline.STAGES),
        mode=pipeline_mode,
        budget_usd=budget_usd,
        output=output_path,
    )
    summary_targets = []
    target_by_key = {pipeline._target_key(row, index): row for index, row in enumerate(payload["targets"])}
    for target_state in run.get("targets", []):
        stages = target_state.get("stages", {}) if isinstance(target_state, dict) else {}
        original = target_by_key.get(target_state.get("target"), {})
        summary_targets.append({
            "target": target_state.get("target"),
            "address": original.get("address"),
            "state": target_state.get("stages") and (
                "completed" if all(isinstance(value, dict) and value.get("state") == "completed" for value in stages.values())
                else "partial"),
            "stages": stages,
        })
    summary = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "network": "offline_replay" if mode == "offline_replay" else mode,
        "sourceTargetsSha256": hashlib.sha256(target_path.read_bytes()).hexdigest(),
        "runPath": str(output_path),
        "state": run.get("state", "partial"),
        "targets": summary_targets,
        "semanticsProven": False,
        "confirmedVulnerability": False,
    }
    temporary = output_path / ".summary.json.tmp"
    temporary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(output_path / "summary.json")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", default="offline_replay",
                        choices=("offline_replay", "replay", "local", "fixed_block_fork"))
    parser.add_argument("--budget-usd", type=float, default=0.0)
    args = parser.parse_args(argv)
    try:
        result = run_e2e(args.targets, args.output, mode=args.mode, budget_usd=args.budget_usd)
    except (OSError, ValueError) as error:
        print(json.dumps({"state": "failed", "error": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({"state": result["state"], "network": result["network"],
                      "output": result["runPath"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
