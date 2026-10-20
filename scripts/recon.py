#!/usr/bin/env python3
"""Bounded, read-only reconnaissance probes for one contract address."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from proxy_history import proxy_history
from rpc_pool import atomic, rpc as rpc_request

ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
MAX_TRANSACTION_SAMPLE = 100
MAX_BLOCK_SCAN = 100
MAX_DEPENDENCIES = 500


class ReconError(ValueError):
    pass


def _valid_address(value: Any, name: str) -> str:
    if not isinstance(value, str) or ADDRESS.fullmatch(value) is None:
        raise ReconError(f"{name} must be a 20-byte address")
    return value.lower()


def _uint(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReconError(f"{name} must be a non-negative integer")
    return value


def _quantity(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        return int(value, 16)
    return None


def _rpc(rpc: Callable[[str, list[Any]], Any], method: str, params: list[Any]) -> Any:
    return rpc(method, params)


def _recent_target_transactions(
    rpc: Callable[[str, list[Any]], Any], address: str, block: int, limit: int, block_scan_limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    transactions: list[dict[str, Any]] = []
    limitations: list[str] = []
    scanned = 0
    for number in range(block, max(-1, block - block_scan_limit), -1):
        scanned += 1
        try:
            payload = _rpc(rpc, "eth_getBlockByNumber", [hex(number), True])
        except Exception:
            limitations.append(f"transaction_block_unavailable:{number}")
            break
        if not isinstance(payload, dict) or not isinstance(payload.get("transactions"), list):
            limitations.append(f"transaction_block_malformed:{number}")
            break
        for transaction in payload["transactions"]:
            if not isinstance(transaction, dict):
                continue
            target = transaction.get("to")
            tx_hash = transaction.get("hash")
            if isinstance(target, str) and target.lower() == address and isinstance(tx_hash, str) and HASH.fullmatch(tx_hash):
                transactions.append(transaction)
                if len(transactions) >= limit:
                    break
        if len(transactions) >= limit:
            break
    if len(transactions) < limit and scanned >= block_scan_limit:
        limitations.append("block_scan_limit_reached")
    return transactions, limitations


def _call_distribution(
    rpc: Callable[[str, list[Any]], Any], address: str, block: int, limit: int, block_scan_limit: int,
    transaction_hashes: list[str] | None,
) -> dict[str, Any]:
    limitations: list[str] = []
    if transaction_hashes is None:
        transactions, limitations = _recent_target_transactions(rpc, address, block, limit, block_scan_limit)
    else:
        if not isinstance(transaction_hashes, list) or len(transaction_hashes) > limit:
            raise ReconError("transaction_hashes must be a list within sample_limit")
        if any(not isinstance(value, str) or HASH.fullmatch(value) is None for value in transaction_hashes):
            raise ReconError("transaction_hashes contains an invalid hash")
        transactions = [{"hash": value.lower(), "input": None} for value in transaction_hashes]

    counts: dict[str, int] = {}
    trace_rows = []
    for transaction in transactions:
        tx_hash = transaction["hash"].lower()
        calldata = transaction.get("input")
        selector = calldata[:10].lower() if isinstance(calldata, str) and re.fullmatch(r"0x[0-9a-fA-F]{8,}", calldata) else "unknown"
        counts[selector] = counts.get(selector, 0) + 1
        try:
            trace = _rpc(rpc, "debug_traceTransaction", [tx_hash, {"disableMemory": True, "disableStorage": True, "disableStack": True}])
            if isinstance(trace, dict) and (isinstance(trace.get("structLogs"), list) or isinstance(trace.get("result"), dict)):
                trace_rows.append({"transactionHash": tx_hash, "state": "available"})
            else:
                trace_rows.append({"transactionHash": tx_hash, "state": "unavailable"})
                limitations.append(f"trace_unavailable:{tx_hash}")
        except Exception:
            trace_rows.append({"transactionHash": tx_hash, "state": "unavailable"})
            limitations.append(f"trace_unavailable:{tx_hash}")

    sample_count = len(transactions)
    concentration = max(counts.values(), default=0) / sample_count if sample_count else 0.0
    return {
        "state": "available" if sample_count and len(trace_rows) == sample_count and all(row["state"] == "available" for row in trace_rows) else ("partial" if sample_count else "unavailable"),
        "sampleTransactions": sample_count,
        "distribution": dict(sorted(counts.items())),
        "concentration": concentration,
        "traces": trace_rows,
        "limitations": limitations,
    }


def _dependency_probe(dependencies: list[dict[str, Any]] | None) -> dict[str, Any]:
    if dependencies is None:
        return {"state": "unavailable", "sampleCount": 0, "riskCount": 0, "risk": 0.0, "items": [],
                "limitations": ["dependency inventory was not supplied; no dependency graph is inferred"]}
    if not isinstance(dependencies, list) or len(dependencies) > MAX_DEPENDENCIES:
        raise ReconError(f"dependencies must be a list of at most {MAX_DEPENDENCIES} items")
    items = []
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            raise ReconError(f"dependencies[{index}] must be an object")
        name = dependency.get("name")
        risk = dependency.get("risk")
        if not isinstance(name, str) or not name or not isinstance(risk, bool):
            raise ReconError(f"dependencies[{index}] requires name and boolean risk")
        items.append({"name": name[:160], "risk": risk, "evidence": str(dependency.get("evidence", ""))[:500]})
    risk_count = sum(1 for item in items if item["risk"])
    return {"state": "available", "sampleCount": len(items), "riskCount": risk_count,
            "risk": risk_count / len(items) if items else 0.0, "items": items, "limitations": []}


def build_recon_profile(
    rpc: Callable[[str, list[Any]], Any], address: str, *, chain_id: int, block: int,
    from_block: int | None = None, transaction_hashes: list[str] | None = None,
    dependencies: list[dict[str, Any]] | None = None, reachable_assets_usd: float = 0.0,
    sample_limit: int = 25, block_scan_limit: int = 20, history_page_size: int = 2_000,
    history_max_pages: int = 64,
) -> dict[str, Any]:
    """Collect bounded probes; ``rpc`` must perform read-only JSON-RPC calls."""
    target = _valid_address(address, "address")
    chain_id = _uint(chain_id, "chain_id")
    block = _uint(block, "block")
    start = max(0, block - 100_000) if from_block is None else _uint(from_block, "from_block")
    if start > block:
        raise ReconError("from_block must not exceed block")
    if isinstance(reachable_assets_usd, bool) or not isinstance(reachable_assets_usd, (int, float)) or not math.isfinite(reachable_assets_usd) or reachable_assets_usd < 0:
        raise ReconError("reachable_assets_usd must be a finite non-negative number")
    if not 1 <= sample_limit <= MAX_TRANSACTION_SAMPLE:
        raise ReconError(f"sample_limit must be between 1 and {MAX_TRANSACTION_SAMPLE}")
    if not 1 <= block_scan_limit <= MAX_BLOCK_SCAN:
        raise ReconError(f"block_scan_limit must be between 1 and {MAX_BLOCK_SCAN}")

    try:
        upgrades = proxy_history(rpc, target, start, block, page_size=history_page_size, max_pages=history_max_pages)
        upgrades_probe = {"state": upgrades.get("state", "unavailable"), "complete": upgrades.get("complete", False),
                          "fromBlock": start, "toBlock": block, "upgradeCount": len(upgrades.get("events", [])),
                          "events": upgrades.get("events", []), "history": upgrades,
                          "limitations": upgrades.get("limitations", []) + ([upgrades["error"]] if upgrades.get("error") else [])}
    except Exception as error:
        upgrades_probe = {"state": "unavailable", "complete": False, "fromBlock": start, "toBlock": block,
                          "upgradeCount": 0, "events": [], "limitations": [f"proxy_history_error:{type(error).__name__}"]}
    upgrades_probe["upgradeRecency"] = 0.0
    if upgrades_probe["events"] and block > start:
        last_block = max((_quantity(row.get("block")) or start) for row in upgrades_probe["events"])
        upgrades_probe["upgradeRecency"] = max(0.0, min(1.0, 1.0 - (block - last_block) / (block - start)))

    calls = _call_distribution(rpc, target, block, sample_limit, block_scan_limit, transaction_hashes)
    dependency_probe = _dependency_probe(dependencies)
    concentration = calls["concentration"]
    score = (math.log10(float(reachable_assets_usd) + 1.0)
             * (1.0 + 0.5 * upgrades_probe["upgradeRecency"] + 0.3 * upgrades_probe["upgradeCount"])
             * concentration * (1.0 + 0.4 * dependency_probe["risk"]))
    return {
        "schemaVersion": 1,
        "address": target,
        "chainId": chain_id,
        "block": block,
        "probes": {"upgrades": upgrades_probe, "callDistribution": calls, "dependencies": dependency_probe},
        "score": score,
        "evidence": {
            "reachableAssetsUsd": float(reachable_assets_usd),
            "upgradeEventCount": upgrades_probe["upgradeCount"],
            "upgradeRecency": upgrades_probe["upgradeRecency"],
            "callConcentration": concentration,
            "dependencyRisk": dependency_probe["risk"],
        },
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "limitations": [
            "Upgrade events are limited to the EIP-1967 topics and RPC log completeness is provider-dependent.",
            "Call concentration is measured by calldata selector among sampled target transactions.",
            "debug_traceTransaction support varies by provider; unavailable traces lower probe state.",
            "Dependency risk and reachable assets require externally supplied evidence.",
        ],
    }


def write_profile(path: str | Path, profile: dict[str, Any]) -> None:
    atomic(Path(path), json.dumps(profile, ensure_ascii=False, indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--chain-id", required=True, type=int)
    parser.add_argument("--block", required=True, type=int)
    parser.add_argument("--output", required=True)
    parser.add_argument("--reachable-assets-usd", type=float, default=0.0)
    parser.add_argument("--sample-limit", type=int, default=25)
    args = parser.parse_args(argv)
    try:
        profile = build_recon_profile(
            lambda method, params: rpc_request(args.rpc_url, method, params), args.address,
            chain_id=args.chain_id, block=args.block, reachable_assets_usd=args.reachable_assets_usd,
            sample_limit=args.sample_limit,
        )
        write_profile(args.output, profile)
    except (ReconError, OSError, ValueError) as error:
        print(f"recon failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"output": args.output, "score": profile["score"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
