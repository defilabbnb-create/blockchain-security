#!/usr/bin/env python3
"""Build a bounded, read-only graph of proxy implementations."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

import proxy_history as history

SCHEMA_VERSION = 1
PROXIABLE_UUID_SELECTOR = "0x52d1902d"
DIAMOND_FACETS_SELECTOR = "0x7a0ed627"
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")


class ProxyGraphError(ValueError):
    pass


class _BudgetExceeded(ProxyGraphError):
    pass


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _selector(raw: str) -> str:
    if not isinstance(raw, str) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", raw):
        raise ProxyGraphError("custom slot must be a 4-byte function selector")
    return raw.lower()


def _decode_diamond_facets(value: Any) -> list[dict[str, Any]]:
    """Decode the ABI return from IDiamondLoupe.facets()."""
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ProxyGraphError("diamond facets response is malformed")
    data = bytes.fromhex(value[2:])
    if len(data) < 64 or len(data) % 32:
        raise ProxyGraphError("diamond facets response is truncated")
    words = [int.from_bytes(data[index:index + 32], "big") for index in range(0, len(data), 32)]
    array_offset = words[0]
    if array_offset % 32 or array_offset + 32 > len(data):
        raise ProxyGraphError("diamond facets array offset is invalid")
    count = int.from_bytes(data[array_offset:array_offset + 32], "big")
    if count > 4096:
        raise ProxyGraphError("diamond facets count exceeds limit")
    base = array_offset + 32
    result = []
    for index in range(count):
        entry_offset = int.from_bytes(data[base + index * 32:base + (index + 1) * 32], "big")
        entry = base + entry_offset
        if entry % 32 or entry + 64 > len(data):
            raise ProxyGraphError("diamond facet entry offset is invalid")
        address_word = data[entry:entry + 32]
        if any(address_word[:12]):
            raise ProxyGraphError("diamond facet address has nonzero padding")
        facet_address = "0x" + address_word[12:].hex()
        selectors_offset = int.from_bytes(data[entry + 32:entry + 64], "big")
        selectors_start = entry + selectors_offset
        if selectors_offset % 32 or selectors_start + 32 > len(data):
            raise ProxyGraphError("diamond facet selector offset is invalid")
        selectors_count = int.from_bytes(data[selectors_start:selectors_start + 32], "big")
        if selectors_count > 65536 or selectors_start + 32 + selectors_count * 32 > len(data):
            raise ProxyGraphError("diamond facet selector array is truncated")
        selectors = []
        for offset in range(selectors_count):
            word = data[selectors_start + 32 + offset * 32:selectors_start + 64 + offset * 32]
            if any(word[4:]):
                raise ProxyGraphError("diamond selector ABI padding is invalid")
            selectors.append("0x" + word[:4].hex())
        result.append({"address": facet_address, "selectors": selectors})
    return result


def _source_comparison(fetch_source: Callable[[str, str], Any] | None,
                       addresses: list[str]) -> dict[str, Any]:
    if fetch_source is None:
        return {"state": "not_checked", "sourceConflict": False,
                "reason": "source_fetcher_not_configured", "sources": []}
    reports = []
    conflicts = []
    for address in addresses:
        observations = []
        for provider in ("sourcify", "etherscan_v2"):
            try:
                row = fetch_source(provider, address)
            except Exception as error:
                observations.append({"provider": provider, "state": "unavailable",
                                     "reason": type(error).__name__})
                continue
            if not isinstance(row, dict):
                observations.append({"provider": provider, "state": "unavailable",
                                     "reason": "invalid_response"})
                continue
            bytecode = row.get("bytecode")
            source = row.get("source")
            if not isinstance(bytecode, str) or not HEX.fullmatch(bytecode) or source is None:
                observations.append({"provider": provider, "state": "unavailable",
                                     "reason": "missing_bytecode_or_source"})
                continue
            source_bytes = (json.dumps(source, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode("utf-8")
                            if isinstance(source, (dict, list)) else str(source).encode("utf-8"))
            observation = {"provider": provider, "state": "available",
                           "bytecodeSha256": _sha256(bytes.fromhex(bytecode[2:])),
                           "sourceSha256": _sha256(source_bytes)}
            observations.append(observation)
        available = [item for item in observations if item["state"] == "available"]
        conflict = len(available) == 2 and (
            available[0]["bytecodeSha256"] != available[1]["bytecodeSha256"] or
            available[0]["sourceSha256"] != available[1]["sourceSha256"])
        if conflict:
            conflicts.append(address)
        reports.append({"address": address, "sourceConflict": conflict,
                        "observations": observations})
    return {"state": "checked", "sourceConflict": bool(conflicts),
            "conflictingAddresses": conflicts, "sources": reports}


def build_proxy_graph(
    rpc: Callable[[str, list[Any]], Any],
    address: str,
    chain_id: int,
    block: int | str,
    *,
    max_rpc_calls: int = 64,
    max_depth: int = 8,
    custom_slots: list[dict[str, str]] | None = None,
    fetch_source: Callable[[str, str], Any] | None = None,
) -> dict[str, Any]:
    """Resolve a bounded implementation chain using RPC reads only.

    ``fetch_source`` is an optional adapter called with (``sourcify`` or
    ``etherscan_v2``, address). It should return ``{"bytecode": "0x...",
    "source": ...}``; keeping credentials/network transport outside this
    module makes offline operation deterministic.
    """
    root = history._address(address, "address")
    number = history._quantity(block, "block")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id < 0:
        raise ProxyGraphError("chain_id must be a non-negative integer")
    if isinstance(max_rpc_calls, bool) or not isinstance(max_rpc_calls, int) or max_rpc_calls < 1:
        raise ProxyGraphError("max_rpc_calls must be a positive integer")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 1 <= max_depth <= 64:
        raise ProxyGraphError("max_depth must be between 1 and 64")
    custom_slots = custom_slots or []
    for row in custom_slots:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"]:
            raise ProxyGraphError("custom slot requires a name and slot")
        history._word(row.get("slot"), "custom slot")

    calls = 0

    def bounded_rpc(method: str, params: list[Any]) -> Any:
        nonlocal calls
        if calls >= max_rpc_calls:
            raise _BudgetExceeded("max_rpc_calls_exhausted")
        calls += 1
        return rpc(method, params)

    chain = []
    limitations = []
    visited = set()
    current = root
    current_impl = None
    complete = True
    try:
        for depth in range(max_depth):
            if current in visited:
                limitations.append("implementation_cycle_detected")
                complete = False
                break
            visited.add(current)
            snapshot = history.resolve_proxy_at_block(bounded_rpc, current, number)
            if snapshot.get("state") != "verified":
                # A normal non-proxy has zero EIP-1967 slots; retain it as a
                # terminal node, while RPC failures lower coverage.
                if snapshot.get("error") == "implementation has no code at pinned block":
                    limitations.append("implementation_without_code")
                    complete = False
                    break
                if snapshot.get("error", "").startswith("rpc_") or "block" in snapshot.get("error", ""):
                    limitations.append(snapshot.get("error", "proxy_resolution_failed"))
                    complete = False
                    break
                break
            impl = snapshot.get("implementation")
            if impl:
                uuid = bounded_rpc("eth_call", [{"to": impl, "data": PROXIABLE_UUID_SELECTOR}, hex(number)])
                if isinstance(uuid, str) and uuid.lower() == history.IMPL_SLOT:
                    snapshot["proxyKind"] = "uups"
            if not impl:
                for custom in custom_slots:
                    slot_value = bounded_rpc("eth_getStorageAt", [current, custom["slot"], hex(number)])
                    candidate = history._slot_address(slot_value, f"{custom['name']} slot")
                    if candidate:
                        impl = candidate
                        snapshot["customSlot"] = custom["name"]
                        limitations.append("custom_proxy_slot_requires_manual_validation")
                        break
            if not impl:
                # UUPS is an implementation capability layered over ERC-1967.
                uuid = bounded_rpc("eth_call", [{"to": current, "data": PROXIABLE_UUID_SELECTOR}, hex(number)])
                if isinstance(uuid, str) and uuid.lower() == history.IMPL_SLOT:
                    snapshot["proxyKind"] = "uups"
                else:
                    facets_raw = bounded_rpc("eth_call", [{"to": current, "data": DIAMOND_FACETS_SELECTOR}, hex(number)])
                    try:
                        facets = _decode_diamond_facets(facets_raw)
                    except ProxyGraphError:
                        facets = []
                    if facets:
                        snapshot["proxyKind"] = "diamond"
                        snapshot["facets"] = facets
                        for facet in facets:
                            chain.append({"address": facet["address"], "slot": "diamond.facets",
                                          "sinceBlock": None, "codeHash": None,
                                          "selectors": facet["selectors"]})
                    break
                # The implementation itself is terminal when it exposes
                # proxiableUUID but has no implementation slot of its own.
                break
            kind = "custom" if snapshot.get("customSlot") else (
                "beacon" if snapshot["slots"].get("beacon") else
                "uups" if snapshot.get("proxyKind") == "uups" else "eip1967")
            chain.append({"address": impl, "slot": snapshot.get("customSlot") or
                          (history.BEACON_SLOT if kind == "beacon" else history.IMPL_SLOT),
                          "sinceBlock": None,
                          "codeHash": (snapshot.get("implementationCode") or {}).get("sha256"),
                          "proxyKind": kind})
            current_impl = impl
            if depth == max_depth - 1:
                limitations.append("max_depth_reached")
                complete = False
                break
            current = impl
    except _BudgetExceeded as error:
        limitations.append(str(error))
        complete = False

    sources = _source_comparison(fetch_source, list(dict.fromkeys([root] + [row["address"] for row in chain])))
    if sources["state"] != "checked":
        limitations.append(sources["reason"])
        complete = False
    coverage = {"complete": complete, "gaps": []}
    if not complete:
        coverage["gaps"] = [{"kind": "resolution_incomplete", "detail": reason}
                            for reason in limitations]
    if sources["state"] != "checked":
        coverage["gaps"].append({"kind": "source_verification_unavailable", "detail": sources["reason"]})
    return {"schemaVersion": SCHEMA_VERSION, "address": root, "chainId": chain_id,
            "block": number, "implementationChain": chain, "currentImplementation": current_impl,
            "sourceConflict": sources["sourceConflict"], "sourceVerification": sources,
            "coverage": coverage, "limitations": list(dict.fromkeys(limitations)),
            "rpcCalls": calls}


__all__ = ["build_proxy_graph", "ProxyGraphError"]
