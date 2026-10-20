#!/usr/bin/env python3
"""Read-only EIP-1967 proxy resolution at fixed blocks and bounded history.

The module accepts a small JSON-RPC callable (``rpc(method, params)``), so it
can be used with either the campaign pool or deterministic test fixtures.  It
never sends a transaction.  A result is deliberately conservative: missing
or malformed historical evidence is returned as ``partial``/``unsupported``
and is never converted into an inferred implementation.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any, Callable

IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
BEACON_IMPLEMENTATION_SELECTOR = "0x5c60da1b"
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
WORD = re.compile(r"^0x[0-9a-fA-F]{64}$")

# These are the OpenZeppelin ERC-1967 event signatures.  They are exported so
# callers/tests can use exactly the same filter without a hashing dependency.
UPGRADED_TOPIC = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"
BEACON_UPGRADED_TOPIC = "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e"
ADMIN_CHANGED_TOPIC = "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"
# The exact topics are configurable because custom proxy implementations may
# emit equivalent events under another signature.  The default filter remains
# intentionally narrow and is never treated as proof of a complete history.
DEFAULT_EVENT_TOPICS = (UPGRADED_TOPIC, BEACON_UPGRADED_TOPIC, ADMIN_CHANGED_TOPIC)


class ProxyHistoryError(ValueError):
    pass


def _quantity(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ProxyHistoryError(f"{name} must be a non-negative integer")
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        return int(value, 16)
    raise ProxyHistoryError(f"{name} is not a valid JSON-RPC quantity")


def _address(value: Any, name: str) -> str:
    if not isinstance(value, str) or not ADDRESS.fullmatch(value):
        raise ProxyHistoryError(f"{name} is not a 20-byte address")
    return value.lower()


def _hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ProxyHistoryError(f"{name} is not a 32-byte hash")
    return value.lower()


def _word(value: Any, name: str) -> str:
    if not isinstance(value, str) or not WORD.fullmatch(value):
        raise ProxyHistoryError(f"{name} is not a 32-byte storage word")
    return value.lower()


def _slot_address(value: str, name: str) -> str | None:
    word = _word(value, name)
    address = "0x" + word[-40:]
    return None if int(address, 16) == 0 else address


def _code(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, str) or re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is None:
        raise ProxyHistoryError(f"{name} is not valid bytecode")
    raw = bytes.fromhex(value[2:])
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "empty": len(raw) == 0}


def _call(rpc: Callable[[str, list[Any]], Any], method: str, params: list[Any]) -> Any:
    try:
        return rpc(method, params)
    except Exception as exc:
        message = str(exc)[:240]
        lowered = message.lower()
        if any(token in lowered for token in ("-32601", "unsupported", "not supported", "method not found")):
            raise ProxyHistoryError(f"rpc_unsupported:{method}:{message}") from exc
        raise ProxyHistoryError(f"rpc_failed:{method}:{message}") from exc


def resolve_proxy_at_block(
    rpc: Callable[[str, list[Any]], Any],
    proxy: str,
    block: int | str,
    *,
    expected_block_hash: str | None = None,
) -> dict[str, Any]:
    """Resolve EIP-1967 slots and code, all pinned to one block.

    The block hash is always read and checked.  ``state=verified`` means only
    that these read observations agree at this block; it does not prove that
    the contract follows every proxy standard.
    """
    address = _address(proxy, "proxy")
    number = _quantity(block, "block")
    tag = hex(number)
    expected = _hash(expected_block_hash, "expected_block_hash") if expected_block_hash else None
    try:
        header = _call(rpc, "eth_getBlockByNumber", [tag, False])
        if not isinstance(header, dict):
            raise ProxyHistoryError("block header is not an object")
        actual_number = _quantity(header.get("number"), "block.number")
        actual_hash = _hash(header.get("hash"), "block.hash")
        if actual_number != number:
            raise ProxyHistoryError("block number mismatch")
        if expected and actual_hash != expected:
            raise ProxyHistoryError("block hash mismatch")
        slot_values = {}
        for name, slot in (("implementation", IMPL_SLOT), ("beacon", BEACON_SLOT), ("admin", ADMIN_SLOT)):
            slot_values[name] = _word(_call(rpc, "eth_getStorageAt", [address, slot, tag]), f"{name} slot")
        implementation = _slot_address(slot_values["implementation"], "implementation slot")
        beacon = _slot_address(slot_values["beacon"], "beacon slot")
        admin = _slot_address(slot_values["admin"], "admin slot")
        beacon_implementation = None
        if beacon and not implementation:
            result = _call(rpc, "eth_call", [{"to": beacon, "data": BEACON_IMPLEMENTATION_SELECTOR}, tag])
            beacon_implementation = _slot_address(_word(result, "beacon implementation"), "beacon implementation")
        effective = implementation or beacon_implementation
        proxy_code = _code(_call(rpc, "eth_getCode", [address, tag]), "proxy code")
        implementation_code = None
        if effective:
            implementation_code = _code(_call(rpc, "eth_getCode", [effective, tag]), "implementation code")
            if implementation_code["empty"]:
                raise ProxyHistoryError("implementation has no code at pinned block")
        return {
            "state": "verified",
            "proxy": address,
            "block": number,
            "blockHex": tag,
            "blockHash": actual_hash,
            "slots": {"implementation": implementation, "beacon": beacon, "admin": admin},
            "implementation": effective,
            "beaconImplementation": beacon_implementation,
            "proxyCode": proxy_code,
            "implementationCode": implementation_code,
            "provenance": {"blockNumber": number, "blockHash": actual_hash, "readMethods": ["eth_getBlockByNumber", "eth_getStorageAt", "eth_getCode", "eth_call"]},
            "limitations": ["Only EIP-1967 slots are resolved; custom proxy layouts are unsupported.", "Read observations do not prove upgrade history completeness or source semantics."],
        }
    except ProxyHistoryError as exc:
        state = "unsupported" if str(exc).startswith("rpc_unsupported:") else "failed"
        return {"state": state, "proxy": address, "block": number, "error": str(exc), "complete": False}


def proxy_history(
    rpc: Callable[[str, list[Any]], Any],
    proxy: str,
    from_block: int | str,
    to_block: int | str,
    *,
    page_size: int = 2_000,
    max_pages: int = 64,
    event_topics: tuple[str, ...] = DEFAULT_EVENT_TOPICS,
) -> dict[str, Any]:
    """Build a bounded upgrade timeline from ERC-1967 event logs.

    The initial state is resolved at ``from_block`` and each event block is
    re-read with its block hash.  A provider cannot prove that a log range was
    complete, so the report records this limitation.  Multiple events in one
    block are sorted by transaction/log index but mark the timeline partial:
    state between same-block events is not independently observable.
    """
    address = _address(proxy, "proxy")
    start = _quantity(from_block, "from_block")
    end = _quantity(to_block, "to_block")
    if end < start:
        raise ProxyHistoryError("to_block must be >= from_block")
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 50_000:
        raise ProxyHistoryError("page_size must be between 1 and 50000")
    if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not 1 <= max_pages <= 1024:
        raise ProxyHistoryError("max_pages must be between 1 and 1024")
    topics = tuple(_hash(item, "event topic") for item in event_topics)
    baseline = resolve_proxy_at_block(rpc, address, start)
    result: dict[str, Any] = {"schemaVersion": 1, "state": "partial", "complete": False, "proxy": address,
                               "fromBlock": start, "toBlock": end, "baseline": baseline, "events": [], "snapshots": [],
                               "pages": 0, "limitations": ["RPC log completeness is provider-dependent and cannot be proven from eth_getLogs alone.",
                                                                  "Custom upgrade events and non-EIP-1967 proxy layouts are outside this timeline."]}
    if baseline.get("state") != "verified":
        result["error"] = "baseline_resolution_failed"
        return result
    logs: list[dict[str, Any]] = []
    cursor = start
    while cursor <= end:
        if result["pages"] >= max_pages:
            result["error"] = "max_pages_reached_before_to_block"
            return result
        page_end = min(end, cursor + page_size - 1)
        try:
            rows = _call(rpc, "eth_getLogs", [{"address": address, "fromBlock": hex(cursor), "toBlock": hex(page_end), "topics": [list(topics)]}])
        except ProxyHistoryError as exc:
            result["error"] = str(exc)
            result["state"] = "unsupported" if str(exc).startswith("rpc_unsupported:") else "failed"
            return result
        result["pages"] += 1
        if not isinstance(rows, list):
            result["error"] = "eth_getLogs result is not an array"
            return result
        for row in rows:
            if not isinstance(row, dict):
                result["error"] = "malformed log entry"
                return result
            try:
                row_number = _quantity(row.get("blockNumber"), "log.blockNumber")
                row_hash = _hash(row.get("blockHash"), "log.blockHash")
                log_index = _quantity(row.get("logIndex"), "log.logIndex")
                tx_index = _quantity(row.get("transactionIndex"), "log.transactionIndex")
                row_address = _address(row.get("address"), "log.address")
            except ProxyHistoryError as exc:
                result["error"] = str(exc)
                return result
            if row_address != address or not start <= row_number <= end or not cursor <= row_number <= page_end:
                result["error"] = "log outside requested page or address"
                return result
            logs.append({"block": row_number, "blockHash": row_hash, "transactionIndex": tx_index, "logIndex": log_index,
                         "topics": row.get("topics"), "data": row.get("data"), "transactionHash": row.get("transactionHash")})
        cursor = page_end + 1
    logs.sort(key=lambda row: (row["block"], row["transactionIndex"], row["logIndex"]))
    result["events"] = logs
    by_block: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in logs:
        by_block[row["block"]].append(row)
    same_block = [block for block, rows in by_block.items() if len(rows) > 1]
    if same_block:
        result["sameBlockOrderingUncertain"] = same_block
        result["limitations"].append("Multiple upgrade events share a block; log ordering is retained but intermediate state is not claimed.")
    for block, rows in sorted(by_block.items()):
        hashes = {row["blockHash"] for row in rows}
        if len(hashes) != 1:
            result["error"] = "same block has conflicting log hashes"
            return result
        snapshot = resolve_proxy_at_block(rpc, address, block, expected_block_hash=next(iter(hashes)))
        if snapshot.get("state") != "verified":
            result["error"] = f"snapshot_failed_at_block_{block}"
            result["snapshots"].append(snapshot)
            return result
        result["snapshots"].append(snapshot)
    result["complete"] = not bool(same_block)
    result["state"] = "verified" if result["complete"] else "partial"
    return result


__all__ = ["resolve_proxy_at_block", "proxy_history", "ProxyHistoryError", "IMPL_SLOT", "BEACON_SLOT", "ADMIN_SLOT", "DEFAULT_EVENT_TOPICS"]
