#!/usr/bin/env python3
"""Extract conservative semantic hints from Heimdall output or EVM bytecode.

The result is heuristic evidence.  It never claims source equivalence or a
confirmed vulnerability; callers must validate every hint against other
representations and dynamic evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

MAX_INPUT_CHARS = 16 * 1024 * 1024
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
SLOT_RE = re.compile(r"(?:slot|storage|sload|sstore)\s*\(?\s*(0x[0-9a-fA-F]{1,64}|\d+)", re.I)
FUNCTION_RE = re.compile(r"(?:function\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", re.I)
SELECTOR_RE = re.compile(r"(?:selector|function\s*id|method)\s*[:=]?\s*(0x[0-9a-fA-F]{8})", re.I)
CONSTANT_RE = re.compile(r"\b(?:0x[0-9a-fA-F]{8,64}|\d{4,})\b")

_OPS = {
    0x35: "CALLDATALOAD", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP",
    0x57: "JUMPI", 0x5B: "JUMPDEST", 0xF1: "CALL", 0xF2: "CALLCODE",
    0xF4: "DELEGATECALL", 0xFA: "STATICCALL", 0xFF: "SELFDESTRUCT",
}


def _entity_id(kind: str, value: str) -> str:
    return hashlib.sha256(f"decompiled:{kind}:{value}".encode()).hexdigest()


def _canonical_text(value: Any) -> tuple[str, dict[str, Any]]:
    if isinstance(value, bytes):
        return value.hex(), {"kind": "bytes", "raw": value}
    if isinstance(value, str):
        text = value
        if text.startswith("0x") and re.fullmatch(r"0x[0-9a-fA-F]*", text) and len(text) % 2 == 0:
            try:
                raw = bytes.fromhex(text[2:])
                return text, {"kind": "bytecode", "raw": raw}
            except ValueError:
                pass
        return text, {"kind": "text", "raw": text}
    if isinstance(value, dict):
        # Heimdall adapters commonly expose pseudocode under one of these keys.
        for key in ("pseudocode", "output", "text", "code", "decompiled"):
            if isinstance(value.get(key), str):
                return _canonical_text(value[key])
        if isinstance(value.get("bytecode"), str):
            return _canonical_text(value["bytecode"])
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return encoded, {"kind": "json", "raw": encoded}
    raise ValueError("input must be text, bytecode, bytes, or an object")


def _decode(raw: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pc = 0
    while pc < len(raw):
        start = pc
        opcode = raw[pc]
        pc += 1
        name = _OPS.get(opcode)
        if name is None:
            name = f"PUSH{opcode - 0x5f}" if 0x60 <= opcode <= 0x7f else f"OP_0x{opcode:02x}"
        row: dict[str, Any] = {"pc": start, "opcode": name}
        if 0x60 <= opcode <= 0x7f:
            width = opcode - 0x5f
            row["immediate"] = raw[pc:pc + width].hex()
            if pc + width > len(raw):
                row["truncated"] = True
            pc = min(len(raw), pc + width)
        rows.append(row)
    return rows


def _risk_hint(kind: str, detail: str, refs: list[Any]) -> dict[str, Any]:
    return {"kind": kind, "detail": detail[:500], "confidence": "low", "refs": refs[:32]}


def _from_bytecode(raw: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    instructions = _decode(raw)
    entities: list[dict[str, Any]] = []
    hints: list[dict[str, Any]] = []
    low: list[str] = []
    current_block = None
    jumpdest_count = 0
    for row in instructions:
        pc = row["pc"]
        if row["opcode"] == "JUMPDEST":
            jumpdest_count += 1
            current_block = f"pc:{pc}"
            entities.append({"id": _entity_id("block", current_block), "kind": "basic_block", "name": current_block, "pc": pc})
        if row["opcode"] in ("SLOAD", "SSTORE"):
            entity = f"{row['opcode']}@{pc}"
            entities.append({"id": _entity_id("storage", entity), "kind": "storage_access", "operation": row["opcode"], "pc": pc})
        if row["opcode"] in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            entity = f"{row['opcode']}@{pc}"
            entities.append({"id": _entity_id("call", entity), "kind": "external_call", "target": "dynamic", "operation": row["opcode"], "pc": pc})
            if row["opcode"] == "DELEGATECALL":
                hints.append(_risk_hint("DELEGATECALL_DYNAMIC", "delegatecall target is not recovered as a constant", [pc]))
        if row["opcode"] == "SELFDESTRUCT":
            hints.append(_risk_hint("SELFDESTRUCT", "selfdestruct opcode present in recovered bytecode", [pc]))
        if row["opcode"] == "SSTORE":
            hints.append(_risk_hint("ARBITRARY_SSTORE", "storage write target could not be attributed to source layout", [pc]))
        if row["opcode"] == "CALLDATALOAD" and any(next_row["opcode"] in ("JUMP", "JUMPI") for next_row in instructions[instructions.index(row) + 1:instructions.index(row) + 4]):
            hints.append(_risk_hint("CALLDATALOAD_DERIVED_JUMP", "calldata appears to influence a jump target", [pc]))
    if jumpdest_count > 64:
        hints.append(_risk_hint("LONG_JUMPDEST_CHAIN", f"{jumpdest_count} jump destinations were recovered", []))
    # PUSH20 literals immediately preceding an external call are address hints.
    for index, row in enumerate(instructions):
        if row["opcode"] == "PUSH20" and isinstance(row.get("immediate"), str):
            address = "0x" + row["immediate"][-40:]
            if index + 1 < len(instructions) and instructions[index + 1]["opcode"] in ("CALL", "DELEGATECALL", "STATICCALL"):
                hints.append(_risk_hint("HARDCODED_ADDRESS", f"constant call target {address}", [row["pc"]]))
    if any(row.get("truncated") for row in instructions):
        low.append("truncated_push_instruction")
    return entities, hints, low


def _from_text(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    entities: list[dict[str, Any]] = []
    hints: list[dict[str, Any]] = []
    low: list[str] = []
    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        selector = SELECTOR_RE.search(stripped)
        function = FUNCTION_RE.search(stripped)
        if function and (stripped.lower().startswith("function") or "function" in stripped.lower()):
            name = function.group(1)
            signature = f"{name}({function.group(2).strip()})"
            entities.append({"id": _entity_id("function", signature), "kind": "function", "name": name, "signature": signature, "selector": selector.group(1).lower() if selector else None, "sourceRef": {"line": line_no}})
        for match in SLOT_RE.finditer(stripped):
            value = match.group(1)
            entities.append({"id": _entity_id("storage", value), "kind": "storage_access", "slot": value.lower(), "sourceRef": {"line": line_no}})
        for address in ADDRESS_RE.findall(stripped):
            if not re.search(r"(?:constant|literal|push|hardcoded)", stripped, re.I):
                continue
            hints.append(_risk_hint("HARDCODED_ADDRESS", f"hardcoded address {address.lower()}", [{"line": line_no}]))
        lowered = stripped.lower()
        if "delegatecall" in lowered:
            dynamic = not bool(re.search(r"delegatecall\s*\([^)]*0x[0-9a-f]{40}", lowered))
            if dynamic:
                hints.append(_risk_hint("DELEGATECALL_DYNAMIC", "delegatecall target is derived or unresolved", [{"line": line_no}]))
        if "selfdestruct" in lowered:
            hints.append(_risk_hint("SELFDESTRUCT", "selfdestruct appears in decompiler output", [{"line": line_no}]))
        if "sstore" in lowered:
            hints.append(_risk_hint("ARBITRARY_SSTORE", "sstore target is not bound to a verified source layout", [{"line": line_no}]))
        if re.search(r"calldataload", lowered) and re.search(r"\bjumpi?\b|jump\s*\(", lowered):
            hints.append(_risk_hint("CALLDATALOAD_DERIVED_JUMP", "calldata-derived control flow appears in pseudocode", [{"line": line_no}]))
    if not entities:
        low.append("function_and_storage_entities_not_recovered")
    return entities, hints, low


def extract_semantics(value: Any) -> dict[str, Any]:
    canonical, info = _canonical_text(value)
    if len(canonical) > MAX_INPUT_CHARS:
        raise ValueError(f"input exceeds {MAX_INPUT_CHARS} characters")
    raw = info.get("raw") if info["kind"] == "bytecode" else None
    if isinstance(raw, bytes):
        entities, hints, low = _from_bytecode(raw)
        input_kind = "bytecode"
        input_sha = hashlib.sha256(raw).hexdigest()
    else:
        text = str(info.get("raw", canonical))
        entities, hints, low = _from_text(text)
        input_kind = "pseudocode" if info["kind"] != "json" else "heimdall_json"
        input_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    # Deduplicate hints while preserving first evidence location.
    seen: set[tuple[str, str]] = set()
    unique_hints = []
    for hint in hints:
        key = (hint["kind"], hint["detail"])
        if key not in seen:
            seen.add(key)
            unique_hints.append(hint)
    return {
        "schemaVersion": 1,
        "inputKind": input_kind,
        "inputSha256": input_sha,
        "entities": entities,
        "lowConfidenceBlocks": low,
        "riskHints": unique_hints,
        "semanticsProven": False,
        "highLevelSemanticsRecovered": bool(entities),
        "crossValidation": {"state": "not_performed", "scope": "heuristic decompiler semantic extraction", "semanticsProven": False},
        "limitations": [
            "Decompiler output is heuristic and may omit unreachable or optimized code.",
            "Risk hints are observations, not confirmed vulnerabilities.",
            "Entity IDs are stable for identical normalized input but do not prove source identity.",
        ],
    }


def write_semantics(output: str | Path, value: Any) -> dict[str, Any]:
    result = extract_semantics(value)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        value = json.loads(args.input.read_text(encoding="utf-8")) if args.input.suffix.lower() == ".json" else args.input.read_text(encoding="utf-8")
        result = write_semantics(args.output, value)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps({"output": str(args.output), "riskHintCount": len(result["riskHints"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
