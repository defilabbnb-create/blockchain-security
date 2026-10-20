"""Independent byte-level cross-checks for deterministic EVM disassembly.

This module intentionally does not reconstruct Solidity, Yul, stack state, or
reachability.  It is a second opcode/PC tokenizer used to catch decoder or
report serialization drift.  A consistent result is therefore only evidence
that two byte-level decoders agree on the supplied bytes; it is not semantic
validation and it is not a second high-level decompiler.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter


MAX_BYTECODE_BYTES = 131_072
_BYTECODE_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})+")

# Keep this table local and deliberately independent from bytecode_analysis.py.
# It is a tokenization reference, not an EVM semantics table.
_OPCODES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
    0x0A: "EXP", 0x0B: "SIGNEXTEND", 0x10: "LT", 0x11: "GT", 0x12: "SLT",
    0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR",
    0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR",
    0x1D: "SAR", 0x20: "KECCAK256", 0x30: "ADDRESS", 0x31: "BALANCE",
    0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
    0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH", 0x41: "COINBASE",
    0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "DIFFICULTY_OR_PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE", 0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
    0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC",
    0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST", 0x5C: "TLOAD", 0x5D: "TSTORE",
    0x5E: "MCOPY", 0x5F: "PUSH0", 0xA0: "LOG0", 0xA1: "LOG1", 0xA2: "LOG2",
    0xA3: "LOG3", 0xA4: "LOG4", 0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE",
    0xF3: "RETURN", 0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
    0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
for _width in range(1, 33):
    _OPCODES[0x5F + _width] = f"PUSH{_width}"
for _depth in range(1, 17):
    _OPCODES[0x7F + _depth] = f"DUP{_depth}"
    _OPCODES[0x8F + _depth] = f"SWAP{_depth}"


def _raw_bytecode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("bytecode must be non-empty, even-length 0x hex")
    if len(value) > 2 + MAX_BYTECODE_BYTES * 2:
        raise ValueError(f"bytecode exceeds {MAX_BYTECODE_BYTES} byte limit")
    if _BYTECODE_RE.fullmatch(value) is None:
        raise ValueError("bytecode must be non-empty, even-length 0x hex")
    raw = bytes.fromhex(value[2:])
    if len(raw) > MAX_BYTECODE_BYTES:
        raise ValueError(f"bytecode exceeds {MAX_BYTECODE_BYTES} byte limit")
    return raw


def _instruction_digest(instructions: list[dict]) -> str:
    canonical = "\n".join(
        f"{row['pc']}|{row['opcode']}|{row.get('immediate', '')}|{int(bool(row.get('truncatedPush')))}"
        for row in instructions
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def decode_opcode_pc(bytecode: str) -> dict:
    """Decode raw bytes into independent PC/opcode tokens.

    Immediate bytes are retained only for digesting and mismatch diagnostics.
    This function performs no stack simulation, control-flow analysis, or
    semantic interpretation.
    """
    raw = _raw_bytecode(bytecode)
    instructions = []
    pc = 0
    while pc < len(raw):
        start = pc
        value = raw[pc]
        pc += 1
        opcode = _OPCODES.get(value, f"UNKNOWN_0x{value:02x}")
        row = {"pc": start, "opcode": opcode}
        if 0x60 <= value <= 0x7F:
            width = value - 0x5F
            available = min(width, len(raw) - pc)
            row["immediate"] = raw[pc:pc + available].hex()
            if available != width:
                row["truncatedPush"] = True
            pc += available
        instructions.append(row)
    counts = Counter(row["opcode"] for row in instructions)
    return {
        "schemaVersion": 1,
        "engine": "independent-opcode-pc-decoder",
        "kind": "opcode_pc_tokenization",
        "inputSha256": hashlib.sha256(raw).hexdigest(),
        "inputBytecodeBytes": len(raw),
        "decodedBytes": pc,
        "instructionCount": len(instructions),
        "opcodeCounts": dict(sorted(counts.items())),
        "unknownOpcodeCount": sum(1 for row in instructions if row["opcode"].startswith("UNKNOWN_")),
        "truncatedPushCount": sum(1 for row in instructions if row.get("truncatedPush")),
        "instructionDigest": _instruction_digest(instructions),
        "complete": pc == len(raw) and not any(row.get("truncatedPush") for row in instructions),
        "semanticsProven": False,
        "highLevelSemanticsRecovered": False,
        "instructions": instructions,
        "limitations": [
            "Only independent opcode/PC tokenization and input binding are checked.",
            "This is not a second Solidity/Yul decompiler and does not recover high-level semantics.",
            "Agreement does not prove control-flow reachability, stack correctness, deployed behavior, or absence of vulnerabilities.",
        ],
    }


def compare_disassembly(primary_report: dict) -> dict:
    """Compare a primary disassembly report with the independent tokenizer."""
    result = {
        "schemaVersion": 1,
        "kind": "opcode_pc_cross_check",
        "engine": "independent-opcode-pc-decoder",
        "state": "unavailable",
        "scope": "byte-level opcode/PC tokenization and input binding only",
        "semanticsProven": False,
        "highLevelSemanticsRecovered": False,
        "isSecondHighLevelDecompiler": False,
        "mismatches": [],
        "limitations": [
            "A consistent result is not semantic validation and is not a vulnerability finding.",
            "No stack simulation, control-flow proof, source recovery, or reachability claim is made.",
        ],
    }
    if not isinstance(primary_report, dict):
        result["reason"] = "primary_report_not_object"
        return result
    bytecode = primary_report.get("runtimeBytecode")
    try:
        independent = decode_opcode_pc(bytecode)
    except (TypeError, ValueError) as error:
        result["reason"] = f"independent_decoder_error:{type(error).__name__}"
        result["error"] = str(error)[:240]
        return result
    result.update({
        "state": "consistent",
        "inputSha256": independent["inputSha256"],
        "inputBytecodeBytes": independent["inputBytecodeBytes"],
        "independentInstructionCount": independent["instructionCount"],
        "independentDecodedBytes": independent["decodedBytes"],
        "independentInstructionDigest": independent["instructionDigest"],
        "independentOpcodeCounts": independent["opcodeCounts"],
        "independentUnknownOpcodeCount": independent["unknownOpcodeCount"],
        "independentTruncatedPushCount": independent["truncatedPushCount"],
        "independentComplete": independent["complete"],
    })
    # Check the primary report's declared input identity as well as the
    # independently re-hashed runtimeBytecode.  This catches stale or edited
    # summary fields even when the instruction array itself still matches.
    declared_hash = primary_report.get("bytecodeSha256")
    if declared_hash != independent["inputSha256"]:
        result["mismatches"].append({
            "field": "bytecodeSha256", "primary": declared_hash,
            "independent": independent["inputSha256"],
        })
    declared_bytes = primary_report.get("bytecodeBytes")
    if declared_bytes != independent["inputBytecodeBytes"]:
        result["mismatches"].append({
            "field": "bytecodeBytes", "primary": declared_bytes,
            "independent": independent["inputBytecodeBytes"],
        })
    primary_instructions = primary_report.get("instructions")
    if not isinstance(primary_instructions, list):
        result["state"] = "mismatch" if result["mismatches"] else "unavailable"
        result["reason"] = "primary_instructions_not_array"
        return result

    normalized_primary = []
    for row in primary_instructions:
        if not isinstance(row, dict) or not isinstance(row.get("pc"), int) or not isinstance(row.get("opcode"), str):
            result["state"] = "mismatch" if result["mismatches"] else "unavailable"
            result["reason"] = "primary_instruction_shape_invalid"
            return result
        normalized_primary.append({
            "pc": row["pc"], "opcode": row["opcode"],
            **({"immediate": row["immediate"]} if isinstance(row.get("immediate"), str) else {}),
            **({"truncatedPush": True} if row.get("truncatedPush") else {}),
        })
    expected = independent["instructions"]
    result["primaryInstructionCount"] = len(normalized_primary)
    result["primaryInstructionDigest"] = _instruction_digest(normalized_primary)
    result["primaryDecodedBytes"] = primary_report.get("decodedBytes")
    result["primaryOpcodeCounts"] = primary_report.get("opcodeCounts")
    result["primaryUnknownOpcodeCount"] = sum(
        1 for row in normalized_primary if row["opcode"].startswith("UNKNOWN_")
    )
    result["primaryTruncatedPushCount"] = sum(1 for row in normalized_primary if row.get("truncatedPush"))
    comparisons = [
        ("bytecodeSha256", primary_report.get("bytecodeSha256"), independent["inputSha256"]),
        ("bytecodeBytes", primary_report.get("bytecodeBytes"), independent["inputBytecodeBytes"]),
        ("instructionArrayCount", len(normalized_primary), len(expected)),
        ("instructionCount", primary_report.get("instructionCount"), independent["instructionCount"]),
        ("decodedBytes", primary_report.get("decodedBytes"), independent["decodedBytes"]),
        ("instructionDigest", result["primaryInstructionDigest"], independent["instructionDigest"]),
        ("opcodeCounts", primary_report.get("opcodeCounts"), independent["opcodeCounts"]),
        ("unknownOpcodeCount", result["primaryUnknownOpcodeCount"], independent["unknownOpcodeCount"]),
        ("truncatedPushCount", result["primaryTruncatedPushCount"], independent["truncatedPushCount"]),
        ("opcodeCounts", result["primaryOpcodeCounts"], independent["opcodeCounts"]),
    ]
    for field, observed, expected_value in comparisons:
        if observed != expected_value:
            result["mismatches"].append({"field": field, "primary": observed, "independent": expected_value})
    if result["mismatches"]:
        result["state"] = "mismatch"
    return result


def attach_opcode_cross_validation(decompilation: dict, primary_report: dict) -> dict:
    """Attach the byte-level check while preserving existing artifact checks."""
    if not isinstance(decompilation, dict):
        return decompilation
    check = compare_disassembly(primary_report)
    cross = dict(decompilation.get("crossValidation") or {})
    cross["opcodePcCrossCheck"] = check
    cross["independentDecoderCompleted"] = check.get("state") in {"consistent", "mismatch"}
    cross["independentDecoderName"] = "independent-opcode-pc-decoder"
    cross["comparedHighLevelEngineCount"] = 0
    cross["agreementScope"] = "opcode/PC tokenization only; no high-level decompiler agreement or semantic proof"
    primary_hash = primary_report.get("bytecodeSha256") if isinstance(primary_report, dict) else None
    primary_bytes = primary_report.get("bytecodeBytes") if isinstance(primary_report, dict) else None
    decompiler_hash = decompilation.get("inputSha256")
    decompiler_bytes = decompilation.get("inputBytecodeBytes")
    if (isinstance(primary_hash, str) and isinstance(primary_bytes, int)
            and not isinstance(primary_bytes, bool)
            and isinstance(decompiler_hash, str)
            and isinstance(decompiler_bytes, int) and not isinstance(decompiler_bytes, bool)):
        binding_state = "consistent" if (primary_hash == decompiler_hash and
                                           primary_bytes == decompiler_bytes) else "mismatch"
        cross["decompilerInputBinding"] = {
            "state": binding_state,
            "primarySha256": primary_hash,
            "decompilerSha256": decompiler_hash,
            "primaryBytecodeBytes": primary_bytes,
            "decompilerBytecodeBytes": decompiler_bytes,
        }
        if binding_state == "mismatch":
            cross["state"] = "input_mismatch"
            decompilation["executionState"] = decompilation.get("state")
            decompilation["state"] = "failed"
            decompilation["error"] = "decompiler_input_binding_mismatch"
    else:
        cross["decompilerInputBinding"] = {"state": "unavailable"}
    if check.get("state") in {"consistent", "mismatch"}:
        current = cross.get("state")
        if current in (None, "not_performed", "opcode_consistent", "opcode_mismatch"):
            cross["state"] = "opcode_consistent" if check["state"] == "consistent" else "opcode_mismatch"
    decompilation["crossValidation"] = cross
    return decompilation


__all__ = ["decode_opcode_pc", "compare_disassembly", "attach_opcode_cross_validation"]
