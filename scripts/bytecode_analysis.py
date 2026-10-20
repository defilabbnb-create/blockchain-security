#!/usr/bin/env python3
"""Deterministic EVM runtime-bytecode disassembly and triage hints.

This is not a decompiler and does not infer Solidity semantics or reachability.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import warnings
from pathlib import Path

try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings('ignore', category=NotOpenSSLWarning)
except ImportError:
    pass

from decompiler_adapter import run_heimdall
from decompiler_crosscheck import attach_opcode_cross_validation, compare_disassembly
from repr_cache import cache_key as repr_cache_key, get_or_build as repr_get_or_build
from unified_ir import from_bytecode_report


ROOT = Path(__file__).resolve().parent.parent


OPCODES = {
    0x00: 'STOP', 0x01: 'ADD', 0x02: 'MUL', 0x03: 'SUB', 0x04: 'DIV',
    0x05: 'SDIV', 0x06: 'MOD', 0x07: 'SMOD', 0x08: 'ADDMOD', 0x09: 'MULMOD',
    0x0A: 'EXP', 0x0B: 'SIGNEXTEND', 0x10: 'LT', 0x11: 'GT', 0x12: 'SLT',
    0x13: 'SGT', 0x14: 'EQ', 0x15: 'ISZERO', 0x16: 'AND', 0x17: 'OR',
    0x18: 'XOR', 0x19: 'NOT', 0x1A: 'BYTE', 0x1B: 'SHL', 0x1C: 'SHR',
    0x1D: 'SAR', 0x20: 'KECCAK256', 0x30: 'ADDRESS', 0x31: 'BALANCE',
    0x32: 'ORIGIN', 0x33: 'CALLER', 0x34: 'CALLVALUE', 0x35: 'CALLDATALOAD',
    0x36: 'CALLDATASIZE', 0x37: 'CALLDATACOPY', 0x38: 'CODESIZE',
    0x39: 'CODECOPY', 0x3A: 'GASPRICE', 0x3B: 'EXTCODESIZE',
    0x3C: 'EXTCODECOPY', 0x3D: 'RETURNDATASIZE', 0x3E: 'RETURNDATACOPY',
    0x3F: 'EXTCODEHASH', 0x40: 'BLOCKHASH', 0x41: 'COINBASE', 0x42: 'TIMESTAMP',
    0x43: 'NUMBER', 0x44: 'DIFFICULTY_OR_PREVRANDAO', 0x45: 'GASLIMIT', 0x46: 'CHAINID',
    0x47: 'SELFBALANCE', 0x48: 'BASEFEE', 0x49: 'BLOBHASH', 0x4A: 'BLOBBASEFEE',
    0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE', 0x53: 'MSTORE8', 0x54: 'SLOAD',
    0x55: 'SSTORE', 0x56: 'JUMP', 0x57: 'JUMPI', 0x58: 'PC', 0x59: 'MSIZE',
    0x5A: 'GAS', 0x5B: 'JUMPDEST', 0x5C: 'TLOAD', 0x5D: 'TSTORE',
    0x5E: 'MCOPY', 0x5F: 'PUSH0', 0xA0: 'LOG0', 0xA1: 'LOG1', 0xA2: 'LOG2',
    0xA3: 'LOG3', 0xA4: 'LOG4', 0xF0: 'CREATE', 0xF1: 'CALL',
    0xF2: 'CALLCODE', 0xF3: 'RETURN', 0xF4: 'DELEGATECALL', 0xF5: 'CREATE2',
    0xFA: 'STATICCALL', 0xFD: 'REVERT', 0xFE: 'INVALID', 0xFF: 'SELFDESTRUCT',
}
for _n in range(1, 33):
    OPCODES[0x5F + _n] = f'PUSH{_n}'
for _n in range(1, 17):
    OPCODES[0x7F + _n] = f'DUP{_n}'
    OPCODES[0x8F + _n] = f'SWAP{_n}'

TERMINATORS = {'STOP', 'JUMP', 'JUMPI', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT'}
EXTERNAL_CALLS = {'CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'}
EIP1967_SLOTS = {
    'implementation': '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
    'beacon': 'a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',
    'admin': 'b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
}
# EIP-1167's canonical deployed clone runtime. The implementation address is
# the only variable segment; keeping the prefix/suffix exact avoids treating a
# generic DELEGATECALL dispatcher as a clone.
EIP1167_PREFIX = bytes.fromhex('363d3d373d3d3d363d73')
EIP1167_SUFFIX = bytes.fromhex('5af43d82803e903d91602b57fd5bf3')
MAX_BYTECODE_BYTES = 131_072
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_METADATA_TRAILER_BYTES = 4096
MAX_CBOR_ITEMS = 128
MAX_CBOR_DEPTH = 8
HARD_FORK_ORDER = ('frontier', 'homestead', 'byzantium', 'constantinople', 'istanbul',
                   'berlin', 'london', 'paris', 'shanghai', 'cancun', 'prague', 'osaka', 'latest')
OPCODE_ACTIVATION = {
    'PUSH0': 'shanghai',
    'TLOAD': 'cancun', 'TSTORE': 'cancun', 'MCOPY': 'cancun',
    'BLOBHASH': 'cancun', 'BLOBBASEFEE': 'cancun',
}


def _opcode_activation(opcode, hardfork):
    required = OPCODE_ACTIVATION.get(opcode)
    if required is None:
        return None
    if not isinstance(hardfork, str) or not hardfork.strip():
        return {'requiredHardfork': required, 'status': 'unverified', 'active': None}
    normalized = hardfork.strip().lower().replace('-', '')
    aliases = {'prevrandao': 'paris', 'merge': 'paris'}
    normalized = aliases.get(normalized, normalized)
    # `latest` is a CLI convenience value, not a chain/block identity.  It
    # must remain unverified instead of silently asserting that every modern
    # opcode is active on an unknown historical deployment.
    if normalized == 'latest' or normalized not in HARD_FORK_ORDER:
        return {'requiredHardfork': required, 'status': 'unverified', 'active': None}
    active = HARD_FORK_ORDER.index(normalized) >= HARD_FORK_ORDER.index(required)
    return {'requiredHardfork': required, 'status': 'active' if active else 'inactive', 'active': active}


def _read_cbor_argument(data, offset, additional):
    if additional < 24:
        return additional, offset
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
    if width is None or offset + width > len(data):
        raise ValueError('invalid or indefinite CBOR argument')
    value = int.from_bytes(data[offset:offset + width], 'big')
    return value, offset + width


def _read_cbor_item(data, offset, budget, depth=0):
    budget[0] += 1
    if budget[0] > MAX_CBOR_ITEMS or depth > MAX_CBOR_DEPTH or offset >= len(data):
        raise ValueError('CBOR metadata exceeds structural limits')
    initial = data[offset]
    offset += 1
    major, additional = initial >> 5, initial & 0x1f
    argument, offset = _read_cbor_argument(data, offset, additional)
    if major in (0, 1):
        return major, argument, offset
    if major in (2, 3):
        end = offset + argument
        if end > len(data):
            raise ValueError('truncated CBOR string')
        value = data[offset:end]
        if major == 3:
            value = value.decode('utf-8')
        return major, value, end
    if major == 4:
        values = []
        for _ in range(argument):
            _, value, offset = _read_cbor_item(data, offset, budget, depth + 1)
            values.append(value)
        return major, values, offset
    if major == 5:
        pairs = []
        for _ in range(argument):
            _, key, offset = _read_cbor_item(data, offset, budget, depth + 1)
            _, value, offset = _read_cbor_item(data, offset, budget, depth + 1)
            pairs.append((key, value))
        return major, pairs, offset
    if major == 6:
        _, value, offset = _read_cbor_item(data, offset, budget, depth + 1)
        return major, value, offset
    if major == 7 and additional < 24:
        return major, argument, offset
    if major == 7 and additional == 24 and argument < 32:
        raise ValueError('reserved CBOR simple value')
    if major == 7 and additional in (24, 25, 26, 27):
        return major, argument, offset
    raise ValueError('unsupported CBOR item')


def _metadata_candidate(raw):
    if len(raw) < 4:
        return None
    trailer_length = int.from_bytes(raw[-2:], 'big')
    start = len(raw) - 2 - trailer_length
    if trailer_length < 6 or trailer_length > MAX_METADATA_TRAILER_BYTES or start < 0:
        return None
    trailer = raw[start:-2]
    try:
        major, pairs, end = _read_cbor_item(trailer, 0, [0])
    except (UnicodeDecodeError, ValueError):
        return None
    if major != 5 or end != len(trailer) or not 1 <= len(pairs) <= 32:
        return None
    metadata = {}
    for key, value in pairs:
        if isinstance(key, str):
            if key in metadata:
                return None
            metadata[key] = value
    has_compiler = isinstance(metadata.get('solc'), bytes) and len(metadata['solc']) == 3
    hash_value = metadata.get('ipfs')
    has_hash = isinstance(hash_value, bytes) and len(hash_value) == 34
    has_hash = has_hash or any(
        isinstance(metadata.get(key), bytes) and len(metadata[key]) == 32
        for key in ('bzzr0', 'bzzr1')
    )
    if has_compiler and has_hash:
        return {'startPc': start, 'byteLength': trailer_length, 'detection': 'CBOR trailer candidate'}
    return None


def _classify_runtime_bytecode(raw, instructions, metadata, slot_hints, external_calls):
    """Return a conservative runtime shape classification.

    This is intentionally a shape classifier rather than a semantic detector:
    the evidence is limited to exact EIP-1167 bytes, literal EIP-1967 slots,
    observed delegatecall opcodes, and decoder completeness. A proxy candidate
    still requires runtime execution and storage evidence before it can be
    treated as a verified proxy or vulnerability.
    """
    truncated = [item['pc'] for item in instructions if item.get('truncatedPush')]
    delegatecalls = [item['pc'] for item in external_calls if item.get('opcode') == 'DELEGATECALL']
    slot_kinds = sorted({item['kind'] for item in slot_hints})
    evidence = []

    if len(raw) == len(EIP1167_PREFIX) + 20 + len(EIP1167_SUFFIX) and raw.startswith(EIP1167_PREFIX) and raw.endswith(EIP1167_SUFFIX):
        implementation = '0x' + raw[len(EIP1167_PREFIX):len(EIP1167_PREFIX) + 20].hex()
        evidence.append({
            'kind': 'eip1167_minimal_proxy_shape',
            'confidence': 'observed',
            'prefix': EIP1167_PREFIX.hex(),
            'suffix': EIP1167_SUFFIX.hex(),
            'implementation': implementation,
        })
        return {
            'kind': 'minimal_proxy_clone',
            'confidence': 'observed',
            'codeCompleteness': 'complete',
            'proxyCandidate': True,
            'implementationAddress': implementation,
            'evidence': evidence,
            'limitations': ['The implementation address is embedded in clone bytecode; its code and storage were not resolved here.'],
        }

    if truncated:
        evidence.append({'kind': 'truncated_push', 'confidence': 'observed', 'pcs': truncated})

    if delegatecalls and slot_kinds:
        evidence.append({
            'kind': 'eip1967_slot_and_delegatecall',
            'confidence': 'heuristic',
            'delegatecallPcs': delegatecalls,
            'slotKinds': slot_kinds,
        })
        if any(kind.endswith('_implementation_slot_literal') for kind in slot_kinds):
            kind = 'eip1967_implementation_proxy_candidate'
        elif any(kind.endswith('_beacon_slot_literal') for kind in slot_kinds):
            kind = 'eip1967_beacon_proxy_candidate'
        else:
            kind = 'eip1967_proxy_candidate'
        return {
            'kind': kind,
            'confidence': 'heuristic',
            'codeCompleteness': 'truncated' if truncated else 'complete',
            'proxyCandidate': True,
            'evidence': evidence,
            'limitations': [
                'Slot literals and DELEGATECALL indicate a proxy shape candidate; runtime storage reads, beacon behavior, and implementation code were not executed or resolved.',
            ],
        }

    if delegatecalls:
        evidence.append({'kind': 'delegatecall', 'confidence': 'heuristic', 'pcs': delegatecalls})
        return {
            'kind': 'delegatecall_proxy_candidate',
            'confidence': 'heuristic',
            'codeCompleteness': 'truncated' if truncated else 'complete',
            'proxyCandidate': True,
            'evidence': evidence,
            'limitations': ['DELEGATECALL alone does not identify a proxy standard or prove target selection.'],
        }

    return {
        'kind': 'runtime_contract',
        'confidence': 'observed' if not truncated else 'partial',
        'codeCompleteness': 'truncated' if truncated else 'complete',
        'proxyCandidate': False,
        'evidence': evidence,
        'limitations': ([] if not truncated else [
            'A PUSH immediate is truncated; opcode and control-flow observations after the truncation are incomplete.',
        ]),
    }


def _push_immediate_target(instruction):
    """Return a complete constant pushed by a PUSH instruction, if any."""
    if not isinstance(instruction, dict) or instruction.get('truncatedPush'):
        return None
    opcode = instruction.get('opcode')
    immediate = instruction.get('immediate')
    if opcode == 'PUSH0':
        return 0
    if not isinstance(opcode, str) or not opcode.startswith('PUSH') or opcode == 'PUSH0':
        return None
    if not isinstance(immediate, str) or not immediate:
        return None
    try:
        return int(immediate, 16)
    except ValueError:
        return None


def _control_flow_edges(instructions):
    """Build conservative instruction-level control-flow hints.

    This intentionally does not simulate the EVM stack or claim reachability.
    Only the common direct ``PUSH target [PUSH condition] JUMP[I]`` shape is
    resolved; all other dynamic jumps retain an explicit unknown target.
    """
    if not instructions:
        return []

    executable = [not item.get('inMetadataCandidate', False) for item in instructions]
    instruction_by_pc = {item['pc']: item for item in instructions}
    edges = []
    seen = set()

    def add(source, target, kind, target_kind, **extra):
        if target is not None and instruction_by_pc.get(target, {}).get('inMetadataCandidate', False):
            return
        key = (source, target, kind, target_kind, tuple(sorted(extra.items())))
        if key in seen:
            return
        seen.add(key)
        row = {
            'fromPc': source,
            'toPc': target,
            'kind': kind,
            'targetKind': target_kind,
            'confidence': 'heuristic',
            'semanticsProven': False,
        }
        row.update(extra)
        edges.append(row)

    for index, instruction in enumerate(instructions):
        if not executable[index]:
            continue
        source = instruction['pc']
        opcode = instruction.get('opcode')
        next_index = index + 1
        next_pc = (instructions[next_index]['pc']
                   if next_index < len(instructions) and executable[next_index] else None)

        # Ordinary instruction flow and the false branch of JUMPI both fall
        # through to the next executable instruction. A metadata candidate is
        # never entered by an inferred edge.
        if opcode not in {'JUMP', 'STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT'} and next_pc is not None:
            add(source, next_pc, 'sequential', 'static')

        if opcode not in {'JUMP', 'JUMPI'}:
            continue

        target = None
        target_source = None
        if opcode == 'JUMP':
            if index > 0:
                target = _push_immediate_target(instructions[index - 1])
                target_source = index - 1 if target is not None else None
        elif index > 1:
            # JUMPI consumes target first and condition second. Resolve only
            # the direct PUSH target + PUSH condition shape; anything else is
            # deliberately left dynamic rather than guessed.
            target = _push_immediate_target(instructions[index - 2])
            target_source = index - 2 if target is not None else None
            if target_source is not None and _push_immediate_target(instructions[index - 1]) is None:
                target = None

        target_instruction = instruction_by_pc.get(target) if target is not None else None
        target_filtered = target_instruction is not None and target_instruction.get('inMetadataCandidate', False)
        if target is not None and not target_filtered:
            add(source, target, 'jump' if opcode == 'JUMP' else 'conditional_true', 'static',
                targetPcIsJumpdest=bool(target_instruction and target_instruction.get('opcode') == 'JUMPDEST'),
                targetSourcePc=instructions[target_source]['pc'] if target_source is not None else None)
        else:
            add(source, None, 'jump' if opcode == 'JUMP' else 'conditional_true', 'unknown',
                unknownReason='target_in_metadata_candidate' if target_filtered else 'dynamic_stack_target')

        if opcode == 'JUMPI' and next_pc is not None:
            add(source, next_pc, 'conditional_false', 'static')

    return edges


def _literal_event_and_error_candidates(instructions):
    """Collect bounded literal candidates without assigning ABI semantics.

    A literal is only reported when a nearby logging or revert instruction is
    present in executable bytes. Stack order, calldata origin, and selector
    meaning remain unresolved, so each row is explicitly heuristic.
    """
    event_topics = []
    error_selectors = []
    for index, instruction in enumerate(instructions):
        if instruction.get('inMetadataCandidate') or instruction.get('truncatedPush'):
            continue
        opcode = instruction.get('opcode', '')
        immediate = instruction.get('immediate')
        if not isinstance(immediate, str) or not immediate:
            continue
        lookahead = [row for row in instructions[index + 1:index + 13]
                     if not row.get('inMetadataCandidate')]
        if opcode == 'PUSH32' and len(immediate) == 64:
            log = next((row for row in lookahead if row.get('opcode') in {'LOG0', 'LOG1', 'LOG2', 'LOG3', 'LOG4'}), None)
            if log is not None:
                event_topics.append({
                    'pc': instruction['pc'],
                    'topic': '0x' + immediate.lower(),
                    'logOpcode': log['opcode'],
                    'logPc': log['pc'],
                    'heuristic': 'literal PUSH32 near LOG opcode; topic stack order and event ABI are not proven',
                })
        if opcode == 'PUSH4' and len(immediate) == 8:
            revert = next((row for row in lookahead if row.get('opcode') == 'REVERT'), None)
            mstore = next((row for row in lookahead if row.get('opcode') in {'MSTORE', 'MSTORE8'}), None)
            if revert is not None and mstore is not None:
                error_selectors.append({
                    'pc': instruction['pc'],
                    'selector': '0x' + immediate.lower(),
                    'revertPc': revert['pc'],
                    'heuristic': 'literal PUSH4 near memory write and REVERT; error ABI and reachability are not proven',
                })
    return event_topics, error_selectors


def analyze_runtime_bytecode(bytecode, *, chain_id=None, address=None, block=None, block_hash=None, hardfork=None,
                             bytecode_kind='runtime'):
    if bytecode_kind not in ('runtime', 'creation'):
        raise ValueError('bytecode_kind must be runtime or creation')
    if not isinstance(bytecode, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', bytecode):
        raise ValueError(f'{bytecode_kind} bytecode must be non-empty, even-length 0x hex')
    if (len(bytecode) - 2) // 2 > MAX_BYTECODE_BYTES:
        raise ValueError(f'runtime bytecode exceeds {MAX_BYTECODE_BYTES} byte limit')
    raw = bytes.fromhex(bytecode[2:])
    metadata = _metadata_candidate(raw)
    instructions = []
    pc = 0
    # Decode all bytes, including possible metadata. A heuristic trailer marker
    # must never silently remove bytes that could still be executable.
    while pc < len(raw):
        offset = pc
        value = raw[pc]
        pc += 1
        name = OPCODES.get(value, f'UNKNOWN_0x{value:02x}')
        row = {'pc': offset, 'opcode': name}
        activation = _opcode_activation(name, hardfork)
        if activation:
            row['opcodeActivation'] = activation
        if metadata and offset >= metadata['startPc']:
            row['inMetadataCandidate'] = True
        if 0x60 <= value <= 0x7F:
            width = value - 0x5F
            available = min(width, len(raw) - pc)
            row['immediate'] = raw[pc:pc + available].hex()
            if available != width:
                row['truncatedPush'] = True
            pc += available
        instructions.append(row)

    opcode_counts = {}
    executable_opcode_counts = {}
    jumpdestinations = []
    calls = []
    storage = []
    selectors = []
    block_starts = {0} if instructions else set()
    for index, ins in enumerate(instructions):
        name = ins['opcode']
        opcode_counts[name] = opcode_counts.get(name, 0) + 1
        executable = not ins.get('inMetadataCandidate', False)
        if executable:
            executable_opcode_counts[name] = executable_opcode_counts.get(name, 0) + 1
        if name == 'JUMPDEST' and executable:
            jumpdestinations.append(ins['pc'])
            block_starts.add(ins['pc'])
        if name in EXTERNAL_CALLS and executable:
            calls.append({'pc': ins['pc'], 'opcode': name, 'inMetadataCandidate': ins.get('inMetadataCandidate', False)})
        if name in ('SLOAD', 'SSTORE', 'TLOAD', 'TSTORE') and executable:
            activation = ins.get('opcodeActivation')
            if not activation or activation.get('active') is not False:
                storage.append({'pc': ins['pc'], 'opcode': name,
                                'inMetadataCandidate': ins.get('inMetadataCandidate', False),
                                **({'opcodeActivation': activation} if activation else {})})
        if (name in TERMINATORS and executable and index + 1 < len(instructions) and
                not instructions[index + 1].get('inMetadataCandidate', False)):
            block_starts.add(instructions[index + 1]['pc'])
        if name == 'PUSH4' and executable and ins.get('immediate') and not ins.get('truncatedPush'):
            lookahead = instructions[index + 1:index + 9]
            if any(row.get('inMetadataCandidate', False) for row in lookahead):
                continue
            value = int(ins['immediate'], 16)
            shift = None
            if len(lookahead) >= 2 and lookahead[0]['opcode'] == 'PUSH1' and lookahead[1]['opcode'] == 'SHL':
                shift = int(lookahead[0]['immediate'], 16)
                if not 224 <= shift < 256:
                    continue
                value = ((value << shift) & ((1 << 256) - 1)) >> 224
                lookahead = lookahead[2:]
            if lookahead and lookahead[0]['opcode'].startswith('DUP'):
                lookahead = lookahead[1:]
            if not lookahead or lookahead[0]['opcode'] != 'EQ':
                continue
            tail = lookahead[1:]
            if tail and tail[0]['opcode'] == 'ISZERO':
                tail = tail[1:]
            if len(tail) >= 2 and tail[0]['opcode'] in ('PUSH1','PUSH2','PUSH3','PUSH4') and tail[1]['opcode'] == 'JUMPI':
                selectors.append({'pc': ins['pc'], 'selector': f'0x{value:08x}', 'literal': '0x' + ins['immediate'], 'shift': shift, 'inMetadataCandidate': ins.get('inMetadataCandidate', False), 'heuristic': 'literal comparison followed by conditional jump; calldata origin not proven'})

    slot_hints = []
    for ins in instructions:
        if not ins.get('inMetadataCandidate') and ins['opcode'].startswith('PUSH') and ins.get('immediate'):
            for label, slot in EIP1967_SLOTS.items():
                if ins['immediate'].lower().rjust(64, '0') == slot:
                    slot_hints.append({'pc': ins['pc'], 'kind': 'eip1967_' + label + '_slot_literal'})

    control_flow_edges = _control_flow_edges(instructions)
    event_topic_candidates, error_selector_candidates = _literal_event_and_error_candidates(instructions)

    classification = _classify_runtime_bytecode(
        raw, instructions, metadata, slot_hints, calls,
    )
    if bytecode_kind == 'creation':
        classification = {
            'kind': 'creation_code',
            'confidence': 'partial' if classification.get('codeCompleteness') == 'truncated' else 'observed',
            'codeCompleteness': classification.get('codeCompleteness', 'complete'),
            'proxyCandidate': False,
            'evidence': [{'kind': 'creation_code_input', 'confidence': 'observed'}],
            'limitations': ['Init code was disassembled as supplied; returned runtime code and constructor effects were not reconstructed.'],
        }

    fingerprint = hashlib.sha256(raw).hexdigest()
    report = {
        'schemaVersion': 1,
        'analysisType': 'deterministic_evm_runtime_disassembly' if bytecode_kind == 'runtime' else 'deterministic_evm_creation_disassembly',
        'bytecodeKind': ('deployed runtime; source is not reconstructed' if bytecode_kind == 'runtime'
                         else 'creation bytecode; init code and returned runtime are not reconstructed'),
        'inputBytecodeKind': bytecode_kind,
        'bytecodeClassification': classification,
        'bytecodeSha256': fingerprint,
        'runtimeBytecode': '0x' + raw.hex(),
        'bytecodeBytes': len(raw),
        'decodedBytes': len(raw),
        'metadataTrailer': metadata,
        'hardfork': hardfork if isinstance(hardfork, str) and hardfork.strip() else None,
        'instructionCount': len(instructions),
        'opcodeCounts': opcode_counts,
        'executableOpcodeCounts': executable_opcode_counts,
        'selectorCandidates': selectors,
        'eventTopicCandidates': event_topic_candidates,
        'errorSelectorCandidates': error_selector_candidates,
        'externalCallSites': calls,
        'storageOperationSites': storage,
        'jumpdestinations': jumpdestinations,
        'basicBlockStartHints': sorted(block_starts),
        'controlFlowEdges': control_flow_edges,
        'eip1967SlotLiteralHints': slot_hints,
        'instructions': instructions,
        'decompilation': {'state': 'not_performed', 'highLevelSemanticsRecovered': False},
        'limitations': [
            'Instruction decoding and selector/basic-block hints only; no stack simulation or control-flow proof.',
            'controlFlowEdges are conservative instruction-level hints; static jump targets use only direct PUSH patterns, dynamic targets remain unknown, and reachability is not proven.',
            'Event topics and error selectors are bounded literal candidates near LOG/REVERT patterns; ABI meaning, stack order, and reachability are not proven.',
            'All bytes are retained. Metadata markers are heuristic; embedded data can decode as instructions.',
            'Opcode names use the modern EVM set; activation and meaning depend on the target chain and block.',
            'Opcode presence does not prove reachability, exploitability, or a vulnerability.',
            'This deterministic report is not Solidity/Vyper source reconstruction; optional decompiler output remains heuristic and separate.',
            'Dynamic behavior requires a separate target-specific EVM test harness.',
        ],
    }
    for key, value in (('chainId', chain_id), ('address', address), ('block', block), ('blockHash', block_hash)):
        if value is not None:
            report[key] = value
    # Independent opcode/PC tokenization catches decoder/report drift.  It is
    # deliberately byte-level only: no stack, reachability, source recovery,
    # or vulnerability semantics are inferred by this cross-check.
    report['opcodePcCrossCheck'] = compare_disassembly(report)
    return report


def analyze_bytecode(bytecode, *, bytecode_kind='runtime', **anchors):
    """Analyze a typed bytecode value while preserving empty-code evidence.

    The legacy runtime entry point stays strict. This entry point is used by
    ingestion so an EOA/empty account is represented explicitly instead of
    becoming a generic parse failure.
    """
    if bytecode == '0x' and bytecode_kind in ('runtime', 'creation'):
        report = {
            'schemaVersion': 1,
            'analysisType': 'deterministic_evm_runtime_disassembly' if bytecode_kind == 'runtime' else 'deterministic_evm_creation_disassembly',
            'bytecodeKind': 'empty account code' if bytecode_kind == 'runtime' else 'empty creation bytecode',
            'inputBytecodeKind': bytecode_kind,
            'bytecodeSha256': hashlib.sha256(b'').hexdigest(), 'runtimeBytecode': '0x',
            'bytecodeBytes': 0, 'decodedBytes': 0, 'metadataTrailer': None,
            'hardfork': anchors.get('hardfork'), 'instructionCount': 0,
            'opcodeCounts': {}, 'executableOpcodeCounts': {}, 'selectorCandidates': [],
            'eventTopicCandidates': [], 'errorSelectorCandidates': [],
            'externalCallSites': [], 'storageOperationSites': [], 'jumpdestinations': [],
            'basicBlockStartHints': [], 'controlFlowEdges': [], 'eip1967SlotLiteralHints': [], 'instructions': [],
            'bytecodeClassification': {'kind': 'empty_code', 'confidence': 'observed', 'codeCompleteness': 'complete',
                                       'proxyCandidate': False, 'evidence': [], 'limitations': ['No deployed code exists at the supplied anchor.']},
            'decompilation': {'state': 'not_performed', 'highLevelSemanticsRecovered': False},
            'limitations': ['The account has no bytecode; no control-flow or semantic analysis was performed.'],
        }
        for key, value in (('chainId', anchors.get('chain_id')), ('address', anchors.get('address')),
                           ('block', anchors.get('block')), ('blockHash', anchors.get('block_hash'))):
            if value is not None: report[key] = value
        report['opcodePcCrossCheck'] = {
            'schemaVersion': 1,
            'kind': 'opcode_pc_cross_check',
            'engine': 'independent-opcode-pc-decoder',
            'state': 'consistent',
            'scope': 'byte-level opcode/PC tokenization and input binding only',
            'inputSha256': report['bytecodeSha256'],
            'inputBytecodeBytes': 0,
            'primaryInstructionCount': 0,
            'independentInstructionCount': 0,
            'mismatches': [],
            'semanticsProven': False,
            'highLevelSemanticsRecovered': False,
            'isSecondHighLevelDecompiler': False,
            'limitations': ['No bytecode exists; no semantic or reachability claim is made.'],
        }
        return report
    return analyze_runtime_bytecode(bytecode, **anchors, bytecode_kind=bytecode_kind)


def extract_runtime_bytecode(value):
    if isinstance(value, dict):
        runtime = value.get('runtimeBytecode')
        candidates = [
            runtime.get('onchainBytecode') if isinstance(runtime, dict) else runtime,
            value.get('runtimeCode'),
        ]
        candidates = [candidate for candidate in candidates
                      if isinstance(candidate, str) and candidate.startswith('0x')]
        normalized = {candidate.lower() for candidate in candidates}
        if len(normalized) > 1:
            raise ValueError('conflicting runtime bytecode candidates')
        if candidates:
            return candidates[0]
    if isinstance(value, str) and value.startswith('0x'):
        return value
    raise ValueError('no runtime bytecode found; expected Sourcify runtimeBytecode.onchainBytecode or 0x hex')


def extract_bytecode(value, *, bytecode_kind='auto'):
    """Extract typed runtime/creation bytecode without silently switching kinds."""
    if bytecode_kind not in ('auto', 'runtime', 'creation'):
        raise ValueError('bytecode_kind must be auto, runtime, or creation')
    if isinstance(value, str):
        return value, 'runtime' if bytecode_kind == 'auto' else bytecode_kind
    if not isinstance(value, dict):
        raise ValueError('bytecode input must be an object or 0x hex string')
    runtime = value.get('runtimeBytecode')
    creation = value.get('creationBytecode')
    runtime_values = [runtime.get('onchainBytecode') if isinstance(runtime, dict) else runtime, value.get('runtimeCode')]
    creation_values = [creation.get('onchainBytecode') if isinstance(creation, dict) else creation, value.get('creationCode')]
    runtime_values = [x for x in runtime_values if isinstance(x, str) and x.startswith('0x')]
    creation_values = [x for x in creation_values if isinstance(x, str) and x.startswith('0x')]
    def choose(values, label):
        if len({x.lower() for x in values}) > 1: raise ValueError(f'conflicting {label} bytecode candidates')
        return values[0] if values else None
    runtime_value, creation_value = choose(runtime_values, 'runtime'), choose(creation_values, 'creation')
    if bytecode_kind == 'runtime' and runtime_value is not None: return runtime_value, 'runtime'
    if bytecode_kind == 'creation' and creation_value is not None: return creation_value, 'creation'
    if bytecode_kind == 'auto':
        if runtime_value is not None: return runtime_value, 'runtime'
        if creation_value is not None: return creation_value, 'creation'
    raise ValueError(f'no {bytecode_kind} bytecode found')


def extract_input_anchors(value):
    """Preserve chain/block provenance when a prior report is re-analyzed."""
    if not isinstance(value, dict):
        return {}
    anchors = {}
    for output, keys in {
        'chain_id': ('chainId', 'chain_id'),
        'address': ('address',),
        'block': ('block', 'blockNumber', 'block_number'),
        'block_hash': ('blockHash', 'block_hash'),
        'hardfork': ('hardfork', 'evmHardfork', 'evm_hardfork'),
    }.items():
        for key in keys:
            if value.get(key) is not None:
                anchors[output] = value[key]
                break
    return anchors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='Sourcify verified-source.json or a text file containing 0x runtime bytecode')
    parser.add_argument('--output', help='write JSON report to this path; stdout when omitted')
    parser.add_argument('--chain-id', type=int)
    parser.add_argument('--address')
    parser.add_argument('--block')
    parser.add_argument('--block-hash')
    parser.add_argument('--evm-hardfork', help='fork used for opcode activation semantics; unknown means unverified')
    parser.add_argument('--bytecode-kind', choices=('auto', 'runtime', 'creation'), default='auto',
                        help='select runtime or creation bytecode; auto prefers runtime')
    parser.add_argument('--decompiler', choices=('heimdall',),
                        help='run a local heuristic decompiler after deterministic disassembly')
    parser.add_argument('--decompiler-binary', type=Path,
                        default=ROOT / 'work/tools/heimdall/heimdall')
    parser.add_argument('--decompiler-output-dir', type=Path,
                        help='new directory for raw decompiler outputs and logs')
    parser.add_argument('--decompiler-timeout', type=float, default=120)
    parser.add_argument('--decompiler-hardfork', default='latest')
    parser.add_argument('--ir-output', type=Path,
                        help='write the stable unified IR document to this new file')
    args = parser.parse_args(argv)
    if args.decompiler and not args.decompiler_output_dir:
        parser.error('--decompiler-output-dir is required with --decompiler')
    if args.decompiler_output_dir and not args.decompiler:
        parser.error('--decompiler-output-dir requires --decompiler')
    if args.ir_output and os.path.lexists(args.ir_output):
        parser.error('--ir-output must not already exist')
    if args.output and os.path.lexists(args.output):
        parser.error('--output must not already exist')
    input_path = Path(args.input)
    try:
        if input_path.stat().st_size > MAX_INPUT_BYTES:
            parser.error(f'input exceeds {MAX_INPUT_BYTES} byte limit')
        raw = input_path.read_text()
    except OSError as error:
        parser.error(str(error))
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = raw.strip()
    anchors = extract_input_anchors(parsed)
    selected_bytecode, selected_kind = extract_bytecode(parsed, bytecode_kind=args.bytecode_kind)
    analysis_anchors = {
        'chain_id': args.chain_id if args.chain_id is not None else anchors.get('chain_id'),
        'address': args.address if args.address is not None else anchors.get('address'),
        'block': args.block if args.block is not None else anchors.get('block'),
        'block_hash': args.block_hash if args.block_hash is not None else anchors.get('block_hash'),
        'hardfork': args.evm_hardfork if args.evm_hardfork is not None else anchors.get('hardfork'),
    }
    source_digest = hashlib.sha256(selected_bytecode.encode('ascii')).hexdigest()
    compiler_version = 'unknown'
    if isinstance(parsed, dict):
        version_value = (parsed.get('compilation') or {}).get('compilerVersion')
        if isinstance(version_value, str) and version_value:
            compiler_version = version_value.split('+')[0]
    key = repr_cache_key(source_digest, compiler_version,
                         {'bytecodeKind': selected_kind, 'anchors': analysis_anchors})
    built_report = {}

    def build_bytecode_ir():
        report_value = analyze_bytecode(selected_bytecode, bytecode_kind=selected_kind, **analysis_anchors)
        built_report['report'] = report_value
        return {'bytecode-ir.json': {'state': 'completed', 'report': report_value}}

    cached = repr_get_or_build(
        key, build_bytecode_ir,
        inputs={'sourceBundleSha256': source_digest, 'solcVersion': compiler_version,
                'compileSettingsCanonicalJson': {'bytecodeKind': selected_kind, 'anchors': analysis_anchors}},
        tool_versions={'bytecodeAnalysisSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        required_artifacts=('bytecode-ir.json',))
    if cached['cacheHit']:
        cache_payload = json.loads(cached['artifacts']['bytecode-ir.json'].decode('utf-8'))
        report = cache_payload['report']
    else:
        report = built_report['report']
    report['reprCache'] = {'key': key, 'cacheHit': cached['cacheHit'],
                           'meta': str((ROOT / 'work' / 'repr-cache' / key / 'meta.json').relative_to(ROOT))}
    decompiler_state = None
    if args.decompiler == 'heimdall' and selected_kind != 'runtime':
        report['decompilation'] = {'state': 'not_performed', 'reason': 'decompiler requires deployed runtime bytecode', 'highLevelSemanticsRecovered': False}
        decompiler_state = report['decompilation']['state']
    elif args.decompiler == 'heimdall':
        report['decompilation'] = run_heimdall(
            report['runtimeBytecode'], binary=args.decompiler_binary,
            output_dir=args.decompiler_output_dir,
            timeout_seconds=args.decompiler_timeout,
            hardfork=args.decompiler_hardfork,
        )
        # Bind the decompiler artifact record to the same independent
        # byte-level check used by the primary report.  A mismatch is
        # surfaced as evidence; it never becomes a semantic conclusion.
        attach_opcode_cross_validation(report['decompilation'], report)
        decompiler_state = report['decompilation']['state']
    if args.ir_output:
        ir_document = from_bytecode_report(report)
        args.ir_output.parent.mkdir(parents=True, exist_ok=True)
        with args.ir_output.open('x', encoding='utf-8') as output:
            output.write(json.dumps(ir_document, ensure_ascii=False, indent=2) + '\n')
        report['unifiedIR'] = {
            'state': ir_document['state'], 'documentId': ir_document['documentId'],
            'report': str(args.ir_output), 'functionCount': len(ir_document['functions']),
            'operationCount': len(ir_document['operations']), 'linkCount': len(ir_document['links']),
            'semanticsProven': False,
        }
    text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        with Path(args.output).open('x', encoding='utf-8') as output:
            output.write(text)
    else:
        sys.stdout.write(text)
    return 0 if decompiler_state in (None, 'completed') else 1


if __name__ == '__main__':
    sys.exit(main())
