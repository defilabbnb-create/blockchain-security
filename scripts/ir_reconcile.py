"""Compare source-derived and deployed-bytecode unified IR conservatively."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'flare-scan' / 'tools' / 'pylibs'))

try:
    from eth_hash.auto import keccak
except ImportError:
    keccak = None


SELECTOR = re.compile(r'^0x[0-9a-fA-F]{8}$')
SLOT = re.compile(r'^(?:0x)?[0-9a-fA-F]{1,64}$')
EIP1967_SLOT_KINDS = {
    'implementation': '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
    'beacon': 'a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',
    'admin': 'b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
}


def _canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _source_signature(function):
    name = function.get('name')
    if not isinstance(name, str):
        return None
    match = re.search(r'([A-Za-z_$][A-Za-z0-9_$]*\([^()]*\))$', name)
    return match.group(1) if match else None


def _source_selectors(document):
    selectors = {}
    unresolved = []
    functions = document.get('functions')
    if not isinstance(functions, list):
        return selectors, ['source IR has no functions array']
    for function in functions:
        if not isinstance(function, dict):
            continue
        if function.get('entrypoint') is False:
            continue
        signature = _source_signature(function)
        if signature is None:
            unresolved.append({'kind': 'function_signature', 'function': function.get('name')})
            continue
        if keccak is None:
            unresolved.append({'kind': 'keccak_unavailable', 'signature': signature})
            continue
        selector = '0x' + keccak(signature.encode('utf-8'))[:4].hex()
        ref = function.get('sourceRef') if isinstance(function.get('sourceRef'), dict) else {}
        selectors.setdefault(selector, {'selector': selector, 'name': signature,
                                        'sourceRef': {key: ref[key] for key in ('file', 'lines') if key in ref}})
    return selectors, unresolved


def _bytecode_selectors(document):
    result = {}
    for function in document.get('functions', []):
        if not isinstance(function, dict):
            continue
        selector = function.get('selector')
        if isinstance(selector, str) and SELECTOR.fullmatch(selector):
            normalized = selector.lower()
            result.setdefault(normalized, {'selector': normalized, 'name': function.get('name', normalized),
                                           'sourceRef': function.get('sourceRef', {})})
    return result


def _unresolved_object(items):
    if not items:
        return {'reason': ''}
    reasons = [item.get('reason') for item in items if isinstance(item, dict) and isinstance(item.get('reason'), str) and item.get('reason')]
    return {'reason': '; '.join(dict.fromkeys(reasons)) or 'reconciliation evidence is incomplete',
            'details': items}


def _slot_values(items):
    values = set()
    if not isinstance(items, list):
        return values
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get('storageSlot')
        if value is None and isinstance(item.get('effect'), dict):
            value = item['effect'].get('storageSlot')
        if isinstance(value, str) and SLOT.fullmatch(value):
            values.add(value.lower().removeprefix('0x').rjust(64, '0'))
    return values


def _pc(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _range_from(value):
    if not isinstance(value, dict):
        return None
    start = _pc(value.get('startPc', value.get('startPC', value.get('pcStart', value.get('entryPc')))))
    end = _pc(value.get('endPc', value.get('endPC', value.get('pcEnd'))))
    if end is None and start is not None and isinstance(value.get('size'), int):
        end = start + max(0, value['size'] - 1)
    if start is None or end is None or end < start:
        return None
    return start, end


def _function_regions(bytecode_ir, selectors):
    """Return selector -> PC ranges from explicit dispatch/CFG evidence."""
    blocks = {}
    raw_blocks = bytecode_ir.get('basicBlocks', [])
    if isinstance(raw_blocks, list):
        for block in raw_blocks:
            if not isinstance(block, dict):
                continue
            region = _range_from(block)
            if region is None:
                continue
            for key in (block.get('id'), block.get('blockId'), block.get('basicBlockId')):
                if key is not None:
                    blocks[str(key)] = region

    dispatch = bytecode_ir.get('selectorDispatch', bytecode_ir.get('dispatchTable'))
    if isinstance(dispatch, dict):
        dispatch_rows = []
        for selector, value in dispatch.items():
            if isinstance(value, dict):
                row = dict(value)
                row.setdefault('selector', selector)
                dispatch_rows.append(row)
    elif isinstance(dispatch, list):
        dispatch_rows = [row for row in dispatch if isinstance(row, dict)]
    else:
        dispatch_rows = []
    if dispatch_rows:
        for row in dispatch_rows:
            selector = str(row.get('selector', '')).lower()
            if not SELECTOR.fullmatch(selector):
                continue
            region = _range_from(row)
            if region is None:
                block_id = row.get('basicBlockId', row.get('blockId'))
                if block_id is not None:
                    region = blocks.get(str(block_id))
            if region:
                selectors.setdefault(selector, {'selector': selector, 'name': selector})['pcRange'] = region

    regions = {}
    functions = bytecode_ir.get('functions', [])
    if not isinstance(functions, list):
        functions = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        selector = function.get('selector')
        if not isinstance(selector, str) or not SELECTOR.fullmatch(selector):
            continue
        selector = selector.lower()
        ranges = []
        direct = _range_from(function)
        if direct:
            ranges.append(direct)
        for key in ('basicBlockIds', 'basicBlocks', 'blockIds'):
            ids = function.get(key)
            if isinstance(ids, list):
                ranges.extend(blocks[str(block_id)] for block_id in ids if str(block_id) in blocks)
        for key in ('basicBlockId', 'blockId'):
            if function.get(key) is not None and str(function[key]) in blocks:
                ranges.append(blocks[str(function[key])])
        dispatch_region = selectors.get(selector, {}).get('pcRange')
        if dispatch_region:
            ranges.append(dispatch_region)
        if ranges:
            regions[selector] = sorted(set(ranges))
    return regions


def _opcode_rows(bytecode_ir):
    rows = []
    seen = set()
    for collection in (bytecode_ir.get('operations', []), bytecode_ir.get('instructions', [])):
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, dict) or not isinstance(item.get('opcode'), str):
                continue
            pc = _pc(item.get('pc'))
            key = (pc, item['opcode'])
            if key in seen:
                continue
            seen.add(key)
            rows.append({**item, 'pc': pc})
    return rows


def _risk_hints(rows):
    opcodes = {item.get('opcode') for item in rows if isinstance(item.get('opcode'), str)}
    hints = []
    delegatecall_rows = [item for item in rows if item.get('opcode') == 'DELEGATECALL']
    if delegatecall_rows:
        hints.append('DELEGATECALL')
        if any(item.get('targetKind') == 'dynamic' or item.get('target') is None for item in delegatecall_rows):
            hints.append('NONCONSTANT_DELEGATECALL_TARGET')
    if 'SELFDESTRUCT' in opcodes:
        hints.append('SELFDESTRUCT')
    if any(item.get('opcode') == 'SSTORE' and item.get('slotKind') in ('dynamic', None) for item in rows):
        hints.append('ARBITRARY_SSTORE')
    return hints


def reconcile(source_ir, bytecode_ir, *, source_sha256=None, contract=None):
    if source_ir is not None and not isinstance(source_ir, dict):
        raise ValueError('source IR must be an object or null')
    if bytecode_ir is not None and not isinstance(bytecode_ir, dict):
        raise ValueError('bytecode IR must be an object or null')
    source_hash = source_sha256 if isinstance(source_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', source_sha256) else None
    source_hash = source_hash or (_canonical_hash(source_ir) if source_ir is not None else None)
    bytecode_hash = _canonical_hash(bytecode_ir) if bytecode_ir is not None else None
    report = {
        'schemaVersion': 1,
        'contract': contract or ((bytecode_ir or {}).get('contract') or {}).get('address'),
        'sourceSha256': source_hash,
        'sourceIrSha256': _canonical_hash(source_ir) if source_ir is not None else None,
        'bytecodeIrSha256': bytecode_hash,
        'sourceFaithfulnessScore': 0.0,
        'sourceOnlyFunctions': [], 'bytecodeOnlyFunctions': [], 'divergentControlFlow': [],
        'comparisons': {}, 'unresolved': [], 'confirmedVulnerability': False,
    }
    if source_ir is None:
        report['unresolved'].append({'kind': 'source_ir', 'reason': 'source IR is missing'})
    if bytecode_ir is None:
        report['unresolved'].append({'kind': 'bytecode_ir', 'reason': 'bytecode IR is missing'})
    if source_ir is None or bytecode_ir is None:
        report['unresolved'].append({'kind': 'reconciliation', 'reason': 'both IR documents are required'})
        report['unresolved'] = _unresolved_object(report['unresolved'])
        return report

    source_selectors, signature_issues = _source_selectors(source_ir)
    bytecode_selectors = _bytecode_selectors(bytecode_ir)
    report['sourceOnlyFunctions'] = [source_selectors[key] for key in sorted(source_selectors.keys() - bytecode_selectors.keys())]
    bytecode_only = [bytecode_selectors[key] for key in sorted(bytecode_selectors.keys() - source_selectors.keys())]
    operations = bytecode_ir.get('operations', [])
    opcode_rows = _opcode_rows(bytecode_ir)
    opcodes = {item.get('opcode') for item in opcode_rows if isinstance(item.get('opcode'), str)}
    storage_rows = bytecode_ir.get('storageAccesses', [])
    dynamic_storage = any(isinstance(item, dict) and (
        item.get('slotKind') == 'dynamic' or item.get('storageSlot') in (None, 'dynamic') or
        (isinstance(item.get('effect'), dict) and item['effect'].get('storageSlot') in (None, 'dynamic'))
    ) for item in storage_rows) if isinstance(storage_rows, list) else False
    if not dynamic_storage:
        instructions = {item.get('pc'): item for item in bytecode_ir.get('instructions', []) if isinstance(item, dict)}
        for item in operations if isinstance(operations, list) else []:
            if not isinstance(item, dict) or item.get('opcode') != 'SSTORE':
                continue
            previous = instructions.get(item.get('pc') - 1)
            dynamic_storage = not (isinstance(previous, dict) and str(previous.get('opcode', '')).startswith('PUSH'))
            if dynamic_storage:
                break
    if dynamic_storage and not any('ARBITRARY_SSTORE' in _risk_hints([row]) for row in opcode_rows):
        # The storage access record can prove a dynamic slot even when the
        # opcode row itself has no slot metadata.
        for row in opcode_rows:
            if row.get('opcode') == 'SSTORE':
                row['slotKind'] = 'dynamic'
    regions = _function_regions(bytecode_ir, bytecode_selectors)
    report['granularity'] = 'function' if regions else 'contract'
    report['unattributedOpcodes'] = []
    report['functionRiskHints'] = {}
    grouped = {selector: [] for selector in regions}
    if regions:
        for row in opcode_rows:
            pc = row.get('pc')
            if pc is None:
                # Legacy operation rows without a PC cannot be assigned
                # without inventing a function boundary; retain them in the
                # contract-level comparison only.
                continue
            matches = [selector for selector, ranges in regions.items()
                       if pc is not None and any(start <= pc <= end for start, end in ranges)]
            if len(matches) == 1:
                grouped[matches[0]].append(row)
            elif len(matches) == 0:
                report['unattributedOpcodes'].append({'pc': pc, 'opcode': row.get('opcode'), 'reason': 'outside_function_ranges'})
            else:
                report['unattributedOpcodes'].append({'pc': pc, 'opcode': row.get('opcode'), 'reason': 'overlapping_function_ranges'})
        if report['unattributedOpcodes']:
            report['unresolved'].append({'kind': 'unattributed_opcodes',
                                         'reason': 'some opcodes could not be assigned to one function'})
    else:
        grouped['__contract__'] = opcode_rows
    for item in bytecode_only:
        selector = item.get('selector')
        rows = grouped.get(selector, grouped.get('__contract__', []))
        hints = _risk_hints(rows)
        if dynamic_storage and any(row.get('opcode') == 'SSTORE' for row in rows):
            if 'ARBITRARY_SSTORE' not in hints:
                hints.append('ARBITRARY_SSTORE')
        item['opcodes'] = ','.join(sorted(opcode for opcode in {row.get('opcode') for row in rows} if isinstance(opcode, str)))
        item['riskHints'] = hints
        item['granularity'] = report['granularity']
    if regions:
        for selector, rows in grouped.items():
            report['functionRiskHints'][selector] = {
                'opcodes': sorted({row.get('opcode') for row in rows if isinstance(row.get('opcode'), str)}),
                'riskHints': _risk_hints(rows),
                'granularity': 'function',
            }
    if report['granularity'] == 'contract' and any(row.get('opcode') == 'DELEGATECALL' for row in opcode_rows):
        report['unresolved'].append({'kind': 'delegatecall_target', 'reason': 'function dispatch ranges are unavailable; risk is reported at contract granularity'})
    report['bytecodeOnlyFunctions'] = bytecode_only
    report['comparisons']['functionSelectors'] = {
        'matched': sorted(source_selectors.keys() & bytecode_selectors.keys()),
        'sourceOnly': sorted(source_selectors.keys() - bytecode_selectors.keys()),
        'bytecodeOnly': sorted(bytecode_selectors.keys() - source_selectors.keys()),
    }
    if signature_issues:
        report['unresolved'].extend({'kind': 'source_function', **item} for item in signature_issues)

    source_slots = _slot_values(source_ir.get('storageAccesses'))
    bytecode_slots = _slot_values(bytecode_ir.get('storageAccesses'))
    classification = (bytecode_ir.get('contract') or {}).get('bytecodeClassification') or {}
    classification_evidence = classification.get('evidence', []) if isinstance(classification, dict) else []
    eip_kinds = sorted({kind for evidence in classification_evidence if isinstance(evidence, dict)
                        for kind in evidence.get('slotKinds', []) if isinstance(kind, str)})
    report['comparisons']['storageSlots'] = {
        'matched': sorted(source_slots & bytecode_slots),
        'sourceOnly': sorted(source_slots - bytecode_slots),
        'bytecodeOnly': sorted(bytecode_slots - source_slots),
        'eip1967SlotKinds': eip_kinds,
    }
    if not source_slots or not bytecode_slots:
        report['unresolved'].append({'kind': 'storage_slots', 'reason': 'one or both IR documents lack literal storage slot values'})
    elif source_slots != bytecode_slots:
        report['comparisons']['storageSlots']['state'] = 'divergent'

    source_targets = {item.get('target') for item in source_ir.get('operations', [])
                      if isinstance(item, dict) and isinstance(item.get('target'), str)}
    bytecode_targets = {item.get('target') for item in bytecode_ir.get('operations', [])
                        if isinstance(item, dict) and isinstance(item.get('target'), str)}
    report['comparisons']['externalCallTargets'] = {
        'matched': sorted(source_targets & bytecode_targets),
        'sourceOnly': sorted(source_targets - bytecode_targets),
        'bytecodeOnly': sorted(bytecode_targets - source_targets),
    }
    if not source_targets or not bytecode_targets:
        report['unresolved'].append({'kind': 'external_call_targets', 'reason': 'one or both IR documents lack resolved call targets'})

    source_topics = {item.get('topic', '').lower() for item in source_ir.get('events', [])
                     if isinstance(item, dict) and isinstance(item.get('topic'), str)}
    bytecode_topics = {item.get('topic', '').lower() for item in bytecode_ir.get('events', [])
                       if isinstance(item, dict) and isinstance(item.get('topic'), str)}
    report['comparisons']['eventTopics'] = {
        'matched': sorted(source_topics & bytecode_topics),
        'sourceOnly': sorted(source_topics - bytecode_topics),
        'bytecodeOnly': sorted(bytecode_topics - source_topics),
    }
    if not source_topics or not bytecode_topics:
        report['unresolved'].append({'kind': 'event_topics', 'reason': 'one or both IR documents lack event topic values'})

    source_keys, bytecode_keys = set(source_selectors), set(bytecode_selectors)
    total = len(source_keys | bytecode_keys)
    report['sourceFaithfulnessScore'] = (len(source_keys & bytecode_keys) / total) if total else 0.0
    report['unresolved'] = _unresolved_object(report['unresolved'])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_ir', type=Path)
    parser.add_argument('bytecode_ir', type=Path)
    parser.add_argument('--source-sha256')
    parser.add_argument('--contract')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        source = json.loads(args.source_ir.read_text(encoding='utf-8'))
    except FileNotFoundError:
        source = None
    try:
        bytecode = json.loads(args.bytecode_ir.read_text(encoding='utf-8'))
    except FileNotFoundError:
        bytecode = None
    result = reconcile(source, bytecode, source_sha256=args.source_sha256, contract=args.contract)
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(f'.{args.output.name}.{os.getpid()}.tmp')
        temporary.write_text(text, encoding='utf-8')
        temporary.replace(args.output)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
