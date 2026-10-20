"""Stable, evidence-preserving IR adapters for bytecode and Slither reports.

The IR deliberately represents candidates and observations. It never upgrades
static paths or decompiler output into proven reachability or source semantics.
"""
import hashlib
import json
import re
from bisect import bisect_right
from pathlib import Path


SCHEMA_VERSION = 1


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


def entity_id(kind, key):
    if not isinstance(kind, str) or not kind:
        raise ValueError('entity kind must be a non-empty string')
    return hashlib.sha256(_canonical({'kind': kind, 'key': key}).encode('utf-8')).hexdigest()[:24]


def effect_site_id(source_sha256, file_name, start, length, kind):
    """Identify an exact source-mapped effect span across static and EVM evidence."""
    if (not isinstance(source_sha256, str) or len(source_sha256) != 64 or
            any(char not in '0123456789abcdef' for char in source_sha256) or
            not isinstance(file_name, str) or not file_name or
            type(start) is not int or start < 0 or
            type(length) is not int or length < 1 or
            kind not in ('state_write', 'external_call', 'contract_creation', 'selfdestruct')):
        raise ValueError('effect site requires a source hash, file, byte span, and supported kind')
    key = '\0'.join((source_sha256, file_name, str(start), str(length), kind))
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def _require_dict(report, label):
    if not isinstance(report, dict):
        raise ValueError(f'{label} must be an object')


def _source_ref(kind, *, file=None, pc=None, lines=None, bytecode_sha256=None):
    result = {'kind': kind}
    if file is not None:
        if not isinstance(file, str) or not file:
            raise ValueError('source file must be a non-empty string')
        result['file'] = file
    if pc is not None:
        if not isinstance(pc, int) or isinstance(pc, bool) or pc < 0:
            raise ValueError('source pc must be a non-negative integer')
        result['pc'] = pc
    if lines is not None:
        if not isinstance(lines, list) or not all(isinstance(line, int) and line > 0 for line in lines):
            raise ValueError('source lines must be positive integers')
        result['lines'] = list(lines)
    if bytecode_sha256 is not None:
        result['bytecodeSha256'] = bytecode_sha256
    return result


def _bytecode_classification(value):
    """Validate and copy the conservative runtime shape classification."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError('bytecodeClassification must be an object')
    required = ('kind', 'confidence', 'codeCompleteness', 'proxyCandidate')
    if any(not isinstance(value.get(key), str) or not value[key] for key in required[:3]):
        raise ValueError('bytecodeClassification requires non-empty kind, confidence, and codeCompleteness')
    if type(value.get('proxyCandidate')) is not bool:
        raise ValueError('bytecodeClassification proxyCandidate must be boolean')
    implementation = value.get('implementationAddress')
    if implementation is not None:
        if (not isinstance(implementation, str) or
                not re.fullmatch(r'0x[0-9a-fA-F]{40}', implementation)):
            raise ValueError('bytecodeClassification implementationAddress must be a 20-byte hex address')
    evidence = value.get('evidence', [])
    limitations = value.get('limitations', [])
    if not isinstance(evidence, list) or not all(isinstance(item, dict) for item in evidence):
        raise ValueError('bytecodeClassification evidence must be a list of objects')
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        raise ValueError('bytecodeClassification limitations must be a list of strings')
    # Canonical JSON gives the IR its own immutable-by-convention snapshot and
    # rejects non-JSON values before they can affect document identity.
    return json.loads(_canonical(value))


def _evidence(kind, key, *, source, confidence='heuristic', **fields):
    value = {'id': entity_id('evidence', key), 'kind': kind, 'source': source,
             'confidence': confidence}
    value.update(fields)
    return value


def _contract(entity_key, name, source, confidence, **fields):
    value = {'id': entity_id('contract', entity_key), 'kind': 'contract',
             'name': name, 'source': source, 'confidence': confidence}
    value.update(fields)
    return value


def _sort_unique(items):
    unique = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
            raise ValueError('IR entities require a non-empty string id')
        # Identical repeats are harmless; conflicting content would make the
        # merged document depend on input order, so reject it.
        current = unique.get(item['id'])
        if current is not None and _canonical(item) != _canonical(current):
            raise ValueError(f'conflicting IR entities share id {item["id"]}')
        if current is None:
            unique[item['id']] = item
    return [unique[key] for key in sorted(unique)]


def _semantic_entities(items, *, kind, contract_id, evidence_id, source='analysis'):
    """Copy explicitly reported semantic dimensions without inventing meaning."""
    if items is None:
        return []
    if not isinstance(items, list):
        raise ValueError(f'{kind} must be a list')
    entities = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f'{kind} contain malformed entries')
        copied = json.loads(_canonical(item))
        copied.pop('id', None)
        copied.pop('kind', None)
        copied.pop('contractId', None)
        copied.pop('evidenceIds', None)
        entity = {
            'id': entity_id(kind, {'contractId': contract_id, 'index': index, 'value': copied}),
            'kind': kind,
            'contractId': contract_id,
            'source': source,
            'confidence': copied.pop('confidence', 'heuristic'),
            'semanticsProven': copied.pop('semanticsProven', False),
            'evidenceIds': [evidence_id],
        }
        entity.update(copied)
        entities.append(entity)
    return entities


def _bytecode_literal_entities(items, *, kind, contract_id, evidence_id,
                                instruction_id_for_pc, secondary_pc_field,
                                secondary_id_field):
    """Promote bounded literal candidates while retaining their instruction anchors.

    These rows are observations only.  The source candidate and its nearby
    LOG/REVERT instruction are identity links; neither link proves stack
    order, ABI meaning, reachability, or a security property.
    """
    if items is None:
        return []
    if not isinstance(items, list):
        raise ValueError(f'{kind}s must be a list')
    entities = []
    for candidate in items:
        if not isinstance(candidate, dict):
            raise ValueError(f'{kind}s contain malformed entries')
        source_pc = candidate.get('pc')
        secondary_pc = candidate.get(secondary_pc_field)
        if (type(source_pc) is not int or source_pc < 0 or
                type(secondary_pc) is not int or secondary_pc < 0):
            raise ValueError(f'{kind}s require non-negative integer pc anchors')
        source_instruction_id = instruction_id_for_pc(source_pc)
        secondary_instruction_id = instruction_id_for_pc(secondary_pc)
        copied = json.loads(_canonical(candidate))
        # Producer-controlled identity and semantic fields are not trusted.
        # Reinsert the canonical references and the conservative semantic flag
        # below so a report cannot claim a proven event or error.
        reported_confidence = copied.pop('confidence', 'heuristic')
        if not isinstance(reported_confidence, str) or not reported_confidence:
            raise ValueError(f'{kind}s confidence must be a non-empty string')
        for field in ('id', 'kind', 'contractId', 'source', 'evidenceIds',
                      'semanticsProven', 'instructionId', secondary_id_field):
            copied.pop(field, None)
        entity_key = {'contractId': contract_id, 'candidate': copied,
                      'confidence': reported_confidence}
        entity = {
            'id': entity_id(kind, entity_key), 'kind': kind,
            'contractId': contract_id, 'source': 'bytecode',
            'confidence': reported_confidence, 'semanticsProven': False,
            'evidenceIds': [evidence_id], 'instructionId': source_instruction_id,
            secondary_id_field: secondary_instruction_id,
        }
        entity.update(copied)
        entity['semanticsProven'] = False
        entity['evidenceIds'] = [evidence_id]
        entity['instructionId'] = source_instruction_id
        entity[secondary_id_field] = secondary_instruction_id
        entities.append(entity)
    return entities


SEMANTIC_DIMENSIONS = (
    'parameters', 'memoryAccesses', 'storageAccesses', 'assetFlows', 'stateTransitions',
    'roles', 'permissions', 'events', 'errors',
)


def _dimension_state(items):
    return 'available' if items else 'not_recorded'


def _document(*, state, contract, functions, basic_blocks, instructions,
              operations, links, evidence, limitations, source_documents=None,
              contracts=None, parameters=None, memory_accesses=None,
              storage_accesses=None, asset_flows=None, state_transitions=None,
              roles=None, permissions=None, control_flow_edges=None,
              events=None, errors=None):
    categories = {
        'contract': contract,
        'functions': _sort_unique(functions),
        'basicBlocks': _sort_unique(basic_blocks),
        'instructions': _sort_unique(instructions),
        'operations': _sort_unique(operations),
        'links': _sort_unique(links),
        'controlFlowEdges': _sort_unique(control_flow_edges or []),
        'evidence': _sort_unique(evidence),
        'parameters': _sort_unique(parameters or []),
        'memoryAccesses': _sort_unique(memory_accesses or []),
        'storageAccesses': _sort_unique(storage_accesses or []),
        'assetFlows': _sort_unique(asset_flows or []),
        'stateTransitions': _sort_unique(state_transitions or []),
        'roles': _sort_unique(roles or []),
        'permissions': _sort_unique(permissions or []),
        'events': _sort_unique(events or []),
        'errors': _sort_unique(errors or []),
    }
    field_states = {dimension: _dimension_state(categories[key]) for dimension, key in (
        ('parameters', 'parameters'), ('memoryAccesses', 'memoryAccesses'),
        ('storageAccesses', 'storageAccesses'), ('assetFlows', 'assetFlows'),
        ('stateTransitions', 'stateTransitions'),
        ('roles', 'roles'), ('permissions', 'permissions'),
        ('events', 'events'), ('errors', 'errors'),
    )}
    document_key = {key: value for key, value in categories.items() if key != 'evidence'}
    document_key['evidenceIds'] = [item['id'] for item in categories['evidence']]
    document_key['fieldStates'] = field_states
    if contracts is not None:
        document_key['contracts'] = _sort_unique(contracts)
    result = {
        'schemaVersion': SCHEMA_VERSION,
        'state': state,
        'documentId': hashlib.sha256(_canonical(document_key).encode('utf-8')).hexdigest()[:24],
        'contract': contract,
        'functions': categories['functions'],
        'basicBlocks': categories['basicBlocks'],
        'instructions': categories['instructions'],
        'operations': categories['operations'],
        'links': categories['links'],
        'controlFlowEdges': categories['controlFlowEdges'],
        'evidence': categories['evidence'],
        'parameters': categories['parameters'],
        'memoryAccesses': categories['memoryAccesses'],
        'storageAccesses': categories['storageAccesses'],
        'assetFlows': categories['assetFlows'],
        'stateTransitions': categories['stateTransitions'],
        'roles': categories['roles'],
        'permissions': categories['permissions'],
        'events': categories['events'],
        'errors': categories['errors'],
        'fieldStates': field_states,
        'sourceDocuments': sorted(set(source_documents or [])),
        'limitations': sorted(set(str(item) for item in limitations)),
    }
    if contracts is not None:
        result['contracts'] = _sort_unique(contracts)
    return result


def from_bytecode_report(report):
    _require_dict(report, 'bytecode report')
    digest = report.get('bytecodeSha256')
    if not isinstance(digest, str) or len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest):
        raise ValueError('bytecode report requires bytecodeSha256 to be 64 lowercase hexadecimal characters')
    instructions_input = report.get('instructions')
    if not isinstance(instructions_input, list):
        raise ValueError('bytecode report requires instructions list')
    runtime_bytecode = report.get('runtimeBytecode')
    runtime_raw = None
    if runtime_bytecode is not None:
        if (not isinstance(runtime_bytecode, str) or
                not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', runtime_bytecode)):
            raise ValueError('runtimeBytecode must be non-empty, even-length 0x hex')
        runtime_raw = bytes.fromhex(runtime_bytecode[2:])
        if hashlib.sha256(runtime_raw).hexdigest() != digest:
            raise ValueError('runtimeBytecode does not match bytecodeSha256')
    contract_key = {'bytecodeSha256': digest, 'chainId': report.get('chainId'),
                    'address': report.get('address')}
    classification = _bytecode_classification(report.get('bytecodeClassification'))
    name = report.get('contractName')
    if not isinstance(name, str) or not name:
        name = f'contract_{digest[:12]}'
    contract = _contract(contract_key, name, 'bytecode', 'heuristic',
                         chainId=report.get('chainId'), address=report.get('address'))
    if classification is not None:
        contract['bytecodeClassification'] = classification
    contract_id = contract['id']
    evidence = _evidence(
        'bytecode_report', {'bytecodeSha256': digest, 'chainId': report.get('chainId'),
                            'address': report.get('address'),
                            'bytecodeClassification': classification}, source='bytecode',
        confidence='observed', bytecodeSha256=digest, block=report.get('block'),
        blockHash=report.get('blockHash'),
    )
    if classification is not None:
        evidence['bytecodeClassification'] = classification
    evidence_id = evidence['id']
    starts = report.get('basicBlockStartHints', [])
    if not isinstance(starts, list) or not all(type(pc) is int and pc >= 0 for pc in starts):
        raise ValueError('basicBlockStartHints must contain non-negative integers')
    # Every derived bytecode observation must point at one decoded instruction.
    # Keeping only a repeated pc/opcode pair allows a malformed producer to
    # create evidence that cannot be navigated back to the retained bytes.
    instruction_by_pc = {}
    instruction_by_key = {}
    for item in instructions_input:
        if not isinstance(item, dict) or not isinstance(item.get('pc'), int) or isinstance(item.get('pc'), bool) or item.get('pc') < 0:
            raise ValueError('instructions contain a non-negative integer pc')
        opcode = item.get('opcode')
        if not isinstance(opcode, str) or not opcode:
            raise ValueError('instructions contain a non-empty opcode')
        pc = item['pc']
        if runtime_raw is not None and pc >= len(runtime_raw):
            raise ValueError('instruction pc is outside runtimeBytecode')
        if pc in instruction_by_pc:
            raise ValueError(f'instructions contain duplicate pc {pc}')
        instruction_by_pc[pc] = item
        instruction_by_key[(pc, opcode)] = item

    block_starts = sorted(set(starts))
    if any(pc not in instruction_by_pc for pc in block_starts):
        raise ValueError('basicBlockStartHints must reference decoded instruction offsets')
    blocks = []
    for pc in block_starts:
        blocks.append({'id': entity_id('basic_block', {'contractId': contract_id, 'pc': pc}),
                       'kind': 'basic_block', 'pc': pc, 'synthetic': True,
                       'sourceRef': _source_ref('bytecode', pc=pc, bytecode_sha256=digest),
                       'confidence': 'heuristic'})
    block_by_pc = {item['pc']: item['id'] for item in blocks}

    def instruction_id(pc, opcode):
        instruction = instruction_by_key.get((pc, opcode))
        if instruction is None:
            raise ValueError(f'bytecode observation does not match an instruction at pc {pc}')
        return entity_id('instruction', {'contractId': contract_id, 'pc': pc, 'opcode': opcode})

    def instruction_id_for_pc(pc):
        instruction = instruction_by_pc.get(pc)
        if instruction is None:
            raise ValueError(f'candidate does not match an instruction at pc {pc}')
        return instruction_id(pc, instruction['opcode'])

    functions = []
    for candidate in report.get('selectorCandidates', []):
        if (not isinstance(candidate, dict) or not isinstance(candidate.get('selector'), str) or
                not isinstance(candidate.get('pc'), int) or isinstance(candidate.get('pc'), bool) or candidate.get('pc') < 0):
            raise ValueError('selectorCandidates contain malformed entries')
        selector = candidate['selector'].lower()
        selector_instruction_id = instruction_id(candidate['pc'], instruction_by_pc[candidate['pc']]['opcode']) if candidate['pc'] in instruction_by_pc else None
        if selector_instruction_id is None:
            raise ValueError(f'selector candidate does not match an instruction at pc {candidate["pc"]}')
        functions.append({
            'id': entity_id('function', {'contractId': contract_id, 'selector': selector,
                                         'pc': candidate['pc']}),
            'kind': 'function', 'contractId': contract_id, 'selector': selector,
            'name': f'selector_{selector[2:]}' if selector.startswith('0x') else f'selector_{selector}',
            'source': 'bytecode', 'confidence': 'heuristic', 'semanticsProven': False,
            'sourceRef': _source_ref('bytecode', pc=candidate['pc'], bytecode_sha256=digest),
            'instructionId': selector_instruction_id,
            'evidenceIds': [evidence_id],
        })
    events = _bytecode_literal_entities(
        report.get('eventTopicCandidates', []), kind='event',
        contract_id=contract_id, evidence_id=evidence_id,
        instruction_id_for_pc=instruction_id_for_pc,
        secondary_pc_field='logPc', secondary_id_field='logInstructionId',
    )
    errors = _bytecode_literal_entities(
        report.get('errorSelectorCandidates', []), kind='error',
        contract_id=contract_id, evidence_id=evidence_id,
        instruction_id_for_pc=instruction_id_for_pc,
        secondary_pc_field='revertPc', secondary_id_field='revertInstructionId',
    )
    instruction_entities = []
    links = []
    for item in instructions_input:
        if not isinstance(item, dict) or not isinstance(item.get('pc'), int) or not isinstance(item.get('opcode'), str):
            raise ValueError('instructions contain malformed entries')
        pc = item['pc']
        current_instruction_id = instruction_id(pc, item['opcode'])
        instruction_entities.append({
            'id': current_instruction_id, 'kind': 'instruction', 'contractId': contract_id,
            'pc': pc, 'opcode': item['opcode'], 'immediate': item.get('immediate'),
            'sourceRef': _source_ref('bytecode', pc=pc, bytecode_sha256=digest),
            'confidence': 'observed', 'evidenceIds': [evidence_id],
        })
        block_index = bisect_right(block_starts, pc) - 1
        if block_index >= 0:
            prior = block_starts[block_index]
            links.append({'id': entity_id('link', {'kind': 'block_contains', 'block': block_by_pc[prior], 'instruction': current_instruction_id}),
                          'kind': 'block_contains', 'from': block_by_pc[prior], 'to': current_instruction_id,
                          'confidence': 'heuristic', 'semanticsProven': False,
                          'evidenceIds': [evidence_id]})

    # Preserve conservative CFG hints as first-class observations. Known
    # endpoints are bound to decoded instructions; dynamic targets remain
    # explicit (toPc=None) without inventing a destination or reachability.
    control_flow_edges = []
    for edge in report.get('controlFlowEdges', []):
        if not isinstance(edge, dict):
            raise ValueError('controlFlowEdges contain malformed entries')
        from_pc = edge.get('fromPc')
        to_pc = edge.get('toPc')
        kind = edge.get('kind')
        if (type(from_pc) is not int or from_pc < 0 or from_pc not in instruction_by_pc or
                (to_pc is not None and (type(to_pc) is not int or to_pc < 0 or to_pc not in instruction_by_pc))):
            raise ValueError('controlFlowEdges contain endpoints outside decoded instructions')
        if not isinstance(kind, str) or not kind:
            raise ValueError('controlFlowEdges require a non-empty kind')
        normalized = {
            'fromPc': from_pc, 'toPc': to_pc, 'kind': kind,
            'fromInstructionId': instruction_id(from_pc, instruction_by_pc[from_pc]['opcode']),
            'confidence': edge.get('confidence', 'heuristic'),
            'semanticsProven': False, 'evidenceIds': [evidence_id],
        }
        if not isinstance(normalized['confidence'], str) or not normalized['confidence']:
            raise ValueError('controlFlowEdges confidence must be a non-empty string')
        if to_pc is not None:
            normalized['toInstructionId'] = instruction_id(to_pc, instruction_by_pc[to_pc]['opcode'])
        for field in ('targetPc', 'targetKind', 'unknownReason', 'targetPcIsJumpdest', 'targetSourcePc'):
            if field in edge:
                value = edge[field]
                if field == 'targetPc' and value is not None and (type(value) is not int or value < 0):
                    raise ValueError('controlFlowEdges targetPc must be a non-negative integer or null')
                if field == 'targetPcIsJumpdest' and type(value) is not bool:
                    raise ValueError('controlFlowEdges targetPcIsJumpdest must be boolean')
                if field == 'targetSourcePc' and (type(value) is not int or value < 0):
                    raise ValueError('controlFlowEdges targetSourcePc must be a non-negative integer')
                if field in ('targetKind', 'unknownReason') and (not isinstance(value, str) or not value):
                    raise ValueError(f'controlFlowEdges {field} must be a non-empty string')
                normalized[field] = value
        edge_id = entity_id('control_flow_edge', {
            key: value for key, value in normalized.items()
            if key not in ('evidenceIds', 'semanticsProven')
        })
        normalized.update({'id': edge_id, 'kind': 'control_flow_edge',
                           'edgeKind': kind, 'contractId': contract_id})
        control_flow_edges.append(normalized)
        if to_pc is not None:
            links.append({'id': entity_id('link', {
                              'kind': 'control_flow_edge',
                              'from': normalized['fromInstructionId'],
                              'to': normalized['toInstructionId'],
                              'edge': edge_id}),
                          'kind': 'control_flow_edge',
                          'from': normalized['fromInstructionId'],
                          'to': normalized['toInstructionId'],
                          'controlFlowEdgeId': edge_id,
                          'confidence': normalized['confidence'],
                          'semanticsProven': False, 'evidenceIds': [evidence_id]})
    parameters = _semantic_entities(report.get('parameters', []), kind='parameter',
                                    contract_id=contract_id, evidence_id=evidence_id)
    memory_accesses = _semantic_entities(
        report.get('memoryAccesses', report.get('memoryOperationSites', [])),
        kind='memory_access', contract_id=contract_id, evidence_id=evidence_id,
    )
    storage_accesses = _semantic_entities(
        report.get('storageAccesses', report.get('storageOperationSites', [])),
        kind='storage_access', contract_id=contract_id, evidence_id=evidence_id,
    )
    asset_flows = _semantic_entities(report.get('assetFlows', []), kind='asset_flow',
                                     contract_id=contract_id, evidence_id=evidence_id)
    state_transitions = _semantic_entities(
        report.get('stateTransitions', []), kind='state_transition',
        contract_id=contract_id, evidence_id=evidence_id,
    )
    roles = _semantic_entities(report.get('roles', []), kind='role',
                               contract_id=contract_id, evidence_id=evidence_id)
    for role in roles:
        role['sourceRef'] = _location_ref(role.pop('location', None))
    permissions = _semantic_entities(report.get('permissions', []), kind='permission',
                                     contract_id=contract_id, evidence_id=evidence_id)
    # Bind bytecode-backed memory/storage observations to the retained
    # instruction where the producer supplied a program counter. This is an
    # identity link only; it does not prove stack semantics or reachability.
    instruction_ids_by_key = {
        (item['pc'], item['opcode']): instruction_id(item['pc'], item['opcode'])
        for item in instructions_input
    }
    for collection in (memory_accesses, storage_accesses):
        for item in collection:
            pc, opcode = item.get('pc'), item.get('opcode')
            if isinstance(pc, int) and isinstance(opcode, str):
                instruction_ref = instruction_ids_by_key.get((pc, opcode))
                if instruction_ref is not None:
                    item['instructionId'] = instruction_ref

    operations = []
    for category, operation_kind in (('externalCallSites', 'external_call'), ('storageOperationSites', 'storage_access')):
        for item in report.get(category, []):
            if not isinstance(item, dict) or not isinstance(item.get('pc'), int) or not isinstance(item.get('opcode'), str):
                raise ValueError(f'{category} contain malformed entries')
            pc = item['pc']
            if isinstance(pc, bool) or pc < 0:
                raise ValueError(f'{category} contain a non-negative integer pc')
            current_instruction_id = instruction_id(pc, item['opcode'])
            operation_id = entity_id('operation', {'contractId': contract_id, 'kind': operation_kind,
                                                   'pc': pc, 'opcode': item['opcode']})
            operations.append({
                'id': operation_id,
                'kind': operation_kind, 'opcode': item['opcode'], 'pc': pc,
                'instructionId': current_instruction_id,
                'sourceRef': _source_ref('bytecode', pc=pc, bytecode_sha256=digest),
                'confidence': 'heuristic', 'semanticsProven': False,
                'evidenceIds': [evidence_id],
            })
            links.append({'id': entity_id('link', {'kind': 'operation_instruction', 'operation': operation_id,
                                                   'instruction': current_instruction_id}),
                          'kind': 'operation_instruction', 'from': operation_id, 'to': current_instruction_id,
                          'confidence': 'observed', 'semanticsProven': False,
                          'evidenceIds': [evidence_id]})
    unknown = any(item.get('opcode', '').startswith('UNKNOWN_') or item.get('truncatedPush')
                  for item in instructions_input if isinstance(item, dict))
    limitations = list(report.get('limitations') or []) + [
        'Selector candidates are literal comparisons; calldata origin and dispatch reachability are not proven.',
        'Basic blocks and control-flow edges are conservative offset observations, not a reachability proof.',
    ]
    return _document(state='partial' if unknown else 'available', contract=contract,
                     functions=functions, basic_blocks=blocks,
                     instructions=instruction_entities, operations=operations,
                     links=links, evidence=[evidence], limitations=limitations,
                     control_flow_edges=control_flow_edges,
                     parameters=parameters, memory_accesses=memory_accesses,
                     storage_accesses=storage_accesses, asset_flows=asset_flows,
                     state_transitions=state_transitions, roles=roles,
                     permissions=permissions, events=events, errors=errors)


def from_call_graph(report):
    _require_dict(report, 'call graph report')
    if not isinstance(report.get('state'), str):
        raise ValueError('call graph report requires state')
    fingerprint = report.get('analysisInputFingerprint')
    if not isinstance(fingerprint, str) or not fingerprint:
        stable_seed = {
            'entrypoints': sorted(str(item.get('function')) for item in report.get('entrypoints', []) if isinstance(item, dict)),
            'edges': sorted(_canonical(item) for item in report.get('edges', []) if isinstance(item, dict)),
            'counts': {key: report.get(key) for key in ('contractCount', 'functionCount', 'edgeCount')},
        }
        fingerprint = hashlib.sha256(_canonical(stable_seed).encode('utf-8')).hexdigest()
    contract = _contract({'analysisInputFingerprint': fingerprint},
                         str(report.get('contractName') or 'slither_analysis_target'),
                         'slither_ir', 'heuristic',
                         analysisInputFingerprint=fingerprint)
    contract_id = contract['id']
    evidence = _evidence('call_graph_report', {'fingerprint': fingerprint}, source='slither_ir',
                         confidence='observed', analysisInputFingerprint=fingerprint,
                         reportState=report['state'])
    evidence_id = evidence['id']
    entrypoint_by_name = {}
    functions = []
    blocks = []
    for entry in report.get('entrypoints', []):
        if not isinstance(entry, dict) or not isinstance(entry.get('function'), str):
            raise ValueError('entrypoints contain malformed entries')
        name = entry['function']
        function_id = entity_id('function', {'contractId': contract_id, 'name': name})
        entrypoint_by_name[name] = function_id
        functions.append({'id': function_id, 'kind': 'function', 'contractId': contract_id,
                          'name': name, 'source': 'slither_ir', 'confidence': 'heuristic',
                          'entrypoint': True, 'visibility': entry.get('visibility'),
                          'semanticsProven': False, 'sourceRef': _location_ref(entry.get('location')),
                          'evidenceIds': [evidence_id]})
        blocks.append({'id': entity_id('basic_block', {'contractId': contract_id, 'function': name}),
                       'kind': 'basic_block', 'functionId': function_id, 'synthetic': True,
                       'sourceRef': _location_ref(entry.get('location')), 'confidence': 'heuristic',
                       'evidenceIds': [evidence_id]})
    parameter_rows = []
    permission_rows = []
    for entry in report.get('entrypoints', []):
        values = entry.get('parameters', [])
        if values is None:
            values = []
        if not isinstance(values, list):
            raise ValueError('entrypoint parameters must be a list')
        for value in values:
            if not isinstance(value, dict):
                raise ValueError('entrypoint parameters contain malformed entries')
            parameter_rows.append({**value, 'function': entry['function']})
        candidates = entry.get('permissionCandidates', [])
        if candidates is None:
            candidates = []
        if not isinstance(candidates, list):
            raise ValueError('entrypoint permissionCandidates must be a list')
        for value in candidates:
            if not isinstance(value, dict):
                raise ValueError('entrypoint permissionCandidates contain malformed entries')
            permission_rows.append({**value, 'function': entry['function']})
    parameters = _semantic_entities(parameter_rows, kind='parameter', contract_id=contract_id, evidence_id=evidence_id)
    permissions = _semantic_entities(permission_rows, kind='permission', contract_id=contract_id, evidence_id=evidence_id)
    for permission in permissions:
        permission['sourceRef'] = _location_ref(permission.pop('location', None))
    operations = []
    links = []
    for edge in report.get('edges', []):
        if not isinstance(edge, dict) or not isinstance(edge.get('from'), str) or not isinstance(edge.get('to'), str):
            continue
        from_id = entrypoint_by_name.setdefault(edge['from'], entity_id('function', {'contractId': contract_id, 'name': edge['from']}))
        to_id = entrypoint_by_name.setdefault(edge['to'], entity_id('function', {'contractId': contract_id, 'name': edge['to']}))
        links.append({'id': entity_id('link', {'kind': edge.get('kind', 'call'), 'from': from_id, 'to': to_id,
                                               'location': edge.get('location')}),
                      'kind': edge.get('kind', 'call'), 'from': from_id, 'to': to_id,
                      'sourceRef': _location_ref(edge.get('location')), 'confidence': 'heuristic',
                      'semanticsProven': False, 'evidenceIds': [evidence_id]})
    for path in report.get('paths', []):
        if not isinstance(path, dict) or not isinstance(path.get('effect'), dict):
            continue
        effect = path['effect']
        entry = path.get('entrypoint')
        function_id = entrypoint_by_name.get(entry) or entity_id('function', {'contractId': contract_id, 'name': str(entry)})
        operation_key = {'contractId': contract_id, 'entrypoint': entry, 'path': path.get('path', []), 'effect': effect}
        operation_id = entity_id('operation', operation_key)
        operations.append({'id': operation_id, 'kind': effect.get('kind', 'unknown_effect'),
                           'functionId': function_id, 'effect': effect, 'path': path.get('path', []),
                           'effectSiteId': effect.get('effectSiteId'),
                           'pathFeasibility': path.get('pathFeasibility', 'not_proven'),
                           'sourceRef': _location_ref(effect.get('location')), 'confidence': 'heuristic',
                           'semanticsProven': False, 'evidenceIds': [evidence_id]})
        links.append({'id': entity_id('link', {'kind': 'function_effect', 'from': function_id, 'to': operation_id}),
                      'kind': 'function_effect', 'from': function_id, 'to': operation_id,
                      'confidence': 'heuristic', 'semanticsProven': False, 'evidenceIds': [evidence_id]})
    explicit_storage = report.get('storageAccesses')
    if explicit_storage is None:
        explicit_storage = [
            {'entrypoint': path.get('entrypoint'), 'path': path.get('path', []), 'effect': path.get('effect')}
            for path in report.get('paths', [])
            if isinstance(path, dict) and isinstance(path.get('effect'), dict) and
            path['effect'].get('kind') in ('state_read', 'state_write', 'storage_read', 'storage_write')
        ]
    storage_accesses = _semantic_entities(explicit_storage, kind='storage_access',
                                          contract_id=contract_id, evidence_id=evidence_id)
    memory_accesses = _semantic_entities(report.get('memoryAccesses', []), kind='memory_access',
                                         contract_id=contract_id, evidence_id=evidence_id)
    asset_flows = _semantic_entities(report.get('assetFlows', []), kind='asset_flow',
                                     contract_id=contract_id, evidence_id=evidence_id)
    state_transitions = _semantic_entities(report.get('stateTransitions', []), kind='state_transition',
                                           contract_id=contract_id, evidence_id=evidence_id)
    roles = _semantic_entities(report.get('roles', []), kind='role',
                               contract_id=contract_id, evidence_id=evidence_id)
    permissions = _sort_unique(permissions + _semantic_entities(report.get('permissions', []), kind='permission',
                                                                  contract_id=contract_id, evidence_id=evidence_id))
    for name, function_id in entrypoint_by_name.items():
        if not any(item['id'] == function_id for item in functions):
            functions.append({'id': function_id, 'kind': 'function', 'contractId': contract_id,
                              'name': name, 'source': 'slither_ir', 'confidence': 'heuristic',
                              'entrypoint': False, 'semanticsProven': False,
                              'sourceRef': _source_ref('slither_ir'), 'evidenceIds': [evidence_id]})
    state = 'partial' if report['state'] in ('partial', 'failed') else 'available'
    limitations = list(report.get('limitations') or []) + [
        'Static paths are structural candidates; path feasibility, authorization and runtime reachability are not proven.',
    ]
    return _document(state=state, contract=contract, functions=functions,
                     basic_blocks=blocks, instructions=[], operations=operations,
                     links=links, evidence=[evidence], limitations=limitations,
                     parameters=parameters, memory_accesses=memory_accesses,
                     storage_accesses=storage_accesses, asset_flows=asset_flows,
                     state_transitions=state_transitions, roles=roles,
                     permissions=permissions)


def _location_ref(location):
    if not isinstance(location, dict):
        return _source_ref('slither_ir')
    file_name = location.get('file')
    lines = location.get('lines')
    return _source_ref('slither_ir', file=file_name if isinstance(file_name, str) and file_name != 'unknown' else None,
                       lines=lines if isinstance(lines, list) and all(isinstance(line, int) and line > 0 for line in lines) else None)


def _validate_document(document):
    """Validate the local identity graph before it is combined with another document."""
    if document.get('schemaVersion') != SCHEMA_VERSION:
        raise ValueError('IR document schemaVersion must be 1')
    contract = document.get('contract')
    if contract is not None and (not isinstance(contract, dict) or not contract.get('id')):
        raise ValueError('IR document contract is required')
    contracts = document.get('contracts')
    if contracts is not None and (not isinstance(contracts, list) or
                                  not all(isinstance(item, dict) and item.get('id') for item in contracts)):
        raise ValueError('IR document contracts must be a list of entities')
    contract_entities = contracts if contracts is not None else ([contract] if contract is not None else [])
    if not contract_entities:
        raise ValueError('IR document contract is required')
    contract_ids = {item['id'] for item in contract_entities}
    if contract is not None and contract['id'] not in contract_ids:
        raise ValueError('IR document contract is missing from contracts')
    document_id = document.get('documentId')
    if not isinstance(document_id, str) or not document_id:
        raise ValueError('IR document documentId is required')
    source_documents = document.get('sourceDocuments', [])
    if not isinstance(source_documents, list) or not all(isinstance(item, str) and item for item in source_documents):
        raise ValueError('IR document sourceDocuments must contain non-empty strings')

    categories = ('functions', 'basicBlocks', 'instructions', 'operations', 'links', 'controlFlowEdges', 'evidence',
                  'parameters', 'memoryAccesses', 'storageAccesses', 'assetFlows',
                  'stateTransitions', 'roles', 'permissions', 'events', 'errors')
    entities = {}
    all_ids = set(contract_ids)
    for category in categories:
        values = document.get(category, [])
        if not isinstance(values, list):
            raise ValueError(f'IR document {category} must be a list')
        ids = set()
        for item in values:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id']:
                raise ValueError(f'IR document {category} contain malformed entities')
            if item['id'] in ids:
                raise ValueError(f'IR document {category} contain duplicate entity ids')
            if item['id'] in all_ids:
                raise ValueError(f'IR document entities reuse id {item["id"]}')
            ids.add(item['id'])
        entities[category] = values
        all_ids.update(ids)
    field_states = document.get('fieldStates')
    if not isinstance(field_states, dict):
        raise ValueError('IR document fieldStates must be an object')
    expected_dimensions = {
        'parameters': 'parameters', 'memoryAccesses': 'memoryAccesses',
        'storageAccesses': 'storageAccesses', 'assetFlows': 'assetFlows',
        'stateTransitions': 'stateTransitions', 'roles': 'roles',
        'permissions': 'permissions', 'events': 'events', 'errors': 'errors',
    }
    for dimension, category in expected_dimensions.items():
        state = field_states.get(dimension)
        if state not in ('available', 'not_recorded'):
            raise ValueError(f'IR document fieldStates.{dimension} is invalid')
        expected_state = 'available' if entities[category] else 'not_recorded'
        if state != expected_state:
            raise ValueError(f'IR document fieldStates.{dimension} does not match data')
    evidence_ids = {item['id'] for item in entities['evidence']}
    category_ids = {
        'functions': {item['id'] for item in entities['functions']},
        'basicBlocks': {item['id'] for item in entities['basicBlocks']},
        'instructions': {item['id'] for item in entities['instructions']},
        'operations': {item['id'] for item in entities['operations']},
        'parameters': {item['id'] for item in entities['parameters']},
        'memoryAccesses': {item['id'] for item in entities['memoryAccesses']},
        'storageAccesses': {item['id'] for item in entities['storageAccesses']},
        'assetFlows': {item['id'] for item in entities['assetFlows']},
        'stateTransitions': {item['id'] for item in entities['stateTransitions']},
        'roles': {item['id'] for item in entities['roles']},
        'permissions': {item['id'] for item in entities['permissions']},
        'events': {item['id'] for item in entities['events']},
        'errors': {item['id'] for item in entities['errors']},
        'controlFlowEdges': {item['id'] for item in entities['controlFlowEdges']},
    }
    for category in categories:
        for item in entities[category]:
            evidence_refs = item.get('evidenceIds', [])
            if not isinstance(evidence_refs, list) or not all(isinstance(ref, str) for ref in evidence_refs):
                raise ValueError(f'IR document {category} contain malformed evidenceIds')
            if any(ref not in evidence_ids for ref in evidence_refs):
                raise ValueError(f'IR document {category} contain dangling evidence reference')
            reference_sets = {
                'contractId': contract_ids,
                'functionId': category_ids['functions'],
                'blockId': category_ids['basicBlocks'],
                'basicBlockId': category_ids['basicBlocks'],
                'instructionId': category_ids['instructions'],
                'fromInstructionId': category_ids['instructions'],
                'toInstructionId': category_ids['instructions'],
                'operationId': category_ids['operations'],
                'parameterId': category_ids['parameters'],
                'memoryAccessId': category_ids['memoryAccesses'],
                'storageAccessId': category_ids['storageAccesses'],
                'assetFlowId': category_ids['assetFlows'],
                'stateTransitionId': category_ids['stateTransitions'],
                'roleId': category_ids['roles'],
                'permissionId': category_ids['permissions'],
                'eventId': category_ids['events'],
                'errorId': category_ids['errors'],
                'controlFlowEdgeId': category_ids['controlFlowEdges'],
            }
            for field in ('instructionId', 'logInstructionId', 'revertInstructionId'):
                if field in item and (not isinstance(item[field], str) or
                                      item[field] not in category_ids['instructions']):
                    raise ValueError(f'IR document {category} contain dangling {field} reference')
            if category in ('events', 'errors') and item.get('semanticsProven') is not False:
                raise ValueError(f'IR document {category} semanticsProven must remain false')
            for field, valid_ids in reference_sets.items():
                if field in item and (not isinstance(item[field], str) or item[field] not in valid_ids):
                    raise ValueError(f'IR document {category} contain dangling {field} reference')
            if category == 'links':
                for field in ('from', 'to'):
                    if not isinstance(item.get(field), str) or item[field] not in all_ids:
                        raise ValueError('IR document links contain dangling entity reference')

    # The document id is the content address of the identity graph.  Checking
    # it here prevents a caller from relabelling mutated evidence as an older
    # document and then merging it by the stale id.
    canonical_categories = {
        'contract': contract,
        'functions': sorted(entities['functions'], key=lambda item: item['id']),
        'basicBlocks': sorted(entities['basicBlocks'], key=lambda item: item['id']),
        'instructions': sorted(entities['instructions'], key=lambda item: item['id']),
        'operations': sorted(entities['operations'], key=lambda item: item['id']),
        'links': sorted(entities['links'], key=lambda item: item['id']),
        'controlFlowEdges': sorted(entities['controlFlowEdges'], key=lambda item: item['id']),
        'parameters': sorted(entities['parameters'], key=lambda item: item['id']),
        'memoryAccesses': sorted(entities['memoryAccesses'], key=lambda item: item['id']),
        'storageAccesses': sorted(entities['storageAccesses'], key=lambda item: item['id']),
        'assetFlows': sorted(entities['assetFlows'], key=lambda item: item['id']),
        'stateTransitions': sorted(entities['stateTransitions'], key=lambda item: item['id']),
        'roles': sorted(entities['roles'], key=lambda item: item['id']),
        'permissions': sorted(entities['permissions'], key=lambda item: item['id']),
        'events': sorted(entities['events'], key=lambda item: item['id']),
        'errors': sorted(entities['errors'], key=lambda item: item['id']),
    }
    document_key = dict(canonical_categories)
    document_key['evidenceIds'] = sorted(evidence_ids)
    document_key['fieldStates'] = field_states
    if contracts is not None:
        document_key['contracts'] = sorted(contracts, key=lambda item: item['id'])
    expected_document_id = hashlib.sha256(_canonical(document_key).encode('utf-8')).hexdigest()[:24]
    if document_id != expected_document_id:
        raise ValueError('IR document documentId does not match its content')


def validate_ir_document(document):
    """Public validator for callers that persist or exchange an IR document."""
    _validate_document(document)
    return True


def merge_ir_documents(*documents):
    if not documents or not all(isinstance(document, dict) for document in documents):
        raise ValueError('merge requires one or more IR documents')
    categories = ('functions', 'basicBlocks', 'instructions', 'operations', 'links', 'controlFlowEdges', 'evidence',
                  'parameters', 'memoryAccesses', 'storageAccesses', 'assetFlows',
                  'stateTransitions', 'roles', 'permissions', 'events', 'errors')
    contracts = []
    limitations = []
    states = []
    source_documents = []
    for document in documents:
        _validate_document(document)
        document_contracts = document.get('contracts')
        if document_contracts is None:
            document_contracts = [document['contract']]
        contracts.extend(document_contracts)
        states.append(document.get('state'))
        source_documents.extend(document.get('sourceDocuments') or [document.get('documentId')])
        limitations.extend(document.get('limitations') or [])
    contract_entities = _sort_unique(contracts)
    entities = {category: _sort_unique([item for document in documents for item in document.get(category, [])])
                for category in categories}
    # A multi-contract result is a collection, not one contract. Keep the
    # single-contract shape for compatibility while avoiding a false identity.
    merged_contract = contract_entities[0] if len(contract_entities) == 1 else None
    state = 'partial' if any(value in ('partial', 'failed') for value in states) else 'available'
    result = _document(state=state, contract=merged_contract,
                       functions=entities['functions'], basic_blocks=entities['basicBlocks'],
                       instructions=entities['instructions'], operations=entities['operations'],
                       links=entities['links'], evidence=entities['evidence'],
                       control_flow_edges=entities['controlFlowEdges'],
                       limitations=limitations, source_documents=source_documents,
                       contracts=contract_entities,
                       parameters=entities['parameters'],
                       memory_accesses=entities['memoryAccesses'],
                       storage_accesses=entities['storageAccesses'],
                       asset_flows=entities['assetFlows'],
                       state_transitions=entities['stateTransitions'],
                       roles=entities['roles'], permissions=entities['permissions'],
                       events=entities['events'], errors=entities['errors'])
    return result
