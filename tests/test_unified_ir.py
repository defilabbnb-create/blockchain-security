import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('unified_ir', ROOT / 'scripts' / 'unified_ir.py')
IR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IR)


def bytecode_report():
    return {
        'schemaVersion': 1, 'bytecodeSha256': 'a' * 64, 'chainId': 19,
        'address': '0x' + '1' * 40, 'block': '0x10', 'blockHash': '0x' + '2' * 64,
        'basicBlockStartHints': [0, 3],
        'instructions': [
            {'pc': 0, 'opcode': 'PUSH1', 'immediate': '60'},
            {'pc': 2, 'opcode': 'SSTORE'},
            {'pc': 3, 'opcode': 'CALL'},
        ],
        'selectorCandidates': [{'pc': 0, 'selector': '0xa9059cbb'}],
        'eventTopicCandidates': [{'pc': 0, 'topic': '0x' + '1' * 64,
                                  'logOpcode': 'LOG1', 'logPc': 3,
                                  'heuristic': 'bounded event topic candidate'}],
        'errorSelectorCandidates': [{'pc': 0, 'selector': '0xdeadbeef',
                                     'revertPc': 3,
                                     'heuristic': 'bounded error selector candidate'}],
        'externalCallSites': [{'pc': 3, 'opcode': 'CALL'}],
        'storageOperationSites': [{'pc': 2, 'opcode': 'SSTORE'}],
        'limitations': ['opcode reachability not proven'],
    }


def call_graph_report():
    return {
        'schemaVersion': 2, 'state': 'partial', 'analysisInputFingerprint': 'b' * 64,
        'entrypoints': [{'function': 'Vault.withdraw(uint256)', 'visibility': 'external',
                         'location': {'file': 'Vault.sol', 'lines': [10]},
                         'permissionCandidates': [{'kind': 'modifier_gate_candidate',
                                                   'modifier': 'onlyRole(WITHDRAWER_ROLE)',
                                                   'location': {'file': 'Vault.sol', 'lines': [9]},
                                                   'confidence': 'heuristic',
                                                   'semanticsProven': False}]}],
        'edges': [{'from': 'Vault.withdraw(uint256)', 'to': 'Vault._settle(uint256)',
                   'kind': 'internal_call', 'location': {'file': 'Vault.sol', 'lines': [12]}}],
        'paths': [{'entrypoint': 'Vault.withdraw(uint256)',
                   'path': ['Vault.withdraw(uint256)', 'Vault._settle(uint256)'],
                   'pathFeasibility': 'not_proven',
                   'effect': {'kind': 'state_write', 'variable': 'Vault.credit',
                              'location': {'file': 'Vault.sol', 'lines': [20]}}}],
        'limitations': ['bounded path'],
    }


class UnifiedIRTests(unittest.TestCase):
    def test_effect_site_ids_bind_content_file_byte_span_and_effect_kind(self):
        base = IR.effect_site_id('a' * 64, 'Vault.sol', 12, 5, 'state_write')
        self.assertEqual(base, IR.effect_site_id('a' * 64, 'Vault.sol', 12, 5, 'state_write'))
        self.assertNotEqual(base, IR.effect_site_id('b' * 64, 'Vault.sol', 12, 5, 'state_write'))
        self.assertNotEqual(base, IR.effect_site_id('a' * 64, 'Other.sol', 12, 5, 'state_write'))
        self.assertNotEqual(base, IR.effect_site_id('a' * 64, 'Vault.sol', 13, 5, 'state_write'))
        self.assertNotEqual(base, IR.effect_site_id('a' * 64, 'Vault.sol', 12, 5, 'external_call'))
        for values in [
            ('A' * 64, 'Vault.sol', 12, 5, 'state_write'),
            ('a' * 64, 'Vault.sol', True, 5, 'state_write'),
            ('a' * 64, 'Vault.sol', 12, 0, 'state_write'),
            ('a' * 64, 'Vault.sol', 12, 5, 'unknown'),
        ]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                IR.effect_site_id(*values)

    def test_bytecode_report_has_stable_entities_and_structured_evidence(self):
        document = IR.from_bytecode_report(bytecode_report())
        self.assertEqual(document['schemaVersion'], 1)
        self.assertEqual(document['state'], 'available')
        self.assertEqual(document['contract']['source'], 'bytecode')
        self.assertEqual(len(document['functions']), 1)
        self.assertEqual(len(document['instructions']), 3)
        self.assertEqual({operation['semanticsProven'] for operation in document['operations']}, {False})
        self.assertTrue(all(operation['evidenceIds'] for operation in document['operations']))
        self.assertTrue(all('pc' in item['sourceRef'] for item in document['instructions']))
        instruction_ids = {item['id'] for item in document['instructions']}
        self.assertTrue(all(item['instructionId'] in instruction_ids for item in document['functions']))
        self.assertTrue(all(item['instructionId'] in instruction_ids for item in document['operations']))
        event = document['events'][0]
        error = document['errors'][0]
        self.assertEqual(event['instructionId'], next(item['id'] for item in document['instructions'] if item['pc'] == 0))
        self.assertEqual(event['logInstructionId'], next(item['id'] for item in document['instructions'] if item['pc'] == 3))
        self.assertEqual(error['instructionId'], event['instructionId'])
        self.assertEqual(error['revertInstructionId'], event['logInstructionId'])
        self.assertFalse(event['semanticsProven'])
        self.assertFalse(error['semanticsProven'])
        self.assertEqual(document['fieldStates']['events'], 'available')
        self.assertEqual(document['fieldStates']['errors'], 'available')
        self.assertTrue(any(link['kind'] == 'operation_instruction' for link in document['links']))

    def test_literal_candidate_entities_are_order_independent_and_mergeable(self):
        left = IR.from_bytecode_report(bytecode_report())
        right_report = copy.deepcopy(bytecode_report())
        right_report['eventTopicCandidates'].reverse()
        right_report['errorSelectorCandidates'].reverse()
        right = IR.from_bytecode_report(right_report)
        self.assertEqual(left['documentId'], right['documentId'])
        merged = IR.merge_ir_documents(left, right)
        self.assertEqual(len(merged['events']), 1)
        self.assertEqual(len(merged['errors']), 1)
        self.assertTrue(IR.validate_ir_document(merged))

    def test_literal_candidate_entities_reject_dangling_instruction_or_proven_semantics(self):
        document = IR.from_bytecode_report(bytecode_report())
        dangling = copy.deepcopy(document)
        dangling['events'][0]['logInstructionId'] = 'missing-instruction'
        with self.assertRaisesRegex(ValueError, 'logInstructionId'):
            IR.validate_ir_document(dangling)

        unproven = copy.deepcopy(document)
        unproven['errors'][0]['semanticsProven'] = True
        with self.assertRaisesRegex(ValueError, 'semanticsProven'):
            IR.validate_ir_document(unproven)

    def test_bytecode_report_preserves_control_flow_edges_without_proving_reachability(self):
        report = bytecode_report()
        report['controlFlowEdges'] = [
            {'fromPc': 0, 'toPc': 2, 'kind': 'sequential',
             'targetKind': 'static', 'confidence': 'heuristic',
             'semanticsProven': True},
            {'fromPc': 2, 'toPc': None, 'kind': 'jump',
             'targetKind': 'unknown', 'unknownReason': 'dynamic_stack_target'},
        ]
        document = IR.from_bytecode_report(report)
        self.assertEqual(len(document['controlFlowEdges']), 2)
        known = next(edge for edge in document['controlFlowEdges'] if edge['edgeKind'] == 'sequential')
        unknown = next(edge for edge in document['controlFlowEdges'] if edge['edgeKind'] == 'jump')
        self.assertFalse(any(edge['semanticsProven'] for edge in document['controlFlowEdges']))
        self.assertEqual(known['fromPc'], 0)
        self.assertEqual(known['toPc'], 2)
        self.assertIn('fromInstructionId', known)
        self.assertIn('toInstructionId', known)
        self.assertEqual(unknown['toPc'], None)
        self.assertNotIn('toInstructionId', unknown)
        cfg_links = [link for link in document['links'] if link['kind'] == 'control_flow_edge']
        self.assertEqual(len(cfg_links), 1)
        self.assertEqual(cfg_links[0]['controlFlowEdgeId'], known['id'])
        self.assertTrue(IR.validate_ir_document(document))

    def test_bytecode_report_rejects_control_flow_edge_outside_decoded_instructions(self):
        report = bytecode_report()
        report['controlFlowEdges'] = [{'fromPc': 0, 'toPc': 99, 'kind': 'jump'}]
        with self.assertRaisesRegex(ValueError, 'controlFlowEdges.*endpoints'):
            IR.from_bytecode_report(report)

    def test_semantic_dimensions_are_explicit_and_preserve_reported_observations(self):
        report = bytecode_report()
        report.update({
            'parameters': [{'name': 'amount', 'type': 'uint256', 'index': 0}],
            'memoryAccesses': [{'pc': 0, 'opcode': 'PUSH1', 'access': 'write'}],
            'assetFlows': [{'kind': 'token_transfer', 'from': 'caller', 'to': 'vault', 'amount': 'unknown'}],
            'stateTransitions': [{'from': 'active', 'to': 'paused', 'trigger': 'selector_0xa9059cbb'}],
        })
        document = IR.from_bytecode_report(report)

        self.assertEqual(document['fieldStates']['parameters'], 'available')
        self.assertEqual(document['fieldStates']['memoryAccesses'], 'available')
        self.assertEqual(document['fieldStates']['storageAccesses'], 'available')
        self.assertEqual(document['fieldStates']['assetFlows'], 'available')
        self.assertEqual(document['fieldStates']['stateTransitions'], 'available')
        self.assertEqual(document['parameters'][0]['name'], 'amount')
        instruction_by_pc = {item['pc']: item['id'] for item in document['instructions']}
        memory = next(item for item in document['memoryAccesses'] if item['pc'] == 0)
        storage = next(item for item in document['storageAccesses'] if item['pc'] == 2)
        self.assertEqual(memory['instructionId'], instruction_by_pc[0])
        self.assertEqual(storage['instructionId'], instruction_by_pc[2])
        self.assertEqual(storage['opcode'], 'SSTORE')
        self.assertEqual(document['assetFlows'][0]['amount'], 'unknown')
        self.assertEqual(document['stateTransitions'][0]['from'], 'active')
        self.assertTrue(IR.validate_ir_document(document))

    def test_semantic_dimensions_fail_closed_when_schema_types_or_states_are_tampered(self):
        document = IR.from_bytecode_report(bytecode_report())
        malformed = copy.deepcopy(document)
        malformed['assetFlows'] = {}
        with self.assertRaisesRegex(ValueError, 'assetFlows must be a list'):
            IR.validate_ir_document(malformed)

        stale_state = copy.deepcopy(document)
        stale_state['fieldStates']['parameters'] = 'available'
        with self.assertRaisesRegex(ValueError, 'fieldStates.parameters'):
            IR.validate_ir_document(stale_state)

        missing_state = copy.deepcopy(document)
        del missing_state['fieldStates']['memoryAccesses']
        with self.assertRaisesRegex(ValueError, 'fieldStates.memoryAccesses'):
            IR.validate_ir_document(missing_state)

        stale_event_state = copy.deepcopy(document)
        stale_event_state['fieldStates']['events'] = 'not_recorded'
        with self.assertRaisesRegex(ValueError, 'fieldStates.events'):
            IR.validate_ir_document(stale_event_state)

    def test_permission_modifier_candidates_keep_provenance_without_claiming_authorization(self):
        report = call_graph_report()
        permission = IR.from_call_graph(report)['permissions'][0]
        self.assertEqual(permission['kind'], 'permission')
        self.assertEqual(permission['modifier'], 'onlyRole(WITHDRAWER_ROLE)')
        self.assertEqual(permission['sourceRef'], {'kind': 'slither_ir', 'file': 'Vault.sol', 'lines': [9]})
        self.assertEqual(permission['confidence'], 'heuristic')
        self.assertFalse(permission['semanticsProven'])
        self.assertEqual(permission['function'], 'Vault.withdraw(uint256)')
        self.assertEqual(IR.from_call_graph(report)['fieldStates']['permissions'], 'available')
        self.assertEqual(IR.from_call_graph(call_graph_report() | {'entrypoints': [{'function': 'Vault.withdraw(uint256)', 'visibility': 'external'}]})['fieldStates']['permissions'], 'not_recorded')
        self.assertTrue(IR.validate_ir_document(IR.from_call_graph(report)))

    def test_bytecode_classification_is_preserved_as_unproven_contract_evidence(self):
        report = bytecode_report()
        report['bytecodeClassification'] = {
            'kind': 'minimal_proxy_clone', 'confidence': 'observed',
            'codeCompleteness': 'complete', 'proxyCandidate': True,
            'implementationAddress': '0x' + '3' * 40,
            'evidence': [{'kind': 'eip1167_minimal_proxy_shape', 'confidence': 'observed'}],
            'limitations': ['implementation code was not resolved'],
        }
        document = IR.from_bytecode_report(report)
        self.assertEqual(document['contract']['bytecodeClassification']['kind'], 'minimal_proxy_clone')
        self.assertEqual(document['contract']['bytecodeClassification']['implementationAddress'], '0x' + '3' * 40)
        evidence = document['evidence'][0]
        self.assertEqual(evidence['bytecodeClassification']['confidence'], 'observed')
        self.assertFalse(any(item.get('semanticsProven') is True for item in document['operations']))

    def test_bytecode_classification_rejects_malformed_addresses(self):
        report = bytecode_report()
        report['bytecodeClassification'] = {
            'kind': 'minimal_proxy_clone', 'confidence': 'observed',
            'codeCompleteness': 'complete', 'proxyCandidate': True,
            'implementationAddress': '0x1234',
        }
        with self.assertRaisesRegex(ValueError, 'implementationAddress'):
            IR.from_bytecode_report(report)

    def test_large_bytecode_report_assigns_each_instruction_to_nearest_block_start(self):
        instruction_count = 12_000
        report = {
            'bytecodeSha256': 'd' * 64,
            'instructions': [{'pc': pc, 'opcode': 'STOP'} for pc in range(instruction_count)],
            'basicBlockStartHints': list(range(0, instruction_count, 2)),
        }

        document = IR.from_bytecode_report(report)
        block_by_id = {block['id']: block['pc'] for block in document['basicBlocks']}
        instruction_pc = {instruction['id']: instruction['pc'] for instruction in document['instructions']}
        membership = [link for link in document['links'] if link['kind'] == 'block_contains']

        self.assertEqual(len(membership), instruction_count)
        self.assertEqual(
            {(block_by_id[link['from']], instruction_pc[link['to']]) for link in membership},
            {(pc - pc % 2, pc) for pc in range(instruction_count)},
        )

    def test_bytecode_report_rejects_duplicate_or_unbound_observation_offsets(self):
        duplicate = copy.deepcopy(bytecode_report())
        duplicate['instructions'].append({'pc': 2, 'opcode': 'STOP'})
        with self.assertRaisesRegex(ValueError, 'duplicate pc'):
            IR.from_bytecode_report(duplicate)

        missing_selector = copy.deepcopy(bytecode_report())
        missing_selector['selectorCandidates'][0]['pc'] = 99
        with self.assertRaisesRegex(ValueError, 'selector candidate'):
            IR.from_bytecode_report(missing_selector)

        mismatched_operation = copy.deepcopy(bytecode_report())
        mismatched_operation['externalCallSites'][0]['opcode'] = 'DELEGATECALL'
        with self.assertRaisesRegex(ValueError, 'does not match an instruction'):
            IR.from_bytecode_report(mismatched_operation)

        dangling_block = copy.deepcopy(bytecode_report())
        dangling_block['basicBlockStartHints'] = [True]
        with self.assertRaisesRegex(ValueError, 'basicBlockStartHints'):
            IR.from_bytecode_report(dangling_block)

        dangling_block['basicBlockStartHints'] = [99]
        with self.assertRaisesRegex(ValueError, 'decoded instruction offsets'):
            IR.from_bytecode_report(dangling_block)

    def test_bytecode_report_rejects_invalid_sha256(self):
        for value in ['a' * 63, 'g' + 'a' * 63, 'A' + 'a' * 63]:
            with self.subTest(value=value):
                report = copy.deepcopy(bytecode_report())
                report['bytecodeSha256'] = value
                with self.assertRaisesRegex(ValueError, 'bytecodeSha256'):
                    IR.from_bytecode_report(report)

    def test_bytecode_report_binds_optional_runtime_bytes_to_digest_and_offsets(self):
        report = bytecode_report()
        report['runtimeBytecode'] = '0x6000'
        report['bytecodeSha256'] = __import__('hashlib').sha256(bytes.fromhex('6000')).hexdigest()
        with self.assertRaisesRegex(ValueError, 'instruction pc'):
            IR.from_bytecode_report(report)

        report = bytecode_report()
        report['runtimeBytecode'] = '0x6000'
        with self.assertRaisesRegex(ValueError, 'does not match'):
            IR.from_bytecode_report(report)

    def test_call_graph_preserves_partial_and_unproven_path(self):
        document = IR.from_call_graph(call_graph_report())
        self.assertEqual(document['state'], 'partial')
        self.assertEqual(document['contract']['source'], 'slither_ir')
        self.assertEqual(document['operations'][0]['pathFeasibility'], 'not_proven')
        self.assertIn('path feasibility', ' '.join(document['limitations']))
        self.assertEqual(document['operations'][0]['semanticsProven'], False)

    def test_call_graph_operation_exposes_the_shared_effect_site_id(self):
        report = call_graph_report()
        effect = report['paths'][0]['effect']
        source_hash = 'c' * 64
        effect.update({'sourceSha256': source_hash,
                       'effectSiteId': IR.effect_site_id(source_hash, 'Vault.sol', 200, 8, 'state_write'),
                       'location': {'file': 'Vault.sol', 'lines': [20], 'start': 200, 'length': 8}})

        operation = IR.from_call_graph(report)['operations'][0]

        self.assertEqual(operation['effectSiteId'], effect['effectSiteId'])
        self.assertEqual(operation['effect']['effectSiteId'], effect['effectSiteId'])

    def test_entity_ids_and_document_id_ignore_input_array_order(self):
        left = bytecode_report()
        right = copy.deepcopy(left)
        right['instructions'].reverse()
        right['selectorCandidates'].reverse()
        right['externalCallSites'].reverse()
        right['storageOperationSites'].reverse()
        self.assertEqual(IR.from_bytecode_report(left)['documentId'], IR.from_bytecode_report(right)['documentId'])
        self.assertEqual(
            sorted(item['id'] for item in IR.from_bytecode_report(left)['instructions']),
            sorted(item['id'] for item in IR.from_bytecode_report(right)['instructions']),
        )

    def test_merge_deduplicates_entities_and_links_and_records_sources(self):
        first = IR.from_bytecode_report(bytecode_report())
        second = IR.from_bytecode_report(bytecode_report())
        second['state'] = 'partial'
        merged = IR.merge_ir_documents(first, second)
        self.assertEqual(merged['state'], 'partial')
        self.assertEqual(len(merged['instructions']), 3)
        self.assertEqual(len(merged['operations']), 2)
        self.assertEqual(len(merged['sourceDocuments']), 1)
        self.assertEqual(len(merged['contracts']), 1)

    def test_semantic_dimensions_are_explicit_and_content_bound(self):
        document = IR.from_bytecode_report(bytecode_report())
        for category in ('parameters', 'memoryAccesses', 'storageAccesses', 'assetFlows', 'stateTransitions'):
            self.assertIn(category, document)
            if category == 'storageAccesses':
                self.assertEqual(len(document[category]), 1)
                self.assertEqual(document['fieldStates'][category], 'available')
            else:
                self.assertEqual(document[category], [])
                self.assertEqual(document['fieldStates'][category], 'not_recorded')
        self.assertTrue(IR.validate_ir_document(document))
        tampered = copy.deepcopy(document)
        tampered['fieldStates']['assetFlows'] = 'available'
        with self.assertRaisesRegex(ValueError, 'fieldStates.assetFlows'):
            IR.validate_ir_document(tampered)

    def test_merge_keeps_bytecode_and_slither_contracts_separate(self):
        bytecode = IR.from_bytecode_report(bytecode_report())
        slither = IR.from_call_graph(call_graph_report())
        merged = IR.merge_ir_documents(bytecode, slither)

        self.assertIsNone(merged['contract'])
        self.assertEqual(
            {item['id'] for item in merged['contracts']},
            {bytecode['contract']['id'], slither['contract']['id']},
        )
        ids = {item['id'] for category in ('functions', 'basicBlocks', 'instructions', 'operations', 'evidence')
               for item in merged[category]}
        ids.update(item['id'] for item in merged['contracts'])
        for link in merged['links']:
            self.assertIn(link['from'], ids)
            self.assertIn(link['to'], ids)
        self.assertEqual(
            IR.merge_ir_documents(bytecode, slither)['documentId'],
            IR.merge_ir_documents(slither, bytecode)['documentId'],
        )

    def test_nested_merge_preserves_contracts_and_source_documents(self):
        bytecode = IR.from_bytecode_report(bytecode_report())
        slither = IR.from_call_graph(call_graph_report())
        nested = IR.merge_ir_documents(IR.merge_ir_documents(bytecode, bytecode), slither)
        direct = IR.merge_ir_documents(bytecode, slither)

        self.assertIsNone(nested['contract'])
        self.assertEqual(nested['contracts'], direct['contracts'])
        self.assertEqual(nested['sourceDocuments'], direct['sourceDocuments'])
        self.assertEqual(nested['documentId'], direct['documentId'])

    def test_merge_rejects_dangling_references_and_conflicting_ids(self):
        document = IR.from_bytecode_report(bytecode_report())
        dangling = copy.deepcopy(document)
        dangling['links'][0]['to'] = 'missing-entity'
        with self.assertRaises(ValueError):
            IR.merge_ir_documents(dangling)

        conflicting = copy.deepcopy(document)
        conflicting['instructions'][0]['opcode'] = 'STOP'
        with self.assertRaises(ValueError):
            IR.merge_ir_documents(document, conflicting)

    def test_merge_rejects_stale_document_id_and_wrong_reference_category(self):
        document = IR.from_bytecode_report(bytecode_report())
        stale = copy.deepcopy(document)
        stale['instructions'][0]['opcode'] = 'STOP'
        with self.assertRaisesRegex(ValueError, 'documentId'):
            IR.merge_ir_documents(stale)

        wrong_category = copy.deepcopy(document)
        wrong_category['operations'][0]['instructionId'] = wrong_category['contract']['id']
        # Recompute nothing intentionally: the typed-reference check should
        # reject this before any caller can rely on the stale graph identity.
        with self.assertRaisesRegex(ValueError, 'instructionId'):
            IR.merge_ir_documents(wrong_category)

    def test_bad_reports_are_rejected(self):
        with self.assertRaises(ValueError):
            IR.from_bytecode_report({'instructions': []})
        with self.assertRaises(ValueError):
            IR.from_call_graph({'state': 'completed', 'entrypoints': 'bad'})
        with self.assertRaises(ValueError):
            IR.merge_ir_documents({'schemaVersion': 2})


if __name__ == '__main__':
    unittest.main()
