import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
import bytecode_analysis as ANALYSIS
from bytecode_analysis import analyze_runtime_bytecode, analyze_bytecode, extract_runtime_bytecode, extract_bytecode, extract_input_anchors, EIP1967_SLOTS


class BytecodeAnalysisTests(unittest.TestCase):
    def test_control_flow_edges_resolve_direct_jump_and_sequential_flow(self):
        report = analyze_runtime_bytecode('0x6003565b00')
        edges = report['controlFlowEdges']
        self.assertIn({
            'fromPc': 0, 'toPc': 2, 'kind': 'sequential', 'targetKind': 'static',
            'confidence': 'heuristic', 'semanticsProven': False,
        }, edges)
        self.assertIn({
            'fromPc': 2, 'toPc': 3, 'kind': 'jump', 'targetKind': 'static',
            'confidence': 'heuristic', 'semanticsProven': False,
            'targetPcIsJumpdest': True, 'targetSourcePc': 0,
        }, edges)
        self.assertFalse(any(edge['toPc'] == 3 and edge['kind'] == 'sequential' for edge in edges))

    def test_control_flow_edges_include_conditional_true_and_false_hints(self):
        report = analyze_runtime_bytecode('0x6006600157005b00')
        edges = report['controlFlowEdges']
        true_edge = next(edge for edge in edges if edge['kind'] == 'conditional_true')
        false_edge = next(edge for edge in edges if edge['kind'] == 'conditional_false')
        self.assertEqual((true_edge['fromPc'], true_edge['toPc']), (4, 6))
        self.assertTrue(true_edge['targetPcIsJumpdest'])
        self.assertEqual(true_edge['targetSourcePc'], 0)
        self.assertEqual((false_edge['fromPc'], false_edge['toPc']), (4, 5))
        self.assertEqual(false_edge['targetKind'], 'static')

    def test_control_flow_edges_keep_dynamic_jump_target_unknown(self):
        report = analyze_runtime_bytecode('0x355600')
        edge = next(edge for edge in report['controlFlowEdges'] if edge['kind'] == 'jump')
        self.assertEqual(edge['fromPc'], 1)
        self.assertIsNone(edge['toPc'])
        self.assertEqual(edge['targetKind'], 'unknown')
        self.assertEqual(edge['unknownReason'], 'dynamic_stack_target')

    def test_control_flow_edges_do_not_enter_metadata_candidate(self):
        trailer = (bytes.fromhex('a2') + b'\x64ipfs\x58\x22' + bytes(range(34)) +
                   b'\x64solc\x43\x00\x08\x18')
        raw = bytes.fromhex('600356') + trailer + len(trailer).to_bytes(2, 'big')
        report = analyze_runtime_bytecode('0x' + raw.hex())
        edge = next(edge for edge in report['controlFlowEdges'] if edge['kind'] == 'jump')
        self.assertIsNone(edge['toPc'])
        self.assertEqual(edge['targetKind'], 'unknown')
        self.assertEqual(edge['unknownReason'], 'target_in_metadata_candidate')
        self.assertFalse(any(edge['toPc'] >= report['metadataTrailer']['startPc']
                             for edge in report['controlFlowEdges'] if edge['toPc'] is not None))

    def test_event_and_error_literals_are_bounded_candidates(self):
        event_topic = '11' * 32
        report = analyze_runtime_bytecode(
            '0x7f' + event_topic + '60006000a1'
            '63deadbeef60005260006004fd'
        )
        self.assertEqual(report['eventTopicCandidates'], [{
            'pc': 0, 'topic': '0x' + event_topic,
            'logOpcode': 'LOG1', 'logPc': 37,
            'heuristic': 'literal PUSH32 near LOG opcode; topic stack order and event ABI are not proven',
        }])
        self.assertEqual(report['errorSelectorCandidates'][0]['selector'], '0xdeadbeef')
        self.assertEqual(report['errorSelectorCandidates'][0]['revertPc'], 50)
        self.assertTrue(any('ABI meaning' in limitation for limitation in report['limitations']))

    def test_event_and_error_candidates_ignore_metadata(self):
        trailer = (bytes.fromhex('a2') + b'\x64ipfs\x58\x22' + bytes(range(34)) +
                   b'\x64solc\x43\x00\x08\x18')
        raw = bytes.fromhex('7f' + ('22' * 32) + '60006000a1') + trailer + len(trailer).to_bytes(2, 'big')
        report = analyze_runtime_bytecode('0x' + raw.hex())
        self.assertEqual(len(report['eventTopicCandidates']), 1)
        self.assertEqual(report['eventTopicCandidates'][0]['pc'], 0)

    def test_push_data_is_not_decoded_as_calls_or_jumpdestinations(self):
        report = analyze_runtime_bytecode('0x63f1f4555b00')
        self.assertEqual([x['opcode'] for x in report['instructions']], ['PUSH4', 'STOP'])
        self.assertFalse(report['externalCallSites'])
        self.assertFalse(report['jumpdestinations'])
        self.assertEqual(report['bytecodeSha256'], hashlib.sha256(bytes.fromhex('63f1f4555b00')).hexdigest())

    def test_normal_and_shift_optimized_dispatch_literals(self):
        report = analyze_runtime_bytecode('0x63a9059cbb14601057631b2ce7f360e11b81141561006557')
        self.assertEqual([x['selector'] for x in report['selectorCandidates']], ['0xa9059cbb', '0x3659cfe6'])
        self.assertFalse(analyze_runtime_bytecode('0x634e487b7160e01b600052')['selectorCandidates'])

    def test_truncated_push_and_unknown_opcode_preserve_original_bytes(self):
        report = analyze_runtime_bytecode('0x0c61ff')
        self.assertEqual(report['instructions'][0]['opcode'], 'UNKNOWN_0x0c')
        self.assertTrue(report['instructions'][1]['truncatedPush'])
        self.assertEqual(report['instructions'][1]['immediate'], 'ff')

    def test_slot_hints_and_chain_anchor_are_recorded(self):
        report = analyze_runtime_bytecode('0x7f' + EIP1967_SLOTS['implementation'] + '54f4', chain_id=1088, block='0x10', block_hash='0xabc')
        self.assertEqual(report['eip1967SlotLiteralHints'][0]['kind'], 'eip1967_implementation_slot_literal')
        self.assertEqual(report['storageOperationSites'][0]['pc'], 33)
        self.assertEqual(report['externalCallSites'][0]['pc'], 34)
        self.assertEqual(report['bytecodeClassification']['kind'], 'eip1967_implementation_proxy_candidate')
        self.assertEqual(report['bytecodeClassification']['confidence'], 'heuristic')
        self.assertTrue(report['bytecodeClassification']['proxyCandidate'])
        self.assertEqual(report['block'], '0x10')
        self.assertEqual(report['decompilation']['state'], 'not_performed')

    def test_exact_eip1167_runtime_extracts_implementation_without_semantic_claim(self):
        implementation = bytes.fromhex('11' * 20)
        raw = ANALYSIS.EIP1167_PREFIX + implementation + ANALYSIS.EIP1167_SUFFIX
        report = analyze_runtime_bytecode('0x' + raw.hex())
        classification = report['bytecodeClassification']
        self.assertEqual(classification['kind'], 'minimal_proxy_clone')
        self.assertEqual(classification['confidence'], 'observed')
        self.assertEqual(classification['implementationAddress'], '0x' + implementation.hex())
        self.assertTrue(classification['proxyCandidate'])
        self.assertEqual(classification['codeCompleteness'], 'complete')
        self.assertIn('eip1167_minimal_proxy_shape', [item['kind'] for item in classification['evidence']])

    def test_delegatecall_without_standard_slot_stays_a_proxy_candidate(self):
        report = analyze_runtime_bytecode('0x60006000f4')
        classification = report['bytecodeClassification']
        self.assertEqual(classification['kind'], 'delegatecall_proxy_candidate')
        self.assertEqual(classification['confidence'], 'heuristic')
        self.assertTrue(classification['proxyCandidate'])

    def test_truncated_push_marks_runtime_classification_partial(self):
        report = analyze_runtime_bytecode('0x61ff')
        classification = report['bytecodeClassification']
        self.assertEqual(classification['kind'], 'runtime_contract')
        self.assertEqual(classification['codeCompleteness'], 'truncated')
        self.assertEqual(classification['confidence'], 'partial')
        self.assertFalse(classification['proxyCandidate'])

    def test_modern_opcode_activation_is_explicit_and_old_fork_hints_are_excluded(self):
        report = analyze_runtime_bytecode('0x5f5c5d5e494a', hardfork='berlin')
        rows = {row['opcode']: row for row in report['instructions']}
        self.assertEqual(rows['PUSH0']['opcodeActivation']['status'], 'inactive')
        self.assertEqual(rows['TLOAD']['opcodeActivation']['status'], 'inactive')
        self.assertEqual(rows['BLOBHASH']['opcodeActivation']['status'], 'inactive')
        self.assertFalse(report['storageOperationSites'])
        unknown = analyze_runtime_bytecode('0x5f5c', hardfork=None)
        self.assertEqual(unknown['instructions'][0]['opcodeActivation']['status'], 'unverified')

    def test_latest_is_not_a_verified_chain_fork(self):
        report = analyze_runtime_bytecode('0x5f5c', hardfork='latest')
        rows = {row['opcode']: row for row in report['instructions']}
        self.assertEqual(rows['PUSH0']['opcodeActivation']['status'], 'unverified')
        self.assertIsNone(rows['PUSH0']['opcodeActivation']['active'])

    def test_metadata_candidate_is_marked_but_never_discards_bytes(self):
        trailer = (bytes.fromhex('a2') + b'\x64ipfs\x58\x22' + bytes(range(34)) +
                   b'\x64solc\x43\x00\x08\x18')
        raw = b'\x00' + trailer + len(trailer).to_bytes(2, 'big')
        report = analyze_runtime_bytecode('0x' + raw.hex())
        self.assertEqual(report['metadataTrailer']['startPc'], 1)
        self.assertEqual(report['metadataTrailer']['detection'], 'CBOR trailer candidate')
        self.assertEqual(report['decodedBytes'], len(raw))
        self.assertTrue(any(x.get('inMetadataCandidate') for x in report['instructions']))

    def test_malformed_metadata_markers_do_not_hide_executable_hints(self):
        trailer = (bytes.fromhex('a20000') + bytes.fromhex('63aabbccdd14600057') +
                   b'ipfssolc' + bytes.fromhex('60006000f455'))
        raw = b'\x00' + trailer + len(trailer).to_bytes(2, 'big')
        report = analyze_runtime_bytecode('0x' + raw.hex())
        self.assertIsNone(report['metadataTrailer'])
        self.assertEqual([row['selector'] for row in report['selectorCandidates']], ['0xaabbccdd'])
        self.assertEqual([row['opcode'] for row in report['externalCallSites']], ['DELEGATECALL'])
        self.assertEqual([row['opcode'] for row in report['storageOperationSites']], ['SSTORE'])
        self.assertEqual(report['opcodeCounts'].get('PUSH4'), 1)
        self.assertEqual(report['executableOpcodeCounts'].get('PUSH4'), 1)

    def test_duplicate_solc_metadata_does_not_hide_trailer_opcode_hints(self):
        trailer = (bytes.fromhex('a364697066735822') + bytes(34) +
                   bytes.fromhex('64736f6c634300081864736f6c6343000818') +
                   bytes.fromhex('63aabbccdd14601057f455'))
        raw = b'\x00' + trailer + len(trailer).to_bytes(2, 'big')
        report = analyze_runtime_bytecode('0x' + raw.hex())
        self.assertIsNone(report['metadataTrailer'])
        self.assertTrue(any(row['selector'] == '0xaabbccdd' for row in report['selectorCandidates']))
        self.assertTrue(any(row['opcode'] == 'DELEGATECALL' for row in report['externalCallSites']))
        self.assertTrue(any(row['opcode'] == 'SSTORE' for row in report['storageOperationSites']))

    def test_valid_bzzr1_solidity_metadata_is_recognized(self):
        trailer = (bytes.fromhex('a2') + b'\x65bzzr1\x58\x20' + bytes(range(32)) +
                   b'\x64solc\x43\x00\x08\x18')
        raw = b'\x00' + trailer + len(trailer).to_bytes(2, 'big')
        report = analyze_runtime_bytecode('0x' + raw.hex())
        self.assertEqual(report['metadataTrailer']['startPc'], 1)

    def test_rejects_bad_hex_and_ambiguous_creation_bytecode(self):
        for bytecode in ('0x', '0x123', '0xzz', '1234', None):
            with self.assertRaises(ValueError):
                analyze_runtime_bytecode(bytecode)
        with self.assertRaises(ValueError):
            extract_runtime_bytecode({'creationBytecode': {'onchainBytecode': '0x6000'}, 'bytecode': '0x6000'})
        with self.assertRaisesRegex(ValueError, 'conflicting runtime bytecode'):
            extract_runtime_bytecode({'runtimeBytecode': {'onchainBytecode': '0x6000'}, 'runtimeCode': '0x6001'})
        self.assertEqual(extract_runtime_bytecode({'runtimeBytecode': {'onchainBytecode': '0x6000'}}), '0x6000')
        self.assertEqual(extract_runtime_bytecode(analyze_runtime_bytecode('0x6000')), '0x6000')

    def test_typed_extraction_distinguishes_creation_and_runtime(self):
        value = {'creationBytecode': {'onchainBytecode': '0x60006000'}, 'runtimeBytecode': {'onchainBytecode': '0x6000'}}
        self.assertEqual(extract_bytecode(value), ('0x6000', 'runtime'))
        self.assertEqual(extract_bytecode(value, bytecode_kind='creation'), ('0x60006000', 'creation'))
        creation = analyze_bytecode('0x60006000', bytecode_kind='creation')
        self.assertEqual(creation['inputBytecodeKind'], 'creation')
        self.assertEqual(creation['analysisType'], 'deterministic_evm_creation_disassembly')
        self.assertEqual(creation['bytecodeClassification']['kind'], 'creation_code')

    def test_empty_code_is_explicitly_classified(self):
        report = analyze_bytecode('0x', bytecode_kind='runtime', address='0x' + '11' * 20)
        self.assertEqual(report['bytecodeClassification']['kind'], 'empty_code')
        self.assertEqual(report['bytecodeBytes'], 0)
        self.assertEqual(report['address'], '0x' + '11' * 20)

    def test_cli_input_report_preserves_chain_anchors_without_repeating_flags(self):
        source = analyze_runtime_bytecode('0x6000', chain_id=100, address='0x' + '11' * 20,
                                          block='0x123', block_hash='0x' + '22' * 32, hardfork='cancun')
        self.assertEqual(extract_input_anchors(source), {
            'chain_id': 100, 'address': '0x' + '11' * 20, 'block': '0x123',
            'block_hash': '0x' + '22' * 32, 'hardfork': 'cancun',
        })
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / 'input.json'
            source_path.write_text(json.dumps(source))
            output = root / 'output.json'
            self.assertEqual(ANALYSIS.main([str(source_path), '--output', str(output)]), 0)
            report = json.loads(output.read_text())
            self.assertEqual(report['chainId'], 100)
            self.assertEqual(report['address'], '0x' + '11' * 20)
            self.assertEqual(report['block'], '0x123')
            self.assertEqual(report['blockHash'], '0x' + '22' * 32)
            self.assertEqual(report['hardfork'], 'cancun')

    def test_cli_records_optional_decompiler_result_and_fails_incomplete_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'runtime.hex'
            source.write_text('0x6000')
            report_path = root / 'analysis.json'
            output_dir = root / 'decompilation'
            decompilation = {
                'state': 'partial',
                'engine': 'heimdall-rs',
                'sourceVerified': False,
                'outputKind': 'inferred_pseudocode_not_verified_source',
            }
            with mock.patch.object(ANALYSIS, 'run_heimdall', return_value=decompilation) as run:
                result = ANALYSIS.main([
                    str(source), '--output', str(report_path), '--decompiler', 'heimdall',
                    '--decompiler-output-dir', str(output_dir),
                ])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(report_path.read_text())['decompilation'], decompilation)
            self.assertEqual(run.call_args.kwargs['output_dir'], output_dir)

    def test_cli_writes_unified_ir_to_a_new_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'runtime.hex'
            source.write_text('0x6000')
            report_path = root / 'analysis.json'
            ir_path = root / 'unified-ir.json'
            result = ANALYSIS.main([
                str(source), '--output', str(report_path), '--ir-output', str(ir_path),
            ])

            self.assertEqual(result, 0)
            report = json.loads(report_path.read_text())
            ir = json.loads(ir_path.read_text())
            self.assertEqual(report['unifiedIR']['documentId'], ir['documentId'])
            self.assertEqual(ir['schemaVersion'], 1)
            with self.assertRaises(SystemExit):
                ANALYSIS.main([str(source), '--ir-output', str(ir_path)])

    @unittest.skipUnless((ANALYSIS.ROOT / 'work/tools/heimdall/heimdall').is_file(),
                         'local Heimdall binary is unavailable')
    def test_real_heimdall_output_is_bound_to_runtime_and_unified_ir(self):
        runtime = '0x600060005260206000f3'
        expected_hash = hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'runtime.hex'
            report_path = root / 'analysis.json'
            ir_path = root / 'unified-ir.json'
            decompiler_dir = root / 'decompilation'
            source.write_text(runtime + '\n')

            result = ANALYSIS.main([
                str(source), '--output', str(report_path), '--ir-output', str(ir_path),
                '--decompiler', 'heimdall', '--decompiler-output-dir', str(decompiler_dir),
                '--decompiler-timeout', '15', '--decompiler-hardfork', 'cancun',
            ])

            report = json.loads(report_path.read_text())
            ir = json.loads(ir_path.read_text())
            decompilation = report['decompilation']
            # Heimdall can exit non-zero without writing anything to stderr, so
            # assert with the adapter's own record instead of a bare exit code.
            self.assertEqual(
                result, 0,
                'heimdall decompilation did not complete: '
                f'state={decompilation.get("state")} '
                f'error={decompilation.get("error")} '
                f'exitCode={decompilation.get("exitCode")} '
                f'timedOut={decompilation.get("timedOut")} '
                f'toolVersion={decompilation.get("toolVersion")} '
                f'artifacts={[item.get("path") for item in decompilation.get("artifacts") or []]} '
                f'inputSha256={decompilation.get("inputSha256")} '
                f'binarySha256={decompilation.get("binarySha256")}',
            )
            self.assertEqual(decompilation['state'], 'completed')
            self.assertEqual(decompilation['inputSha256'], expected_hash)
            self.assertEqual(decompilation['crossValidation']['state'], 'opcode_consistent')
            self.assertTrue(decompilation['artifacts'])
            for artifact in decompilation['artifacts']:
                artifact_path = decompiler_dir / artifact['path']
                artifact_bytes = artifact_path.read_bytes()
                self.assertEqual(len(artifact_bytes), artifact['size'])
                self.assertEqual(hashlib.sha256(artifact_bytes).hexdigest(), artifact['sha256'])
            self.assertEqual(report['bytecodeSha256'], expected_hash)
            self.assertEqual(ir['evidence'][0]['bytecodeSha256'], expected_hash)
            self.assertEqual(report['unifiedIR']['documentId'], ir['documentId'])
            self.assertTrue(all(item['confidence'] != 'proven' for item in ir['functions']))

    def test_cli_rejects_symlink_output_without_overwriting_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'runtime.hex'
            source.write_text('0x6000')
            target = root / 'protected.json'
            target.write_text('keep')
            output = root / 'analysis.json'
            output.symlink_to(target)
            with self.assertRaises(SystemExit):
                ANALYSIS.main([str(source), '--output', str(output)])
            self.assertEqual(target.read_text(), 'keep')

