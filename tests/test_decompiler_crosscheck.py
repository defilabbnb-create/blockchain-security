import copy
import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from bytecode_analysis import analyze_bytecode, analyze_runtime_bytecode
from decompiler_crosscheck import (
    attach_opcode_cross_validation,
    compare_disassembly,
    decode_opcode_pc,
)


class DecompilerCrossCheckTests(unittest.TestCase):
    def test_oversized_bytecode_is_rejected_before_regex_scanning(self):
        import decompiler_crosscheck as crosscheck

        value = '0x' + '00' * (crosscheck.MAX_BYTECODE_BYTES + 1)
        regex = mock.Mock(fullmatch=mock.Mock(
            side_effect=AssertionError('regex scanned oversized input'),
        ))
        with mock.patch.object(crosscheck, '_BYTECODE_RE', regex):
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                decode_opcode_pc(value)
        regex.fullmatch.assert_not_called()

    def test_independent_decoder_binds_input_and_preserves_push_boundaries(self):
        bytecode = '0x6003565b00'
        decoded = decode_opcode_pc(bytecode)
        self.assertEqual(decoded['engine'], 'independent-opcode-pc-decoder')
        self.assertEqual(decoded['inputSha256'], hashlib.sha256(bytes.fromhex('6003565b00')).hexdigest())
        self.assertEqual([(row['pc'], row['opcode']) for row in decoded['instructions']],
                         [(0, 'PUSH1'), (2, 'JUMP'), (3, 'JUMPDEST'), (4, 'STOP')])
        self.assertTrue(decoded['complete'])
        self.assertFalse(decoded['semanticsProven'])
        self.assertFalse(decoded['highLevelSemanticsRecovered'])

    def test_primary_report_cross_check_is_consistent_without_semantic_claim(self):
        report = analyze_runtime_bytecode('0x6003565b00')
        check = report['opcodePcCrossCheck']
        self.assertEqual(check['state'], 'consistent')
        self.assertEqual(check['scope'], 'byte-level opcode/PC tokenization and input binding only')
        self.assertFalse(check['isSecondHighLevelDecompiler'])
        self.assertFalse(check['semanticsProven'])
        self.assertEqual(check['mismatches'], [])

    def test_mismatch_is_explicit_and_does_not_become_semantic_failure(self):
        report = analyze_runtime_bytecode('0x6000')
        altered = copy.deepcopy(report)
        altered['instructions'][0]['opcode'] = 'STOP'
        check = compare_disassembly(altered)
        self.assertEqual(check['state'], 'mismatch')
        self.assertTrue(any(item['field'] == 'instructionDigest' for item in check['mismatches']))
        self.assertFalse(check['semanticsProven'])
        self.assertFalse(check['highLevelSemanticsRecovered'])

    def test_invalid_instruction_array_does_not_hide_an_input_hash_mismatch(self):
        report = analyze_runtime_bytecode('0x6000')
        report['bytecodeSha256'] = '0' * 64
        report['instructions'] = None

        check = compare_disassembly(report)

        self.assertEqual(check['state'], 'mismatch')
        self.assertEqual(check['reason'], 'primary_instructions_not_array')
        self.assertTrue(any(item['field'] == 'bytecodeSha256' for item in check['mismatches']))

    def test_report_fingerprints_and_aggregates_are_bound_to_decoded_bytes(self):
        report = analyze_runtime_bytecode('0x6001600201')
        for field, value in (
            ('bytecodeSha256', '0' * 64),
            ('bytecodeBytes', 99),
            ('instructionCount', 99),
            ('opcodeCounts', {'STOP': 5}),
        ):
            altered = copy.deepcopy(report)
            altered[field] = value
            check = compare_disassembly(altered)
            self.assertEqual(check['state'], 'mismatch', field)
            self.assertIn(field, {item['field'] for item in check['mismatches']})
            self.assertFalse(check['semanticsProven'])

    def test_truncated_push_is_reported_as_partial_byte_level_evidence(self):
        report = analyze_runtime_bytecode('0x61ff')
        check = report['opcodePcCrossCheck']
        self.assertEqual(check['state'], 'consistent')
        self.assertEqual(check['independentTruncatedPushCount'], 1)
        self.assertFalse(check['independentComplete'])

    def test_attach_preserves_artifact_checks_and_labels_scope(self):
        report = analyze_runtime_bytecode('0x6000')
        decompilation = {
            'state': 'completed',
            'sourceVerified': False,
            'highLevelSemanticsRecovered': False,
            'inputSha256': report['bytecodeSha256'],
            'inputBytecodeBytes': report['bytecodeBytes'],
            'crossValidation': {
                'state': 'not_performed',
                'artifactReferenceState': 'available',
            },
        }
        attach_opcode_cross_validation(decompilation, report)
        cross = decompilation['crossValidation']
        self.assertEqual(cross['state'], 'opcode_consistent')
        self.assertTrue(cross['independentDecoderCompleted'])
        self.assertEqual(cross['comparedHighLevelEngineCount'], 0)
        self.assertEqual(cross['artifactReferenceState'], 'available')
        self.assertEqual(cross['decompilerInputBinding']['state'], 'consistent')
        self.assertIn('no high-level decompiler agreement', cross['agreementScope'])

    def test_attach_marks_decompiler_input_mismatch_and_does_not_report_agreement(self):
        report = analyze_runtime_bytecode('0x6000')
        decompilation = {
            'state': 'completed',
            'inputSha256': '0' * 64,
            'inputBytecodeBytes': 2,
            'crossValidation': {'state': 'not_performed'},
        }

        attach_opcode_cross_validation(decompilation, report)

        cross = decompilation['crossValidation']
        self.assertEqual(cross['decompilerInputBinding']['state'], 'mismatch')
        self.assertEqual(cross['state'], 'input_mismatch')
        self.assertEqual(decompilation['executionState'], 'completed')
        self.assertEqual(decompilation['state'], 'failed')
        self.assertEqual(decompilation['error'], 'decompiler_input_binding_mismatch')

    def test_empty_account_has_explicit_zero_byte_cross_check(self):
        check = analyze_bytecode('0x')['opcodePcCrossCheck']
        self.assertEqual(check['state'], 'consistent')
        self.assertEqual(check['inputBytecodeBytes'], 0)
        self.assertEqual(check['primaryInstructionCount'], 0)
        self.assertFalse(check['semanticsProven'])


if __name__ == '__main__':
    unittest.main()
