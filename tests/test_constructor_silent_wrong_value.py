"""Constructor recovery must fail honestly on boundary input.

Three paths used to produce a `recovered` result whose values belonged to no
parameter:

* the decoder read the first words of a longer payload and ignored the rest;
* the length check for all-static constructors accepted any difference at least
  as large as the head, so a larger difference trimmed at the wrong place;
* a dynamic parameter with no located boundary was decoded from the whole
  transaction input.

Each refusal is paired with the reading that must still succeed, so a fix in
one direction cannot silently become over-refusal in the other.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT))
from abi_decode import AbiDecodeError, decode_constructor_arguments  # noqa: E402

spec = importlib.util.spec_from_file_location('campaign', ROOT / 'scripts/defi-campaign.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

UINT = [{'name': 'a', 'type': 'uint256'}]
ADDRESS = [{'name': 'a', 'type': 'address'}]
BYTES = [{'name': 'a', 'type': 'bytes'}]
# The first words of real creation code: non-zero, not a padded address.
INIT_CODE_WORD = '6080604052348015600f57600080fd5b50'.ljust(64, '0')


def word(value):
    return value.to_bytes(32, 'big').hex()


class DecoderSurplusTests(unittest.TestCase):
    def test_a_static_payload_longer_than_the_parameters_is_refused(self):
        for extra_words in (1, 2):
            with self.subTest(extra_words=extra_words):
                payload = '0x' + word(5) + '00' * 32 * extra_words
                with self.assertRaises(AbiDecodeError):
                    decode_constructor_arguments(payload, UINT)

    def test_creation_code_is_not_read_as_a_uint(self):
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments('0x' + INIT_CODE_WORD + '00' * 32, UINT)

    def test_fewer_words_than_parameters_is_refused_not_an_index_error(self):
        two = [{'name': 'a', 'type': 'uint256'}, {'name': 'b', 'type': 'uint256'}]
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments('0x' + word(1), two)

    def test_an_exact_static_payload_still_decodes(self):
        two = [{'name': 'a', 'type': 'uint256'}, {'name': 'b', 'type': 'uint256'}]
        self.assertEqual(decode_constructor_arguments('0x' + word(1) + word(2), two), [1, 2])

    def test_a_dynamic_payload_with_a_tail_still_decodes(self):
        payload = '0x' + word(0x20) + word(5) + '68656c6c6f'.ljust(64, '0')
        self.assertEqual(decode_constructor_arguments(
            payload, [{'name': 'a', 'type': 'string'}]), ['hello'])


def bundle(declarations, onchain_bytes, recompiled_bytes):
    return {'abi': [{'type': 'constructor', 'inputs': declarations}],
            'creationBytecode': {'onchainBytecode': '0x' + 'ab' * onchain_bytes,
                                 'recompiledBytecode': '0x' + 'cd' * recompiled_bytes}}


class StaticLengthMustBeExactTests(unittest.TestCase):
    def test_a_difference_larger_than_the_static_head_is_refused(self):
        # One address occupies one word.  Two words of difference are not this
        # constructor's arguments, and trimming by them would decode the
        # neighbouring word as the address.
        self.assertIsNone(C.constructor_argument_byte_length(bundle(ADDRESS, 128, 64), ADDRESS))

    def test_a_difference_equal_to_the_static_head_is_the_length(self):
        self.assertEqual(C.constructor_argument_byte_length(bundle(ADDRESS, 96, 64), ADDRESS), 32)

    def test_two_static_parameters_need_exactly_two_words(self):
        two = [{'name': 'a', 'type': 'address'}, {'name': 'b', 'type': 'uint256'}]
        self.assertEqual(C.constructor_argument_byte_length(bundle(two, 128, 64), two), 64)
        self.assertIsNone(C.constructor_argument_byte_length(bundle(two, 160, 64), two))
        self.assertIsNone(C.constructor_argument_byte_length(bundle(two, 96, 64), two))


class DynamicLengthIsALowerBoundTests(unittest.TestCase):
    def test_a_dynamic_parameter_needs_its_offset_word_and_a_length_word(self):
        # Offset word plus length word is 64 bytes at the least.
        self.assertIsNone(C.constructor_argument_byte_length(bundle(BYTES, 96, 64), BYTES))
        self.assertEqual(C.constructor_argument_byte_length(bundle(BYTES, 128, 64), BYTES), 64)

    def test_a_longer_dynamic_tail_is_accepted(self):
        self.assertEqual(C.constructor_argument_byte_length(bundle(BYTES, 192, 64), BYTES), 128)


class Pool:
    def __init__(self, input_hex):
        self.input_hex = input_hex

    def call(self, chain_id, method, params):
        return {'input': self.input_hex, 'blockNumber': '0x10'}, {'url': 'https://rpc.invalid'}


def recoverable(declarations, creation=None):
    data = {'abi': [{'type': 'constructor', 'inputs': declarations}],
            'deployment': {'transactionHash': '0x' + '11' * 32, 'blockNumber': '0x10'}}
    if creation is not None:
        data['creationBytecode'] = creation
    return data


class RecoveryDoesNotDecodeCreationCodeTests(unittest.TestCase):
    def test_a_dynamic_parameter_with_no_located_boundary_is_refused(self):
        # No bytecode pair, so nothing says where the arguments start.
        transaction_input = '0x' + INIT_CODE_WORD + word(0x20) + word(3) + '616263'.ljust(64, '0')
        arguments, evidence = C.recover_constructor_arguments(
            recoverable([{'name': 'a', 'type': 'string'}]), Pool(transaction_input), 1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['state'], 'unavailable')
        self.assertIn('boundary not established', evidence['reason'])

    def test_a_static_parameter_with_no_located_boundary_is_refused_by_the_decoder(self):
        transaction_input = '0x' + INIT_CODE_WORD + '00' * 32
        arguments, evidence = C.recover_constructor_arguments(
            recoverable(UINT), Pool(transaction_input), 1)
        self.assertIsNone(arguments)
        self.assertNotEqual(evidence['state'], 'recovered')

    def test_a_located_boundary_still_recovers(self):
        # 64 bytes of creation code, then one address word; the measured length
        # is 32, so the tail is taken.
        creation = {'onchainBytecode': '0x' + 'ab' * 96, 'recompiledBytecode': '0x' + 'cd' * 64}
        transaction_input = '0x' + 'ab' * 64 + '00' * 12 + '22' * 20
        arguments, evidence = C.recover_constructor_arguments(
            recoverable(ADDRESS, creation), Pool(transaction_input), 1)
        self.assertEqual(arguments, {'a': '0x' + '22' * 20})
        self.assertEqual(evidence['state'], 'recovered')


if __name__ == '__main__':
    unittest.main()
