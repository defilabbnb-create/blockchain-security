"""Tests for the constructor-argument recovery and the literal spelling it needs.

The recovered arguments come from the creation transaction of a verified
deployment, so the values are the ones the chain used.  Two things have to hold
for a deployment built from them to be the same contract: the address literals
carry the checksum Solidity 0.8 demands, and a parameter declared as a contract
type is cast to that contract rather than passed as a bare address.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from abi_decode import AbiDecodeError, decode_constructor_arguments
from deploy_adapter import _constructor_values, _solidity_literal
from keccak import keccak256, to_checksum_address


class KeccakTests(unittest.TestCase):
    def test_keccak256_matches_the_published_digests(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_keccak256_is_not_sha3_256(self):
        import hashlib
        self.assertNotEqual(keccak256(b"").hex(), hashlib.sha3_256(b"").hexdigest())

    def test_eip55_checksum_matches_the_published_vectors(self):
        for address in (
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ):
            self.assertEqual(to_checksum_address(address), address)

    def test_a_lowercase_address_is_checksummed(self):
        self.assertEqual(
            to_checksum_address("0xc5e782e2a4e2cfcb7ed454cf5a7b6aa2bb424b90"),
            "0xC5E782E2A4E2cFCb7eD454CF5a7b6aa2bB424B90")

    def test_a_malformed_address_is_refused(self):
        for bad in ("0x1234", "not-an-address", "0x" + "z" * 40):
            with self.assertRaises(ValueError):
                to_checksum_address(bad)


class ConstructorDecodeTests(unittest.TestCase):
    def test_static_arguments_decode_in_declaration_order(self):
        payload = ("0x" + "00" * 12 + "11" * 20
                   + "0000000000000000000000000000000000000000000000000000000000000002")
        values = decode_constructor_arguments(payload, [
            {"name": "token", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ])
        self.assertEqual(values[0], "0x" + "11" * 20)
        self.assertEqual(values[1], 2)

    def test_a_dynamic_string_argument_decodes(self):
        # One head word holding the offset, then the length and the bytes.
        payload = ("0x"
                   + "0000000000000000000000000000000000000000000000000000000000000020"
                   + "0000000000000000000000000000000000000000000000000000000000000005"
                   + "68656c6c6f000000000000000000000000000000000000000000000000000000")
        values = decode_constructor_arguments(payload, [{"name": "name", "type": "string"}])
        self.assertEqual(values, ["hello"])

    def test_two_strings_decode_with_their_own_offsets(self):
        payload = ("0x"
                   + "0000000000000000000000000000000000000000000000000000000000000040"
                   + "0000000000000000000000000000000000000000000000000000000000000080"
                   + "0000000000000000000000000000000000000000000000000000000000000003"
                   + "6162630000000000000000000000000000000000000000000000000000000000"
                   + "0000000000000000000000000000000000000000000000000000000000000003"
                   + "6465660000000000000000000000000000000000000000000000000000000000")
        values = decode_constructor_arguments(payload, [
            {"name": "a", "type": "string"}, {"name": "b", "type": "string"}])
        self.assertEqual(values, ["abc", "def"])

    def test_a_constructor_without_parameters_needs_no_payload(self):
        self.assertEqual(decode_constructor_arguments("0x", []), [])

    def test_a_missing_payload_for_a_declared_parameter_is_refused(self):
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments("0x", [{"name": "a", "type": "uint256"}])

    def test_a_malformed_payload_is_refused(self):
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments("0xabc", [{"name": "a", "type": "uint256"}])
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments("0xzz", [{"name": "a", "type": "uint256"}])

    def test_an_unsupported_type_is_reported_rather_than_guessed(self):
        payload = "0x" + "00" * 32
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments(payload, [{"name": "a", "type": "uint257"}])

    def test_a_static_element_array_is_refused_at_every_length(self):
        # An `address[]` was routed through the dynamic-element reader, which
        # rejected a one-element array with "unsupported dynamic type address"
        # and returned an empty list for a zero-element one without ever
        # reaching a branch that could refuse.  The empty case is the dangerous
        # one: it looks like a successful decode and would have been handed to a
        # constructor as the real argument, producing a contract that is not the
        # one the chain has.
        empty = "0x" + "00" * 32
        two = ((0x20).to_bytes(32, "big") + (2).to_bytes(32, "big")
               + (0xAAAA).to_bytes(20, "big").ljust(32, b"\0")
               + (0xBBBB).to_bytes(20, "big").ljust(32, b"\0"))
        for payload in (empty, two):
            with self.assertRaises(AbiDecodeError):
                decode_constructor_arguments(payload, [{"name": "a", "type": "address[]"}])

    def test_a_fixed_size_array_is_refused_with_the_decoders_own_error(self):
        # This reached `_decode_static`, which has no array branch, and surfaced
        # as an unrelated `ValueError` from a string parse.  A caller handling
        # `AbiDecodeError` would not have caught it, and the collection run it
        # aborted is not the same as a run that recorded the contract as
        # undecodable.
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments("0x" + "00" * 96, [{"name": "a", "type": "uint256[3]"}])

    def test_a_tuple_array_is_refused(self):
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments("0x" + "00" * 32,
                                         [{"name": "a", "type": "(address,uint256)[]"}])

    def test_an_array_offset_or_length_past_the_payload_is_refused(self):
        # The length word was read without a bounds check, so a payload that
        # declared more elements than it carried surfaced as `IndexError`.
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments("0x" + "ff" * 32, [{"name": "a", "type": "string[]"}])
        past = "0x" + (0x40).to_bytes(32, "big").hex() + "00" * 32
        with self.assertRaises(AbiDecodeError):
            decode_constructor_arguments(past, [{"name": "a", "type": "string[]"}])

    def test_every_complex_type_fails_through_the_one_handled_exception(self):
        # The property the collection line depends on: an argument the decoder
        # cannot handle must arrive as `AbiDecodeError`, never as some other
        # exception that a caller catching only that type would let escape.
        # `string[]` is absent on purpose -- an empty `string[]` really does
        # decode to an empty list, and refusing it would discard a true reading.
        # What matters is that a type it cannot represent is refused rather than
        # approximated, which the static-array case above pins separately.
        payload = "0x" + "00" * 96
        for kind in ("(address,uint256)", "(address,uint256)[]", "uint256[3]",
                     "address[]", "struct Foo", "enum Status",
                     "uint257", "bytes99"):
            with self.subTest(kind=kind):
                with self.assertRaises(AbiDecodeError):
                    decode_constructor_arguments(payload, [{"name": "a", "type": kind}])

    def test_an_empty_dynamic_array_decodes_to_an_empty_list(self):
        # The counterpart to the static case: here the empty list is the truth,
        # and refusing it would mean discarding a reading the decoder got right.
        payload = "0x" + (0x20).to_bytes(32, "big").hex() + "00" * 32
        self.assertEqual(decode_constructor_arguments(payload, [{"name": "a", "type": "string[]"}]),
                         [[]])


class LiteralTests(unittest.TestCase):
    def test_an_address_literal_carries_the_checksum(self):
        self.assertEqual(
            _solidity_literal("0xc5e782e2a4e2cfcb7ed454cf5a7b6aa2bb424b90", "address"),
            "0xC5E782E2A4E2cFCb7eD454CF5a7b6aa2bB424B90")

    def test_a_contract_parameter_is_cast_to_its_declared_type(self):
        self.assertEqual(
            _solidity_literal("0xc5e782e2a4e2cfcb7ed454cf5a7b6aa2bb424b90", "address",
                              "contract IRegistryV1"),
            "IRegistryV1(0xC5E782E2A4E2cFCb7eD454CF5a7b6aa2bB424B90)")

    def test_a_plain_address_parameter_is_not_cast(self):
        self.assertEqual(
            _solidity_literal("0xc5e782e2a4e2cfcb7ed454cf5a7b6aa2bb424b90", "address",
                              "contract IRegistryV1".replace("contract ", "")),
            "0xC5E782E2A4E2cFCb7eD454CF5a7b6aa2bB424B90")

    def test_a_string_literal_is_quoted(self):
        self.assertEqual(_solidity_literal("engine_chip_BOBA", "string"), '"engine_chip_BOBA"')

    def test_an_integer_literal_is_spelled_as_a_number(self):
        self.assertEqual(_solidity_literal(7, "uint256"), "7")

    def test_a_boolean_literal_is_spelled_as_a_keyword(self):
        self.assertEqual(_solidity_literal(True, "bool"), "true")

    def test_an_unsupported_value_is_refused(self):
        with self.assertRaises(ValueError):
            _solidity_literal(object(), "uint256")

    def test_a_missing_value_is_listed_as_missing(self):
        literals, missing = _constructor_values(
            {"inputs": [{"name": "a", "type": "uint256"}, {"name": "b", "type": "address"}]},
            [1])
        self.assertEqual(literals, ["1"])
        self.assertEqual(missing, ["b"])

    def test_values_may_be_given_by_name(self):
        literals, missing = _constructor_values(
            {"inputs": [{"name": "a", "type": "uint256"}]}, {"a": 5})
        self.assertEqual(literals, ["5"])
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
