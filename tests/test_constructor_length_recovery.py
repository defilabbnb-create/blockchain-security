"""The constructor arguments have to come from the deployed code, not from a guess.

`onchainBytecode` is the creation code as it was deployed and already contains
the encoded constructor arguments, so stripping it from the transaction input
strips nothing: the payload equals the prefix and the condition that guards
the strip is never met.  The whole bytecode was then handed to the decoder,
which refused it as not a whole number of words, and the contract was reported
as unrecoverable.  24 of the 63 blocked contracts failed this way.

The recompiled bytecode is the same contract compiled locally without
arguments, so the difference in length is the encoded argument length.

These tests pin both the recovery and the refusal: a length that cannot be
established must not be used to trim the payload, because a wrong trim decodes
shifted bytes into values that look plausible and are not the contract's.
"""
import importlib.util, json, sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts')); sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('campaign',ROOT/'scripts/defi-campaign.py')
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def bundle(declarations,onchain_bytes,recompiled_bytes,with_pair=True):
    data={'abi':[{'type':'constructor','inputs':declarations}]}
    if with_pair:
        data['creationBytecode']={'onchainBytecode':'0x'+('ab'*onchain_bytes),
                                  'recompiledBytecode':'0x'+('cd'*recompiled_bytes)}
    return data


class ArgumentLengthTests(unittest.TestCase):
    def test_the_difference_between_the_two_bytecodes_is_the_length(self):
        data=bundle([{'name':'a','type':'address'}],96,64)
        self.assertEqual(C.constructor_argument_byte_length(data,[{'name':'a','type':'address'}]),32)

    def test_no_bytecode_pair_yields_no_length(self):
        data=bundle([{'name':'a','type':'address'}],96,64,with_pair=False)
        self.assertIsNone(C.constructor_argument_byte_length(data,[{'name':'a','type':'address'}]))

    def test_a_difference_that_is_not_a_whole_number_of_words_is_refused(self):
        data=bundle([{'name':'a','type':'address'}],97,64)
        self.assertIsNone(C.constructor_argument_byte_length(data,[{'name':'a','type':'address'}]))

    def test_no_declared_parameters_needs_no_length(self):
        self.assertEqual(C.constructor_argument_byte_length({},[]),0)

    def test_a_dynamic_argument_type_has_a_known_head_but_an_unknown_tail(self):
        # The ABI fixes the head of a dynamic argument but not the length of
        # its tail, so the ABI alone cannot establish a length.  The bytecode
        # difference is what settles it.
        declarations=[{'name':'a','type':'bytes'}]
        self.assertEqual(C._encoded_argument_length(declarations),32)

    def test_the_static_head_of_a_declaration_list_is_known(self):
        declarations=[{'name':'a','type':'address'},{'name':'b','type':'uint256'}]
        self.assertEqual(C._encoded_argument_length(declarations),64)

    def test_a_dynamic_argument_does_not_contribute_a_static_head(self):
        declarations=[{'name':'a','type':'bytes'}]
        head=C._encoded_argument_length([item for item in declarations
            if not C._is_dynamic_argument(item.get('type') or '')])
        self.assertEqual(head,0)


class RecoveryThroughThePoolTests(unittest.TestCase):
    """The arguments are read back from the creation transaction."""

    class Pool:
        def __init__(self,transaction): self.transaction=transaction; self.calls=[]
        def call(self,chain_id,method,params):
            self.calls.append((chain_id,method,params))
            return self.transaction,'http://rpc.invalid'

    def _transaction(self,arguments_hex):
        return {'input':'0x'+'ab'*40+arguments_hex,'blockNumber':'0x10'}

    def test_static_arguments_are_recovered_from_the_transaction_tail(self):
        # 40 bytes of creation code, then one 32-byte word: the address.
        data=bundle([{'name':'owner','type':'address'}],72,40)
        data['deployment']={'transactionHash':'0x'+'11'*32,'blockNumber':'0x10'}
        pool=self.Pool(self._transaction('00'*12+'ab'*20))
        arguments,evidence=C.recover_constructor_arguments(data,pool,1)
        self.assertIsNotNone(arguments)
        self.assertEqual(evidence['state'],'recovered')
        self.assertEqual(arguments['owner'],'0x'+'ab'*20)

    def test_the_chain_is_queried_through_the_pool(self):
        data=bundle([{'name':'owner','type':'address'}],72,40)
        data['deployment']={'transactionHash':'0x'+'11'*32,'blockNumber':'0x10'}
        pool=self.Pool(self._transaction('00'*12+'ab'*20))
        C.recover_constructor_arguments(data,pool,42220)
        self.assertEqual(pool.calls[0][0],42220)
        self.assertEqual(pool.calls[0][1],'eth_getTransactionByHash')

    def test_a_bundle_without_a_bytecode_pair_is_not_trimmed(self):
        # Without the recompiled code the length of the arguments is unknown,
        # so the payload is left alone and the decode refuses it honestly.
        data=bundle([{'name':'owner','type':'address'}],72,40,with_pair=False)
        data['deployment']={'transactionHash':'0x'+'11'*32,'blockNumber':'0x10'}
        pool=self.Pool(self._transaction('00'*12+'ab'*20))
        arguments,evidence=C.recover_constructor_arguments(data,pool,1)
        self.assertIsNone(arguments)
        self.assertIn('undecodable',evidence['reason'])

    def test_a_creation_transaction_with_no_input_is_refused(self):
        data=bundle([{'name':'owner','type':'address'}],72,40)
        data['deployment']={'transactionHash':'0x'+'11'*32,'blockNumber':'0x10'}
        pool=self.Pool({'input':'0x','blockNumber':'0x10'})
        arguments,evidence=C.recover_constructor_arguments(data,pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['reason'],'creation_transaction_carries_no_input')

    def test_a_block_that_disagrees_with_the_bundle_is_refused(self):
        data=bundle([{'name':'owner','type':'address'}],72,40)
        data['deployment']={'transactionHash':'0x'+'11'*32,'blockNumber':'0x20'}
        pool=self.Pool(self._transaction('00'*12+'ab'*20))
        arguments,evidence=C.recover_constructor_arguments(data,pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['reason'],'creation_transaction_block_disagrees_with_bundle')

    def test_an_unrecoverable_argument_kind_is_refused_before_any_chain_query(self):
        data=bundle([{'name':'a','type':'uint256[]'}],72,40)
        pool=self.Pool(self._transaction('00'*32))
        arguments,evidence=C.recover_constructor_arguments(data,pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['reason'],'constructor_arguments_include_undecodable_kinds')
        self.assertEqual(pool.calls,[])