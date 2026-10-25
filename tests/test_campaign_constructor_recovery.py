import importlib.util, json, sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'scripts'))
import rpc_pool  # noqa: F401
spec=importlib.util.spec_from_file_location('campaign',ROOT/'scripts/defi-campaign.py')
campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)

recover=campaign.recover_constructor_arguments

# A real ABI as solc emits it: the constructor entry carries the declared
# parameters, and a source with no explicit constructor still reports the entry
# with an empty `inputs` list.
PARAMETERISED_ABI=[
    {'type':'constructor','inputs':[{'name':'_feeToSetter','type':'address'}],
     'payable':False,'stateMutability':'nonpayable'},
    {'type':'function','name':'createPair','inputs':[],'outputs':[]}]
NO_ARGUMENT_ABI=[
    {'type':'constructor','inputs':[],'payable':False,'stateMutability':'nonpayable'},
    {'type':'function','name':'deposit','inputs':[],'outputs':[]}]
NO_CONSTRUCTOR_ENTRY=[{'type':'function','name':'deposit','inputs':[],'outputs':[]}]
TUPLE_ABI=[
    {'type':'constructor','inputs':[{'name':'cfg','type':'(address,uint256)'}]}]

DEPLOYER='0x9c33eacc2f50e39940d3afaf2c7b8246b681a374'
# A single `address` argument occupies one 32-byte word, left-padded.
SINGLE_ADDRESS_WORD=DEPLOYER[2:].rjust(64,'0')

class Pool:
    """A pool that answers the one creation-transaction query and nothing else."""
    def __init__(self,input_hex=('0x'+SINGLE_ADDRESS_WORD),block_number='0x9899c3',
                 transaction=None):
        self.input_hex=input_hex
        self.block_number=block_number
        self.transaction=transaction
        self.queries=[]
    def call(self,chain_id,method,params):
        self.queries.append((method,params))
        if method!='eth_getTransactionByHash':
            raise AssertionError(f'unexpected RPC {method}')
        if self.transaction is None:
            self.transaction={'input':self.input_hex,'blockNumber':self.block_number,
                             'transactionHash':params[0]}
        return self.transaction,{'url':'https://rpc.example'}
    def rpc_response(self,*args):
        raise AssertionError('the recovery path must not re-fetch by RPC url')

class RefusesToQuery:
    def call(self,*args):
        raise AssertionError('the chain must not be queried on this path')
    def rpc_response(self,*args):
        raise AssertionError('the chain must not be queried on this path')

def bundle(abi,transaction_hash='0x'+'ab'*32,block_number='0x9899c3',include_deployment=True,
           creation_bytecode=None):
    document={'abi':abi}
    if include_deployment:
        document['deployment']={'transactionHash':transaction_hash,'blockNumber':block_number,
                                'transactionIndex':'0x1','deployer':DEPLOYER}
    if creation_bytecode is not None:
        document['creationBytecode']={'onchainBytecode':creation_bytecode}
    return document


class ConstructorRecoveryTests(unittest.TestCase):
    def test_a_parameterised_constructor_is_decoded_from_the_creation_transaction(self):
        pool=Pool()
        arguments,evidence=recover(bundle(PARAMETERISED_ABI),pool,1)
        self.assertEqual(arguments,{'_feeToSetter':DEPLOYER})
        self.assertEqual(evidence['state'],'recovered')
        self.assertEqual(len(pool.queries),1)
        self.assertEqual(pool.queries[0][0],'eth_getTransactionByHash')

    def test_the_transaction_the_bundle_names_is_the_one_that_is_read(self):
        pool=Pool()
        document=bundle(PARAMETERISED_ABI,transaction_hash='0x'+'cd'*32)
        recover(document,pool,1)
        self.assertEqual(pool.queries[0][1],['0x'+'cd'*32])

    def test_a_transaction_from_a_different_block_is_refused(self):
        # The bundle's deployment record and the transaction the provider hands
        # back have to describe the same deployment.  Agreeing on a block is
        # what ties the recovered arguments to the bytecode the campaign
        # verified, rather than to some other transaction.
        pool=Pool(block_number='0x1')
        arguments,evidence=recover(bundle(PARAMETERISED_ABI,block_number='0x9899c3'),pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['reason'],'creation_transaction_block_disagrees_with_bundle')

    def test_a_no_argument_constructor_needs_no_chain_query(self):
        arguments,evidence=recover(bundle(NO_ARGUMENT_ABI),RefusesToQuery(),1)
        self.assertEqual(arguments,{})
        self.assertEqual(evidence['state'],'not_required')

    def test_a_no_argument_constructor_does_not_depend_on_the_deployment_record(self):
        # Requiring `deployment` here would discard a path that needs no
        # external evidence at all, for no added certainty.
        arguments,evidence=recover(bundle(NO_ARGUMENT_ABI,include_deployment=False),
                                   RefusesToQuery(),1)
        self.assertEqual(arguments,{})
        self.assertEqual(evidence['state'],'not_required')

    def test_a_parameterised_constructor_without_a_creation_transaction_is_reported(self):
        arguments,evidence=recover(bundle(PARAMETERISED_ABI,include_deployment=False),
                                   RefusesToQuery(),1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['state'],'unavailable')
        self.assertEqual(evidence['reason'],'bundle_records_no_creation_transaction')

    def test_an_abi_with_no_constructor_entry_is_reported_rather_than_assumed_empty(self):
        # "Takes no parameters" and "we do not know" are indistinguishable
        # here, and defaulting to empty would deploy a contract that is not the
        # one under review.
        arguments,evidence=recover(bundle(NO_CONSTRUCTOR_ENTRY),RefusesToQuery(),1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['reason'],'constructor_abi_missing')

    def test_a_bundle_without_an_abi_is_reported(self):
        arguments,evidence=recover({'sources':{}},RefusesToQuery(),1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['reason'],'constructor_abi_missing')

    def test_an_undecodable_parameter_is_refused_before_the_chain_is_queried(self):
        arguments,evidence=recover(bundle(TUPLE_ABI),RefusesToQuery(),1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['state'],'unsupported')
        self.assertEqual(evidence['parameters'],['cfg'])

    def test_undecodable_and_parameterless_contracts_are_told_apart(self):
        # Both refuse, but a contract that could never be deployed is a
        # different fact from one whose parameters happen to be unavailable.
        _,unsupported=recover(bundle(TUPLE_ABI),RefusesToQuery(),1)
        _,unavailable=recover(bundle(PARAMETERISED_ABI,include_deployment=False),
                              RefusesToQuery(),1)
        self.assertNotEqual(unsupported['state'],unavailable['state'])

    def test_a_transaction_carrying_no_input_is_reported(self):
        pool=Pool(transaction={'blockNumber':'0x9899c3','transactionHash':'0x'+'ab'*32})
        arguments,evidence=recover(bundle(PARAMETERISED_ABI),pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['reason'],'creation_transaction_carries_no_input')

    def test_a_creation_bytecode_prefix_is_stripped_before_decoding(self):
        # A real calldata is the creation bytecode with the arguments appended,
        # so the arguments are only readable once the provider's own creation
        # bytecode has been removed.
        prefix='0x6080604052348015600f57600080fd5b50'
        pool=Pool(input_hex=prefix+SINGLE_ADDRESS_WORD)
        arguments,evidence=recover(
            bundle(PARAMETERISED_ABI,creation_bytecode=prefix),pool,1)
        self.assertEqual(arguments,{'_feeToSetter':DEPLOYER})
        self.assertTrue(evidence['creationBytecodePrefixStripped'])

    def test_a_payload_whose_prefix_does_not_match_is_refused_not_trimmed(self):
        # Trimming to an assumed length would drop leading bytes of a real
        # argument and could decode a shifted payload into plausible values, so
        # a mismatch is left alone and the wrong word count then fails.
        pool=Pool(input_hex='0x6080604052348015600f57600080fd5b50'+SINGLE_ADDRESS_WORD)
        arguments,evidence=recover(bundle(PARAMETERISED_ABI),pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['state'],'unavailable')
        self.assertFalse(evidence['creationBytecodePrefixStripped'])

    def test_an_undecodable_payload_is_reported_not_raised(self):
        pool=Pool(input_hex='0xdeadbeef')
        arguments,evidence=recover(bundle(PARAMETERISED_ABI),pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['state'],'unavailable')
        self.assertIn('constructor_arguments_undecodable',evidence['reason'])

    def test_an_empty_payload_for_a_declared_parameter_is_reported(self):
        pool=Pool(input_hex='0x')
        arguments,evidence=recover(bundle(PARAMETERISED_ABI),pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence['state'],'unavailable')

    def test_an_rpc_failure_is_reported_rather_than_propagated(self):
        class Failing:
            def call(self,*args): raise TimeoutError('rpc timeout')
            def rpc_response(self,*args): raise AssertionError('must not be reached')
        arguments,evidence=recover(bundle(PARAMETERISED_ABI),Failing(),1)
        self.assertIsNone(arguments)
        self.assertIn('creation_transaction_unavailable',evidence['reason'])

    def test_evidence_names_the_transaction_and_the_block_it_came_from(self):
        pool=Pool()
        _,evidence=recover(bundle(PARAMETERISED_ABI),pool,1)
        self.assertEqual(evidence['transactionHash'],'0x'+'ab'*32)
        self.assertEqual(evidence['blockNumber'],'0x9899c3')
        self.assertTrue(evidence['deploymentBlockCrossChecked'])