"""Recovered constructor arguments through to a real forge verdict.

The campaign recovers constructor values from a verified bundle's creation
transaction, hands them to the harness generator, and runs the result.  Each of
those three steps can quietly produce a verdict that looks right, so this module
pins the whole chain on a pair that differ by a single `require`.

The pair matters more than the assertion does: `violated` only means anything
because the identical assertion against the identical recovered arguments
reports `passed` on the guarded contract.
"""
import hashlib, importlib.util, json as _json, tempfile, time, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('campaign',ROOT/'scripts/defi-campaign.py')
campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)

import harness_gen, dynamic_runner

GUARDED_FIELD='fee'
ENTRYPOINT='withdrawFees()'
OWNER='0x1111111111111111111111111111111111111111'

# The two contracts differ only by the `require` on the privileged entry.  The
# entry takes no arguments on purpose: the admission probe passes placeholder
# values, so an entry taking `uint256` is called as `withdraw(0)`, which an
# unguarded contract admits without changing any state -- the assertion then
# passes on the defective contract and stops discriminating.
VIOLATING='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    uint256 public fee;
    uint256 public swept;

    constructor(address _owner) {
        owner = _owner;
        fee = 100;
    }

    function withdrawFees() external {
        swept += fee;
        fee = 0;
    }
}
'''

GUARDED='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    uint256 public fee;
    uint256 public swept;

    constructor(address _owner) {
        owner = _owner;
        fee = 100;
    }

    function withdrawFees() external {
        require(msg.sender == owner, "not owner");
        swept += fee;
        fee = 0;
    }
}
'''

_IDENTITY={'role':'access_control','template':'unauthorized_caller_cannot_mutate_state',
            'sourceSha256':None,
            'params':{'guardedField':GUARDED_FIELD,'entrypoint':ENTRYPOINT,'toleranceBps':0},
            'sourceRefs':[]}
INVARIANT_ID=hashlib.sha256(_json.dumps(_IDENTITY,sort_keys=True,ensure_ascii=False,
    separators=(',',':')).encode('utf-8')).hexdigest()


def bundle(source):
    settings={'compilationTarget':{'Vault.sol':'Vault'},
              'optimizer':{'enabled':False,'runs':200},
              'evmVersion':'paris','outputSelection':{'*':{'*':[]}}}
    return {
        'schemaVersion':1,
        'sources':{'Vault.sol':{'content':source}},
        'metadata':{'settings':settings},
        'compilation':{'compilerVersion':'0.8.20+commit.a1b79de6'},
        # The creation transaction is the only chain evidence the recovery uses,
        # and the calldata below is a real ABI encoding of the single `address`
        # parameter, left-padded into one 32-byte word.
        'deployment':{'transactionHash':'0x'+'ab'*32,'blockNumber':'0x10',
                      'transactionIndex':'0x0','deployer':'0x'+'22'*20},
        'creationBytecode':{'onchainBytecode':'0x6080604052348015600f57600080fd5b50'},
        'abi':[{'type':'constructor','inputs':[{'name':'_owner','type':'address'}],
                'payable':False,'stateMutability':'nonpayable'},
               {'type':'function','name':'owner','inputs':[],'outputs':[{'type':'address'}]},
               {'type':'function','name':'fee','inputs':[],'outputs':[{'type':'uint256'}]},
               {'type':'function','name':'swept','inputs':[],'outputs':[{'type':'uint256'}]},
               {'type':'function','name':'withdrawFees','inputs':[],'outputs':[]}],
    }


class Pool:
    def call(self,chain_id,method,params):
        if method!='eth_getTransactionByHash':
            raise AssertionError(f'unexpected RPC {method}')
        calldata='0x'+OWNER[2:].rjust(64,'0')
        return ({'input':'0x6080604052348015600f57600080fd5b50'+OWNER[2:].rjust(64,'0'),
                 'blockNumber':'0x10','transactionHash':params[0]},{'url':'https://rpc.example'})
    def rpc_response(self,*args):
        raise AssertionError('must not be reached')


def run(source):
    """Recover arguments, build the harness, run forge. Returns (state, expression, seconds)."""
    document=bundle(source)
    invariants={'schemaVersion':1,'state':'generated',
                'sourceSha256':harness_gen._source_digest(document['sources']),
                'invariants':[{'invariantId':INVARIANT_ID,'role':'access_control',
                               'template':'unauthorized_caller_cannot_mutate_state',
                               'name':'unauthorized caller must not change fee',
                               'description':'any caller invoking the privileged entry must not change fee',
                               'params':{'guardedField':GUARDED_FIELD,
                                         'entrypoint':ENTRYPOINT,'toleranceBps':0},
                               'preconditions':[],
                               'action':{'kind':'function_call','signature':ENTRYPOINT,
                                         'senderRole':'stranger','expect':'violation'}}],
                'detectedRoles':['access_control']}
    arguments,recovery=campaign.recover_constructor_arguments(document,Pool(),1)
    assert arguments=={'_owner':OWNER}, arguments
    assert recovery['state']=='recovered', recovery
    directory=Path(tempfile.mkdtemp(prefix='ctor-e2e-'))
    deployment=harness_gen.generate_harness(invariants,document,directory/'harness',
        compiler_version=document['compilation']['compilerVersion'],
        constructor_arguments=arguments)
    inner=deployment.get('deployment') or {}
    assert inner.get('state')=='inline_deployment', inner
    started=time.monotonic()
    rows=dynamic_runner.run_harness(directory/'harness',mode='local',timeout_seconds=120)
    elapsed=time.monotonic()-started
    assert len(rows)==1, rows
    return rows[0]['state'], inner.get('expression'), elapsed


class RecoveredConstructorRunTests(unittest.TestCase):
    def test_an_unguarded_privileged_entry_is_reported_as_violated(self):
        state,expression,_=run(VIOLATING)
        self.assertEqual(state,'violated')
        self.assertEqual(expression,f'address(new Vault({OWNER}))')

    def test_the_guarded_contract_passes_the_same_assertion(self):
        # This is the half that gives the first test meaning.  Without it the
        # run only shows that something is detected, not that the detection
        # tracks the property rather than always firing.
        state,_,_=run(GUARDED)
        self.assertEqual(state,'passed')

    def test_the_pair_tells_apart_exactly(self):
        self.assertNotEqual(run(VIOLATING)[0],run(GUARDED)[0])

    def test_the_recovered_argument_reaches_the_deployment_expression(self):
        # The value the chain used has to be the value the contract is built
        # with; a harness that silently deploys a default-constructed copy
        # would measure a contract the chain never had.
        _,expression,_=run(VIOLATING)
        self.assertIn(OWNER,expression)
        self.assertNotIn('()',expression.replace('withdrawFees()',''))


class GeneratedHarnessTargetSelectionTests(unittest.TestCase):
    def test_generated_getters_are_not_public_test_targets(self):
        # forge collects every public function on a test contract as a fuzz
        # target before it runs `testInvariant`.  A public `invariantId()`
        # therefore made it try to stand up an invariant-testing environment,
        # fail with "No contracts to fuzz", and exit non-zero -- which the
        # runner cannot tell from a genuine assertion failure by exit code, so
        # every contract was filed as `violated`.  The benchmark script used to
        # patch this after the file was written; the generator now emits
        # `internal` so no caller can forget it.
        directory=Path(tempfile.mkdtemp(prefix='ctor-vis-'))
        invariants={'schemaVersion':1,'state':'generated',
                    'sourceSha256':None,
                    'invariants':[{'invariantId':'a'*64,
                                   'template':'unauthorized_caller_cannot_mutate_state',
                                   'params':{'guardedField':'fee',
                                             'entrypoint':'withdrawFees()'}}],
                    'detectedRoles':[]}
        harness_gen.generate_harness(invariants,bundle(VIOLATING),directory/'harness',
            compiler_version='0.8.20+commit.a1b79de6',constructor_arguments={'_owner':OWNER})
        tests=list((directory/'harness').rglob('*.t.sol'))
        self.assertEqual(len(tests),1)
        text=tests[0].read_text(encoding='utf-8')
        self.assertNotIn('public constant invariantId',text)
        self.assertNotIn('public constant description',text)
        self.assertIn('internal constant invariantId',text)