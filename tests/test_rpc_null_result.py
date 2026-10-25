"""A provider that cannot answer must not be recorded as an answer.

Some JSON-RPC providers answer a query they do not serve with a `null`
result instead of an error.  The pool returned that null as if it were the
answer, and the caller read the absence of the answer as the absence of the
thing it asked about: a creation transaction that exists came back as "carries
no input", and the contract was dropped from the corpus on some attempts and
kept on others.

The corpus measurement is only comparable across runs when a contract lands
the same way every time, so a null result has to be a failed read that moves
on to the next endpoint.
"""
import json, sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import rpc_pool
import importlib.util
spec=importlib.util.spec_from_file_location('campaign',ROOT/'scripts/defi-campaign.py')
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


class FakePool:
    """A pool whose answers are scripted, so the behaviour is not the network's."""

    def __init__(self,answers):
        self.answers=list(answers); self.calls=0

    def call(self,chain_id,method,params,timeout=7):
        self.calls+=1
        answer=self.answers.pop(0) if self.answers else None
        if isinstance(answer,Exception): raise answer
        return answer,'https://example.invalid'


class NullResultIsAFailedReadTests(unittest.TestCase):
    def _pool(self,answers):
        from datetime import datetime,timezone
        observed=datetime.now(timezone.utc).isoformat()
        report={'chains':[{'chainId':1,'endpoints':[
            {'url':'https://a.invalid','host':'a.invalid','healthy':True,
             'observedAt':observed,'latencyMs':100},
            {'url':'https://b.invalid','host':'b.invalid','healthy':True,
             'observedAt':observed,'latencyMs':100},
            {'url':'https://c.invalid','host':'c.invalid','healthy':True,
             'observedAt':observed,'latencyMs':100},
        ]}]}
        pool=rpc_pool.RpcPool(report)
        self.answers=list(answers)
        original=rpc_pool.rpc
        def fake(url,method,params,timeout):
            value=self.answers.pop(0)
            if isinstance(value,Exception): raise value
            return value
        rpc_pool.rpc=fake
        self.addCleanup(lambda: setattr(rpc_pool,'rpc',original))
        return pool

    def test_a_null_result_moves_on_to_the_next_endpoint(self):
        pool=self._pool([None,{'input':'0x1234','blockNumber':'0x10'}])
        value,url=pool.call(1,'eth_getTransactionByHash',['0x'+'ab'*32])
        self.assertEqual(value,{'input':'0x1234','blockNumber':'0x10'})
        self.assertEqual(url,'https://b.invalid')

    def test_a_null_result_on_every_endpoint_raises(self):
        pool=self._pool([None,None,None,None,None,None,None])
        with self.assertRaises(RuntimeError):
            pool.call(1,'eth_getTransactionByHash',['0x'+'ab'*32])


class RecoveryDistinguishesNullFromNoInputTests(unittest.TestCase):
    """The recovery's reason has to say which of the two happened."""

    def _bundle(self):
        return {
            'abi':[{'type':'constructor','inputs':[{'name':'x','type':'uint256'}],'stateMutability':'nonpayable'}],
            'deployment':{'transactionHash':'0x'+'ab'*32,'blockNumber':'0x10'},
        }

    def test_a_null_answer_is_reported_as_a_failed_read(self):
        bundle=self._bundle()
        pool=FakePool([None])
        arguments,evidence=C.recover_constructor_arguments(bundle,pool,1)
        self.assertIsNone(arguments)
        self.assertIn('null',evidence.get('reason',''))

    def test_a_transaction_without_input_is_reported_as_no_input(self):
        bundle=self._bundle()
        pool=FakePool([{'input':'0x','blockNumber':'0x10'}])
        arguments,evidence=C.recover_constructor_arguments(bundle,pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence.get('reason'),'creation_transaction_carries_no_input')

    def test_a_transport_failure_is_retried_before_the_contract_is_dropped(self):
        bundle=self._bundle()
        pool=FakePool([RuntimeError('no endpoint'),RuntimeError('no endpoint'),
                       RuntimeError('no endpoint'),RuntimeError('no endpoint'),
                       RuntimeError('no endpoint')])
        original_sleep=time.sleep
        time.sleep=lambda seconds: None
        self.addCleanup(lambda: setattr(C.time,'sleep',original_sleep))
        arguments,evidence=C.recover_constructor_arguments(bundle,pool,1)
        self.assertIsNone(arguments)
        self.assertEqual(evidence.get('attempts'),C.CONSTRUCTOR_READ_RETRIES+1)
        # The first call plus one call per retry.
        self.assertEqual(pool.calls,C.CONSTRUCTOR_READ_RETRIES+1)

    def test_a_retry_that_succeeds_recovers_the_arguments(self):
        bundle=self._bundle()
        bundle['creationBytecode']={'onchainBytecode':'0x6000','recompiledBytecode':'0x60'}
        pool=FakePool([RuntimeError('no endpoint'),
                       {'input':'0x'+'00'*32,'blockNumber':'0x10'}])
        original_sleep=time.sleep
        time.sleep=lambda seconds: None
        self.addCleanup(lambda: setattr(C.time,'sleep',original_sleep))
        arguments,evidence=C.recover_constructor_arguments(bundle,pool,1)
        self.assertIsNotNone(arguments)
        self.assertEqual(evidence.get('state'),'recovered')


import time  # noqa: E402  (used by the retry tests above)