"""A field bound to an assertion has to be able to carry what it claims to.

One candidate pool was shared across every vulnerability class, so each class
bound to whichever field the contract happened to expose first.  An assertion
about a predictable random source was asked of `totalSupply`, which does not
change between two reads, and an assertion about who holds control was asked
of a balance.  Both then ran, both reported, and neither measured the property
it named -- a result that looks like a finding and is not one.

These tests pin the separation: each class resolves its own field, a class
with no matching field resolves to nothing rather than to a plausible one, and
a numeric field is never accepted where a privilege is required.
"""
import sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import invariant_gen as GEN


def document_with(state_names,functions=(),abi_getters=(),abi_getter_outputs=None):
    return {
        'schemaVersion':1,
        'functions':[{'name':name,'entrypoint':True} for name in functions],
        'storageAccesses':[{'effect':{'variable':f'C.{name}'}} for name in state_names],
        'stateVariables':[{'name':name,'type':'uint256'} for name in state_names],
    }


class SharedPoolSeparationTests(unittest.TestCase):
    """Each vulnerability class resolves the field its property is about."""

    def _substitutions(self,role,**kwargs):
        document=document_with(kwargs.get('state_names',()),kwargs.get('functions',()))
        return GEN._vulnerability_substitutions(document,role,
            abi_getters=kwargs.get('abi_getters'),abi_getter_outputs=kwargs.get('abi_getter_outputs'))

    def test_randomness_does_not_bind_to_a_supply_counter(self):
        # The randomness assertion reads the field twice and requires the two
        # reads to differ.  `totalSupply` does not change, so every one of
        # these failed and was reported as a violated randomness property on
        # contracts that contain no randomness at all.
        substitutions=self._substitutions('bad_randomness',
            state_names=('totalSupply','balance'),
            abi_getters=('totalSupply()','balanceOf(address)'))
        self.assertIsNone(substitutions.get('valueField'))

    def test_randomness_binds_to_a_seed_when_the_contract_has_one(self):
        substitutions=self._substitutions('bad_randomness',
            state_names=('totalSupply','randomSeed'),
            abi_getters=('totalSupply()','randomSeed()'))
        self.assertEqual(substitutions.get('randomnessField'),'randomSeed')

    def test_the_two_randomness_templates_resolve_different_fields(self):
        # The randomness template reads the field twice within one block and
        # requires the two reads to differ; the front-running template reads
        # it across two callers and requires those to differ.  One field
        # cannot answer both, so they resolve separately.
        substitutions=self._substitutions('bad_randomness',
            state_names=('totalSupply','randomSeed','price'),
            abi_getters=('totalSupply()','randomSeed()','price()'))
        self.assertEqual(substitutions.get('randomnessField'),'randomSeed')
        self.assertEqual(substitutions.get('outcomeField'),'price')

    def test_access_control_does_not_bind_to_a_numeric_field(self):
        # The access-control assertion asks whether an unprivileged caller
        # changed the state a privileged entry point protects.  A supply
        # counter is not that state.
        substitutions=self._substitutions('access_control',
            state_names=('totalSupply','balance'),
            abi_getters=('totalSupply()','balanceOf(address)','withdraw(uint256)'))
        self.assertIsNone(substitutions.get('guardedField'))

    def test_access_control_binds_to_the_owner(self):
        substitutions=self._substitutions('access_control',
            state_names=('totalSupply','owner'),
            abi_getters=('totalSupply()','owner()','withdraw(uint256)'))
        self.assertEqual(substitutions.get('guardedField'),'owner')

    def test_denial_of_service_does_not_bind_to_a_token_supply(self):
        # `totalSupply` counts tokens, not the members of the collection a
        # loop walks, so the unbounded-work assertion was measuring the wrong
        # size entirely.
        substitutions=self._substitutions('denial_of_service',
            state_names=('totalSupply',),
            abi_getters=('totalSupply()','distribute()'))
        self.assertIsNone(substitutions.get('collectionSize'))

    def test_denial_of_service_binds_to_a_creditor_count(self):
        substitutions=self._substitutions('denial_of_service',
            state_names=('numberCreditors',),
            abi_getters=('numberCreditors()','distribute()'))
        self.assertEqual(substitutions.get('collectionSize'),'numberCreditors')

    def test_arithmetic_still_binds_to_a_numeric_field(self):
        # The arithmetic assertion is about a number, so the shared numeric
        # pool is the right one for it.
        substitutions=self._substitutions('arithmetic',
            state_names=('totalSupply',),
            abi_getters=('totalSupply()',))
        self.assertEqual(substitutions.get('valueField'),'totalSupply')

    def test_front_running_does_not_bind_to_a_balance(self):
        # The front-running assertion compares two callers.  A balance is the
        # caller's own, so it differs for any two callers whatever the
        # protocol does.
        substitutions=self._substitutions('front_running',
            state_names=('balance','totalSupply'),
            abi_getters=('balanceOf(address)','totalSupply()'))
        self.assertIsNone(substitutions.get('valueField'))


class PrivilegeTypeTests(unittest.TestCase):
    """A privilege has to be held in something that can hold one."""

    def test_a_numeric_getter_is_not_a_privilege(self):
        document=document_with(('totalSupply',))
        substitutions=GEN._vulnerability_substitutions(document,'access_control',
            abi_getters=('totalSupply()','withdraw(uint256)'),
            abi_getter_outputs={'totalSupply':['uint256']})
        self.assertIsNone(substitutions.get('guardedField'))

    def test_an_address_getter_is_a_privilege(self):
        document=document_with(('admin',))
        substitutions=GEN._vulnerability_substitutions(document,'access_control',
            abi_getters=('admin()','withdraw(uint256)'),
            abi_getter_outputs={'admin':['address']})
        self.assertEqual(substitutions.get('guardedField'),'admin')

    def test_a_boolean_getter_can_hold_a_pause_flag(self):
        document=document_with(('paused',))
        substitutions=GEN._vulnerability_substitutions(document,'access_control',
            abi_getters=('paused()','pause()'),
            abi_getter_outputs={'paused':['bool']})
        self.assertEqual(substitutions.get('guardedField'),'paused')

    def test_without_output_types_a_numeric_name_is_still_refused(self):
        # The name says what it is; the type confirms it.  A field called
        # `owner` is accepted on its name, and a field called `totalSupply`
        # is not, whatever the ABI failed to report.
        document=document_with(('totalSupply','owner'))
        substitutions=GEN._vulnerability_substitutions(document,'access_control',
            abi_getters=('totalSupply()','owner()','withdraw(uint256)'))
        self.assertEqual(substitutions.get('guardedField'),'owner')