"""A field the assertion reads has to exist and have to be reachable.

Two failures of the same kind showed up in the real corpus:

  * A modifier was read as a getter.  `onlyWithdrawalManager` ends with
    `manager`, so a suffix match resolved the access-control assertion to a
    field called `manager` that the contract does not have.  The assertion
    then read a value that was not there and reported a violated privilege
    check on a contract whose privilege check was correct.

  * An `internal` function was read as a getter.  `getBlockNumber()` in a
    Compound-style token is `internal view`, and the rendered assertion's
    `staticcall` against it reverts.  The assertion measured nothing while
    reporting a property.

Both are the same shape: the name resolved to something that cannot carry the
value the assertion is about, and nothing downstream noticed.
"""
import sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import invariant_gen as GEN


class ModifierIsNotAGetterTests(unittest.TestCase):
    """A modifier runs before a function body; it is not callable state."""

    def _modifier(self,name):
        return {'name':f'AMTDepositPool::AMTDepositPool.{name}()','entrypoint':False}

    def test_a_modifier_does_not_match_the_field_it_ends_with(self):
        function=self._modifier('onlyWithdrawalManager')
        self.assertFalse(GEN._function_matches(function,'manager'))

    def test_a_modifier_does_not_match_the_field_it_ends_with_case_insensitively(self):
        function=self._modifier('onlyAdminOrWithdrawalManager')
        self.assertFalse(GEN._function_matches(function,'manager'))

    def test_a_real_getter_still_matches(self):
        function={'name':'C.owner()','entrypoint':False,'visibility':'public'}
        self.assertTrue(GEN._function_matches(function,'owner'))

    def test_a_modifier_named_exactly_like_a_field_is_still_refused(self):
        # The name alone does not make it a getter; the convention and the
        # entry point together do.  `onlyOwner` is a modifier, `owner` is a
        # field.
        function=self._modifier('onlyOwner')
        self.assertFalse(GEN._function_matches(function,'onlyOwner'))
        field={'name':'C.owner()','entrypoint':False,'visibility':'public'}
        self.assertTrue(GEN._function_matches(field,'owner'))

    def test_an_entry_point_named_like_a_modifier_is_still_a_getter(self):
        # A public function called `onlyOwner` is callable and does return a
        # value; refusing it would lose a real field.
        function={'name':'C.onlyOwner()','entrypoint':True,'visibility':'public'}
        self.assertTrue(GEN._function_matches(function,'onlyOwner'))

    def test_a_modifier_is_not_resolved_as_a_getter(self):
        functions=[self._modifier('onlyWithdrawalManager')]
        self.assertIsNone(GEN._first_getter(functions,'manager'))


class InternalIsNotAGetterTests(unittest.TestCase):
    """An `internal` function cannot be called by the assertion."""

    def test_an_internal_function_is_not_callable_from_outside(self):
        function={'name':'TToken::TToken.getBlockNumber()','visibility':'internal'}
        self.assertFalse(GEN._is_callable_from_outside(function))

    def test_a_public_function_is_callable_from_outside(self):
        function={'name':'C.owner()','visibility':'public'}
        self.assertTrue(GEN._is_callable_from_outside(function))

    def test_an_external_function_is_callable_from_outside(self):
        function={'name':'C.totalSupply()','visibility':'external'}
        self.assertTrue(GEN._is_callable_from_outside(function))

    def test_a_function_that_records_no_visibility_is_treated_as_reachable(self):
        # The IR's own functions are user-written; a missing visibility field
        # is not evidence that the function is private.
        function={'name':'C.owner()'}
        self.assertTrue(GEN._is_callable_from_outside(function))

    def test_an_internal_function_is_not_resolved_as_a_getter(self):
        functions=[{'name':'TToken::TToken.getBlockNumber()','visibility':'internal'}]
        self.assertIsNone(GEN._first_getter(functions,'blockNumber'))

    def test_a_public_function_is_resolved_as_a_getter(self):
        functions=[{'name':'TToken::TToken.getBlockNumber()','visibility':'public'}]
        self.assertEqual(GEN._first_getter(functions,'blockNumber'),'blockNumber')


class TheRealCasesTests(unittest.TestCase):
    """The two contracts from the real corpus."""

    def _document(self,functions):
        return {'schemaVersion':1,'functions':functions,
                'storageAccesses':[{'effect':{'variable':'C.admin'}}]}

    def test_the_withdrawal_manager_contract_binds_to_a_real_privilege(self):
        # `AMTDepositPool` guards `adminWithdrawMetis` with
        # `onlyAdminOrWithdrawalManager`, and has an `admin` state variable.
        # The privilege field must be `admin`, not `manager`.
        document=self._document([
            {'name':'AMTDepositPool::AMTDepositPool.onlyAdminOrWithdrawalManager()','entrypoint':False},
            {'name':'AMTDepositPool::AMTDepositPool.onlyWithdrawalManager()','entrypoint':False},
            {'name':'AMTDepositPool::AMTDepositPool.adminWithdrawMetis(uint256)','entrypoint':True},
        ])
        substitutions=GEN._vulnerability_substitutions(document,'access_control',
            abi_getters=('admin()','config()','totalDeposits()'),
            abi_getter_outputs={'admin':['address'],'config':['address'],
                                'totalDeposits':['uint256']})
        self.assertNotEqual(substitutions.get('guardedField'),'manager')

    def test_the_compound_token_binds_to_no_randomness_field(self):
        # `getBlockNumber()` is `internal view`; it is a block counter for
        # interest accrual, not a source of randomness, and no external
        # caller can read it.
        document=self._document([
            {'name':'TToken::TToken.getBlockNumber()','entrypoint':False,'visibility':'internal'},
            {'name':'TToken::TToken.supplyRatePerBlock()','entrypoint':False,'visibility':'public'},
        ])
        substitutions=GEN._vulnerability_substitutions(document,'bad_randomness',
            abi_getters=('exchangeRateStored()','accrualBlockNumber()'),
            abi_getter_outputs={'exchangeRateStored':['uint256'],
                                'accrualBlockNumber':['uint256']})
        self.assertIsNone(substitutions.get('randomnessField'))