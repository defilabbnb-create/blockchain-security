"""A suite forge recorded as passing must not be reported as a detection.

Forge's JSON carries the outcome of every test it ran.  The process exit code
does not: it is one bit for the whole invocation, so a suite that passed and a
suite that reverted in the same run look identical from outside.

Reading only the exit code reported every assertion on the contract as violated
whenever any one of them failed.  On the real collected corpus that was 59 of
106 assertions, including suites the very same document recorded as `Success`.

These tests pin both directions: a recorded pass is not suppressed, and a
recorded failure is not lost because a sibling suite succeeded.
"""
import json, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import dynamic_runner

# The generator (harness_gen.py) names an assertion's file and contract after the
# first 16 characters of its invariantId, and forge keys its JSON by
# `<file>:<contract>`.  Fixtures use ids and suite names built the same way; a
# suite called `Invariant_a` is one the generator can never produce, and a
# fixture built on it only passed because attribution used to match loosely.
IDS=['a1b2c3d4e5f60718'+'0'*48,'b2c3d4e5f6071829'+'0'*48]


def _suite_key(identifier):
    return 'test/Invariant_%s.t.sol:Invariant_%s'%(identifier[:16],identifier[:16])


PROVENANCE=json.dumps({'compiler':{'filename':'soljson-v0.8.29.js','version':'0.8.29',
    'selection':'pragma_range_cached'},'event':'selected_solc'})


def suite(status,reason=None,suite_name=_suite_key(IDS[0])):
    return json.dumps({suite_name:{'duration':'1ms','test_results':{
        'testInvariant()':{'status':status,'reason':reason,'logs':[],
            'decoded_logs':[],'kind':{'Unit':{'gas':27573}}}},'warnings':[]}})


MIXED_PASS_AND_FAIL=(
    suite('Success',suite_name=_suite_key(IDS[0]))
    +'\n'+suite('Failure','EvmError: Revert',suite_name=_suite_key(IDS[1]))
    +'\n'+PROVENANCE+'\n')

ALL_PASS=suite('Success')+'\n'+PROVENANCE+'\n'
ALL_FAIL=suite('Failure','EvmError: Revert')+'\n'+PROVENANCE+'\n'
ALL_SKIP=suite('Skipped')+'\n'+PROVENANCE+'\n'


class PerTestOutcomeTests(unittest.TestCase):
    def test_each_suite_is_read_independently(self):
        outcomes=dynamic_runner._forge_test_outcomes(MIXED_PASS_AND_FAIL.encode())
        self.assertEqual(outcomes,{
            _suite_key(IDS[0]):'success',
            _suite_key(IDS[1]):'failure'})

    def test_a_suite_with_one_failing_test_is_a_failure(self):
        # The first result must not decide it, or a real detection is dropped
        # inside the one suite carrying the evidence.
        document=json.dumps({'test/Invariant.t.sol:Invariant_t':{'test_results':{
            'testA()':{'status':'Success'},'testB()':{'status':'Failure','reason':'revert'}}}})
        outcomes=dynamic_runner._forge_test_outcomes((document+'\n').encode())
        self.assertEqual(outcomes,{'test/Invariant.t.sol:Invariant_t':'failure'})

    def test_the_provenance_line_is_not_read_as_a_suite(self):
        outcomes=dynamic_runner._forge_test_outcomes(ALL_PASS.encode())
        self.assertEqual(len(outcomes),1)

    def test_unparseable_output_yields_nothing_rather_than_a_guess(self):
        outcomes=dynamic_runner._forge_test_outcomes(b'not json at all\n{broken\n')
        self.assertEqual(outcomes,{})

    def test_empty_output_yields_nothing(self):
        self.assertEqual(dynamic_runner._forge_test_outcomes(b''),{})


def manifest(directory, rows=2):
    path=Path(directory)/'h'
    path.mkdir(parents=True,exist_ok=True)
    (path/'harness.json').write_text(json.dumps({'schemaVersion':1,'tests':[
        {'invariantId':IDS[i],'path':'test/Invariant_%s.t.sol'%IDS[i][:16],
         'template':'probe','status':'unverified'}
        for i in range(rows)],'deployment':{'state':'inline_deployment'}}),encoding='utf-8')
    return path


class MixedRunClassificationTests(unittest.TestCase):
    def _states(self,stdout,returncode=1,rows=2):
        with tempfile.TemporaryDirectory() as directory:
            path=manifest(directory,rows)
            forge=Path(directory)/'forge-mock'
            forge.write_text('#!/bin/sh\nprintf %s >&2\nexit %d\n'%(
                json.dumps(stdout.replace("'",'"')),returncode),encoding='utf-8')
            forge.chmod(0o755)
            return {row['invariantId']:row['state'] for row in
                dynamic_runner.run_harness(path,mode='local',forge=forge)}

    def _state(self,stdout,returncode=1,rows=2):
        with tempfile.TemporaryDirectory() as directory:
            path=manifest(directory,rows)
            forge=Path(directory)/'forge-mock'
            forge.write_text('#!/bin/sh\nprintf %s >&2\nexit %d\n'%(
                json.dumps(stdout.replace("'",'"')),returncode),encoding='utf-8')
            forge.chmod(0o755)
            return dynamic_runner.run_harness(path,mode='local',forge=forge)[0]['state']

    def test_a_mixed_run_reports_violated(self):
        # One suite reverted, so the contract did break a property.  Reporting
        # the passing suite as violated as well is what the per-test reading
        # removes; reporting the whole contract as passed is the opposite error.
        # Asserted per row: the previous form read only row 0 -- the suite forge
        # recorded as Success -- and expected `violated`, which is the very
        # spreading of one failure across the contract that this file exists to
        # prevent.
        states=self._states(MIXED_PASS_AND_FAIL)
        self.assertEqual(states,{IDS[0]:'passed',IDS[1]:'violated'})

    def test_an_all_pass_run_is_passed_even_with_a_nonzero_exit(self):
        # Foundry can exit non-zero for reasons unrelated to the assertions.
        self.assertEqual(self._state(ALL_PASS,returncode=1,rows=1),'passed')

    def test_an_all_fail_run_is_violated(self):
        self.assertEqual(self._state(ALL_FAIL,rows=1),'violated')

    def test_an_all_skip_run_is_not_a_pass(self):
        self.assertNotEqual(self._state(ALL_SKIP,rows=1),'passed')

    def test_a_compile_failure_is_reported_as_such(self):
        # A harness whose imports do not resolve never compiles, so nothing was
        # measured.  Reporting that as a missing adapter conflates a missing
        # dependency in the bundle with a template this project cannot render.
        compile_error=('Error: Compiler run failed:\n'
            'Error: Source "openzeppelin-solidity/contracts/math/SafeMath.sol" not found: '
            'File import callback not supported\n')
        self.assertEqual(self._state(compile_error),'unavailable')
        self.assertTrue(dynamic_runner._compilation_failed(compile_error.lower()))

    def test_a_missing_import_is_a_compile_failure(self):
        self.assertTrue(dynamic_runner._compilation_failed(
            b'error: source "x/y.sol" not found: file import callback not supported'.decode()))

    def test_an_ordinary_failure_is_not_a_compile_failure(self):
        self.assertFalse(dynamic_runner._compilation_failed(
            b'evmerror: revert'.decode()))


class PerAssertionAttributionTests(unittest.TestCase):
    """A contract-wide state must not be applied to suites forge cleared."""

    def _run(self,stdout,rows):
        with tempfile.TemporaryDirectory() as directory:
            path=manifest(directory,rows)
            forge=Path(directory)/'forge-mock'
            forge.write_text('#!/bin/sh\nprintf %s >&2\nexit 1\n'
                %json.dumps(stdout.replace("'",'"')),encoding='utf-8')
            forge.chmod(0o755)
            return {row['invariantId']:row for row in
                dynamic_runner.run_harness(path,mode='local',forge=forge)}

    def test_a_reverting_suite_does_not_mark_a_passing_suite_violated(self):
        # The defect this pins: forge is invoked once for the contract, so one
        # reverting suite marked every assertion as violated, including the ones
        # forge had just recorded as Success in the same document.
        attributed=dynamic_runner._attribute_per_suite(
            [{'invariantId':'a'*64},{'invariantId':'b'*64}],
            {'test/Invariant_aaaaaaaaaaaaaaaa.t.sol:Invariant_aaaaaaaaaaaaaaaa':'failure',
             'test/Invariant_bbbbbbbbbbbbbbbb.t.sol:Invariant_bbbbbbbbbbbbbbbb':'success'},
            'violated','forge_assertion_or_compilation_failed')
        self.assertEqual(attributed['a'*64],('violated','forge_assertion_failed'))
        self.assertEqual(attributed['b'*64],('passed',None))

    def test_an_assertion_with_no_identifiable_suite_is_unavailable_not_inherited(self):
        # forge recorded a suite for some other assertion and none for this one,
        # so nothing was measured for it.  Inheriting the invocation's state
        # would file a measurement that never happened as a detection or a pass.
        attributed=dynamic_runner._attribute_per_suite(
            [{'invariantId':'c'*64}],
            {'test/Invariant_aaaaaaaaaaaaaaaa.t.sol:Invariant_aaaaaaaaaaaaaaaa':'failure'},
            'violated','forge_assertion_or_compilation_failed')
        self.assertEqual(attributed['c'*64],('unavailable','suite_result_missing'))

    def test_no_per_test_record_means_no_attribution(self):
        self.assertEqual(dynamic_runner._attribute_per_suite(
            [{'invariantId':'a'*64}],{},'violated','r'),{})


def _forge_document(statuses):
    """One forge JSON document per suite, keyed the way real forge keys them."""
    return '\n'.join(suite(status,'EvmError: Revert' if status=='Failure' else None,
                           suite_name=_suite_key(identifier))
                      for identifier,status in statuses.items())+'\n'+PROVENANCE+'\n'


def _run_ids(identifiers,statuses,returncode):
    """Run the real classifier over a manifest built the way the generator builds it."""
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'h'
        path.mkdir()
        (path/'harness.json').write_text(json.dumps({'schemaVersion':1,'tests':[
            {'invariantId':i,'path':'test/Invariant_%s.t.sol'%i[:16],'template':'probe','status':'unverified'}
            for i in identifiers],'deployment':{'state':'inline_deployment'}}),encoding='utf-8')
        forge=Path(directory)/'forge-mock'
        forge.write_text('#!/bin/sh\nprintf %s >&2\nexit %d\n'%(
            json.dumps(_forge_document(statuses).replace("'",'"')),returncode),encoding='utf-8')
        forge.chmod(0o755)
        return {row['invariantId']:row for row in
            dynamic_runner.run_harness(path,mode='local',forge=forge)}


A='a1b2c3d4e5f60718'+'0'*48
B='b2c3d4e5f6071829'+'0'*48
C='c3d4e5f607182930'+'0'*48


class SuiteMissingFromForgeRecordTests(unittest.TestCase):
    """forge ran some suites; an assertion whose suite it never recorded was not measured."""

    def test_a_missing_suite_is_not_passed_when_every_recorded_suite_passed(self):
        rows=_run_ids([A,B,C],{A:'Success',B:'Success'},returncode=0)
        self.assertEqual(rows[A]['state'],'passed')
        self.assertEqual(rows[B]['state'],'passed')
        self.assertEqual(rows[C]['state'],'unavailable')
        self.assertEqual(rows[C]['reason'],'suite_result_missing')

    def test_a_missing_suite_is_not_violated_when_another_suite_failed(self):
        rows=_run_ids([A,B,C],{A:'Failure',B:'Success'},returncode=1)
        self.assertEqual(rows[A]['state'],'violated')
        self.assertEqual(rows[B]['state'],'passed')
        self.assertEqual(rows[C]['state'],'unavailable')
        self.assertEqual(rows[C]['reason'],'suite_result_missing')

    def test_a_recorded_failure_is_still_violated_and_nothing_else_is(self):
        # The opposite direction: tightening attribution must not suppress a
        # genuine detection, nor spread it to the suites that passed.
        rows=_run_ids([A,B,C],{A:'Success',B:'Failure',C:'Success'},returncode=1)
        self.assertEqual({i:r['state'] for i,r in rows.items()},
            {A:'passed',B:'violated',C:'passed'})

    def test_ids_sharing_an_eight_character_prefix_are_attributed_separately(self):
        first='ab12cd34'+'1'*8+'0'*48
        second='ab12cd34'+'2'*8+'0'*48
        rows=_run_ids([first,second],{first:'Failure',second:'Success'},returncode=1)
        self.assertEqual(rows[first]['state'],'violated')
        self.assertEqual(rows[second]['state'],'passed')

    def test_a_suite_that_only_contains_the_prefix_is_not_a_match(self):
        attributed=dynamic_runner._attribute_per_suite(
            [{'invariantId':A,'path':'test/Invariant_%s.t.sol'%A[:16]}],
            {'test/Other_Invariant_%s_extra.t.sol:Other'%A[:16]:'failure'},
            'violated','forge_assertion_or_compilation_failed')
        self.assertEqual(attributed[A],('unavailable','suite_result_missing'))
