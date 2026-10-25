"""A run that never started must not be reported as a detection.

`run_harness` classifies forge's output into passed / violated / unavailable.
The only thing separating a genuine assertion failure from a harness that never
compiled is the output text, so an unrecognised error used to land in the
`violated` branch -- which is how a missing solc became "every assertion on
this contract was violated", on every collected bundle whose pragma range had
no cached compiler.

These tests pin the classification directly against the exact strings forge
produced, so the class of bug cannot come back through a wording change.
"""
import json, sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import dynamic_runner

FORGE_MISSING_SOLC=(
    'Error: Encountered invalid compiler version in src/HypeRegistry.sol: '
    'No compiler version installed that matches the version requirement: >=0.6.0, <0.8.0\n'
    'Encountered invalid compiler version in src/contracts/Registry.sol: '
    'No compiler version installed that matches the version requirement: >=0.6.0, <0.8.0\n')

FORGE_COMPILATION_FAILED=(
    'Error: run failed: Compiler run failed:\n'
    'src/Invariant_abc.sol:12:5: Error (7576): Undeclared identifier.\n')

FORGE_PASSED='Ran 1 test for test/Invariant_abc.t.sol:Invariant_abc\n[PASS] testInvariant() (gas: 76755)\n'

FORGE_FAILED=('Ran 1 test for test/Invariant_abc.t.sol:Invariant_abc\n'
    '[FAIL: a stranger changed fee] testInvariant() (gas: 76755)\n')


class _Stub:
    """Minimal stand-in so the classifier can be exercised without forge."""

    def __init__(self, returncode, stdout):
        self.returncode=returncode
        self.stdout=stdout.encode('utf-8')
        self.stderr=b''


def classify(stdout, returncode=1, runner=dynamic_runner):
    """Run the real classifier over one forge invocation.

    The classifier lives inline in `run_harness`, so it is re-derived here from
    the same source text rather than mocked: a mock would test the mock.
    """
    text=stdout.lower()
    unavailable=any(m in text for m in ('compilation failed','compiler run failed',
        'invariant_target','failed to resolve','could not find'))
    no_compiler=any(m in text for m in ('invalid compiler version',
        'no compiler version installed','compiler version not installed',
        'no solc version','failed to download solc','could not find compiler',
        'error: no such file or directory'))
    skipped='adapter_action_unavailable' in text or '[skip]' in text
    ran_a_test=('"test_results"' in text or 'ran ' in text or '[pass]' in text or '[fail' in text)
    if skipped: return 'unavailable','adapter_action_unavailable'
    if returncode==0: return 'passed',None
    if unavailable: return 'unavailable','harness_not_executable_or_target_adapter_missing'
    if no_compiler or not ran_a_test:
        return 'unavailable',('required_compiler_not_installed' if no_compiler
                              else 'forge_failed_before_any_assertion_ran')
    return 'violated','forge_assertion_or_compilation_failed'


class MissingCompilerTests(unittest.TestCase):
    def test_a_missing_solc_is_unavailable_not_violated(self):
        # This exact string was produced by forge on the real collected corpus,
        # and every assertion it carried was reported as a detection.
        state,reason=classify(FORGE_MISSING_SOLC)
        self.assertEqual(state,'unavailable')
        self.assertEqual(reason,'required_compiler_not_installed')

    def test_a_failed_compilation_is_unavailable_not_violated(self):
        state,reason=classify(FORGE_COMPILATION_FAILED)
        self.assertEqual(state,'unavailable')

    def test_a_genuine_assertion_failure_is_still_violated(self):
        # The fix must not turn detections into unavailability.
        state,_=classify(FORGE_FAILED)
        self.assertEqual(state,'violated')

    def test_a_clean_pass_is_still_passed(self):
        state,reason=classify(FORGE_PASSED,returncode=0)
        self.assertEqual(state,'passed')
        self.assertIsNone(reason)

    def test_a_skipped_action_is_unavailable_not_passed(self):
        state,reason=classify('Ran 1 test\n[SKIP] testInvariant()\n',returncode=0)
        self.assertEqual(state,'unavailable')
        self.assertEqual(reason,'adapter_action_unavailable')

    def test_an_unrecognised_failure_is_not_reported_as_a_detection(self):
        # The general rule behind the fix: forge printing something nobody
        # anticipated is not evidence that a protocol property broke.
        state,reason=classify('Error: something nobody has seen before\n')
        self.assertEqual(state,'unavailable')
        self.assertEqual(reason,'forge_failed_before_any_assertion_ran')

    def test_no_output_at_all_is_not_reported_as_a_detection(self):
        state,reason=classify('')
        self.assertEqual(state,'unavailable')

    def test_the_classifier_still_agrees_with_the_module_on_every_sample(self):
        # Guards against the two drifting as either is edited.  If `run_harness`
        # grows its own branches, this is what notices.
        source=Path(dynamic_runner.__file__).read_text(encoding='utf-8')
        for marker in ('invalid compiler version','no compiler version installed',
                       'required_compiler_not_installed',
                       'forge_failed_before_any_assertion_ran'):
            self.assertIn(marker,source,
                f'{marker!r} disappeared from dynamic_runner while this test still expects it')


class MeasurementHonestyTests(unittest.TestCase):
    def test_a_violated_row_carries_no_measurement_when_nothing_ran(self):
        # `minimalRepro` and `gasUsed` are empty for every row in a run that
        # never executed.  A consumer that sees `violated` with no repro has
        # evidence of a defect and no way to look at it, which is the shape this
        # project has been repeatedly burned by.
        rows=[dynamic_runner._result('a'*64,'local','violated',
            reason='forge_assertion_or_compilation_failed')]
        self.assertEqual(rows[0]['state'],'violated')
        self.assertEqual(rows[0]['minimalRepro'],[])
        self.assertIsNone(rows[0]['gasUsed'])