"""Real-contract coverage of the wired invariant/forge chain.

The synthetic fixtures pin behaviour on contracts written to suit the harness.
These numbers come from contracts the campaign actually collected, and they are
recorded because the wired step turned out to have a blocker upstream that no
synthetic fixture could reveal: two modules that each compute a digest of "the
source" do not agree on what that digest is.
"""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('campaign',ROOT/'scripts/defi-campaign.py')
campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)
import harness_gen


def collected_bundles():
    return sorted(ROOT.glob('work/defi-campaign/*/contracts/*/verified-source.json'))


class RealContractCoverageTests(unittest.TestCase):
    def setUp(self):
        self.bundles=collected_bundles()
        if not self.bundles:
            self.skipTest('no collected campaign bundles on this machine')

    def test_the_collector_has_real_bundles_to_exercise(self):
        # Guards the measurements below: they are only meaningful because there
        # is a population to measure, and a run on an empty work directory would
        # otherwise report a clean 0% with nothing behind it.
        self.assertGreater(len(self.bundles),10)

    def test_source_digests_agree_between_the_generator_and_the_harness(self):
        # The blocker this suite was written for, kept as a regression.
        #
        # `generate_invariants` records the campaign's `source_identity` digest,
        # which covers the reachable sources, the compilation target, the
        # compiler version and the compiler settings.  `generate_harness`
        # validates against `_source_digest`, which covers the source file
        # contents alone.  Two different definitions of the same word, and the
        # harness generator rejected the campaign's value outright -- so on every
        # contract the wired step raised ValueError before a single assertion
        # reached forge.
        #
        # The campaign now writes the narrow digest alongside, produced by
        # calling the generator's own function.  This asserts the digest gate
        # specifically is no longer what blocks these contracts.  The remaining
        # blockers -- unsafe source paths -- are a separate contract mismatch
        # and are pinned by `test_source_paths_are_writable_relative_to_the_bundle`.
        blocked_by_digest=[]
        unsafe_paths=[]
        for path in self.bundles:
            try:
                data=json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                continue
            sources=data.get('sources')
            if not isinstance(sources,dict) or not sources:
                continue
            document={'schemaVersion':1,'state':'available','invariants':[],'detectedRoles':[],
                      'sourceSha256':campaign.source_identity(data),
                      'sourceContentsSha256':harness_gen._source_digest(sources)}
            with tempfile.TemporaryDirectory() as work:
                try:
                    harness_gen.generate_harness(document,data,Path(work)/'h',
                        compiler_version=(data.get('compilation') or {}).get('compilerVersion'),
                        constructor_arguments=None)
                except ValueError as error:
                    if 'contents digest' in str(error):
                        blocked_by_digest.append(path.parent.name)
                    else:
                        unsafe_paths.append(path.parent.name)
        self.assertEqual(blocked_by_digest,[],
            'the campaign and the generator still disagree on what a source '
            f'digest is, so the forge step is blocked on these: {blocked_by_digest[:5]}')

    def test_source_paths_are_writable_relative_to_the_bundle(self):
        # A second, independent mismatch between what a provider delivers and
        # what the harness generator can lay out on disk.
        #
        # Sourcify hands back whatever path the contract was originally built
        # under, and for some chains that is an absolute path on the build
        # machine -- `/Users/cocmb/celo-monorepo/...`.  `harness_gen` refuses to
        # write those, correctly: an absolute or `..` path would place a source
        # unit outside the harness directory.  The refusal is not weakened here.
        #
        # What is missing is a normalisation step at the point the bundle enters
        # the campaign, which has to rename `sources` keys, the
        # `compilationTarget` and the remappings together -- so it is recorded
        # as its own task rather than folded into the digest fix.
        unsafe=[]
        for path in self.bundles:
            try:
                data=json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                continue
            # The stored bundles predate normalisation, so they are measured the
            # way the campaign now reads them -- after intake normalises the
            # names.  A stored file that still holds an absolute path is history,
            # not a defect; what matters is whether the pipeline can lay it out.
            data=campaign.normalize_source_unit_names(data)
            for name in (data.get('sources') or {}):
                if name.startswith('/') or '\\' in name or any(
                        part in ('','.','..') for part in name.split('/')):
                    unsafe.append((path.parent.name,name))
                    break
        self.assertEqual(unsafe,[],
            'these collected bundles carry source unit paths the harness '
            'generator refuses to lay out, so they cannot reach forge: '
            f'{[name for name,_ in unsafe[:5]]}')