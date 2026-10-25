"""A provider can deliver source unit names the rest of the pipeline cannot use.

One collected bundle carried `/Users/cocmb/celo-monorepo/...` -- a path on the
machine the contract was built on.  `harness_gen._safe_source_path` refuses it,
correctly: writing a source unit to an absolute path would place it outside the
harness directory.

The fix normalises names once, at intake, and has to move four things together.
A partial rename is worse than the original problem, because it yields a bundle
that imports nothing and looks merely empty.
"""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('campaign',ROOT/'scripts/defi-campaign.py')
campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)
import harness_gen

normalize=campaign.normalize_source_unit_names

ABSOLUTE={
 'sources':{
  '/Users/build/celo/packages/protocol/contracts/common/Proxy.sol':{'content':'contract Proxy {}'},
  '/Users/build/celo/packages/protocol/contracts/Registry.sol':{'content':'contract Registry {}'},
  'openzeppelin-solidity/contracts/utils/Address.sol':{'content':'library Address {}'},
 },
 'metadata':{'settings':{'compilationTarget':{
  '/Users/build/celo/packages/protocol/contracts/Registry.sol':'Registry'}}},
 'stdJsonInput':{'settings':{'remappings':[
  '/Users/build/celo/packages/protocol/contracts/=contracts/']}},
}


class NormalisationTests(unittest.TestCase):
    def test_an_absolute_path_becomes_a_relative_one(self):
        result=normalize(ABSOLUTE)
        for name in result['sources']:
            self.assertFalse(name.startswith('/'),name)
            self.assertNotIn('..',name)
            harness_gen._safe_source_path(name)

    def test_every_source_unit_is_accepted_by_the_generator_guard(self):
        result=normalize(ABSOLUTE)
        for name in result['sources']:
            harness_gen._safe_source_path(name)

    def test_the_compilation_target_is_renamed_too(self):
        # A `compilationTarget` still naming the old path leaves the generator
        # with no target at all, which it reports as
        # `compilation_target_missing_or_ambiguous` -- a silent loss of the
        # thing the harness is built around.
        result=normalize(ABSOLUTE)
        targets=result['metadata']['settings']['compilationTarget']
        self.assertEqual(list(targets),['Registry.sol'])
        self.assertEqual(list(targets.values()),['Registry'])
        for key in targets:self.assertIn(key,result['sources'])

    def test_a_relative_name_is_left_exactly_as_it_was(self):
        bundle={'sources':{'src/Token.sol':{'content':'contract Token {}'}},
                'metadata':{'settings':{'compilationTarget':{'src/Token.sol':'Token'}}}}
        result=normalize(bundle)
        self.assertEqual(list(result['sources']),['src/Token.sol'])
        self.assertEqual(result['metadata']['settings']['compilationTarget'],
            {'src/Token.sol':'Token'})
        self.assertNotIn('sourceUnitNameNormalizations',result)

    def test_the_original_bundle_is_not_mutated(self):
        original=json.loads(json.dumps(ABSOLUTE))
        normalize(ABSOLUTE)
        self.assertEqual(ABSOLUTE,original)

    def test_two_units_sharing_a_basename_stay_distinct(self):
        # Collapsing them onto one file would silently delete a contract's
        # source and make its imports resolve to the wrong file.
        bundle={'sources':{
         '/Users/a/contracts/Registry.sol':{'content':'contract Registry {}'},
         '/Users/b/contracts/Registry.sol':{'content':'contract Registry2 {}'}},
         'metadata':{'settings':{'compilationTarget':{
          '/Users/a/contracts/Registry.sol':'Registry'}}}}
        result=normalize(bundle)
        names=sorted(result['sources'])
        self.assertEqual(len(names),2)
        self.assertNotEqual(names[0],names[1])
        self.assertEqual(len(set(result['metadata']['settings']['compilationTarget'])),1)

    def test_the_rename_is_recorded_for_the_evidence_record(self):
        # The stored bundle no longer shows what the provider sent, so the
        # transformation has to be readable from the evidence or a reviewer
        # cannot tell a normalised bundle from an altered one.
        result=normalize(ABSOLUTE)
        recorded=result['sourceUnitNameNormalizations']
        self.assertTrue(recorded)
        for row in recorded:
            self.assertTrue(row['from'].startswith('/'))
            self.assertFalse(row['to'].startswith('/'))

    def test_a_bundle_with_no_sources_is_returned_untouched(self):
        self.assertEqual(normalize({}),{})
        self.assertEqual(normalize({'sources':{}}),{'sources':{}})

    def test_content_is_carried_over_unchanged(self):
        result=normalize(ABSOLUTE)
        contents={entry['content'] for entry in result['sources'].values()}
        self.assertEqual(contents,{'contract Proxy {}','contract Registry {}',
                                    'library Address {}'})


@unittest.skipUnless(len(list(ROOT.glob('work/defi-campaign/*/contracts/*/verified-source.json')))>0,
                     'no collected bundles on this machine')
class CollectedBundlesTests(unittest.TestCase):
    def test_every_collected_bundle_becomes_layable(self):
        unusable=[]
        for path in sorted(ROOT.glob('work/defi-campaign/*/contracts/*/verified-source.json')):
            try:
                data=json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                continue
            if not isinstance(data.get('sources'),dict) or not data['sources']:
                continue
            for name in normalize(data)['sources']:
                try:
                    harness_gen._safe_source_path(name)
                except ValueError:
                    unusable.append((path.parent.name,name))
        self.assertEqual(unusable,[],
            'these bundles still carry names the harness generator refuses: '
            f'{unusable[:5]}')

    def test_normalisation_keeps_every_compilation_target_reachable(self):
        broken=[]
        for path in sorted(ROOT.glob('work/defi-campaign/*/contracts/*/verified-source.json')):
            try:
                data=json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                continue
            if not isinstance(data.get('sources'),dict) or not data['sources']:
                continue
            result=normalize(data)
            targets=((result.get('metadata') or {}).get('settings') or {}).get('compilationTarget') or {}
            for key in targets:
                if key not in result['sources']:
                    broken.append((path.parent.name,key))
        self.assertEqual(broken,[],
            f'normalisation left a compilation target pointing at a renamed unit: {broken[:5]}')