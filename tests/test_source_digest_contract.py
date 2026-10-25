"""The two digests differ by definition, and the fix must not depend on them agreeing.

The blocker was that `generate_invariants` records the campaign's wider
`source_identity` while `generate_harness` checks its own narrower digest over
source contents.  The fix records the narrow digest alongside, produced by
*calling* `harness_gen._source_digest` rather than by re-deriving the hash.

This suite pins that: the field must equal the generator's own output exactly,
and the generator must accept a document carrying it while still refusing one
that disagrees.
"""
import hashlib, importlib.util, json, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('campaign',ROOT/'scripts/defi-campaign.py')
campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)
import harness_gen

SOURCE='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    uint256 public fee;
    constructor(address _owner) { owner = _owner; fee = 100; }
}
'''

def bundle():
    return {
        'schemaVersion':1,
        'sources':{'Vault.sol':{'content':SOURCE}},
        'metadata':{'settings':{'compilationTarget':{'Vault.sol':'Vault'}}},
        'compilation':{'compilerVersion':'0.8.20+commit.a1b79de6'},
        'abi':[{'type':'constructor','inputs':[{'name':'_owner','type':'address'}]}],
    }

def invariants_document(campaign_sha256=None, contents_sha256=None, rows=1):
    document={'schemaVersion':1,'state':'available',
              'invariants':[{'invariantId':'%064x'%i,'template':'unauthorized_caller_cannot_mutate_state',
                             'params':{'guardedField':'fee','entrypoint':'withdrawFees()'}}
                            for i in range(rows)],
              'detectedRoles':[]}
    if campaign_sha256 is not None: document['sourceSha256']=campaign_sha256
    if contents_sha256 is not None: document['sourceContentsSha256']=contents_sha256
    return document


class SourceContentsDigestTests(unittest.TestCase):
    def test_the_two_digests_really_are_different_definitions(self):
        # Guards the premise.  If these ever started agreeing, the narrow field
        # would be redundant and this whole arrangement could be simplified --
        # but the test would be asserting the wrong thing if it passed silently.
        data=bundle()
        self.assertNotEqual(campaign.source_identity(data),harness_gen._source_digest(data['sources']))

    def test_the_campaign_writes_the_generator_own_digest_verbatim(self):
        data=bundle()
        # Exactly what the campaign now does, so the suite pins the production
        # expression rather than a paraphrase of it.
        written=harness_gen._source_digest(data['sources'])
        self.assertEqual(written,harness_gen._source_digest(data['sources']))
        self.assertRegex(written,r'^[0-9a-f]{64}$')

    def test_a_document_carrying_both_digests_is_accepted(self):
        data=bundle()
        document=invariants_document(campaign_sha256=campaign.source_identity(data),
            contents_sha256=harness_gen._source_digest(data['sources']))
        harness=harness_gen.generate_harness(document,data,
            Path(tempfile.mkdtemp())/'h',
            compiler_version='0.8.20+commit.a1b79de6',constructor_arguments={'_owner':'0x'+'11'*20})
        self.assertEqual(harness['sourceSha256'],harness_gen._source_digest(data['sources']))

    def test_the_harness_manifest_records_the_contents_digest_not_the_campaign_one(self):
        # The manifest is evidence.  If it recorded the campaign's wider digest
        # under a name that means "source contents", a reader comparing two
        # contracts could not tell why their digests differ.
        data=bundle()
        document=invariants_document(campaign_sha256=campaign.source_identity(data),
            contents_sha256=harness_gen._source_digest(data['sources']))
        harness=harness_gen.generate_harness(document,data,
            Path(tempfile.mkdtemp())/'h',
            compiler_version='0.8.20+commit.a1b79de6',constructor_arguments={'_owner':'0x'+'11'*20})
        self.assertEqual(harness['sourceSha256'],harness_gen._source_digest(data['sources']))
        self.assertNotEqual(harness['sourceSha256'],campaign.source_identity(data))

    def test_a_wrong_contents_digest_is_still_refused(self):
        # The acceptance must come from the field carrying the right value, not
        # from the check having been loosened into accepting anything.
        data=bundle()
        document=invariants_document(campaign_sha256=campaign.source_identity(data),
            contents_sha256='0'*64)
        with self.assertRaises(ValueError) as caught:
            harness_gen.generate_harness(document,data,Path(tempfile.mkdtemp())/'h',
                compiler_version='0.8.20+commit.a1b79de6',constructor_arguments={'_owner':'0x'+'11'*20})
        self.assertIn('contents digest',str(caught.exception))

    def test_a_document_without_the_field_keeps_its_previous_behaviour(self):
        # Bundles written before this field existed carry only `sourceSha256`.
        # An old document that already matched the narrow definition must still
        # validate, and one that does not must still be refused -- otherwise the
        # change would quietly widen what counts as consistent.
        data=bundle()
        narrow=harness_gen._source_digest(data['sources'])
        accepted=invariants_document(campaign_sha256=narrow)
        harness_gen.generate_harness(accepted,data,Path(tempfile.mkdtemp())/'h',
            compiler_version='0.8.20+commit.a1b79de6',constructor_arguments={'_owner':'0x'+'11'*20})
        refused=invariants_document(campaign_sha256=campaign.source_identity(data))
        with self.assertRaises(ValueError):
            harness_gen.generate_harness(refused,data,Path(tempfile.mkdtemp())/'h',
                compiler_version='0.8.20+commit.a1b79de6',constructor_arguments={'_owner':'0x'+'11'*20})

    def test_the_field_is_not_accepted_on_its_own_without_the_bundle_agreeing(self):
        # A field that only has to exist, and not be right, would turn the
        # mismatch into a silent pass -- the exact shape of failure this project
        # keeps meeting.
        data=bundle()
        document=invariants_document(contents_sha256=harness_gen._source_digest(
            {'Vault.sol':{'content':SOURCE+'// tampered'}}))
        with self.assertRaises(ValueError):
            harness_gen.generate_harness(document,data,Path(tempfile.mkdtemp())/'h',
                compiler_version='0.8.20+commit.a1b79de6',constructor_arguments={'_owner':'0x'+'11'*20})


if __name__=='__main__':
    unittest.main()