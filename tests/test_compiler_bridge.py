"""The forge bridge must be used, or no assertion runs at all.

Foundry resolves solc through its own installed-compiler directory.  This
project does not populate that directory -- every release lives in
work/compiler-cache and is reached through `forge-with-solc.py`.  A bare forge
run therefore fails with "No compiler version installed that matches the version
requirement" before any test executes.

That failure is not loud: forge exits non-zero, and a non-zero exit is what a
failed assertion looks like too.  On the real collected corpus every harness
reported `unavailable` from the missing compiler, and before the classifier was
fixed the same runs reported `violated`.
"""
import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import dynamic_runner

BRIDGE=ROOT/'scripts'/'forge-with-solc.py'


def harness_tree(directory, pragma='^0.7.6'):
    root=Path(directory)/'h'
    (root/'src').mkdir(parents=True)
    (root/'test').mkdir(parents=True)
    (root/'src'/'Target.sol').write_text(
        '// SPDX-License-Identifier: MIT\npragma solidity %s;\n'
        'contract Target { uint256 public n; function bump() external { n += 1; } }\n'%pragma,
        encoding='utf-8')
    (root/'src'/'Harness.sol').write_text(
        '// SPDX-License-Identifier: MIT\npragma solidity %s;\n'
        'library Harness { function answer() internal pure returns (uint256) { return 42; } }\n'%pragma,
        encoding='utf-8')
    (root/'test'/'Probe.t.sol').write_text(
        '// SPDX-License-Identifier: MIT\npragma solidity %s;\n'
        'import "../src/Harness.sol";\n'
        'contract ProbeTest { function testAnswer() public { assert(Harness.answer() == 42); } }\n'%pragma,
        encoding='utf-8')
    (root/'foundry.toml').write_text('[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n',
        encoding='utf-8')
    (root/'harness.json').write_text(json.dumps({'schemaVersion':1,'tests':[
        {'invariantId':'a'*64,'template':'probe','status':'unverified'}],
        'deployment':{'state':'inline_deployment'}}),encoding='utf-8')
    return root


class CompilerBridgeSelectionTests(unittest.TestCase):
    def test_a_harness_with_sources_and_a_cache_is_run_through_the_bridge(self):
        with tempfile.TemporaryDirectory() as work:
            root=harness_tree(work)
            command=dynamic_runner._forge_command(dynamic_runner._default_forge(root),root,
                json.loads((root/'harness.json').read_text()))
            self.assertIn(str(BRIDGE),[str(part) for part in command])

    def test_the_bridge_records_the_compiler_the_manifest_was_built_with(self):
        # `auto` would take the newest release the pragma allows, so a harness
        # built with 0.7.6 would silently be rebuilt with a different release.
        with tempfile.TemporaryDirectory() as work:
            root=harness_tree(work)
            manifest=json.loads((root/'harness.json').read_text())
            manifest['deployment']['compilerVersion']='0.7.6+commit.7338295f'
            command=dynamic_runner._forge_command(dynamic_runner._default_forge(root),root,manifest)
            self.assertEqual(command[command.index('--compiler-version')+1],
                '0.7.6+commit.7338295f')

    def test_a_harness_with_no_solidity_stays_on_the_bare_binary(self):
        with tempfile.TemporaryDirectory() as work:
            root=Path(work)/'h'
            root.mkdir()
            (root/'harness.json').write_text(json.dumps({'schemaVersion':1,'tests':[
                {'invariantId':'a'*64,'status':'unverified'}]}),encoding='utf-8')
            command=dynamic_runner._forge_command(dynamic_runner._default_forge(root),root,{})
            self.assertNotIn(str(BRIDGE),[str(part) for part in command])

    def test_an_explicitly_supplied_bridge_is_still_honoured(self):
        # Callers that pass the bridge themselves -- the benchmark path -- keep
        # working unchanged.
        with tempfile.TemporaryDirectory() as work:
            root=harness_tree(work)
            command=dynamic_runner._forge_command(BRIDGE,root,{})
            self.assertEqual(command[0],sys.executable)
            self.assertEqual(command[1],str(BRIDGE))


@unittest.skipUnless((ROOT/'work'/'tools'/'forge').is_file(),'bundled forge unavailable')
class CompilerBridgeExecutionTests(unittest.TestCase):
    def _run(self,root):
        return subprocess.run(
            [str(c) for c in dynamic_runner._forge_command(
                dynamic_runner._default_forge(root),root,
                json.loads((root/'harness.json').read_text()))],
            cwd=root,capture_output=True,text=True,timeout=300)

    def test_a_pragma_the_cached_compilers_cover_reaches_a_real_verdict(self):
        # The end the whole change exists for: a harness compiled through the
        # bridge passes, where the bare binary reported no installed compiler.
        with tempfile.TemporaryDirectory() as work:
            root=harness_tree(work,'^0.7.6')
            result=self._run(root)
            output=((result.stdout or '')+(result.stderr or '')).lower()
            self.assertNotIn('no compiler version installed',output,
                'the bridge did not resolve a cached compiler for ^0.7.6')
            self.assertEqual(result.returncode,0,output[:400])

    def test_the_bridge_reports_which_compiler_it_chose(self):
        # A verdict with no recorded compiler cannot be tied to the source that
        # produced it.
        with tempfile.TemporaryDirectory() as work:
            root=harness_tree(work,'^0.7.6')
            result=self._run(root)
            output=(result.stdout or '')+(result.stderr or '')
            self.assertIn('soljson-v0.7.6',output)
            self.assertIn('pragma_range_cached',output)