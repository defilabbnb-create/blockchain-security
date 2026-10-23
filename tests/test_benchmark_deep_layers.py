import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'benchmark_deep_layers', ROOT / 'scripts' / 'benchmark-deep-layers.py')
DEEP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEEP)


EVAL = importlib.util.spec_from_file_location('deep_eval_pipeline', ROOT / 'scripts' / 'eval_pipeline.py')
EVAL_PIPELINE = importlib.util.module_from_spec(EVAL)
EVAL.loader.exec_module(EVAL_PIPELINE)


class ExecutionBoundaryTests(unittest.TestCase):
    """The deep layers must declare the same boundary the poc runner validates."""

    def _row(self, boundary):
        return {'caseId': 'case', 'sourceSha256': 'a' * 64, 'compilerVersion': '0.8.19',
                'compilerArtifactSha256': 'b' * 64, 'executionBoundary': boundary}

    def test_boundary_matches_the_binding_contract(self):
        boundary = DEEP._local_execution_boundary()
        accepted = DEEP._binding_error('case', 'a' * 64, '0.8.19', 'b' * 64, self._row(boundary))
        self.assertIsNone(accepted, f'binding rejected a valid boundary: {accepted}')

    def test_forged_boundary_is_rejected(self):
        forged = DEEP._local_execution_boundary()
        forged['networkWrites'] = 'remote'
        self.assertEqual(
            DEEP._binding_error('case', 'a' * 64, '0.8.19', 'b' * 64, self._row(forged)),
            'runner_execution_boundary_mismatch')

    def test_wrong_source_hash_is_rejected(self):
        boundary = DEEP._local_execution_boundary()
        self.assertEqual(
            DEEP._binding_error('case', 'c' * 64, '0.8.19', 'b' * 64, self._row(boundary)),
            'runner_source_hash_mismatch')

    def test_offline_environment_removes_every_remote_endpoint(self):
        environment = DEEP.offline_environment()
        for key in DEEP.OFFLINE_STRIPPED_ENV:
            self.assertNotIn(key, environment)
        self.assertEqual(environment['FOUNDRY_OFFLINE'], 'true')
        self.assertNotIn('SOLC_VERSION', environment)


class EvidenceShapeTests(unittest.TestCase):
    """eval_pipeline reads these files by literal key; the shape must stay exact."""

    def _write(self, payload):
        directory = Path(tempfile.mkdtemp())
        (directory / 'invariants.json').write_text(json.dumps(payload), encoding='utf-8')
        return directory

    def test_recognised_invariant_document_is_scored(self):
        source = 'a' * 64
        directory = self._write({'state': 'completed', 'sourceSha256': source,
                                 'detectedIssues': [], 'outcome': 'passed'})
        value, reason = EVAL_PIPELINE._read_layer_file(directory, ('invariants.json',), source)
        self.assertIsNone(reason)
        self.assertEqual(value['state'], 'completed')

    def test_source_hash_mismatch_is_not_scored(self):
        directory = self._write({'state': 'completed', 'sourceSha256': 'b' * 64,
                                 'detectedIssues': []})
        value, reason = EVAL_PIPELINE._read_layer_file(directory, ('invariants.json',), 'a' * 64)
        self.assertIsNone(value)
        self.assertEqual(reason, 'evidence_source_hash_mismatch')

    def test_translated_key_is_not_accepted_as_the_read_field(self):
        """Only findings/issues/detected are read; detectedIssues is normalised upstream.

        Passing a document straight to _layer_evidence with detectedIssues, and no
        upstream normalisation, must not silently read as a scored empty set from an
        unrecognised key: the shape check is what catches a renamed field.
        """
        self.assertEqual(
            EVAL_PIPELINE._layer_evidence({'invariants': {'state': 'scored',
                                                          'detectedIssues': []}},
                                          'invariants'),
            ('unavailable', [], 'evidence_shape_unknown'))
        # 'issues' is a documented alias, so it is accepted rather than rejected.
        self.assertEqual(
            EVAL_PIPELINE._layer_evidence({'invariants': {'state': 'scored', 'issues': []}},
                                          'invariants'),
            ('scored', [], None))
        # A non-string observation list is still rejected.
        self.assertEqual(
            EVAL_PIPELINE._layer_evidence({'invariants': {'state': 'scored',
                                                          'detected': [{'a': 1}]}},
                                          'invariants'),
            ('unavailable', [], 'evidence_shape_invalid'))

    def test_empty_detected_issues_is_a_measured_zero_not_a_gap(self):
        # The real pipeline normalises detectedIssues into findings first; an
        # explicitly empty list must stay scoreable rather than becoming a gap.
        source = 'a' * 64
        directory = self._write({'state': 'completed', 'sourceSha256': source,
                                 'detectedIssues': [], 'outcome': 'passed'})
        evidence = EVAL_PIPELINE._case_layer_evidence(directory, source)
        state, observations, reason = EVAL_PIPELINE._layer_evidence(evidence, 'invariants')
        self.assertEqual(state, 'scored')
        self.assertEqual(observations, [])
        self.assertIsNone(reason)

    def test_unavailable_layer_is_excluded_from_metrics(self):
        source = 'a' * 64
        directory = self._write({'state': 'unavailable', 'sourceSha256': source,
                                 'reason': 'invariant_templates_unavailable', 'detectedIssues': []})
        evidence = EVAL_PIPELINE._case_layer_evidence(directory, source)
        state, observations, reason = EVAL_PIPELINE._layer_evidence(evidence, 'invariants')
        self.assertEqual(state, 'unavailable')
        self.assertEqual(observations, [])
        self.assertEqual(reason, 'invariant_templates_unavailable')


class DetectionLabelTests(unittest.TestCase):
    """Labels are compared to ground truth by exact string, so none may be invented."""

    def test_divergence_labels_would_never_match_ground_truth(self):
        # Documents why detectedIssues stays empty: the repository has no mapping
        # from an IR divergence or a template name to a vulnerability class.
        self.assertEqual(EVAL_PIPELINE.score_case(['erc4626_donation'],
                                                  ['ir_reconcile:0xdeadbeef']),
                         {'truePositiveCount': 0, 'falsePositiveCount': 1, 'falseNegativeCount': 1})
        self.assertEqual(EVAL_PIPELINE.score_case(['erc4626_donation'],
                                                  ['share_price_monotonic']),
                         {'truePositiveCount': 0, 'falsePositiveCount': 1, 'falseNegativeCount': 1})

    def test_empty_observation_set_scores_as_a_true_negative(self):
        self.assertEqual(EVAL_PIPELINE.score_case([], []),
                         {'truePositiveCount': 0, 'falsePositiveCount': 0, 'falseNegativeCount': 0})


class GeneratedWrapperCompatibilityTests(unittest.TestCase):
    """The wrappers must compile under the compilers the corpus pins.

    Every assertion here exists because the corresponding breakage made the whole
    invariants layer report `unavailable` for reasons that had nothing to do with
    the contract under test.
    """

    def test_legacy_and_modern_compilers_sit_on_opposite_sides_of_the_cast(self):
        # A contract instance converts to `address` implicitly in 0.4 and only
        # with an explicit cast from 0.5 on.  The minor version is what carries
        # the distinction -- every release in this corpus is numbered `0.x`.
        self.assertEqual(DEEP._major('0.4.10'), 4)
        self.assertEqual(DEEP._major('0.4.26'), 4)
        self.assertEqual(DEEP._major('0.5.0'), 5)
        self.assertEqual(DEEP._major('0.8.19'), 5)

    def test_unknown_version_falls_to_the_side_that_fails_loudly(self):
        # An unparsable version must not silently pick the permissive spelling.
        self.assertGreater(DEEP._major('nightly'), 5)

    def test_generated_pragma_follows_the_target_instead_of_a_fixed_floor(self):
        harness_gen = DEEP._module('harness_gen.py', 'harness_gen_pragma_test')
        pinned = {'a.sol': {'content': 'pragma solidity 0.4.10;\ncontract A {}\n'}}
        self.assertEqual(harness_gen._pragma_for_sources(pinned), '0.4.10')
        ranged = {'b.sol': {'content': 'pragma solidity ^0.8.19;\ncontract B {}\n'}}
        # A range carries no version to copy, so the floor has to sit below the
        # oldest compiler in the corpus; a higher floor silently excluded the
        # 0.4.10-0.4.21 half of it.
        self.assertEqual(harness_gen._pragma_for_sources(ranged), '>=0.4.11')
        # The generated locals spell out `uint256` below 0.4.22, where the `uint`
        # alias does not exist.
        self.assertTrue(harness_gen._is_pre_0_4_22('0.4.19'))
        self.assertFalse(harness_gen._is_pre_0_4_22('0.8.19'))
        self.assertTrue(harness_gen._is_pre_0_4_22('>=0.4.11'))

    def test_narrowest_pinned_version_wins(self):
        harness_gen = DEEP._module('harness_gen.py', 'harness_gen_pragma_min')
        sources = {'a.sol': {'content': 'pragma solidity 0.8.19;\n'},
                   'b.sol': {'content': 'pragma solidity 0.4.26;\n'}}
        self.assertEqual(harness_gen._pragma_for_sources(sources), '0.4.26')

    def test_rendered_template_uses_no_post_0_4_syntax(self):
        harness_gen = DEEP._module('harness_gen.py', 'harness_gen_template_test')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = 'pragma solidity 0.4.26;\ncontract Vault {}\n'
            bundle = {'sources': {'Vault.sol': {'content': source}},
                      'metadata': {'settings': {'compilationTarget': {'Vault.sol': 'Vault'}}}}
            invariants = {'schemaVersion': 1, 'invariants': [{
                'invariantId': 'a' * 64, 'template': 'arithmetic_result_never_wraps',
                'name': 'wrap', 'description': 'd',
                'params': {'valueField': 'totalSupply', 'toleranceBps': 0}}]}
            harness_gen.generate_harness(invariants, bundle, root / 'harness')
            rendered = (root / 'harness' / 'test' / f'Invariant_{"a" * 16}.t.sol').read_text(encoding='utf-8')
        # `string calldata`, `.code.length` and `uint160(uint256(...))` all fail to
        # parse under 0.4.x, which is what left every assertion unable to run.
        # Comments are stripped first: the template documents the forms it avoids,
        # and matching those would fail on the explanation rather than the code.
        code = re.sub(r'//[^\n]*', '', rendered)
        self.assertNotIn('calldata', code)
        self.assertNotIn('.code.length', code)
        self.assertNotIn('uint160(', code)
        self.assertNotIn('.staticcall', code)
        self.assertIn('pragma solidity 0.4.26;', rendered)

    def test_profile_enables_the_ir_pipeline_the_stack_limit_needs(self):
        harness_gen = DEEP._module('harness_gen.py', 'harness_gen_profile_test')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = {'sources': {'V.sol': {'content': 'pragma solidity 0.8.19;\ncontract V {}\n'}},
                      'metadata': {'settings': {'compilationTarget': {'V.sol': 'V'}}}}
            invariants = {'schemaVersion': 1, 'invariants': []}
            harness_gen.generate_harness(invariants, bundle, root / 'harness')
            profile = (root / 'harness' / 'foundry.toml').read_text(encoding='utf-8')
        # A gate holding several ledger reads exceeds the legacy 16-slot stack and
        # fails with a compiler internal error that names nothing about the target.
        self.assertIn('via_ir = true', profile)
        self.assertIn('optimizer = true', profile)


class InvariantTemplateResolutionTests(unittest.TestCase):
    """Roles and vulnerability classes are named on two different axes."""

    def setUp(self):
        self.gen = DEEP._module('invariant_gen.py', 'invariant_gen_alias_test')

    def test_every_role_that_has_templates_resolves_them(self):
        # The template table is keyed by class name (`reentrancy_guard_rechecked`)
        # while the detectors report the class (`reentrancy`).  Matching on the
        # role alone resolved four of thirteen roles and produced zero assertions
        # for every sample in the suite.
        for role in ('reentrancy', 'access_control', 'arithmetic', 'bad_randomness',
                     'denial_of_service', 'unchecked_low_level_call'):
            key = self.gen._VULNERABILITY_TEMPLATE_ALIASES.get(role)
            self.assertIsNotNone(key, f'{role} has no template entry')
            self.assertTrue(self.gen.VULNERABILITY_TEMPLATES.get(key),
                            f'{role} resolves to an empty template set')

    def test_alias_names_a_real_template_table_key(self):
        for role, key in self.gen._VULNERABILITY_TEMPLATE_ALIASES.items():
            self.assertIn(key, self.gen.VULNERABILITY_TEMPLATES, role)

    def test_role_without_templates_yields_none_rather_than_a_guess(self):
        # `front_running` has no template; inventing one would be the exact
        # fabrication this layer exists to avoid.
        self.assertIsNone(self.gen._VULNERABILITY_TEMPLATE_ALIASES.get('front_running'))


class GeneratedDialectTests(unittest.TestCase):
    """The deployment wrapper is written in the dialect of its target.

    Each of these spellings was verified against a real compiler: `emit` did not
    exist before 0.4.21, `require` took no revert reason before 0.4.22, `uint` was
    not an alias before 0.4.22, and a contract converted to `address` implicitly
    only before 0.5.  Emitting any of them outside their range makes the
    deployment fail with a parser error that names nothing about the target.
    """

    def _wrapper(self, version):
        case = {'sourceText': 'pragma solidity ^%s;\ncontract Target {}\n' % version,
                'sourceName': 'Target.sol', 'groundTruth': {'solcVersion': version}}
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory)
            (harness / 'test').mkdir()
            (harness / 'src').mkdir()
            compiled = {'artifact': {'abi': []}, 'contractName': 'Target'}
            captured = {}

            def fake(args, *, cwd, environment, timeout=240, version=None):
                return subprocess.CompletedProcess(args, 0, 'Ran 1 test\nPASS\n', '')

            original = DEEP._forge_with_solc
            DEEP._forge_with_solc = fake
            try:
                DEEP._local_deployment(case, harness, compiled)
            finally:
                DEEP._forge_with_solc = original
            captured['text'] = (harness / 'test' / 'DeepTarget.t.sol').read_text(encoding='utf-8')
            return captured['text']

    def test_emit_is_used_only_from_0_4_21(self):
        self.assertIn('emit TargetDeployed(', self._wrapper('0.4.25'))
        self.assertNotIn('emit ', self._wrapper('0.4.19'))

    def test_require_reason_is_used_only_from_0_4_22(self):
        self.assertIn('require(deployedSize > 0,', self._wrapper('0.4.25'))
        self.assertIn('require(deployedSize > 0);', self._wrapper('0.4.19'))

    def test_uint_alias_is_used_only_from_0_4_22(self):
        self.assertIn('uint deployedSize;', self._wrapper('0.4.25'))
        self.assertIn('uint256 deployedSize;', self._wrapper('0.4.19'))

    def test_contract_to_address_cast_is_explicit_from_0_5(self):
        self.assertIn('address(deployed)', self._wrapper('0.8.19'))
        # 0.4 allows the bare form, and spelling the cast there is itself an error.
        self.assertNotIn('address(deployed)', self._wrapper('0.4.19'))

    def test_generated_wrapper_carries_no_backticked_comments(self):
        # A 0.4.19 lexer rejects a `//` comment containing a backtick and reports
        # the following line as the syntax error, which misdirects the diagnosis.
        for version in ('0.4.19', '0.8.19'):
            text = self._wrapper(version)
            self.assertNotIn('`', text, version)


class PreReleaseDialectTests(unittest.TestCase):
    """The generated harness parses on the oldest compiler the corpus pins.

    `interface`, `view`, `pure` and destructuring a call result all arrived in
    0.4.11, and 0.4.10 is a pinned corpus version.  Every one of those spellings
    failed to parse in the generated harness, and the run reported every one of
    those samples as "local deployment produced no address" -- a failure caused by
    the harness rather than by the contract under test.
    """

    def _harness(self, version):
        harness_gen = DEEP._module('harness_gen.py', 'harness_gen_dialect')
        invariants = {'schemaVersion': 1, 'sourceSha256': None,
                      'invariants': [{'invariantId': 'a' * 64,
                                      'template': 'unbounded_work_is_bounded',
                                      'description': 'work is bounded',
                                      'params': {'toleranceBps': 0}}]}
        source = 'pragma solidity >=0.4.11;\ncontract Target { }\n'
        bundle = {'sources': {'Target.sol': {'content': source}},
                  'metadata': {'settings': {'compilationTarget': {'Target.sol': 'Target'}}},
                  'abi': []}
        with tempfile.TemporaryDirectory() as directory:
            manifest = harness_gen.generate_harness(invariants, bundle, Path(directory),
                                                    compiler_version=version)
            self.assertEqual(manifest.get('adapterRequiredCount'), 0)
            tests = [row for row in manifest['tests'] if row.get('path')]
            path = Path(directory) / tests[0]['path']
            return path.read_text(encoding='utf-8')

    def test_pragma_follows_the_graded_compiler_not_the_source(self):
        # The sample's own pragma reads `>=0.4.11` while its ground truth names
        # 0.4.10; pinning upward left forge with no installed compiler at all.
        self.assertIn('pragma solidity 0.4.10;', self._harness('0.4.10'))

    def test_no_interface_before_0_4_11(self):
        text = self._harness('0.4.10')
        self.assertNotIn('interface Vm', text)
        self.assertIn('contract Vm', text)

    def test_no_view_or_pure_before_0_4_11(self):
        text = self._harness('0.4.10')
        self.assertNotIn(' private view ', text)
        self.assertNotIn(' private pure ', text)

    def test_modern_compilers_keep_interface_view_and_pure(self):
        text = self._harness('0.8.19')
        self.assertIn('interface Vm', text)
        self.assertIn('private view', text)
        self.assertIn('private pure', text)

    def test_mapping_call_helper_is_always_present(self):
        # The selector hash lives in the harness rather than inline, because the
        # one-argument `keccak256` does not parse before 0.5.
        for version in ('0.4.10', '0.8.19'):
            self.assertIn('function _encodeCall(', self._harness(version), version)

    def test_reads_never_destructure_a_call_result_inline(self):
        from invariant_assertions import _common
        rendered = _common.static_read('t', 'balances(address)', 'guard')
        self.assertNotIn('(bool guardOkRaw, bytes memory guardDataRaw) =', rendered)

    def test_entry_call_does_not_destructure_inline(self):
        from invariant_assertions import _common
        rendered = _common.entry_call('t', 'withdraw()', 'entry')
        self.assertNotIn('(bool entryOk, bytes memory entryData) =', rendered)


class CompiledGetterVisibilityTests(unittest.TestCase):
    """A `public` state variable is readable even when the IR never lists it.

    The IR's function list is the Slither call graph, which walks user-written
    functions only.  Solidity synthesises the getter for `uint256 public fee`,
    so `fee()` is callable and appears in the ABI, yet nothing in the call graph
    records it.  Resolving parameters purely from that list left every contract
    whose ledger is a plain public field looking like it exposed no readable
    state, and all of its role assertions were dropped as adapter-required.
    """

    def setUp(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        import invariant_gen
        self.gen = invariant_gen

    def _document(self, state, functions):
        return {'contract': {'name': 'Pool', 'sourceSha256': 'a' * 64},
                'storageAccesses': [{'effect': {'variable': name, 'type': 'uint256'}}
                                    for name in state],
                'functions': functions}

    def test_abi_getter_resolves_a_field_the_ir_does_not_list(self):
        document = self._document(['fee'], [
            {'name': 'swap(uint256)', 'visibility': 'external'}])
        subs = self.gen._vulnerability_substitutions(
            document, 'access_control', abi_getters=['fee()', 'withdrawFees()'])
        self.assertEqual('fee', subs['guardedField'])

    def test_field_name_is_used_verbatim_when_it_is_the_getter(self):
        # `badDebt` is the field *and* the getter; capitalising it finds nothing.
        document = self._document(['badDebt'], [
            {'name': 'liquidate(address,uint256)', 'visibility': 'external'}])
        subs = self.gen._vulnerability_substitutions(
            document, 'arithmetic', abi_getters=['badDebt()'])
        self.assertEqual('badDebt', subs['valueField'])

    def test_entrypoint_is_resolved_from_the_abi_when_ir_has_no_match(self):
        document = self._document(['fee'], [
            {'name': 'swap(uint256)', 'visibility': 'external'}])
        subs = self.gen._vulnerability_substitutions(
            document, 'access_control', abi_getters=['fee()', 'withdrawFees()'])
        # The renderer embeds this value verbatim into `abi.encodeWithSignature`,
        # so it has to carry the empty argument list itself.
        self.assertEqual('withdrawFees()', subs['entrypoint'])

    def test_unknown_name_is_still_refused(self):
        # Feeding the ABI names through must not weaken the refusal to invent a
        # field: a name the compiler never reported stays unresolved.
        document = self._document(['fee'], [
            {'name': 'swap(uint256)', 'visibility': 'external'}])
        subs = self.gen._vulnerability_substitutions(
            document, 'access_control', abi_getters=['fee()'])
        self.assertIsNone(subs['entrypoint'])

    def test_non_identifier_abi_name_is_discarded(self):
        document = self._document(['fee'], [
            {'name': 'swap(uint256)', 'visibility': 'external'}])
        subs = self.gen._vulnerability_substitutions(
            document, 'access_control', abi_getters=['withdrawFees("); revert();//'])
        self.assertIsNone(subs['entrypoint'])

    def test_generated_row_carries_the_resolved_signature_not_a_literal(self):
        # The generator resolves `balances(address)` from the compiled ABI, but a
        # template that pinned `guardField: 'balances'` discarded it and emitted a
        # call the target does not implement.  This is the end-to-end check that
        # the resolved value survives all the way into the generated row.
        document = self._document(['balances'], [
            {'name': 'withdraw(uint256)', 'visibility': 'external'}])
        source = ('pragma solidity ^0.5.0;\ncontract Target {\n'
                  '  mapping(address => uint256) public balances;\n'
                  '  function withdraw(uint256 amount) external {\n'
                  '    require(balances[msg.sender] >= amount);\n'
                  '    msg.sender.transfer(amount);\n'
                  '    balances[msg.sender] -= amount;\n  }\n}\n')
        generated = self.gen.generate_invariants(
            document, source_sha256='a' * 64, source_text=source,
            abi_getters=['balances(address)', 'withdraw(uint256)'])
        rows = [row for row in generated['invariants']
                if row['template'] == 'state_update_precedes_external_call']
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual('balances(address)', row['params']['guardField'])
            self.assertEqual('balances(address)', row['params']['valueField'])

    def test_resolved_row_renders_a_call_the_target_answers(self):
        document = self._document(['balances'], [
            {'name': 'withdraw(uint256)', 'visibility': 'external'}])
        source = ('pragma solidity ^0.5.0;\ncontract Target {\n'
                  '  mapping(address => uint256) public balances;\n'
                  '  function withdraw(uint256 amount) external {\n'
                  '    require(balances[msg.sender] >= amount);\n'
                  '    msg.sender.transfer(amount);\n'
                  '    balances[msg.sender] -= amount;\n  }\n}\n')
        generated = self.gen.generate_invariants(
            document, source_sha256='a' * 64, source_text=source,
            abi_getters=['balances(address)', 'withdraw(uint256)'])
        row = next(r for r in generated['invariants']
                   if r['template'] == 'state_update_precedes_external_call')
        import invariant_assertions.vuln as vuln
        body = vuln.RENDERERS[row['template']](
            row['params'], {'contract_name': 'Target', 'target_addr_expr': 'target'})
        self.assertIsInstance(body, str)
        # The target implements `balances(address)` only; the scalar form reverts.
        self.assertNotIn('"balances()"', body)
        # The argument must be ABI-encoded as a value.  Passing the call expression
        # inside the signature string makes the target find no matching function,
        # which surfaced as "balances(address(this)) getter unavailable".
        self.assertIn('_encodeCall("balances(address)", address(this))', body)


class VulnerabilityTemplateParameterTests(unittest.TestCase):
    """A template must declare every parameter its renderer requires.

    Substitution was already computed for `entrypoint`, but a template that did
    not name it discarded the value, so the renderer resolved to None and the
    invariant was recorded as adapter-required instead of executed.
    """

    def setUp(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        import invariant_templates_vuln
        import invariant_assertions.vuln as vuln
        self.templates = invariant_templates_vuln.TEMPLATES
        self.vuln = vuln

    def test_every_declared_role_passes_entrypoint_to_its_renderer(self):
        for key in ('access_control_guard_present', 'denial_of_service'):
            for template in self.templates[key]:
                params = {}
                for name in template['params']:
                    if name == 'entrypoint':
                        params[name] = 'withdrawFees()'
                    elif name == 'toleranceBps':
                        params[name] = 0
                    else:
                        params[name] = 'fee'
                body = self.vuln.RENDERERS[template['template']](
                    params, {'contract_name': 'Pool', 'target_addr_expr': 'target'})
                self.assertIsInstance(body, str, template['template'])
                self.assertTrue(body.strip(), template['template'])

    def test_no_template_pins_a_field_name_instead_of_substituting(self):
        # A literal here is not a default, it is a substitute: the substitution map
        # already resolved `balances(address)` from the compiled ABI, and the
        # literal silently replaced it with a bare `balances` that the target does
        # not answer to.  The rendered call then reverts, and the revert is
        # reported as an unreadable precondition rather than as a bad parameter.
        for key, group in self.templates.items():
            for template in group:
                for name, value in template['params'].items():
                    if name == 'toleranceBps':
                        continue
                    self.assertTrue(isinstance(value, str) and value.startswith('$'),
                                    f'{key}.{template["template"]}.{name} = {value!r}')

    def test_parameterised_entrypoint_is_rejected(self):
        # `liquidate(address,uint256)` cannot be called with an encoded empty
        # argument list; rendering it would revert and be read as a violation.
        self.assertIsNone(self.vuln._method_literal({'entrypoint': 'liquidate(address,uint256)'},
                                                    'entrypoint'))

    def test_empty_argument_signature_is_accepted(self):
        self.assertEqual('withdrawFees()',
                         self.vuln._method_literal({'entrypoint': 'withdrawFees()'}, 'entrypoint'))

    def test_every_renderer_runs_for_its_own_template(self):
        # A renderer that names a variable it never defined raises only on the
        # line that uses it, and only for the template that reaches it -- so a
        # sample with that role failed at harness generation with a NameError that
        # named an internal local rather than anything about the contract.  Every
        # template is therefore rendered here, with its declared parameters.
        context = {'contract_name': 'Target', 'target_addr_expr': 'target'}
        for key, group in self.templates.items():
            for template in group:
                params = {}
                for name in template['params']:
                    params[name] = {'entrypoint': 'withdraw()',
                                     'toleranceBps': 0}.get(name, 'fee')
                try:
                    body = self.vuln.RENDERERS[template['template']](params, context)
                except Exception as error:  # noqa: BLE001 - the message is the report
                    self.fail(f'{key}.{template["template"]}: {error!r}')
                self.assertIsInstance(body, str, template['template'])


class MappingGetterRenderingTests(unittest.TestCase):
    """A public mapping must be readable through its generated getter.

    `mapping(address => uint256) public balances` exposes `balances(address)`.  The
    IR lists no user-written function for it, so every substitution fell back to
    the bare field name and the rendered call addressed `balances()`, which the
    contract does not implement -- the assertion then reported an unreadable
    precondition instead of running.
    """

    def setUp(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        from invariant_assertions import _common
        self.common = _common

    def test_scalar_signature_is_called_without_arguments(self):
        self.assertEqual('fee()', self.common.call_expression('fee()'))

    def test_bare_name_is_read_as_the_scalar_form(self):
        self.assertEqual('fee()', self.common.call_expression('fee'))

    def test_mapping_signature_passes_the_caller_address(self):
        self.assertEqual('balances(address(this))',
                         self.common.call_expression('balances(address)'))

    def test_multi_argument_getter_is_refused(self):
        # There is no single slot to read, and encoding values the assertion did
        # not choose would make the comparison meaningless.
        self.assertIsNone(self.common.call_expression('sum(address,address)'))

    def test_non_callable_text_is_refused(self):
        for value in ('', 'a b()', 'fee() extra', 'x(); y()', '1()', None):
            self.assertIsNone(self.common.call_expression(value), value)

    def test_mapping_read_renders_a_well_formed_call(self):
        body = self.common.static_read('reentrancyTarget', 'balances(address)', 'guard')
        # The argument has to travel as a value, not inside the signature string.
        self.assertIn('_encodeCall("balances(address)", address)', body)
        self.assertNotIn('staticcall', body)

    def test_read_does_not_hash_the_selector_in_generated_source(self):
        # `keccak256(bytes)` and a destructured call result are both 0.5+; the
        # corpus pins 0.4.10, where neither compiles.  The selector is hashed by
        # the harness helper and the result is assigned to declared variables.
        body = self.common.static_read('reentrancyTarget', 'balances(address)', 'guard')
        self.assertNotIn('keccak256', body)
        self.assertNotIn('(bool guardOkRaw, bytes memory guardDataRaw) =', body)
        self.assertIn('(guardOkRaw, guardDataRaw) =', body)

    def test_scalar_read_is_unchanged(self):
        body = self.common.static_read('t', 'fee()', 'fee')
        self.assertIn('abi.encodeWithSignature("fee()")', body)


class StaticReadCompatibilityTests(unittest.TestCase):

    def setUp(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        from invariant_assertions import _common
        self.common = _common

    def test_read_does_not_use_staticcall(self):
        rendered = self.common.read_expr('target', 'reserve0', 'before')
        # `address.staticcall` was added in 0.5; naming it made every assertion
        # that reads target state fail to compile.
        self.assertNotIn('.staticcall', rendered)
        self.assertIn('reserve0()', rendered)

    def test_temporaries_are_unique_per_read(self):
        # Two reads of the same field in one function collided on the shared
        # `_ok`/`_data` names and were rejected as duplicate identifiers.
        first = self.common.static_read('t', 'f()', 'a')
        second = self.common.static_read('t', 'f()', 'a2')
        self.assertNotEqual(first, second)
        self.assertNotIn('_ok', first)

    def test_explicit_names_let_a_caller_read_the_same_field_twice(self):
        rendered = self.common.static_read('t', 'f()', 'guard2',
                                           ok_name='guardOk2', data_name='guardData2')
        self.assertIn('bool guardOk2', rendered)
        self.assertIn('bytes memory guardData2', rendered)


class InlineDeploymentRewriteTests(unittest.TestCase):
    def _rendered(self, body='require(true, "x");'):
        # Mirrors the template harness_gen actually emits: the cheat-code address
        # is derived in assembly, the target comes from an envAddress call, and
        # the test is already writable because it reads that storage slot.
        return ('// SPDX-License-Identifier: MIT\npragma solidity >=0.4.22;\n\n'
                'interface Vm {\n    function envAddress(bytes32 name) external view returns (address);\n}\n\n'
                'contract Invariant_0123456789abcdef {\n'
                '    bytes32 public constant invariantId = 0x' + '0' * 64 + ';\n'
                '    string public constant description = "d";\n\n'
                '    function _cheatCodeAddress() private view returns (address out) {\n'
                '        bytes32 slot;\n'
                '        bytes32 word;\n'
                '        assembly {\n'
                '            mstore(0x00, "hevm cheat code")\n'
                '            slot := keccak256(0x00, 0x10)\n'
                '            word := sload(slot)\n'
                '            out := shr(96, word)\n'
                '        }\n'
                '    }\n\n'
                '    function _codeSizeAt(address who) private view returns (uint size) {\n'
                '        assembly { size := extcodesize(who) }\n'
                '    }\n\n'
                '    function testInvariant() public {\n'
                '        address target = Vm(_cheatCodeAddress()).envAddress(bytes32("INVARIANT_TARGET"));\n'
                '        require(_codeSizeAt(target) > 0, "INVARIANT_TARGET has no code");\n'
                f'        {body}\n'
                '    }\n}\n')

    def _rewrite(self, text):
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory)
            (harness / 'test').mkdir()
            (harness / 'test' / 'Invariant_0123456789abcdef.t.sol').write_text(text, encoding='utf-8')
            DEEP._inline_target_deployment(harness, 'Vault.sol', 'Vault')
            return (harness / 'test' / 'Invariant_0123456789abcdef.t.sol').read_text(encoding='utf-8')

    def test_target_lookup_becomes_a_real_deployment(self):
        updated = self._rewrite(self._rendered())
        self.assertIn('Vault deployedTarget = new Vault();', updated)
        self.assertNotIn('INVARIANT_TARGET', updated)
        self.assertIn('import { Vault } from "../src/Vault.sol";', updated)

    def test_deployed_contract_is_exposed_to_the_body_as_an_address(self):
        # The rendered bodies assign `target` straight to an `address` local,
        # which only compiles if `target` is itself an address rather than the
        # contract instance.
        updated = self._rewrite(self._rendered())
        self.assertIn('address target = address(deployedTarget);', updated)

    def test_test_becomes_writable_so_it_can_deploy(self):
        self.assertIn('function testInvariant() public {', self._rewrite(self._rendered()))

    def test_generated_getters_do_not_become_fuzz_targets(self):
        updated = self._rewrite(self._rendered())
        self.assertIn('bytes32 internal constant invariantId', updated)
        self.assertIn('string internal constant description', updated)
        self.assertNotIn('bytes32 public constant invariantId', updated)

    def test_rendered_invariant_body_and_assertion_are_untouched(self):
        body = 'require(reserve0After >= reserve0Before, "constant product k decreased");'
        updated = self._rewrite(self._rendered(body))
        self.assertIn(body, updated)

    def test_unrelated_test_file_is_left_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory)
            (harness / 'test').mkdir()
            other = harness / 'test' / 'DeepTarget.t.sol'
            original = 'contract Other { function f() public pure {} }\n'
            other.write_text(original, encoding='utf-8')
            DEEP._inline_target_deployment(harness, 'Vault.sol', 'Vault')
            self.assertEqual(other.read_text(encoding='utf-8'), original)


class AssertionClassificationTests(unittest.TestCase):
    """A failing setup must never be reported as a violated protocol property."""

    def test_short_reason_is_normalised_to_one_line(self):
        self.assertEqual(DEEP._short('a\nb'), 'a b')
        self.assertEqual(DEEP._short(None), '')
        self.assertEqual(len(DEEP._short('x' * 500)), 120)

    def test_last_hash_prefix_selects_the_enclosing_suite(self):
        output = ('test/Invariant_aaaaaaaaaaaaaaaa.t.sol\nok\n'
                  'test/Invariant_bbbbbbbbbbbbbbbb.t.sol\nresult\n')
        self.assertEqual(DEEP._last_hash_prefix(output, output.index('result')), 'bbbbbbbbbbbbbbbb')

    def test_rows_the_runner_never_executed_are_left_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [{'invariantId': 'a' * 64, 'state': 'unavailable', 'reason': 'forge_not_found'}]
            self.assertEqual(DEEP._refine_assertion_states(Path(directory), rows), rows)

    def test_clean_control_with_one_unusable_assertion_is_not_reported_as_violated(self):
        """The measured 33-clean-amm result, pinned as a regression guard."""
        evidence = json.loads((ROOT / 'benchmark' / 'contracts' / '33-clean-amm'
                               / 'invariants.json').read_text(encoding='utf-8'))
        states = [row.get('state') for row in evidence.get('results') or []]
        self.assertEqual(evidence.get('outcome'), 'passed')
        self.assertNotIn('violated', states)
        self.assertGreaterEqual(evidence.get('executedAssertionCount') or 0, 1)


if __name__ == '__main__':
    unittest.main()