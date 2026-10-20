import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('discovery_plan', ROOT / 'scripts/discovery_plan.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def inputs():
    name = 'Vault::Vault.redeem(uint256,address,address)'
    report = {'verifiedSourceFingerprint': 'a' * 64, 'analysisInputFingerprint': 'c' * 64}
    graph = {'analysisInputFingerprint': 'c' * 64, 'state': 'partial', 'entrypoints': [{'function': name, 'modifiers': ['nonReentrant'],
        'protectionHeuristic': True, 'location': {'file': 'Vault.sol', 'lines': [10]}}],
        'paths': [{'entrypoint': name, 'path': [name], 'pathFeasibility': 'not_proven',
            'effect': {'kind': 'external_call', 'assetRelated': True,
                'sourceSha256': 'a' * 64,
                'effectSiteId': hashlib.sha256('\0'.join(('a' * 64, 'Vault.sol', '100', '4', 'external_call')).encode()).hexdigest(),
                'location': {'file': 'Vault.sol', 'lines': [11], 'start': 100, 'length': 4}}}],
        'truncatedPathCount': 12, 'unresolvedAssemblyCallCount': 1}
    local = {'verifiedSourceFingerprint': 'a' * 64, 'state': 'passed', 'tests': 1, 'passed': 1, 'failed': 0,
        'results': [{'id': 'test-receiver', 'state': 'passed', 'propertyIds': ['settlement.receiver_exact']}],
        'sequences': [{'id': 'test-receiver', 'operations': [
            {'method': 'deposit', 'transactionHash': '0x1'},
            {'method': 'redeem', 'reverted': True},
            {'method': 'approve', 'transactionHash': '0x2'}]}],
        'traces': [{'transactionHash': '0xabc', 'failed': False, 'targetDepth': 1,
            'effects': [
                {'op': 'SSTORE', 'depth': 1,
                    'sourceLocation': {'file': 'Vault.sol', 'lineStart': 10, 'lineEnd': 10}},
                {'op': 'CALL', 'depth': 1,
                    'effectSiteId': hashlib.sha256('\0'.join(('a' * 64, 'Vault.sol', '100', '4', 'external_call')).encode()).hexdigest(),
                    'sourceLocation': {'file': 'Vault.sol', 'lineStart': 11, 'lineEnd': 11,
                        'start': 100, 'length': 4, 'sourceSha256': 'a' * 64}},
            ]}]}
    return report, graph, local


def add_dynamic_match(local, graph, indices, reverted=False):
    local['traces'][0]['failed'] = reverted
    location = {'file': 'Vault.sol', 'lineStart': 11, 'lineEnd': 11,
                'start': 100, 'length': 4, 'sourceSha256': 'a' * 64}
    local['staticCorrelation'] = {'graphFingerprint': mod._digest(graph), 'matches': [{
        'traceIndex': 0, 'effectIndex': 1, 'transactionHash': '0xabc', 'opcode': 'CALL',
        'effectSiteId': hashlib.sha256('\0'.join(('a' * 64, 'Vault.sol', '100', '4', 'external_call')).encode()).hexdigest(),
        'sourceLocation': location,
        'transactionReverted': reverted, 'candidatePathIndices': indices,
        'completePathProven': False,
    }]}


class DiscoveryPlanTests(unittest.TestCase):
    def test_sensitive_entrypoints_without_effect_paths_still_have_obligations(self):
        report, graph, local = inputs()
        graph['entrypoints'].extend([{'function': 'Oracle.price()'}, {'function': 'Vault.setOwner(address)'}])
        plan = mod.build_plan(report, graph, local)
        entries = {row['entrypoint']: row for row in plan['obligations']}
        self.assertIn('oracle.freshness', [p['propertyId'] for p in entries['Oracle.price()']['properties']])
        self.assertEqual(entries['Vault.setOwner(address)']['paths'], [])
        self.assertEqual(plan['obligationsWithoutReportedPaths'], 2)
        self.assertEqual(plan['entrypointsWithoutReportedPaths'], 2)
        self.assertEqual(entries['Vault.setOwner(address)']['pathEvidenceState'], 'no_effect_path_reported')

    def test_legacy_unbound_graph_cannot_receive_fixture_passes(self):
        report, graph, local = inputs()
        report.pop('analysisInputFingerprint')
        plan = mod.build_plan(report, graph, local)
        self.assertFalse(plan['graphInputBound'])
        self.assertTrue(plan['dynamicEvidenceBound'])
        self.assertEqual(plan['fixturePassedPropertyCount'], 0)
        self.assertEqual(plan['sequenceObservation']['operationCount'], 0)
        self.assertIn('图输入绑定 False', mod.render_html(plan))

    def test_all_structural_coverage_cutoffs_are_retained(self):
        report, graph, local = inputs()
        gaps = {'truncatedEdgeCount': 3, 'unresolvedInternalDynamicCallCount': 2,
                'unresolvedAssemblyBlockCount': 1, 'entrypointCount': 9,
                'walkSteps': 80, 'walkBudget': 100, 'internalDynamicWalkBudget': 200}
        graph.update(gaps)
        coverage = mod.build_plan(report, graph, local)['graphCoverage']
        self.assertEqual({key: coverage[key] for key in gaps}, gaps)

    def test_graph_input_fingerprint_must_match_when_driver_binds_it(self):
        report, graph, local = inputs()
        report['analysisInputFingerprint'] = 'c' * 64
        graph['analysisInputFingerprint'] = 'c' * 64
        self.assertTrue(mod.build_plan(report, graph, local)['graphInputBound'])
        graph['analysisInputFingerprint'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'fingerprint mismatch'):
            mod.build_plan(report, graph, local)

    def test_builds_unconfirmed_obligations_preserving_protection_and_gaps(self):
        plan = mod.build_plan(*inputs())
        self.assertEqual(plan['state'], 'partial')
        self.assertEqual(plan['obligationCount'], 1)
        row = plan['obligations'][0]
        self.assertEqual(row['modifiers'], ['nonReentrant'])
        self.assertTrue(row['protectionHeuristic'])
        self.assertFalse(row['confirmed'])
        self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)
        self.assertEqual(plan['graphCoverage']['truncatedPathCount'], 12)
        self.assertEqual(plan['confirmedVulnerabilities'], 0)

    def test_share_allowance_obligations_are_method_hints_not_path_proofs(self):
        report, graph, local = inputs()
        approve = 'Vault.approve(address,uint256)'
        transfer_from = 'Vault.transferFrom(address,address,uint256)'
        transfer = 'Vault.transfer(address,address,uint256)'
        redeem = 'Vault::Vault.redeem(uint256,address,address)'
        graph['entrypoints'].extend({'function': entry} for entry in (approve, transfer_from, transfer))
        local['results'][0]['propertyIds'].extend((
            'authorization.share_allowance', 'accounting.share_conservation'))

        plan = mod.build_plan(report, graph, local)

        by_entry = {
            row['entrypoint']: {prop['propertyId']: prop for prop in row['properties']}
            for row in plan['obligations']
        }
        allowance_entries = {
            entry for entry, properties in by_entry.items()
            if 'authorization.share_allowance' in properties
        }
        self.assertEqual(allowance_entries, {approve, transfer_from})
        for entry in (approve, transfer_from):
            evidence = by_entry[entry]['authorization.share_allowance']
            self.assertEqual(evidence['state'], 'passed_in_fixture')
            self.assertEqual(evidence['entrypointBinding'], 'not_established')
        self.assertIn('accounting.share_conservation', by_entry[transfer_from])
        share_conservation = by_entry[transfer_from]['accounting.share_conservation']
        self.assertEqual(share_conservation['state'], 'passed_in_fixture')
        self.assertEqual(share_conservation['entrypointBinding'], 'not_established')
        self.assertNotIn('accounting.share_conservation', by_entry[approve])
        self.assertEqual(plan['confirmedVulnerabilities'], 0)
        self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_property_requires_explicit_source_bound_consistent_result(self):
        report, graph, local = inputs()
        self.assertEqual(mod.build_plan(report, graph, local)['fixturePassedPropertyCount'], 1)
        for mutation in ('source', 'count', 'result', 'dependency', 'property'):
            bad = copy.deepcopy(local)
            if mutation == 'source': bad['verifiedSourceFingerprint'] = 'b' * 64
            if mutation == 'count': bad['passed'] = 2
            if mutation == 'result': bad['results'][0]['state'] = 'not_run'
            if mutation == 'dependency': bad['verifiedDependencyFingerprint'] = 'b' * 64
            if mutation == 'property': bad['results'][0].pop('propertyIds')
            with self.subTest(mutation=mutation):
                self.assertEqual(mod.build_plan(report, graph, bad)['fixturePassedPropertyCount'], 0)

    def test_suite_pass_and_line_overlap_never_imply_property_coverage(self):
        report, graph, local = inputs()
        local['results'][0]['propertyIds'] = []
        local['staticCorrelation'] = {'matchedEffectCount': 900}
        plan = mod.build_plan(report, graph, local)
        self.assertEqual(plan['fixturePassedPropertyCount'], 0)
        self.assertEqual(plan['untestedPropertyCount'], plan['propertyCount'])
        self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])

    def test_bound_opcode_overlap_is_attached_to_the_indexed_candidate_path(self):
        report, graph, local = inputs()
        graph['paths'].append({**copy.deepcopy(graph['paths'][0]),
            'path': [graph['paths'][0]['entrypoint'], 'Vault.helper()']})
        add_dynamic_match(local, graph, [1])

        plan = mod.build_plan(report, graph, local)

        paths = plan['obligations'][0]['paths']
        observed = next(path for path in paths if 'Vault.helper()' in path['path'])
        unobserved = next(path for path in paths if 'Vault.helper()' not in path['path'])
        evidence = observed['observedDynamicEffects'][0]
        self.assertEqual(evidence['evidenceType'], 'observed_opcode_source_location_overlap')
        self.assertEqual(evidence['opcode'], 'CALL')
        self.assertEqual(evidence['sourceLocation'], {'file': 'Vault.sol', 'lineStart': 11, 'lineEnd': 11})
        self.assertNotIn('observedDynamicEffects', unobserved)
        self.assertIn('不证明完整路径', evidence['interpretation'])
        self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_selfdestruct_site_creates_a_fork_semantics_lifecycle_obligation(self):
        report, graph, local = inputs()
        source_hash = 'a' * 64
        site = hashlib.sha256('\0'.join((source_hash, 'Vault.sol', '100', '4', 'selfdestruct')).encode()).hexdigest()
        graph['paths'][0]['effect'] = {
            'kind': 'selfdestruct', 'sourceSha256': source_hash, 'effectSiteId': site,
            'location': {'file': 'Vault.sol', 'lines': [11], 'start': 100, 'length': 4},
        }
        local['traces'][0]['effects'][1] = {
            'op': 'SELFDESTRUCT', 'depth': 1, 'effectSiteId': site,
            'sourceLocation': {'file': 'Vault.sol', 'lineStart': 11, 'lineEnd': 11,
                               'start': 100, 'length': 4, 'sourceSha256': source_hash},
        }
        local['staticCorrelation'] = {'graphFingerprint': mod._digest(graph), 'matches': [{
            'traceIndex': 0, 'effectIndex': 1, 'transactionHash': '0xabc', 'opcode': 'SELFDESTRUCT',
            'effectSiteId': site, 'sourceLocation': local['traces'][0]['effects'][1]['sourceLocation'],
            'transactionReverted': False, 'candidatePathIndices': [0], 'completePathProven': False,
        }]}

        plan = mod.build_plan(report, graph, local)
        property_rows = plan['obligations'][0]['properties']
        self.assertIn('contract.lifecycle', {row['propertyId'] for row in property_rows})
        self.assertEqual(plan['obligations'][0]['paths'][0]['observedDynamicEffects'][0]['opcode'], 'SELFDESTRUCT')

    def test_reverted_opcode_overlap_is_displayed_as_reverted_observation(self):
        report, graph, local = inputs()
        add_dynamic_match(local, graph, [0], reverted=True)

        plan = mod.build_plan(report, graph, local)

        evidence = plan['obligations'][0]['paths'][0]['observedDynamicEffects'][0]
        self.assertTrue(evidence['transactionReverted'])
        self.assertFalse(evidence['completePathProven'])
        self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_one_observation_keeps_ambiguous_candidate_paths_unproven(self):
        report, graph, local = inputs()
        graph['paths'].append({**copy.deepcopy(graph['paths'][0]),
            'path': [graph['paths'][0]['entrypoint'], 'Vault.helper()']})
        add_dynamic_match(local, graph, [0, 1])

        plan = mod.build_plan(report, graph, local)

        observed = [path['observedDynamicEffects'][0] for path in plan['obligations'][0]['paths']
                    if 'observedDynamicEffects' in path]
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0], observed[1])
        self.assertTrue(all(evidence['completePathProven'] is False for evidence in observed))
        self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_dynamic_match_requires_a_real_trace_and_effect_pointer(self):
        for mutation in ('trace_index', 'effect_index'):
            with self.subTest(mutation=mutation):
                report, graph, local = inputs()
                add_dynamic_match(local, graph, [0])
                match = local['staticCorrelation']['matches'][0]
                if mutation == 'trace_index':
                    match['traceIndex'] = 1
                else:
                    match['effectIndex'] = 2

                plan = mod.build_plan(report, graph, local)

                self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])

    def test_dynamic_match_must_agree_with_referenced_trace_and_effect(self):
        mutations = {
            'transaction_hash': lambda trace, effect, match: match.update(transactionHash='0xforged'),
            'opcode': lambda trace, effect, match: match.update(opcode='STATICCALL'),
            'source_location': lambda trace, effect, match: match['sourceLocation'].update(lineStart=12, lineEnd=12),
            'effect_location': lambda trace, effect, match: effect['sourceLocation'].update(lineStart=12, lineEnd=12),
            'reverted_flag': lambda trace, effect, match: match.update(transactionReverted=True),
            'effect_depth': lambda trace, effect, match: effect.update(depth=2),
            'trace_depth': lambda trace, effect, match: trace.update(targetDepth=2),
        }
        for mutation, corrupt in mutations.items():
            with self.subTest(mutation=mutation):
                report, graph, local = inputs()
                add_dynamic_match(local, graph, [0])
                trace = local['traces'][0]
                effect = trace['effects'][1]
                match = local['staticCorrelation']['matches'][0]
                corrupt(trace, effect, match)

                plan = mod.build_plan(report, graph, local)

                self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])

    def test_dynamic_site_id_mismatch_is_rejected(self):
        report, graph, local = inputs()
        add_dynamic_match(local, graph, [0])
        local['staticCorrelation']['matches'][0]['effectSiteId'] = '0' * 64

        plan = mod.build_plan(report, graph, local)

        self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])
        self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_dynamic_observation_requires_transaction_identity_and_result(self):
        for mutation in ('missing_hash', 'missing_failed', 'unavailable'):
            with self.subTest(mutation=mutation):
                report, graph, local = inputs()
                add_dynamic_match(local, graph, [0])
                trace = local['traces'][0]
                if mutation == 'missing_hash':
                    trace.pop('transactionHash')
                elif mutation == 'missing_failed':
                    trace.pop('failed')
                else:
                    trace['state'] = 'unavailable'

                plan = mod.build_plan(report, graph, local)

                self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])
                self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_malformed_opcode_is_dropped_without_raising(self):
        report, graph, local = inputs()
        add_dynamic_match(local, graph, [0])
        local['staticCorrelation']['matches'][0]['opcode'] = {'not': 'hashable'}

        plan = mod.build_plan(report, graph, local)

        self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])

    def test_dynamic_pointer_indices_reject_booleans_and_negative_values(self):
        for field, value in (('traceIndex', True), ('traceIndex', -1),
                             ('effectIndex', True), ('effectIndex', -1)):
            with self.subTest(field=field, value=value):
                report, graph, local = inputs()
                add_dynamic_match(local, graph, [0])
                local['staticCorrelation']['matches'][0][field] = value

                plan = mod.build_plan(report, graph, local)

                self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])

    def test_invalid_or_out_of_range_candidate_path_indices_are_ignored(self):
        for indices in ([-1], [1], [0, 1], [True], [0, 99], [{}]):
            with self.subTest(indices=indices):
                report, graph, local = inputs()
                add_dynamic_match(local, graph, indices)
                plan = mod.build_plan(report, graph, local)
                self.assertTrue(all('observedDynamicEffects' not in path
                                    for path in plan['obligations'][0]['paths']))
                self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_candidate_index_must_match_the_recorded_source_overlap(self):
        report, graph, local = inputs()
        add_dynamic_match(local, graph, [0])
        local['staticCorrelation']['matches'][0]['sourceLocation']['lineStart'] = 40
        local['staticCorrelation']['matches'][0]['sourceLocation']['lineEnd'] = 40

        plan = mod.build_plan(report, graph, local)

        self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])
        self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_opcode_overlap_requires_both_source_and_graph_input_binding(self):
        report, graph, local = inputs()
        add_dynamic_match(local, graph, [0])
        local['verifiedSourceFingerprint'] = 'b' * 64
        source_unbound = mod.build_plan(report, graph, local)
        self.assertNotIn('observedDynamicEffects', source_unbound['obligations'][0]['paths'][0])

        report, graph, local = inputs()
        add_dynamic_match(local, graph, [0])
        report.pop('analysisInputFingerprint')
        graph_unbound = mod.build_plan(report, graph, local)
        self.assertFalse(graph_unbound['graphInputBound'])
        self.assertNotIn('observedDynamicEffects', graph_unbound['obligations'][0]['paths'][0])
        self.assertEqual(graph_unbound['pathSpecificPropertiesVerified'], 0)

    def test_opcode_overlap_requires_exact_static_correlation_graph_fingerprint(self):
        for fingerprint in ('f' * 64, None):
            with self.subTest(fingerprint=fingerprint):
                report, graph, local = inputs()
                add_dynamic_match(local, graph, [0])
                if fingerprint is None:
                    local['staticCorrelation'].pop('graphFingerprint')
                else:
                    local['staticCorrelation']['graphFingerprint'] = fingerprint

                plan = mod.build_plan(report, graph, local)

                self.assertNotIn('observedDynamicEffects', plan['obligations'][0]['paths'][0])
                self.assertEqual(plan['pathSpecificPropertiesVerified'], 0)

    def test_failed_property_targets_remain_failed_not_covered(self):
        report, graph, local = inputs()
        local.update(state='failed', passed=0, failed=1)
        local['results'][0].update(state='failed', propertyIds=[], targetPropertyIds=['settlement.receiver_exact'])
        plan = mod.build_plan(report, graph, local)
        self.assertEqual(plan['fixtureFailureAssociatedPropertyCount'], 1)
        self.assertEqual(next(p for p in plan['obligations'][0]['properties'] if p['propertyId'] == 'settlement.receiver_exact')['state'], 'failed_scenario_requires_triage')
        self.assertEqual(plan['fixturePassedPropertyCount'], 0)

    def test_adjacent_sequences_preserve_reverts_and_do_not_bridge_scenarios(self):
        report, graph, local = inputs()
        local['sequences'].append({'id': 'new-snapshot', 'operations': [{'method': 'mint', 'transactionHash': '0x3'}]})
        observation = mod.build_plan(report, graph, local)['sequenceObservation']
        self.assertEqual(observation['operationCount'], 4)
        self.assertEqual(observation['distinctTransitionCount'], 2)
        self.assertEqual(observation['transitions'][0]['to'], 'redeem:reverted')

    def test_ids_are_deterministic_and_all_paths_retained(self):
        report, graph, local = inputs()
        graph['paths'].append({**graph['paths'][0], 'effect': {'kind': 'state_write', 'variable': 'balance'}})
        plan = mod.build_plan(report, graph, local)
        graph['paths'].reverse()
        # Graph fingerprint intentionally reflects its original exact representation;
        # stable obligation and path IDs do not depend on input ordering.
        reverse = mod.build_plan(report, graph, local)
        self.assertEqual(plan['obligations'], reverse['obligations'])
        self.assertEqual(plan['candidatePathCount'], 2)

    def test_html_escapes_untrusted_source_and_writes_actual_artifacts(self):
        report, graph, local = inputs()
        entry = '<script>alert(1)</script>.redeem(uint256,address,address)'
        graph['entrypoints'][0]['function'] = entry
        graph['paths'][0]['entrypoint'] = entry
        with tempfile.TemporaryDirectory() as folder:
            summary = mod.write_artifacts(report, graph, local, folder)
            plan = json.loads((Path(folder) / 'discovery-plan.json').read_text())
            markup = (Path(folder) / 'discovery-plan.html').read_text()
            self.assertEqual(plan['planId'], summary['planId'])
            self.assertNotIn('<script>alert(1)</script>', markup)
            self.assertIn('&lt;script&gt;', markup)
            self.assertIn('filter', markup)

    def test_budget_truncation_is_visible(self):
        report, graph, local = inputs()
        other = copy.deepcopy(graph['paths'][0])
        other['entrypoint'] = 'Other.redeem(uint256,address,address)'
        graph['paths'].append(other)
        plan = mod.build_plan(report, graph, local, max_obligations=1)
        self.assertEqual(plan['omittedObligationCount'], 1)
        self.assertEqual(plan['obligationCount'], 1)
