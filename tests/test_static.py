import os
import json
import hashlib
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest import mock
import importlib.util
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / 'flare-scan/tools'


class StaticAnalysisTests(unittest.TestCase):
    def test_dynamic_child_timeout_reaps_process_group(self):
        script = 'import sys,time;sys.stderr.write("partial");sys.stderr.flush();time.sleep(10)'
        with self.assertRaises(subprocess.TimeoutExpired) as context:
            self.static.run_bounded([sys.executable, '-c', script], 0.05)
        self.assertEqual(context.exception.stderr, 'partial')

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_dynamic_runner_kills_group_descendant_after_parent_closes_pipes(self):
        with tempfile.TemporaryDirectory(prefix='dynamic detached pipe ') as folder:
            child_path=Path(folder)/'child.pid'
            script=(
                'import os,pathlib,time\n'
                'pid=os.fork()\n'
                f'if pid: pathlib.Path({str(child_path)!r}).write_text(str(pid))\n'
                'else:\n    os.close(1)\n    os.close(2)\n    time.sleep(30)\n'
            )
            with self.assertRaisesRegex(
                    self.static.ProcessGroupCleanupIncomplete,
                    'analysis_child_process_outlived_parent'):
                self.static.run_bounded([sys.executable,'-c',script],5)
            child=int(child_path.read_text())
            deadline=self.static.time.monotonic()+2
            while self.static.time.monotonic()<deadline:
                try:os.kill(child,0)
                except ProcessLookupError:break
                self.static.time.sleep(0.02)
            else:self.fail('dynamic runner left a same-group descendant alive')

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_process_tree_rss_sums_only_root_and_descendants(self):
        output = '101 1 100\n102 101 200\n103 102 300\n104 1 900\n'
        completed = subprocess.CompletedProcess(['ps'], 0, stdout=output, stderr='')
        with mock.patch.object(self.static.shutil, 'which', return_value='/bin/ps'), \
                mock.patch.object(self.static.subprocess, 'run', return_value=completed):
            self.assertEqual(self.static._process_tree_rss_bytes(101), (100 + 200 + 300) * 1024)

    def test_dynamic_memory_monitor_fails_closed_before_spawning_without_ps(self):
        with mock.patch.object(self.static.shutil, 'which', return_value=None), \
                mock.patch.object(self.static.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(
                    self.static.ProcessMemoryMonitorUnavailable,
                    'process_memory_monitor_unavailable'):
                self.static.run_bounded(
                    [sys.executable, '-c', 'print("must not run")'], 1,
                    max_process_tree_rss_bytes=1024,
                )
        popen.assert_not_called()

    def test_dynamic_memory_monitor_rejects_empty_snapshot_before_spawning(self):
        completed = subprocess.CompletedProcess(['ps'], 0, stdout='', stderr='')
        with mock.patch.object(self.static.shutil, 'which', return_value='/bin/ps'), \
                mock.patch.object(self.static.subprocess, 'run', return_value=completed), \
                mock.patch.object(self.static.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(
                    self.static.ProcessMemoryMonitorUnavailable,
                    'process_memory_monitor_invalid_output'):
                self.static.run_bounded(
                    [sys.executable, '-c', 'print("must not run")'], 1,
                    max_process_tree_rss_bytes=1024,
                )
        popen.assert_not_called()

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_dynamic_memory_monitor_rejects_snapshot_without_target_before_spawning(self):
        completed = subprocess.CompletedProcess(['ps'], 0, stdout='102 1 100\n', stderr='')
        with mock.patch.object(self.static.shutil, 'which', return_value='/bin/ps'), \
                mock.patch.object(self.static.subprocess, 'run', return_value=completed), \
                mock.patch.object(self.static.os, 'getpid', return_value=101), \
                mock.patch.object(self.static.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(
                    self.static.ProcessMemoryMonitorUnavailable,
                    'process_memory_monitor_target_missing'):
                self.static.run_bounded(
                    [sys.executable, '-c', 'print("must not run")'], 1,
                    max_process_tree_rss_bytes=1024,
                )
        popen.assert_not_called()

    def test_dynamic_memory_monitor_rejects_duplicate_pids(self):
        output = '101 1 100\n101 1 200\n'
        completed = subprocess.CompletedProcess(['ps'], 0, stdout=output, stderr='')
        with mock.patch.object(self.static.shutil, 'which', return_value='/bin/ps'), \
                mock.patch.object(self.static.subprocess, 'run', return_value=completed):
            with self.assertRaisesRegex(
                    self.static.ProcessMemoryMonitorUnavailable,
                    'process_memory_monitor_invalid_output'):
                self.static._process_tree_rss_bytes(101)

    def test_runtime_missing_target_snapshot_after_process_exit_retries_drain(self):
        process = mock.Mock(pid=1234)
        process.poll.return_value = 0
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(['node'], 0.25), (b'done', b''),
        ]
        missing = self.static.ProcessMemoryMonitorUnavailable('process_memory_monitor_target_missing')
        with mock.patch.object(self.static, '_process_tree_rss_bytes', side_effect=[100, missing]), \
                mock.patch.object(self.static.subprocess, 'Popen', return_value=process), \
                mock.patch.object(self.static, '_process_group_exists', return_value=False):
            result = self.static.run_bounded(
                ['node', 'harness'], 1, max_process_tree_rss_bytes=1024,
            )

        self.assertEqual((result.stdout, result.stderr), (b'done', b''))

    def test_runtime_missing_target_snapshot_while_process_is_alive_fails_closed(self):
        process = mock.Mock(pid=1234)
        process.poll.return_value = None
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(['node'], 0.25), (b'', b''),
        ]
        missing = self.static.ProcessMemoryMonitorUnavailable('process_memory_monitor_target_missing')
        with mock.patch.object(self.static, '_process_tree_rss_bytes', side_effect=[100, missing]), \
                mock.patch.object(self.static.subprocess, 'Popen', return_value=process), \
                mock.patch.object(self.static.os, 'killpg') as kill_group:
            with self.assertRaisesRegex(
                    self.static.ProcessMemoryMonitorUnavailable,
                    'process_memory_monitor_target_missing'):
                self.static.run_bounded(
                    ['node', 'harness'], 1, max_process_tree_rss_bytes=1024,
                )

        kill_group.assert_called_once_with(1234, self.static.signal.SIGKILL)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_dynamic_memory_budget_kills_and_reaps_process_tree(self):
        with tempfile.TemporaryDirectory(prefix='dynamic memory budget ') as folder:
            pid_path = Path(folder) / 'child.pid'
            script = f'import os,pathlib,time; pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); time.sleep(30)'
            with mock.patch.object(
                    self.static, '_process_tree_rss_bytes', return_value=2048):
                with self.assertRaises(self.static.ProcessTreeMemoryLimitExceeded) as caught:
                    self.static.run_bounded(
                        [sys.executable, '-c', script], 5,
                        max_process_tree_rss_bytes=1024,
                    )
            self.assertEqual(caught.exception.observed_bytes, 2048)
            child = int(pid_path.read_text())
            deadline = self.static.time.monotonic() + 2
            while self.static.time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                self.static.time.sleep(0.02)
            else:
                self.fail('dynamic child remained alive after its memory budget was exceeded')

    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('review_static',ROOT/'scripts/review-static.py')
        cls.static=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.static)

    def test_report_reference_uses_project_root_even_when_cwd_differs(self):
        with tempfile.TemporaryDirectory(prefix='report reference ') as folder:
            project=Path(folder)/'project'
            project.mkdir()
            with mock.patch.object(self.static,'ROOT',project):
                inside=project/'work'/'case'/'call-graph.json'
                outside=Path(folder)/'external'/'call-graph.json'
                self.assertEqual(self.static._report_reference(inside),'work/case/call-graph.json')
                self.assertEqual(self.static._report_reference(outside),str(outside.resolve()))

    def test_dynamic_harness_rejects_unbound_evidence_hashes(self):
        with tempfile.TemporaryDirectory(prefix='dynamic binding ') as folder:
            root = Path(folder)
            bundle = root / 'verified-source.json'
            dynamic_folder = root / 'dynamic-work'
            dynamic_folder.mkdir()
            source_input = {'sources': {'Target.sol': {'content': 'contract Target {}'}}, 'settings': {}}
            payload = {'state': 'passed', 'tests': 1, 'passed': 1, 'failed': 0,
                       'sourceHash': '0' * 64, 'harnessHash': '1' * 64,
                       'harnessSupportHash': '2' * 64}
            completed = subprocess.CompletedProcess([], 0, json.dumps(payload), '')
            with mock.patch.object(self.static, 'run_bounded', return_value=completed):
                result = self.static._run_dynamic_harness(
                    bundle, dynamic_folder, source_input, 'Target.sol',
                    root / 'soljson.js', timeout=1,
                )
            self.assertEqual(result['state'], 'unavailable')
            self.assertEqual(result['reason'], 'dynamic_evidence_binding_failed')
            self.assertIn('source_hash_mismatch', result['evidenceBindingErrors'])
            self.assertEqual(result['runnerLimits']['processTreeRssLimitBytes'],
                             self.static.MAX_DYNAMIC_HARNESS_RSS_BYTES)
            trace_limit = result['runnerLimits']['traceAcquisition']
            self.assertIn('Hardhat 2.22.19 / EDR 0.8.0', trace_limit)
            self.assertIn('no streaming or max-step debug-trace API', trace_limit)
            self.assertIn('RawTrace.trace() and debug_traceTransaction materialize complete traces', trace_limit)
            self.assertIn('MAX_TRACE_STEPS bounds summarization', trace_limit)
            self.assertIn('cannot prevent trace-acquisition allocations', trace_limit)
            self.assertIn('detached descendants may escape',result['runnerLimits']['processTreeCleanup'])

    def test_dynamic_execution_boundary_defaults_to_isolated_local_chain(self):
        expected = self.static._expected_dynamic_execution_boundary({})
        self.assertEqual(expected['mode'], 'isolated_in_process')
        self.assertFalse(expected['requestedFork'])
        self.assertEqual(expected['forkState'], 'not_performed')
        self.assertEqual(self.static._validate_dynamic_execution_boundary({
            **expected, 'networkWrites': 'local_only',
            'forkProbe': {'state': 'not_performed'},
        }, {}), [])

    def test_dynamic_execution_boundary_requires_verified_fixed_block_probe(self):
        env = {
            'DYNAMIC_EXECUTION_MODE': 'fixed_block_fork',
            'DYNAMIC_FORK_RPC_URL': 'https://rpc.example.test/private-token',
            'DYNAMIC_FORK_BLOCK_NUMBER': '0x2a',
        }
        expected = self.static._expected_dynamic_execution_boundary(env)
        valid = {
            **expected,
            'networkWrites': 'local_only',
            'fixedBlockNumber': 42,
            'forkState': 'verified',
            'forkProbe': {'state': 'verified', 'readOnly': True, 'repeatHashMatch': True},
            'rpcEndpoint': {'sha256': expected['rpcUrlHash']},
        }
        self.assertEqual(self.static._validate_dynamic_execution_boundary(valid, env), [])
        invalid = copy.deepcopy(valid)
        invalid['forkProbe']['repeatHashMatch'] = False
        self.assertIn('execution_boundary_fork_probe_not_verified',
                      self.static._validate_dynamic_execution_boundary(invalid, env))

    def test_dynamic_execution_boundary_rejects_partial_fork_configuration(self):
        env = {'DYNAMIC_FORK_RPC_URL': 'https://rpc.example.test'}
        expected = self.static._expected_dynamic_execution_boundary(env)
        self.assertEqual(expected['mode'], 'fixed_block_fork')
        self.assertIsNone(expected['fixedBlockNumber'])
        self.assertIn('execution_boundary_fork_block_invalid',
                      self.static._validate_dynamic_execution_boundary({
                          **expected, 'networkWrites': 'local_only',
                          'forkState': 'unavailable',
                          'forkProbe': {'state': 'unavailable'},
                      }, env))

    def test_dynamic_failure_evidence_fails_closed_for_uncaptured_dimensions(self):
        local = {
            'results': [{'name': 'failed-sequence', 'state': 'failed', 'error': 'assertion failed'}],
            'deterministicFuzz': {'seed': '0x5ec0a11'},
            'transactionEvidence': {'transactions': [{
                'id': 'tx-0', 'scenario': 'failed-sequence', 'sequenceId': 'failed-sequence',
                'transactionHash': '0x' + 'a' * 64, 'from': '0x' + '1' * 40,
                'value': '7', 'selector': '0xdeadbeef', 'rawCalldata': '0xdeadbeef',
                'rawCalldataState': 'available',
            }]},
            'traces': [{'transactionHash': '0x' + 'a' * 64, 'state': 'available', 'traceValid': True}],
        }
        evidence = self.static.build_dynamic_failure_evidence(local, {'argv': ['node', 'harness'], 'cwd': str(ROOT)})
        self.assertEqual(evidence['state'], 'partial')
        self.assertEqual(self.static.validate_dynamic_failure_evidence(evidence), [])
        sample = evidence['samples'][0]
        self.assertEqual(sample['fields']['seed'], {'state': 'available', 'value': '0x5ec0a11'})
        self.assertEqual(sample['fields']['transactionSequence']['state'], 'available')
        self.assertEqual(sample['fields']['trace']['state'], 'available')
        self.assertEqual(sample['fields']['assetChanges']['state'], 'unavailable')
        self.assertEqual(sample['fields']['assetChanges']['reason'], 'not_captured_by_dynamic_harness')
        self.assertFalse(sample['confirmedVulnerability'])

    def test_dynamic_failure_evidence_binds_complete_block_time_and_events(self):
        local = {
            'results': [{'name': 'failed-sequence', 'state': 'failed', 'error': 'assertion failed'}],
            'transactionEvidence': {'transactions': [{
                'id': 'tx-0', 'scenario': 'failed-sequence', 'sequenceId': 'failed-sequence',
                'transactionHash': '0x' + 'a' * 64, 'from': '0x' + '1' * 40,
                'value': '7', 'selector': '0xdeadbeef', 'rawCalldata': '0xdeadbeef',
                'rawCalldataState': 'available', 'blockTime': '1700000000',
                'eventsState': 'available', 'events': [],
            }]},
            'traces': [],
        }
        evidence = self.static.build_dynamic_failure_evidence(local)
        self.assertEqual(self.static.validate_dynamic_failure_evidence(evidence), [])
        fields = evidence['samples'][0]['fields']
        self.assertEqual(fields['blockTime'], {'state': 'available', 'value': ['1700000000']})
        self.assertEqual(fields['events'], {'state': 'available', 'value': [[]]})
        self.assertFalse(evidence['samples'][0]['confirmedVulnerability'])

    def test_dynamic_failure_evidence_validator_rejects_missing_or_fake_dimensions(self):
        value = self.static.build_dynamic_failure_evidence(
            {'results': [{'name': 'failed', 'state': 'failed'}]}, None)
        self.assertEqual(self.static.validate_dynamic_failure_evidence(value), [])
        malformed = copy.deepcopy(value)
        del malformed['samples'][0]['fields']['profit']
        self.assertIn('samples[0]_profit_must_be_available_or_unavailable',
                      self.static.validate_dynamic_failure_evidence(malformed))
        fake = copy.deepcopy(value)
        fake['samples'][0]['confirmedVulnerability'] = True
        self.assertIn('samples[0]_must_not_confirm_vulnerability',
                      self.static.validate_dynamic_failure_evidence(fake))

    def test_dynamic_failure_evidence_without_failed_assertions_is_explicit(self):
        value = self.static.build_dynamic_failure_evidence({'results': [{'name': 'ok', 'state': 'passed'}]})
        self.assertEqual(value['state'], 'not_performed')
        self.assertEqual(value['samples'], [])
        self.assertEqual(self.static.validate_dynamic_failure_evidence(value), [])

    def test_dynamic_harness_reports_process_tree_memory_budget_exhaustion(self):
        with tempfile.TemporaryDirectory(prefix='dynamic memory report ') as folder:
            root = Path(folder)
            bundle = root / 'verified-source.json'
            dynamic_folder = root / 'dynamic-work'
            dynamic_folder.mkdir()
            source_input = {'sources': {'Target.sol': {'content': 'contract Target {}'}}, 'settings': {}}
            failure = self.static.ProcessTreeMemoryLimitExceeded(1024, 2048, '', 'oom guard')
            with mock.patch.object(self.static, 'run_bounded', side_effect=failure):
                result = self.static._run_dynamic_harness(
                    bundle, dynamic_folder, source_input, 'Target.sol', root / 'soljson.js', timeout=1,
                )
            self.assertEqual(result['state'], 'unavailable')
            self.assertEqual(result['reason'], 'dynamic_harness_memory_limit_exceeded')
            self.assertEqual(result['memoryLimitBytes'], 1024)
            self.assertEqual(result['observedSampleBytes'], 2048)
            self.assertIn('not an OS hard quota', result['runnerLimits']['enforcement'])
            self.assertEqual(result['failureEvidence']['state'], 'unavailable')
            self.assertEqual(self.static.validate_dynamic_failure_evidence(result['failureEvidence']), [])

    def test_call_graph_ir_adapter_preserves_unproven_static_semantics(self):
        graph={'schemaVersion':2,'state':'partial','analysisInputFingerprint':'a'*64,
               'entrypoints':[{'function':'Vault.withdraw(uint256)','visibility':'external',
                               'location':{'file':'Vault.sol','lines':[10]}}],
               'edges':[],'paths':[{'entrypoint':'Vault.withdraw(uint256)','path':['Vault.withdraw(uint256)'],
                   'pathFeasibility':'not_proven','effect':{'kind':'state_write','location':{'file':'Vault.sol','lines':[12]}}}]}
        document=self.static.from_call_graph(graph)
        self.assertEqual(document['state'],'partial')
        self.assertEqual(document['operations'][0]['semanticsProven'],False)

    def test_finding_summary_preserves_unconfirmed_severity_buckets(self):
        summary=self.static.finding_summary([
            {'check':'reentrancy-eth','impact':'High','confidence':'Medium','description':'transfer before state update','elements':[{'name':'withdraw()','source_mapping':{'filename_short':'Vault.sol','lines':[31,32]}}]},
            {'check':'timestamp','impact':'Informational','confidence':'High','description':'timestamp used'},
        ])
        self.assertEqual(summary['impactCounts'],{'High':1,'Informational':1})
        self.assertEqual(summary['uniqueFingerprintCount'],2)
        self.assertEqual(summary['highMediumReviewQueue'][0]['check'],'reentrancy-eth')
        self.assertIn('unconfirmed',summary['interpretation'])

    def test_semantic_finding_fingerprint_ignores_element_order_but_preserves_all_elements(self):
        def element(kind,name,line):
            return {'type':kind,'name':name,'source_mapping':{'filename_relative':f'work/runs-v4/s1/static-work/{name}.sol','filename_short':f'{name}.sol','lines':[line]},'type_specific_fields':{'parent':{'type':'contract','name':'Vault'}}}
        left={'check':'reentrancy','impact':'High','confidence':'Medium','elements':[element('function','withdraw',10),element('node','call',13)],'first_markdown_element':'work/runs-v4/s1/static-work/Vault.sol#L10','id':'volatile-a','description':'path A','markdown':'render A'}
        right={'check':'reentrancy','impact':'High','confidence':'Medium','elements':[element('node','call',13),element('function','withdraw',10)],'first_markdown_element':'work/runs-v4/p1/static-work/Vault.sol#L10','id':'volatile-b','description':'path B','markdown':'render B'}
        self.assertEqual(self.static.semantic_finding_fingerprint([left]),self.static.semantic_finding_fingerprint([right]))
        right['elements'].pop()
        self.assertNotEqual(self.static.semantic_finding_fingerprint([left]),self.static.semantic_finding_fingerprint([right]))

    def test_dynamic_worker_reports_elapsed_time_when_runner_raises(self):
        started=__import__('time').monotonic()
        with mock.patch.object(self.static,'_run_target_dynamic',side_effect=RuntimeError('runner failed')):
            value,elapsed,worker_started,worker_ended=self.static._timed_target_dynamic()
        self.assertEqual(value['state'],'unavailable')
        self.assertEqual(value['reason'],'dynamic_analysis_error')
        self.assertGreaterEqual(worker_ended,worker_started)
        self.assertGreaterEqual(elapsed,0)
        self.assertGreaterEqual(worker_started,started)

    def test_source_coverage_summary_supports_sampled_selectors(self):
        coverage={'scope':'sampled target runtime source spans','spans':[{'file':'Engine.sol'}],
                  'sampledSelectors':['0x12345678']}
        summary=self.static.summarize_source_coverage(coverage)
        self.assertEqual(summary['state'],'available')
        self.assertEqual(summary['sampledMethods'],[])
        self.assertEqual(summary['sampledSelectors'],['0x12345678'])
        self.assertEqual(summary['spanCount'],1)

    def test_source_coverage_summary_supports_vault_sampled_methods(self):
        coverage={'scope':'sampled depth-1 target runtime source spans; not exhaustive branch coverage',
                  'spans':[{'file':'Vault.sol','start':1,'length':2,'lineStart':1,'lineEnd':1}],
                  'sampledMethods':['Vault.deposit(uint256)','Vault.withdraw(uint256)']}
        summary=self.static.summarize_source_coverage(coverage)
        self.assertEqual(summary['state'],'available')
        self.assertEqual(summary['sampledMethods'],['Vault.deposit(uint256)','Vault.withdraw(uint256)'])
        self.assertEqual(summary['sampledSelectors'],[])
        self.assertEqual(summary['spanCount'],1)

    def test_malformed_source_coverage_is_reported_as_partial(self):
        summary=self.static.summarize_source_coverage({'sampledMethods':'not-a-list'})
        self.assertEqual(summary['state'],'partial')
        self.assertEqual(summary['spanCount'],None)
        self.assertIn('reason',summary)

    def test_malformed_sampled_selectors_are_reported_as_partial(self):
        summary=self.static.summarize_source_coverage({
            'scope':'sampled depth-1 target runtime source spans',
            'spans':[{'file':'Engine.sol','start':3,'length':5,'lineStart':1,'lineEnd':1}],
            'sampledSelectors':'not-a-list'})
        self.assertEqual(summary['state'],'partial')
        self.assertEqual(summary['sampledSelectors'],[])
        self.assertIn('sampledSelectors',summary['reason'])

    def test_parallel_analysis_slot_is_exclusive_and_reusable_after_release(self):
        with tempfile.TemporaryDirectory(prefix='parallel analysis slot ') as folder:
            with mock.patch.object(self.static,'ROOT',Path(folder)), mock.patch.dict(os.environ,{'FLARE_ANALYSIS_PARALLEL':'on'}):
                first,reason=self.static._acquire_parallel_analysis_slot()
                self.assertIsNotNone(first)
                self.assertIsNone(reason)
                second,reason=self.static._acquire_parallel_analysis_slot()
                self.assertIsNone(second)
                self.assertEqual(reason,'parallel_slot_busy')
                self.static._release_parallel_analysis_slot(first)
                third,reason=self.static._acquire_parallel_analysis_slot()
                self.assertIsNotNone(third)
                self.assertIsNone(reason)
                self.static._release_parallel_analysis_slot(third)

    def test_parallel_slot_auto_gates_memory_and_closes_handle_on_lock_error(self):
        with mock.patch.dict(os.environ,{'FLARE_ANALYSIS_PARALLEL':'auto'}), mock.patch.object(os,'cpu_count',return_value=8), mock.patch.object(self.static,'_available_memory_bytes',return_value=4*1024**3-1):
            self.assertEqual(self.static._acquire_parallel_analysis_slot(),(None,'less_than_4_gib_available'))
        with tempfile.TemporaryDirectory(prefix='parallel slot failure ') as folder:
            handle=(Path(folder)/'slot').open('a+')
            with mock.patch.dict(os.environ,{'FLARE_ANALYSIS_PARALLEL':'on'}), mock.patch.object(Path,'open',return_value=handle), mock.patch.object(self.static.fcntl,'flock',side_effect=OSError('lock failure')):
                with self.assertRaises(OSError):self.static._acquire_parallel_analysis_slot()
            self.assertTrue(handle.closed)

    def test_overlap_waits_for_dynamic_worker_before_releasing_slot_on_interrupt(self):
        started=threading.Event();finish=threading.Event()
        with tempfile.TemporaryDirectory(prefix='overlap interrupt ') as folder:
            handle=(Path(folder)/'slot').open('a+')
            def dynamic():
                started.set()
                if not finish.wait(2):raise RuntimeError('dynamic handshake timed out')
                self.assertFalse(handle.closed)
                return {'state':'passed'}
            with mock.patch.object(self.static,'_acquire_parallel_analysis_slot',return_value=(handle,None)), mock.patch.object(self.static,'_run_target_dynamic',side_effect=dynamic):
                with self.assertRaises(KeyboardInterrupt):
                    with self.static._dynamic_analysis_overlap((),True) as (future,reason):
                        self.assertIsNone(reason);self.assertTrue(started.wait(2))
                        finish.set()
                        raise KeyboardInterrupt('static interrupted')
                self.assertTrue(handle.closed)
                self.assertEqual(future.result()[0]['state'],'passed')

    def test_overlap_falls_back_and_releases_slot_when_worker_submission_fails(self):
        with tempfile.TemporaryDirectory(prefix='overlap submission ') as folder:
            handle=(Path(folder)/'slot').open('a+');executor=mock.Mock()
            executor.submit.side_effect=RuntimeError('executor refused task')
            with mock.patch.object(self.static,'_acquire_parallel_analysis_slot',return_value=(handle,None)), mock.patch.object(self.static.concurrent.futures,'ThreadPoolExecutor',return_value=executor):
                with self.static._dynamic_analysis_overlap((),True) as (future,reason):
                    self.assertIsNone(future)
                    self.assertEqual(reason,'parallel_start_failed:RuntimeError')
                    self.assertTrue(handle.closed)
            executor.shutdown.assert_called_once_with(wait=True)

    def test_analyze_parallel_failure_restores_environment_and_keeps_dynamic_input_isolated(self):
        original_source='pragma solidity 0.8.28; contract VaultV2 {}'
        static_started=threading.Event();dynamic_checked=threading.Event();observed={}
        with tempfile.TemporaryDirectory(prefix='parallel analyze failure ') as folder:
            base=Path(folder);bundle=base/'verified-source.json';handle=(base/'slot').open('a+')
            data={'sources':{'Vault.sol':{'content':original_source}},'compilation':{'compilerVersion':'0.8.28+commit.7893614a'},'metadata':{'settings':{'compilationTarget':{'Vault.sol':'VaultV2'}}},'stdJsonInput':{'settings':{'optimizer':{'enabled':True,'runs':200}}}}
            bundle.write_text(json.dumps(data))
            original_environment=dict(os.environ)
            def compile_failure(platform,**kwargs):
                platform._json['sources']['Vault.sol']['content']='MUTATED BY STATIC COMPILER'
                platform._json['settings']['optimizer']['runs']=999
                os.environ['STATIC_COMPILER_TEST_MARKER']='temporary'
                static_started.set()
                self.assertTrue(dynamic_checked.wait(2))
                raise RuntimeError('static compiler failed after mutation')
            def dynamic(*args):
                self.assertTrue(static_started.wait(2))
                _,dynamic_folder,source_input,_,version,_,_,_,environment=args
                observed.update(folder=dynamic_folder,source_input=source_input,version=version,environment=environment)
                try:
                    self.assertEqual(source_input['sources']['Vault.sol']['content'],original_source)
                    self.assertEqual(source_input['settings']['optimizer']['runs'],200)
                    self.assertEqual(environment,original_environment)
                    self.assertNotIn('STATIC_COMPILER_TEST_MARKER',environment)
                finally:dynamic_checked.set()
                return {'state':'passed','tests':1,'passed':1,'failed':0}
            with mock.patch.object(self.static,'_acquire_parallel_analysis_slot',return_value=(handle,None)), mock.patch('crytic_compile.CryticCompile',side_effect=compile_failure), mock.patch.object(self.static,'_run_target_dynamic',side_effect=dynamic):
                result=self.static.analyze(bundle)
            self.assertEqual(dict(os.environ),original_environment)
            self.assertTrue(handle.closed)
            self.assertEqual(result['state'],'failed')
            self.assertIn('static compiler failed',result['staticError'])
            self.assertEqual(result['localTests']['state'],'passed')
            self.assertEqual(result['analysisExecution']['staticDynamicStages'],'parallel')
            self.assertEqual(observed['folder'],(base/'dynamic-work').resolve())
            self.assertEqual(observed['version'],'0.8.28')
            self.assertEqual(json.loads((base/'static-work/local-test-input.json').read_text())['sources']['Vault.sol']['content'],original_source)
            for key in ('analysisWallMs','staticAnalysisMs','dynamicAnalysisMs','dynamicJoinMs','stageOverlapMs'):
                self.assertGreaterEqual(result['timings'][key],0)
            self.assertFalse(result['confirmed'])

    def test_real_analyze_writes_discovery_artifacts_without_promoting_evidence(self):
        script=textwrap.dedent('''
            import importlib.util,json,sys
            from pathlib import Path
            root,base=Path(sys.argv[1]),Path(sys.argv[2])
            spec=importlib.util.spec_from_file_location('review',root/'scripts/review-static.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
            bundle=base/'verified-source.json'
            data={'sources':{'Vault.sol':{'content':'pragma solidity 0.8.28; contract Vault { uint public total; function withdraw(uint amount) external { total -= amount; } }'}},'compilation':{'compilerVersion':'0.8.28+commit.7893614a'},'metadata':{'settings':{'compilationTarget':{'Vault.sol':'Vault'}}}}
            bundle.write_text(json.dumps(data))
            result=m.analyze(bundle)
            assert result['staticStages']['compile']=='completed',result
            assert result['localTests']['state']=='not_performed',result
            assert result['confirmed'] is False,result
            summary=result['discoveryPlan']
            assert summary['state'] in ('planned','partial'),summary
            assert summary['confirmedVulnerabilities']==0 and summary['pathSpecificPropertiesVerified']==0,summary
            assert Path(summary['report']).is_file() and Path(summary['html']).is_file(),summary
            plan=json.loads(Path(summary['report']).read_text())
            assert plan['obligationCount']>0 and plan['untestedPropertyCount']>0,plan
            assert all(p['state']=='needs_test' for row in plan['obligations'] for p in row['properties']),plan
            assert result['timings']['analysisWallMs']>=result['timings']['discoveryPlanMs']>=0,result
        ''')
        with tempfile.TemporaryDirectory(prefix='analysis plan regression ') as folder:
            run=subprocess.run([sys.executable,'-c',script,str(ROOT),folder],capture_output=True,text=True,timeout=30,env=dict(os.environ,FLARE_ANALYSIS_PARALLEL='off'))
            self.assertEqual(run.returncode,0,run.stderr)

    def test_call_graph_traces_entrypoint_through_internal_call_to_state_and_asset_effects(self):
        def location(file,line):return SimpleNamespace(filename=SimpleNamespace(relative=file,short=file),lines=[line])
        state=SimpleNamespace(name='credit',canonical_name='Vault.credit')
        withdraw=SimpleNamespace(canonical_name='Vault.withdraw(uint256)',contract=SimpleNamespace(name='Vault'),visibility='external',is_constructor=False,is_fallback=False,source_mapping=location('Vault.sol',10),modifiers=[],nodes=[])
        settle=SimpleNamespace(canonical_name='Vault._settle(uint256)',contract=SimpleNamespace(name='Vault'),visibility='internal',is_constructor=False,is_fallback=False,source_mapping=location('Vault.sol',20),modifiers=[],nodes=[])
        internal=SimpleNamespace(function=settle,function_name='_settle')
        withdraw.nodes=[SimpleNamespace(source_mapping=location('Vault.sol',12),state_variables_written=[],internal_calls=[internal],library_calls=[],high_level_calls=[],low_level_calls=[],expression=' _settle(amount)')]
        token_call=SimpleNamespace(function_name='safeTransfer',destination='token',call_value=None)
        settle.nodes=[SimpleNamespace(source_mapping=location('Vault.sol',22),state_variables_written=[state],internal_calls=[],library_calls=[],high_level_calls=[token_call],low_level_calls=[],expression='credit[msg.sender] = 0; token.safeTransfer(msg.sender, amount)')]
        contract=SimpleNamespace(name='Vault',functions=[withdraw,settle])
        report=self.static.build_call_graph([contract],['Vault'])
        self.assertEqual(report['entrypointCount'],1)
        self.assertEqual(report['stateWritePathCount'],1)
        self.assertEqual(report['externalCallPathCount'],1)
        self.assertEqual(report['assetRelatedCallPathCount'],1)
        self.assertTrue(all(row['pathFeasibility']=='not_proven' for row in report['paths']))
        self.assertEqual({row['effect']['kind'] for row in report['paths']},{'state_write','external_call'})
        self.assertEqual(report['paths'][0]['path'][0],'Vault::Vault.withdraw(uint256)')
        self.assertTrue(all(row['effect']['location']['file']=='Vault.sol' for row in report['paths']))

    def test_call_graph_emits_modifier_permissions_and_role_name_candidates_as_unproven(self):
        def location(file,line):return SimpleNamespace(filename=SimpleNamespace(relative=file,short=file),lines=[line])
        modifier=SimpleNamespace(name='onlyRole',canonical_name='Vault.onlyRole(bytes32)',source_mapping=location('Vault.sol',8))
        function=SimpleNamespace(canonical_name='Vault.withdraw()',contract=SimpleNamespace(name='Vault'),
            visibility='external',is_constructor=False,is_fallback=False,source_mapping=location('Vault.sol',10),
            modifiers=[modifier],nodes=[SimpleNamespace(source_mapping=location('Vault.sol',11),state_variables_written=[],
                internal_calls=[],library_calls=[],high_level_calls=[],low_level_calls=[],expression='')])

        report=self.static.build_call_graph([SimpleNamespace(name='Vault',functions=[function])],['Vault'])

        self.assertEqual(report['permissions'][0]['kind'],'modifier_gate_candidate')
        self.assertEqual(report['permissions'][0]['modifier'],'Vault.onlyRole(bytes32)')
        self.assertEqual(report['permissions'][0]['confidence'],'heuristic')
        self.assertFalse(report['permissions'][0]['semanticsProven'])
        self.assertEqual(report['roles'][0]['kind'],'role_name_candidate')
        self.assertEqual(report['roles'][0]['discovery'],'modifier_name')
        self.assertFalse(report['roles'][0]['semanticsProven'])

    def test_call_graph_attaches_effect_site_ids_to_exact_source_spans(self):
        source_hash='d'*64
        mapping=SimpleNamespace(filename=SimpleNamespace(relative='Vault.sol',short='Vault.sol'),
                                lines=[12],start=100,length=8)
        state=SimpleNamespace(name='credit',canonical_name='Vault.credit')
        token_call=SimpleNamespace(function_name='safeTransfer',destination='token',call_value=None)
        node=SimpleNamespace(source_mapping=mapping,state_variables_written=[state],internal_calls=[],
            library_calls=[],high_level_calls=[token_call],low_level_calls=[],expression='credit = 0; token.safeTransfer()')
        function=SimpleNamespace(canonical_name='Vault.withdraw()',contract=SimpleNamespace(name='Vault'),
            visibility='external',is_constructor=False,is_fallback=False,source_mapping=mapping,
            modifiers=[],nodes=[node])

        report=self.static.build_call_graph([SimpleNamespace(name='Vault',functions=[function])],['Vault'],
            source_digests={'Vault.sol':source_hash})

        by_kind={path['effect']['kind']:path['effect'] for path in report['paths']}
        for kind,effect in by_kind.items():
            self.assertEqual(effect['sourceSha256'],source_hash)
            self.assertEqual(effect['location']['start'],100)
            self.assertEqual(effect['location']['length'],8)
            self.assertEqual(effect['effectSiteId'],self.static.effect_site_id(source_hash,'Vault.sol',100,8,kind))

    def test_source_alias_exact_match_is_not_overridden_by_a_shorter_suffix(self):
        item=SimpleNamespace(source_mapping=SimpleNamespace(
            filename=SimpleNamespace(relative='lib/A.sol',short='A.sol'),lines=[1]))

        location=self.static._source_location(item,{'A.sol':'A.sol','lib/A.sol':'lib/A.sol'})

        self.assertEqual(location['file'],'lib/A.sol')

    def test_call_graph_distinguishes_unknown_zero_and_nonzero_native_value(self):
        def call(name,value):
            return SimpleNamespace(function_name=name,destination='receiver',call_value=value)
        self.assertEqual(self.static._value_transfer_evidence(SimpleNamespace(call_value=None))['state'],'not_attached')
        self.assertEqual(self.static._value_transfer_evidence(SimpleNamespace(call_value=SimpleNamespace(value='0')))['state'],'zero')
        self.assertEqual(self.static._value_transfer_evidence(SimpleNamespace(call_value=SimpleNamespace(value='5')))['state'],'nonzero')
        self.assertEqual(self.static._value_transfer_evidence(SimpleNamespace(call_value=SimpleNamespace(name='amount')))['state'],'unknown')
        fn=SimpleNamespace(canonical_name='Vault.execute()',contract=SimpleNamespace(name='Vault'),visibility='external',is_constructor=False,is_fallback=False,source_mapping=None,modifiers=[],nodes=[])
        fn.nodes=[SimpleNamespace(source_mapping=None,state_variables_written=[],internal_calls=[],library_calls=[],high_level_calls=[call('sendMessage',SimpleNamespace(value='0')),call('pay',SimpleNamespace(name='amount')),call('sendTip',SimpleNamespace(value='5'))],low_level_calls=[],expression='external calls')]
        report=self.static.build_call_graph([SimpleNamespace(name='Vault',functions=[fn])],['Vault'])
        effects=[row['effect'] for row in report['paths']]
        by_name={effect['function']:effect for effect in effects}
        self.assertFalse(by_name['sendMessage']['sendsValue'])
        self.assertIsNone(by_name['pay']['sendsValue'])
        self.assertTrue(by_name['sendTip']['sendsValue'])
        self.assertEqual(report['assetRelatedCallPathCount'],1)
        self.assertEqual(by_name['pay']['valueTransferEvidence']['state'],'unknown')

    def test_static_dynamic_correlation_deduplicates_executed_opcodes(self):
        source_hash='a'*64
        location={'file':'Vault.sol','lines':[12,13],'start':100,'length':8}
        site=self.static.effect_site_id(source_hash,'Vault.sol',100,8,'state_write')
        self.assertEqual(site,'4c4476a32cc8b1b5a8099cd106c9a51cae7f648c65783c1623c9620eee519011')
        effect={'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,'location':location}
        runtime_location={'file':'Vault.sol','lineStart':12,'lineEnd':13,'start':100,'length':8,'sourceSha256':source_hash}
        graph={'paths':[{'effect':effect},{'effect':copy.deepcopy(effect)}]}
        local={'traces':[{'transactionHash':'0xabc','failed':False,'targetDepth':2,'effects':[{'depth':2,'op':'SSTORE','effectSiteId':site,'sourceLocation':runtime_location}]}]}
        report=self.static.correlate_dynamic_effects(graph,local)
        self.assertEqual(report['matchedEffectCount'],1)
        self.assertEqual(report['candidatePathPairCount'],2)
        self.assertEqual(report['sourceOverlapCandidatePathPairCount'],2)
        self.assertEqual(len(report['matches'][0]['candidatePathIndices']),2)
        self.assertEqual(report['matches'][0]['effectSiteId'],site)
        self.assertFalse(report['matches'][0]['completePathProven'])
        graph_bytes=json.dumps(graph,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
        self.assertEqual(report['graphFingerprint'],hashlib.sha256(graph_bytes).hexdigest())

    def test_static_dynamic_correlation_rejects_depth_opcode_and_source_mismatches(self):
        graph={'paths':[{'effect':{'kind':'state_write','location':{'file':'Vault.sol','lines':[12]}}}]}
        mismatches=[
            {'depth':1,'op':'SSTORE','sourceLocation':{'file':'Vault.sol','lineStart':12,'lineEnd':12}},
            {'depth':2,'op':'CALL','sourceLocation':{'file':'Vault.sol','lineStart':12,'lineEnd':12}},
            {'depth':2,'op':'SSTORE','sourceLocation':{'file':'Other.sol','lineStart':12,'lineEnd':12}},
            {'depth':2,'op':'SSTORE','sourceLocation':{'file':'Vault.sol','lineStart':30,'lineEnd':30}},
        ]
        local={'traces':[{'targetDepth':2,'effects':[effect]} for effect in mismatches]}

        report=self.static.correlate_dynamic_effects(graph,local)

        self.assertEqual(report['matchedEffectCount'],0)
        self.assertEqual(report['candidatePathPairCount'],0)
        self.assertEqual(report['matches'],[])

    def test_static_dynamic_correlation_validates_limit(self):
        for invalid_limit in (-1, 1.5, True):
            with self.subTest(limit=invalid_limit), self.assertRaisesRegex(
                ValueError, 'limit must be a non-negative integer',
            ):
                self.static.correlate_dynamic_effects({}, {}, limit=invalid_limit)

        source_hash='f'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',120,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[12],'start':120,'length':4}}}]}
        local={'traces':[{'transactionHash':'0xlimit','failed':False,'targetDepth':2,'effects':[{'depth':2,'op':'SSTORE','effectSiteId':site,
            'sourceLocation':{'file':'Vault.sol','lineStart':12,'lineEnd':12,'start':120,'length':4,'sourceSha256':source_hash}}]}]}
        report=self.static.correlate_dynamic_effects(graph,local,limit=0)
        self.assertEqual(report['matchedEffectCount'],1)
        self.assertEqual(report['sourceOverlapCandidatePathPairCount'],1)
        self.assertEqual(report['reportedMatches'],0)
        self.assertEqual(report['matches'],[])
        self.assertEqual(report['truncatedMatches'],1)

    def _correlation_fixture(self,count,repeated_site=False):
        source_hash='a'*64
        paths=[];effects=[]
        for index in range(count):
            start=100 if repeated_site else 100+index*8
            line=12 if repeated_site else index+1
            site=self.static.effect_site_id(source_hash,'Vault.sol',start,4,'state_write')
            paths.append({'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
                'location':{'file':'Vault.sol','lines':[line],'start':start,'length':4}}})
            effects.append({'depth':1,'op':'SSTORE','effectSiteId':site,
                'sourceLocation':{'file':'Vault.sol','lineStart':line,'lineEnd':line,
                                  'start':start,'length':4,'sourceSha256':source_hash}})
        return {'paths':paths},{'traces':[{'transactionHash':'0xscale','failed':False,'effects':effects}]}

    def test_static_dynamic_correlation_preserves_path_then_execution_order_across_opcodes(self):
        graph,local=self._correlation_fixture(3)
        first,second,third=graph['paths']
        second['effect']['kind']='external_call'
        location=second['effect']['location']
        site=self.static.effect_site_id('a'*64,'Vault.sol',location['start'],4,'external_call')
        second['effect']['effectSiteId']=site
        first_run,second_run,third_run=local['traces'][0]['effects']
        second_run.update(op='DELEGATECALL',effectSiteId=site)
        callcode=copy.deepcopy(second_run);callcode['op']='CALLCODE'
        staticcall=copy.deepcopy(second_run);staticcall['op']='STATICCALL'
        graph['paths']=[second,first,copy.deepcopy(second),third,copy.deepcopy(first)]
        local['traces'][0]['effects']=[first_run,second_run,callcode,third_run]
        local['traces'].append({'transactionHash':'0xnext','failed':True,'effects':[staticcall]})
        expected=[(0,1),(0,2),(1,0),(0,0),(0,3)]
        for limit in (0,1,2,3,4,20):
            with self.subTest(limit=limit):
                report=self.static.correlate_dynamic_effects(graph,local,limit=limit)
                self.assertEqual([(row['traceIndex'],row['effectIndex']) for row in report['matches']],expected[:limit])
                self.assertEqual(report['matchedEffectCount'],5)
                self.assertEqual(report['candidatePathPairCount'],9)
                self.assertEqual(report['sourceOverlapCandidatePathPairCount'],9)
                self.assertEqual(report['reportedMatches'],min(5,limit))
                self.assertEqual(report['truncatedMatches'],max(0,5-limit))
                for match in report['matches']:
                    indices=[0,2] if match['opcode'] in ('DELEGATECALL','CALLCODE','STATICCALL') else [1,4] if match['effectIndex']==0 else [3]
                    self.assertEqual(match['candidatePathIndices'],indices[:limit])
                    self.assertFalse(match['completePathProven'])

    def test_static_dynamic_correlation_counts_unbound_inclusive_line_overlaps(self):
        graph,local=self._correlation_fixture(1)
        base=local['traces'][0]['effects'][0]
        graph['paths'][0]['effect']['location']['lines']=[10,20]
        effects=[]
        for line_start,line_end in ((1,10),(20,30),(15,15),(1,9),(21,30)):
            effect=copy.deepcopy(base)
            effect['sourceLocation'].update(lineStart=line_start,lineEnd=line_end)
            effects.append(effect)
        effects[0]['sourceLocation']['sourceSha256']='bad'
        effects[1]['effectSiteId']='bad'
        effects[2]['sourceLocation']['start']=-1
        local['traces'][0]['effects']=effects
        report=self.static.correlate_dynamic_effects(graph,local,limit=1)
        self.assertEqual(report['sourceOverlapCandidatePathPairCount'],3)
        self.assertEqual(report['unboundSourceOverlapCandidatePathPairCount'],3)
        self.assertEqual(report['candidatePathPairCount'],0)
        self.assertEqual(report['matchedEffectCount'],0)
        self.assertEqual(report['matches'],[])

    def test_static_dynamic_correlation_counts_union_members_once_and_finds_first_path(self):
        graph,local=self._correlation_fixture(1)
        base_path=graph['paths'][0]
        graph['paths']=[]
        for lines in ([30],[10],[20,10],[15],[30]):
            path=copy.deepcopy(base_path);path['effect']['location']['lines']=lines
            graph['paths'].append(path)
        base_effect=local['traces'][0]['effects'][0]
        effects=[]
        for line_start,line_end in ((1,35),(10,10),(21,29),(30,30),(15,15),(20,20),(1,9)):
            effect=copy.deepcopy(base_effect)
            effect['sourceLocation'].update(lineStart=line_start,lineEnd=line_end)
            effects.append(effect)
        local['traces'][0]['effects']=effects
        expected_order=[0,3,1,4,5]
        expected_indices={0:[0,1,2,3,4],3:[0,4],1:[1,2],4:[2,3],5:[2]}
        for limit in (0,1,2,20):
            with self.subTest(limit=limit):
                report=self.static.correlate_dynamic_effects(graph,local,limit=limit)
                self.assertEqual(report['matchedEffectCount'],5)
                self.assertEqual(report['candidatePathPairCount'],12)
                self.assertEqual(report['sourceOverlapCandidatePathPairCount'],12)
                self.assertEqual([row['effectIndex'] for row in report['matches']],expected_order[:limit])
                for match in report['matches']:
                    self.assertEqual(match['candidatePathIndices'],expected_indices[match['effectIndex']][:limit])

    def test_static_dynamic_correlation_reads_distinct_site_line_bounds_once(self):
        class CountedSource(dict):
            line_reads=0
            def get(self,key,default=None):
                if key in ('lineStart','lineEnd'):type(self).line_reads+=1
                return super().get(key,default)
        graph,local=self._correlation_fixture(400)
        for effect in local['traces'][0]['effects']:
            effect['sourceLocation']=CountedSource(effect['sourceLocation'])
        report=self.static.correlate_dynamic_effects(graph,local,limit=1)
        self.assertEqual(CountedSource.line_reads,800)
        self.assertEqual(report['matchedEffectCount'],400)
        self.assertEqual(report['candidatePathPairCount'],400)
        self.assertEqual(report['sourceOverlapCandidatePathPairCount'],400)
        self.assertEqual(report['reportedMatches'],1)

    def test_static_dynamic_correlation_caps_peak_full_match_storage(self):
        graph,local=self._correlation_fixture(120,repeated_site=True)
        function=self.static.correlate_dynamic_effects
        for limit in (0,1,3):
            with self.subTest(limit=limit):
                peak=[0]
                def observe(frame,event,arg):
                    if frame.f_code is function.__code__ and event in ('line','return'):
                        peak[0]=max(peak[0],len(frame.f_locals.get('matches_by_execution',{})))
                    return observe
                previous=sys.gettrace()
                try:
                    sys.settrace(observe)
                    report=function(graph,local,limit=limit)
                finally:sys.settrace(previous)
                self.assertEqual(peak[0],limit)
                self.assertEqual(report['matchedEffectCount'],120)
                self.assertEqual(report['candidatePathPairCount'],14400)
                self.assertEqual(report['sourceOverlapCandidatePathPairCount'],14400)
                self.assertEqual(report['reportedMatches'],limit)
                self.assertEqual(report['truncatedMatches'],120-limit)
                for match in report['matches']:
                    self.assertEqual(match['candidatePathIndices'],list(range(limit)))

    def test_static_dynamic_correlation_repeated_site_work_does_not_multiply_pairs(self):
        function=self.static.correlate_dynamic_effects
        counts=[]
        for size in (80,400):
            graph,local=self._correlation_fixture(size,repeated_site=True)
            events=[0]
            def observe(frame,event,arg):
                if (event=='line' and frame.f_code.co_filename==function.__code__.co_filename and
                        frame.f_code.co_name in ('correlate_dynamic_effects','candidate_executions')):
                    events[0]+=1
                return observe
            previous=sys.gettrace()
            try:
                sys.settrace(observe)
                report=function(graph,local,limit=1)
            finally:sys.settrace(previous)
            counts.append(events[0])
            self.assertEqual(report['candidatePathPairCount'],size*size)
            self.assertEqual(report['matchedEffectCount'],size)
            self.assertEqual(report['matches'][0]['candidatePathIndices'],[0])
        # Five times the input allows subquadratic overhead, not 25x pair walks.
        self.assertLess(counts[1],counts[0]*8)

    def test_static_dynamic_correlation_without_traces(self):
        graph={'paths':[{'effect':{'kind':'state_write','location':{'file':'Vault.sol','lines':[20]}}}]}
        report=self.static.correlate_dynamic_effects(graph,{'traces':[]})

        self.assertEqual(report['state'],'not_performed')
        self.assertEqual(report['matchedEffectCount'],0)
        self.assertEqual(report['candidatePathPairCount'],0)
        self.assertEqual(report['reportedMatches'],0)
        self.assertEqual(report['matches'],[])

    def test_static_dynamic_correlation_distinguishes_invalid_and_partial_trace_evidence(self):
        source_hash='e'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',600,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[60],'start':600,'length':4}}}]}
        runtime={'file':'Vault.sol','lineStart':60,'lineEnd':60,'start':600,'length':4,'sourceSha256':source_hash}
        valid={'state':'available','traceValid':True,'transactionHash':'0xvalid','failed':False,'targetDepth':1,
               'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,'sourceLocation':runtime}]}
        invalid={'state':'unavailable','traceValid':False,'transactionHash':'0xinvalid'}

        partial=self.static.correlate_dynamic_effects(graph,{'traces':[invalid,valid]})
        self.assertEqual(partial['state'],'partial')
        self.assertEqual(partial['traceCount'],2)
        self.assertEqual(partial['validTraceCount'],1)
        self.assertEqual(partial['invalidTraceCount'],1)
        self.assertEqual(partial['matchedEffectCount'],1)

        unavailable=self.static.correlate_dynamic_effects(graph,{'traces':[invalid]})
        self.assertEqual(unavailable['state'],'unavailable')
        self.assertEqual(unavailable['validTraceCount'],0)
        self.assertEqual(unavailable['invalidTraceCount'],1)
        self.assertEqual(unavailable['matchedEffectCount'],0)

    def test_static_dynamic_correlation_marks_effect_truncation_partial(self):
        source_hash='f'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',610,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[61],'start':610,'length':4}}}]}
        trace={'state':'available','traceValid':True,'transactionHash':'0xtruncated','failed':False,'targetDepth':1,
               'effectCount':3,'reportedEffectCount':1,'effectsTruncated':True,
               'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,
                           'sourceLocation':{'file':'Vault.sol','lineStart':61,'lineEnd':61,
                                             'start':610,'length':4,'sourceSha256':source_hash}}]}
        report=self.static.correlate_dynamic_effects(graph,{'traces':[trace]})
        self.assertEqual(report['state'],'partial')
        self.assertEqual(report['validTraceCount'],1)
        self.assertEqual(report['truncatedTraceCount'],1)
        self.assertEqual(report['truncatedEffectCount'],2)
        self.assertEqual(report['matchedEffectCount'],1)

    def test_static_dynamic_correlation_accepts_partial_trace_state(self):
        source_hash='a'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',615,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[61],'start':615,'length':4}}}]}
        trace={'state':'partial','traceValid':True,'transactionHash':'0xpartial-state','failed':False,'targetDepth':1,
               'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,
                           'sourceLocation':{'file':'Vault.sol','lineStart':61,'lineEnd':61,
                                             'start':615,'length':4,'sourceSha256':source_hash}}]}
        report=self.static.correlate_dynamic_effects(graph,{'traces':[trace]})
        self.assertEqual(report['state'],'partial')
        self.assertEqual(report['validTraceCount'],1)
        self.assertEqual(report['partialStateTraceCount'],1)
        self.assertEqual(report['matchedEffectCount'],1)

    def test_static_dynamic_correlation_marks_step_limited_trace_partial(self):
        source_hash='9'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',620,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[62],'start':620,'length':4}}}]}
        trace={'state':'available','traceValid':True,'transactionHash':'0xstep-limited','failed':False,'targetDepth':1,
               'steps':250001,'processedSteps':250000,'stepsTruncated':True,'effectCountComplete':False,
               'effectCount':1,'reportedEffectCount':1,'effectsTruncated':False,
               'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,
                           'sourceLocation':{'file':'Vault.sol','lineStart':62,'lineEnd':62,
                                             'start':620,'length':4,'sourceSha256':source_hash}}]}
        report=self.static.correlate_dynamic_effects(graph,{'traces':[trace]})
        self.assertEqual(report['state'],'partial')
        self.assertEqual(report['validTraceCount'],1)
        self.assertEqual(report['stepTruncatedTraceCount'],1)
        self.assertEqual(report['matchedEffectCount'],1)

    def test_static_dynamic_correlation_rejects_available_trace_without_validity_attestation(self):
        source_hash='1'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',620,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[62],'start':620,'length':4}}}]}
        trace={'state':'available','transactionHash':'0xattestation','failed':False,'targetDepth':1,
               'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,
                           'sourceLocation':{'file':'Vault.sol','lineStart':62,'lineEnd':62,
                                             'start':620,'length':4,'sourceSha256':source_hash}}]}
        report=self.static.correlate_dynamic_effects(graph,{'traces':[trace]})
        self.assertEqual(report['state'],'unavailable')
        self.assertEqual(report['invalidTraceCount'],1)
        self.assertEqual(report['matchedEffectCount'],0)

    def test_static_dynamic_correlation_rejects_truncation_without_consistent_counts(self):
        trace={'state':'available','traceValid':True,'transactionHash':'0xtrunc-bad','failed':False,
               'targetDepth':1,'effectsTruncated':True,'effects':[{'depth':1,'op':'SSTORE'}]}
        report=self.static.correlate_dynamic_effects({}, {'traces':[trace]})
        self.assertEqual(report['state'],'unavailable')
        self.assertEqual(report['invalidTraceCount'],1)

    def test_static_dynamic_correlation_rejects_missing_effects_without_truncation_flag(self):
        trace={'state':'available','traceValid':True,'transactionHash':'0xtrunc-hidden','failed':False,
               'targetDepth':1,'effectCount':2,'reportedEffectCount':1,'effectsTruncated':False,
               'effects':[{'depth':1,'op':'SSTORE'}]}
        report=self.static.correlate_dynamic_effects({}, {'traces':[trace]})
        self.assertEqual(report['state'],'unavailable')
        self.assertEqual(report['invalidTraceCount'],1)

    def test_static_dynamic_correlation_binds_selfdestruct_opcode_to_candidate_site(self):
        source_hash='d'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',630,8,'selfdestruct')
        graph={'paths':[{'effect':{'kind':'selfdestruct','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[63],'start':630,'length':8}}}]}
        trace={'state':'available','traceValid':True,'transactionHash':'0xdestroy','failed':False,'targetDepth':1,
               'effects':[{'depth':1,'op':'SELFDESTRUCT','effectSiteId':site,
                           'sourceLocation':{'file':'Vault.sol','lineStart':63,'lineEnd':63,'start':630,
                                             'length':8,'sourceSha256':source_hash}}]}
        report=self.static.correlate_dynamic_effects(graph,{'traces':[trace]})
        self.assertEqual(report['matchedEffectCount'],1)
        self.assertEqual(report['matches'][0]['opcode'],'SELFDESTRUCT')
        self.assertIn('not proven',report['scope'])

    def test_static_dynamic_correlation_marks_reverted_match_unproven(self):
        source_hash='b'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',200,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[20],'start':200,'length':4}}}]}
        local={'traces':[{'transactionHash':'0xfailed','failed':True,'targetDepth':1,
            'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,'sourceLocation':{'file':'Vault.sol','lineStart':20,'lineEnd':20,'start':200,'length':4,'sourceSha256':source_hash}}]}]}

        report=self.static.correlate_dynamic_effects(graph,local)

        self.assertEqual(report['matchedEffectCount'],1)
        self.assertEqual(len(report['matches']),1)
        self.assertTrue(report['matches'][0]['transactionReverted'])
        self.assertFalse(report['matches'][0]['completePathProven'])
        self.assertIn('complete path, authorization and deployed reachability are not proven',report['scope'])

    def test_static_dynamic_correlation_does_not_bind_source_line_overlap_without_matching_site_id(self):
        source_hash='c'*64
        static_site=self.static.effect_site_id(source_hash,'Vault.sol',300,5,'state_write')
        runtime_site=self.static.effect_site_id(source_hash,'Vault.sol',305,5,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':static_site,
            'location':{'file':'Vault.sol','lines':[30],'start':300,'length':5}}}]}
        local={'traces':[{'transactionHash':'0xabc','failed':False,'targetDepth':1,
            'effects':[{'depth':1,'op':'SSTORE','effectSiteId':runtime_site,
                'sourceLocation':{'file':'Vault.sol','lineStart':30,'lineEnd':30,'start':305,'length':5,'sourceSha256':source_hash}}]}]}

        report=self.static.correlate_dynamic_effects(graph,local)

        self.assertEqual(report['matchedEffectCount'],0)
        self.assertEqual(report['candidatePathPairCount'],0)
        self.assertEqual(report['sourceOverlapCandidatePathPairCount'],1)
        self.assertEqual(report['unboundSourceOverlapCandidatePathPairCount'],1)
        self.assertEqual(report['matches'],[])

    def test_static_dynamic_correlation_skips_malformed_source_file_without_crashing(self):
        source_hash='a'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',300,5,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':['Vault.sol'],'lines':[30],'start':300,'length':5}}}]}
        local={'traces':[{'transactionHash':'0xmalformed-file','failed':False,'targetDepth':1,
            'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,
                'sourceLocation':{'file':'Vault.sol','lineStart':30,'lineEnd':30,'start':300,'length':5,'sourceSha256':source_hash}}]}]}

        report=self.static.correlate_dynamic_effects(graph,local)

        self.assertEqual(report['state'],'available')
        self.assertEqual(report['sourceOverlapCandidatePathPairCount'],0)
        self.assertEqual(report['candidatePathPairCount'],0)
        self.assertEqual(report['matches'],[])

    def test_static_dynamic_correlation_skips_invalid_line_and_byte_spans(self):
        source_hash='7'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',300,5,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[30],'start':300,'length':5}}}]}
        runtime={'file':'Vault.sol','lineStart':30,'lineEnd':30,'start':300,'length':5,
                 'sourceSha256':source_hash}
        local={'traces':[{'transactionHash':'0xinvalid-span','failed':False,'targetDepth':1,
            'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,'sourceLocation':runtime}]}]}

        for bad_lines in ('30', [True], [0]):
            with self.subTest(bad_lines=bad_lines):
                candidate=copy.deepcopy(graph)
                candidate['paths'][0]['effect']['location']['lines']=bad_lines
                report=self.static.correlate_dynamic_effects(candidate,local)
                self.assertEqual(report['state'],'available')
                self.assertEqual(report['sourceOverlapCandidatePathPairCount'],0)
                self.assertEqual(report['candidatePathPairCount'],0)

        for bad_start,bad_length in ((-1,5),(300,0)):
            with self.subTest(bad_start=bad_start,bad_length=bad_length):
                candidate=copy.deepcopy(graph)
                candidate['paths'][0]['effect']['location']['start']=bad_start
                candidate['paths'][0]['effect']['location']['length']=bad_length
                report=self.static.correlate_dynamic_effects(candidate,local)
                self.assertEqual(report['state'],'available')
                self.assertEqual(report['sourceOverlapCandidatePathPairCount'],1)
                self.assertEqual(report['candidatePathPairCount'],0)

        for line_start,line_end in ((0,30),(31,30)):
            with self.subTest(line_start=line_start,line_end=line_end):
                bad_local=copy.deepcopy(local)
                bad_local['traces'][0]['effects'][0]['sourceLocation']['lineStart']=line_start
                bad_local['traces'][0]['effects'][0]['sourceLocation']['lineEnd']=line_end
                report=self.static.correlate_dynamic_effects(graph,bad_local)
                self.assertEqual(report['state'],'available')
                self.assertEqual(report['sourceOverlapCandidatePathPairCount'],0)
                self.assertEqual(report['candidatePathPairCount'],0)

    def test_static_dynamic_correlation_tolerates_non_list_graph_paths(self):
        report=self.static.correlate_dynamic_effects({'paths':{'effect':{}}}, {'traces':[]})
        self.assertEqual(report['state'],'not_performed')
        self.assertEqual(report['matchedEffectCount'],0)

    def test_static_dynamic_site_id_accepts_callcode_as_an_external_call(self):
        source_hash='9'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',400,6,'external_call')
        graph={'paths':[{'effect':{'kind':'external_call','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[40],'start':400,'length':6}}}]}
        local={'traces':[{'transactionHash':'0xcallcode','failed':False,'targetDepth':1,
            'effects':[{'depth':1,'op':'CALLCODE','effectSiteId':site,
                'sourceLocation':{'file':'Vault.sol','lineStart':40,'lineEnd':40,'start':400,'length':6,'sourceSha256':source_hash}}]}]}

        report=self.static.correlate_dynamic_effects(graph,local)

        self.assertEqual(report['matchedEffectCount'],1)
        self.assertEqual(report['matches'][0]['opcode'],'CALLCODE')
        self.assertEqual(report['matches'][0]['effectSiteId'],site)

    def test_static_dynamic_correlation_rejects_incomplete_transaction_evidence(self):
        source_hash='8'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',500,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[50],'start':500,'length':4}}}]}
        base={'transactionHash':'0xvalid','failed':False,'targetDepth':1,'effects':[
            {'depth':1,'op':'SSTORE','effectSiteId':site,
             'sourceLocation':{'file':'Vault.sol','lineStart':50,'lineEnd':50,'start':500,'length':4,'sourceSha256':source_hash}}]}
        for mutation in ('missing_hash','missing_failed','unavailable'):
            with self.subTest(mutation=mutation):
                trace=copy.deepcopy(base)
                if mutation=='missing_hash':trace.pop('transactionHash')
                elif mutation=='missing_failed':trace.pop('failed')
                else:trace['state']='unavailable'

                report=self.static.correlate_dynamic_effects(graph,{'traces':[trace]})

                self.assertEqual(report['state'],'unavailable')
                self.assertEqual(report['validTraceCount'],0)
                self.assertEqual(report['invalidTraceCount'],1)
                self.assertEqual(report['matchedEffectCount'],0)
                self.assertEqual(report['matches'],[])

    def test_static_dynamic_correlation_rejects_malformed_source_digest(self):
        source_hash='a'*63
        site=self.static.effect_site_id('a'*64,'Vault.sol',500,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[50],'start':500,'length':4}}}]}
        local={'traces':[{'transactionHash':'0xmalformed-digest','failed':False,'targetDepth':1,
            'effects':[{'depth':1,'op':'SSTORE','effectSiteId':site,
                'sourceLocation':{'file':'Vault.sol','lineStart':50,'lineEnd':50,'start':500,'length':4,'sourceSha256':source_hash}}]}]}

        report=self.static.correlate_dynamic_effects(graph,local)

        self.assertEqual(report['sourceOverlapCandidatePathPairCount'],1)
        self.assertEqual(report['candidatePathPairCount'],0)
        self.assertEqual(report['matchedEffectCount'],0)

    def test_static_dynamic_correlation_rejects_mismatched_site_id_with_matching_span(self):
        source_hash='5'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',510,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[51],'start':510,'length':4}}}]}
        local={'traces':[{'transactionHash':'0xwrong-site','failed':False,'targetDepth':1,
            'effects':[{'depth':1,'op':'SSTORE','effectSiteId':'0'*64,
                'sourceLocation':{'file':'Vault.sol','lineStart':51,'lineEnd':51,'start':510,'length':4,'sourceSha256':source_hash}}]}]}

        report=self.static.correlate_dynamic_effects(graph,local)

        self.assertEqual(report['sourceOverlapCandidatePathPairCount'],1)
        self.assertEqual(report['candidatePathPairCount'],0)
        self.assertEqual(report['matchedEffectCount'],0)

    def test_static_dynamic_correlation_reports_malformed_trace_collection_as_unavailable(self):
        report=self.static.correlate_dynamic_effects({}, {'traces':{'transactionHash':'0xbad'}})

        self.assertEqual(report['state'],'unavailable')
        self.assertEqual(report['invalidTraceCount'],1)
        self.assertEqual(report['matchedEffectCount'],0)
        self.assertEqual(report['matches'],[])

    def test_static_dynamic_correlation_rejects_boolean_depth_and_lines(self):
        source_hash='3'*64
        site=self.static.effect_site_id(source_hash,'Vault.sol',700,4,'state_write')
        graph={'paths':[{'effect':{'kind':'state_write','sourceSha256':source_hash,'effectSiteId':site,
            'location':{'file':'Vault.sol','lines':[1],'start':700,'length':4}}}]}
        base={'transactionHash':'0xbool-check','failed':False,'targetDepth':1,'effects':[
            {'depth':1,'op':'SSTORE','effectSiteId':site,
             'sourceLocation':{'file':'Vault.sol','lineStart':1,'lineEnd':1,'start':700,'length':4,'sourceSha256':source_hash}}]}

        for field in ('depth','lineStart','lineEnd'):
            with self.subTest(field=field):
                trace=copy.deepcopy(base)
                if field=='depth':trace['effects'][0]['depth']=True
                else:trace['effects'][0]['sourceLocation'][field]=True

                report=self.static.correlate_dynamic_effects(graph,{'traces':[trace]})

                self.assertEqual(report['matchedEffectCount'],0)
                self.assertEqual(report['candidatePathPairCount'],0)

    def test_static_dynamic_correlation_fingerprint_tracks_canonical_graph_input(self):
        graph={'paths':[{'effect':{'kind':'state_write','location':{'file':'Vault.sol','lines':[20]}}}]}
        local={'traces':[]}
        fingerprint=self.static.correlate_dynamic_effects(graph,local)['graphFingerprint']

        reordered={'paths':[{'effect':{'location':{'lines':[20],'file':'Vault.sol'},'kind':'state_write'}}]}
        self.assertEqual(self.static.correlate_dynamic_effects(reordered,local)['graphFingerprint'],fingerprint)

        changed=copy.deepcopy(graph)
        changed['paths'][0]['effect']['location']['lines']=[21]
        self.assertNotEqual(self.static.correlate_dynamic_effects(changed,local)['graphFingerprint'],fingerprint)

    def test_call_graph_top_k_keeps_asset_effects_and_marks_incomplete_reports(self):
        fn=SimpleNamespace(canonical_name='Vault.execute()',contract=SimpleNamespace(name='Vault'),visibility='external',is_constructor=False,is_fallback=False,source_mapping=None,modifiers=[],nodes=[])
        calls=[SimpleNamespace(function_name='alphaHelper',destination='target',call_value=None),SimpleNamespace(function_name='safeTransfer',destination='token',call_value=None)]
        fn.nodes=[SimpleNamespace(source_mapping=None,state_variables_written=[],internal_calls=[],library_calls=[],high_level_calls=calls,low_level_calls=[],expression='calls')]
        report=self.static.build_call_graph([SimpleNamespace(name='Vault',functions=[fn])],['Vault'],max_paths=1)
        self.assertEqual(report['state'],'partial')
        self.assertEqual(report['totalPathCount'],2)
        self.assertEqual(report['reportedPathCount'],1)
        self.assertEqual(report['truncatedPathCount'],1)
        self.assertEqual(report['paths'][0]['effect']['function'],'safeTransfer')
        self.assertIn('asset calls',report['pathSelectionPolicy'])

    def test_call_graph_bounds_recursive_and_large_path_enumeration(self):
        def function(name,visibility='internal'):
            return SimpleNamespace(canonical_name=f'Vault.{name}()',contract=SimpleNamespace(name='Vault'),visibility=visibility,is_constructor=False,is_fallback=False,source_mapping=None,modifiers=[],nodes=[])
        a,b=function('a','external'),function('b')
        a.nodes=[SimpleNamespace(source_mapping=None,state_variables_written=[],internal_calls=[SimpleNamespace(function=b,function_name='b')],library_calls=[],high_level_calls=[],low_level_calls=[],expression='b()')]
        b.nodes=[SimpleNamespace(source_mapping=None,state_variables_written=[SimpleNamespace(name='x')],internal_calls=[SimpleNamespace(function=a,function_name='a')],library_calls=[],high_level_calls=[],low_level_calls=[],expression='x = 1')]
        report=self.static.build_call_graph([SimpleNamespace(name='Vault',functions=[a,b])],['Vault'],max_paths=1,max_depth=4)
        self.assertEqual(report['reportedPathCount'],1)
        self.assertEqual(report['stateWritePathCount'],1)
        self.assertFalse(report['walkBudgetExceeded'])
        self.assertEqual(len(report['paths'][0]['path']),2)

    def test_solc_shell_wrapper_resolves_symlinked_invocation_path(self):
        with tempfile.TemporaryDirectory(prefix='solc symlink ') as folder:
            alias=Path(folder)/'bin'/'solc'
            alias.parent.mkdir()
            alias.symlink_to(TOOLS/'solc-wrapper.sh')
            run=subprocess.run([str(alias),'--version'],capture_output=True,text=True,timeout=10,
                env=dict(os.environ,SOLC_VERSION='0.8.28'))
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('Version: 0.8.28',run.stdout)

    def test_inherited_entrypoint_uses_target_contract_source(self):
        def loc(file):return SimpleNamespace(filename=SimpleNamespace(relative=file),lines=[1])
        contract=SimpleNamespace(name='Vault',source_mapping=loc('work/Vault.sol'))
        fn=SimpleNamespace(canonical_name='ERC20.transfer(address,uint256)',contract=contract,visibility='public',source_mapping=loc('lib/ERC20.sol'),nodes=[SimpleNamespace(source_mapping=None,state_variables_written=[SimpleNamespace(name='balance')],internal_calls=[],high_level_calls=[],low_level_calls=[])],modifiers=[])
        contract.functions=[fn]
        g=self.static.build_call_graph([contract],['Vault'],['Vault.sol'],{'work/Vault.sol':'Vault.sol'})
        self.assertEqual(g['entrypointCount'],1)
        self.assertEqual(g['entrypoints'][0]['location']['file'],'lib/ERC20.sol')
        self.assertEqual(g['stateWritePathCount'],1)

    def test_call_graph_rejects_zero_budgets(self):
        for field in ('max_paths','max_depth','max_entrypoints','max_walk_steps','max_reported_edges','max_unresolved_calls','max_dynamic_targets','max_dynamic_walk_steps'):
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.static.build_call_graph([],**{field:0})

    def test_call_graph_marks_dynamic_cfg_budget_exhaustion_partial(self):
        assignment_type=type('Assignment',(),{})
        dynamic_call_type=type('InternalDynamicCall',(),{})
        pointer=SimpleNamespace(canonical_name='Vault.dispatch().f')
        target=SimpleNamespace(canonical_name='Vault._target()',name='_target',contract=SimpleNamespace(name='Vault'),visibility='internal',is_constructor=False,is_fallback=False,source_mapping=None,modifiers=[],nodes=[])
        assignment=assignment_type();assignment.lvalue=pointer;assignment.rvalue=target
        predecessor=SimpleNamespace(irs=[assignment],fathers=[])
        dynamic_call=dynamic_call_type();dynamic_call.function=pointer
        call_node=SimpleNamespace(irs=[dynamic_call],fathers=[predecessor],state_variables_written=[],source_mapping=None)
        entry=SimpleNamespace(canonical_name='Vault.dispatch()',name='dispatch',contract=SimpleNamespace(name='Vault'),visibility='external',is_constructor=False,is_fallback=False,source_mapping=None,modifiers=[],nodes=[call_node])
        graph=self.static.build_call_graph([SimpleNamespace(name='Vault',functions=[entry,target])],['Vault'],max_dynamic_walk_steps=1)
        self.assertEqual(graph['internalDynamicWalkSteps'],1)
        self.assertEqual(graph['state'],'partial')
        self.assertEqual(graph['unresolvedInternalDynamicCallCount'],1)
        self.assertIn('cfg_walk_budget_exceeded',graph['unresolvedInternalCalls'][0]['reasons'])

    def test_call_graph_marks_raw_inline_assembly_unresolved_and_partial(self):
        def location(file,line):return SimpleNamespace(filename=SimpleNamespace(relative=file),lines=[line])
        raw_assembly=SimpleNamespace(type=SimpleNamespace(name='ASSEMBLY'),source_mapping=location('Legacy.sol',7),inline_asm={'operations':['opaque assembly']},state_variables_written=[],internal_calls=[],high_level_calls=[],low_level_calls=[],irs=[],expression=None)
        function=SimpleNamespace(canonical_name='Legacy.run()',contract=SimpleNamespace(name='Legacy'),visibility='external',is_constructor=False,is_fallback=False,source_mapping=location('Legacy.sol',6),modifiers=[],nodes=[raw_assembly])
        graph=self.static.build_call_graph([SimpleNamespace(name='Legacy',functions=[function])],['Legacy'])
        self.assertEqual(graph['state'],'partial')
        self.assertEqual(graph['unresolvedAssemblyBlockCount'],1)
        self.assertEqual(graph['unresolvedAssemblyBlocks'][0]['kind'],'unresolved_inline_assembly')
        self.assertEqual(graph['unresolvedAssemblyBlocks'][0]['location']['lines'],[7])

    def test_call_graph_marks_unlisted_yul_solidity_call_unresolved(self):
        def location(file,line):return SimpleNamespace(filename=SimpleNamespace(relative=file),lines=[line])
        solidity_call_type=type('SolidityCall',(),{})
        call=solidity_call_type();call.function=SimpleNamespace(name='unmodeledBuiltin(uint256)');call.arguments=[SimpleNamespace(name='value')]
        node=SimpleNamespace(type=SimpleNamespace(name='EXPRESSION'),scope=SimpleNamespace(is_yul=True),source_mapping=location('Inline.sol',9),state_variables_written=[],internal_calls=[call],high_level_calls=[],low_level_calls=[],irs=[call],expression='unmodeledBuiltin(value)')
        function=SimpleNamespace(canonical_name='Inline.run()',contract=SimpleNamespace(name='Inline'),visibility='external',is_constructor=False,is_fallback=False,source_mapping=location('Inline.sol',8),modifiers=[],nodes=[node])
        graph=self.static.build_call_graph([SimpleNamespace(name='Inline',functions=[function])],['Inline'])
        self.assertEqual(graph['state'],'partial')
        self.assertEqual(graph['unresolvedAssemblyCallCount'],1)
        self.assertEqual(graph['unresolvedAssemblyCalls'][0]['name'],'unmodeledBuiltin(uint256)')

    def test_call_graph_counts_recognized_yul_control_and_data_builtins(self):
        def location(file,line):return SimpleNamespace(filename=SimpleNamespace(relative=file),lines=[line])
        call_type=type('SolidityCall',(),{})
        names=['byte(uint256,uint256)','keccak256(uint256,uint256)','mload(uint256)',
               'mstore(uint256,uint256)','mstore8(uint256,uint256)','mulmod(uint256,uint256,uint256)',
               'revert(uint256,uint256)']
        calls=[]
        for name in names:
            call=call_type();call.function=SimpleNamespace(name=name);call.arguments=[SimpleNamespace(name='value')]
            calls.append(call)
        mstore_call=call_type();mstore_call.function=SimpleNamespace(name='mstore(uint256,uint256)');mstore_call.arguments=[SimpleNamespace(name='value')]
        calls.append(mstore_call)
        node=SimpleNamespace(type=SimpleNamespace(name='EXPRESSION'),scope=SimpleNamespace(is_yul=True),
            source_mapping=location('Inline.sol',9),state_variables_written=[],internal_calls=[],
            high_level_calls=[],low_level_calls=[],irs=calls,expression='assembly builtins')
        function=SimpleNamespace(canonical_name='Inline.run()',contract=SimpleNamespace(name='Inline'),
            visibility='external',is_constructor=False,is_fallback=False,source_mapping=location('Inline.sol',8),
            modifiers=[],nodes=[node])
        graph=self.static.build_call_graph([SimpleNamespace(name='Inline',functions=[function])],['Inline'])
        self.assertEqual(graph['state'],'completed')
        self.assertEqual(graph['unresolvedAssemblyCallCount'],0)
        self.assertEqual(graph['recognizedYulControlOrDataCallCount'],len(names)+1)
        self.assertEqual(set(graph['recognizedYulControlOrDataCallsByName']),
                         {'byte','keccak256','mload','mstore','mstore8','mulmod','revert'})
        self.assertEqual(graph['recognizedYulControlOrDataCallsByName']['mstore'],2)
        self.assertEqual(graph['stateWritePathCount'],0)
        self.assertEqual(graph['externalCallPathCount'],0)

    def test_call_graph_keeps_yul_storage_write_and_call_as_effects(self):
        def location(file,line):return SimpleNamespace(filename=SimpleNamespace(relative=file),lines=[line])
        call_type=type('SolidityCall',(),{})
        calls=[]
        for name in ('sstore(uint256,uint256)','call(uint256,uint256,uint256,uint256,uint256,uint256,uint256)'):
            call=call_type();call.function=SimpleNamespace(name=name);call.arguments=[SimpleNamespace(name='value')]
            calls.append(call)
        node=SimpleNamespace(type=SimpleNamespace(name='EXPRESSION'),scope=SimpleNamespace(is_yul=True),
            source_mapping=location('Inline.sol',9),state_variables_written=[],internal_calls=[],
            high_level_calls=[],low_level_calls=[],irs=calls,expression='assembly effects')
        function=SimpleNamespace(canonical_name='Inline.run()',contract=SimpleNamespace(name='Inline'),
            visibility='external',is_constructor=False,is_fallback=False,source_mapping=location('Inline.sol',8),
            modifiers=[],nodes=[node])
        graph=self.static.build_call_graph([SimpleNamespace(name='Inline',functions=[function])],['Inline'])
        self.assertEqual(graph['state'],'completed')
        self.assertEqual(graph['unresolvedAssemblyCallCount'],0)
        self.assertEqual(graph['recognizedYulControlOrDataCallCount'],0)
        self.assertEqual(graph['stateWritePathCount'],1)
        self.assertEqual(graph['externalCallPathCount'],1)

    def test_real_slither_keeps_inherited_receive_and_native_calls(self):
        with tempfile.TemporaryDirectory(prefix='callgraph regression ') as folder:
            base=Path(folder)
            (base/'Base.sol').write_text('pragma solidity 0.8.28; contract Base { uint public value; function inheritedSet(uint n) public {value=n;} }')
            (base/'Vault.sol').write_text('pragma solidity 0.8.28; import "./Base.sol"; contract Vault is Base { receive() external payable {value++;} function payout(address payable to) external {to.transfer(1);} function ping(address payable to) external {bool ok=to.send(0); require(ok);} }')
            script=textwrap.dedent('''
                import sys,importlib.util
                from pathlib import Path
                root,base=Path(sys.argv[1]),Path(sys.argv[2]);tools=root/'flare-scan/tools'
                sys.path[:0]=[str(tools/'pylibs'),str(tools)]
                from crytic_compile import CryticCompile
                from crytic_compile.platform.solc import Solc
                from slither.slither import Slither
                spec=importlib.util.spec_from_file_location('review',root/'scripts/review-static.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
                s=Slither(CryticCompile(Solc(str(base/'Vault.sol')),solc=str(tools/'solc-wrapper.sh'),solc_working_dir=str(base),cwd=str(base)))
                graph=m.build_call_graph(s.contracts,['Vault'],['Vault.sol'])
                entries=[x['function'] for x in graph['entrypoints']]
                assert any('inheritedSet' in x for x in entries),entries
                assert any(x['kind']=='fallback_or_receive' for x in graph['entrypoints'])
                effects=[x['effect'] for x in graph['paths']]
                assert any(x.get('callKind')=='native_transfer' and x['valueTransferEvidence']['state']=='nonzero' for x in effects),effects
                assert any(x.get('callKind')=='native_send' and x['valueTransferEvidence']['state']=='zero' for x in effects),effects
                assert not any(x.get('target')=='require' for x in graph['unresolvedInternalCalls'])
            ''')
            run=subprocess.run([sys.executable,'-c',script,str(ROOT),folder],capture_output=True,text=True,timeout=30,env=dict(os.environ,SOLC_VERSION='0.8.28'))
            self.assertEqual(run.returncode,0,run.stderr)

    def test_real_slither_traces_inline_assembly_effects_without_misclassifying_require_or_revert(self):
        with tempfile.TemporaryDirectory(prefix='inline assembly effect regression ') as folder:
            base=Path(folder)
            (base/'InlineEffects.sol').write_text(textwrap.dedent('''
                pragma solidity 0.8.28;
                contract InlineEffects {
                    function writeSlots(uint256 value) external {
                        assembly {
                            sstore(0, value)
                            tstore(1, value)
                        }
                    }
                    function delegate(address target, bytes calldata data) external returns (bool ok) {
                        assembly {
                            ok := delegatecall(gas(), target, data.offset, data.length, 0, 0)
                        }
                        require(ok, "delegate failed");
                        if (!ok) { revert("delegate failed"); }
                    }
                    function guard(bool ready) external pure {
                        require(ready, "not ready");
                        if (!ready) { revert("not ready"); }
                    }
                    function destroy(address payable recipient) external {
                        selfdestruct(recipient);
                    }
                }
            '''))
            script=textwrap.dedent('''
                import sys,importlib.util
                from pathlib import Path
                root,base=Path(sys.argv[1]),Path(sys.argv[2]);tools=root/'flare-scan/tools'
                sys.path[:0]=[str(tools/'pylibs'),str(tools)]
                from crytic_compile import CryticCompile
                from crytic_compile.platform.solc import Solc
                from slither.slither import Slither
                spec=importlib.util.spec_from_file_location('review',root/'scripts/review-static.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
                compilation=CryticCompile(Solc(str(base/'InlineEffects.sol')),solc=str(tools/'solc-wrapper.sh'),solc_args='--evm-version cancun',solc_working_dir=str(base),cwd=str(base))
                s=Slither(compilation)
                graph=m.build_call_graph(s.contracts,['InlineEffects'],source_aliases={'InlineEffects.sol':'InlineEffects.sol'})
                effects=[row['effect'] for row in graph['paths']]
                writes=[effect for effect in effects if effect['kind']=='state_write']
                assert {effect.get('storageSlot') for effect in writes}=={'0','1'},writes
                assert all(effect['resolution']=='inline_assembly_slot_candidate' for effect in writes),writes
                calls=[effect for effect in effects if effect['kind']=='external_call']
                delegate=[effect for effect in calls if effect.get('callKind')=='inline_assembly_delegatecall']
                assert len(delegate)==1,delegate
                assert delegate[0]['destination']=='unknown' and delegate[0]['targetResolution']=='not_decoded_from_inline_assembly_arguments',delegate
                assert delegate[0]['valueTransferEvidence']['state']=='unknown',delegate
                destruction=[effect for effect in effects if effect['kind']=='selfdestruct']
                assert destruction and all(effect['opcode']=='SELFDESTRUCT' for effect in destruction),effects
                assert graph['selfdestructPathCount']>=1,graph
                assert all(effect['location']['file']=='InlineEffects.sol' and effect['location']['lines'] for effect in writes+delegate)
                assert not any(effect.get('function') in ('require','revert') for effect in calls),calls
                assert graph['state']=='partial' and graph['unresolvedAssemblyBlockCount']==0,graph
                assert graph['unresolvedAssemblyCallCount']==1 and graph['unresolvedAssemblyCalls'][0]['name']=='gas()',graph['unresolvedAssemblyCalls']
                skipped=Slither(compilation,skip_assembly=True)
                skipped_graph=m.build_call_graph(skipped.contracts,['InlineEffects'])
                assert skipped_graph['state']=='partial' and skipped_graph['unresolvedAssemblyBlockCount']==2,skipped_graph
                assert all(block['reason']=='assembly_block_has_no_parsed_yul_scope' for block in skipped_graph['unresolvedAssemblyBlocks'])
            ''')
            run=subprocess.run([sys.executable,'-c',script,str(ROOT),folder],capture_output=True,text=True,timeout=30,env=dict(os.environ,SOLC_VERSION='0.8.28'))
            self.assertEqual(run.returncode,0,run.stderr)

    def test_real_slither_resolves_local_function_pointer_candidates_and_marks_unknown_partial(self):
        with tempfile.TemporaryDirectory(prefix='dynamic function pointer coverage ') as folder:
            base=Path(folder)
            (base/'Dispatch.sol').write_text('''pragma solidity 0.8.28;
contract DynamicDispatch {
    uint public first;
    uint public second;
    function() internal private storedTarget;

    function dispatch(bool chooseFirst) external {
        function() internal f;
        if (chooseFirst) { f = _first; } else { f = _second; }
        f();
    }

    function dispatchUnknown() external { storedTarget(); }
    function _first() internal { first = 1; }
    function _second() internal { second = 2; }
}
''')
            script=textwrap.dedent('''
                import sys,importlib.util
                from pathlib import Path
                root,base=Path(sys.argv[1]),Path(sys.argv[2]);tools=root/'flare-scan/tools'
                sys.path[:0]=[str(tools/'pylibs'),str(tools)]
                from crytic_compile import CryticCompile
                from crytic_compile.platform.solc import Solc
                from slither.slither import Slither
                spec=importlib.util.spec_from_file_location('review',root/'scripts/review-static.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
                s=Slither(CryticCompile(Solc(str(base/'Dispatch.sol')),solc=str(tools/'solc-wrapper.sh'),solc_working_dir=str(base),cwd=str(base)))
                graph=m.build_call_graph(s.contracts,['DynamicDispatch'])
                dispatcher='DynamicDispatch::DynamicDispatch.dispatch(bool)'
                paths=[row for row in graph['paths'] if row['entrypoint']==dispatcher and row['effect']['kind']=='state_write']
                assert {row['effect']['variable'] for row in paths}=={'DynamicDispatch.first','DynamicDispatch.second'},paths
                assert {target.rsplit('.',1)[-1] for row in paths for target in row['path']} >= {'_first()','_second()'},paths
                candidate_edges=[edge for edge in graph['edges'] if edge['kind']=='internal_dynamic_candidate']
                assert {edge['to'].rsplit('.',1)[-1] for edge in candidate_edges}=={'_first()','_second()'},candidate_edges
                assert all(edge['resolution']=='conservative_function_pointer_candidate' and edge['pathFeasibility']=='not_proven' for edge in candidate_edges)
                unresolved=[row for row in graph['unresolvedInternalCalls'] if row['from'].endswith('dispatchUnknown()')]
                assert len(unresolved)==1 and unresolved[0]['kind']=='unresolved_dynamic_internal_call',unresolved
                assert 'no_reaching_definition' in unresolved[0]['reasons'],unresolved
                assert graph['internalDynamicCallCount']==2 and graph['resolvedInternalDynamicCallCount']==1
                assert graph['unresolvedInternalDynamicCallCount']==1 and graph['unresolvedInternalCallCount']==1
                assert graph['state']=='partial',graph
                assert all(row['pathFeasibility']=='not_proven' for row in paths)
            ''')
            run=subprocess.run([sys.executable,'-c',script,str(ROOT),folder],capture_output=True,text=True,timeout=30,env=dict(os.environ,SOLC_VERSION='0.8.28'))
            self.assertEqual(run.returncode,0,run.stderr)

    def test_same_named_library_structs_resolve_by_declaration(self):
        with tempfile.TemporaryDirectory(prefix='slither fixture ') as folder:
            base = Path(folder)
            (base / 'A.sol').write_text('pragma solidity 0.8.28; library Checkpoints { struct Trace { uint256 value; } }')
            (base / 'B.sol').write_text('pragma solidity 0.8.28; library Checkpoints { struct Trace { address owner; } }')
            (base / 'X.sol').write_text('pragma solidity 0.8.28; import {Checkpoints as A} from "./A.sol"; import {Checkpoints as B} from "./B.sol"; contract X { A.Trace internal a; B.Trace internal b; }')
            script = textwrap.dedent('''
                import sys
                from pathlib import Path
                tools, base = Path(sys.argv[1]), Path(sys.argv[2])
                sys.path[:0] = [str(tools), str(tools / 'pylibs')]
                from crytic_compile import CryticCompile
                from crytic_compile.platform.solc import Solc
                from slither.slither import Slither
                from slither_compat import install_struct_resolution
                compilation = CryticCompile(Solc(str(base / 'X.sol')), solc=str(tools / 'solc-wrapper.sh'), solc_working_dir=str(base), cwd=str(base))
                stats = install_struct_resolution(compilation)
                slither = Slither(compilation)
                contract = slither.get_contract_from_name('X')[0]
                a = contract.get_state_variable_from_name('a').type.type
                b = contract.get_state_variable_from_name('b').type.type
                assert str(a.elems['value'].type) == 'uint256'
                assert str(b.elems['owner'].type) == 'address'
                assert a.source_mapping.filename.absolute != b.source_mapping.filename.absolute
                assert stats['resolvedReferences'] >= 2
            ''')
            run = subprocess.run([sys.executable, '-c', script, str(TOOLS), folder], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_inventory_excludes_dependencies_and_reports_wrong_repo(self):
        sys.path.insert(0, str(TOOLS))
        from collect import collect
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'contracts/project/src').mkdir(parents=True)
            (base / 'contracts/project/node_modules/vendor').mkdir(parents=True)
            (base / 'contracts/wrong-project').mkdir(parents=True)
            (base / 'contracts/project/src/A.sol').write_text('contract A {}')
            (base / 'contracts/project/node_modules/vendor/B.sol').write_text('contract B {}')
            result = collect(base)['projects']
            self.assertEqual(result[0]['sourceCount'], 1)
            self.assertEqual(result[1]['status'], 'no_solidity_sources')
