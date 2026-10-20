import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'decompiler_adapter', ROOT / 'scripts' / 'decompiler_adapter.py',
)
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)


class HeimdallAdapterTests(unittest.TestCase):
    def test_oversized_bytecode_is_rejected_before_regex_scanning(self):
        value = '0x' + '00' * (ADAPTER.MAX_BYTECODE_BYTES + 1)
        with mock.patch.object(ADAPTER.re, 'fullmatch', side_effect=AssertionError('regex scanned oversized input')) as fullmatch:
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                ADAPTER._validate_bytecode(value)
        fullmatch.assert_not_called()

    def test_keyboard_interrupt_during_communicate_cleans_up_and_propagates(self):
        interrupted = KeyboardInterrupt('caller cancelled')
        process = mock.Mock()
        process.communicate.side_effect = interrupted
        with mock.patch.object(ADAPTER.subprocess, 'Popen', return_value=process), \
                mock.patch.object(ADAPTER, '_terminate_and_reap') as cleanup:
            with self.assertRaises(KeyboardInterrupt) as caught:
                ADAPTER._run_process(['heimdall', '--version'], timeout=5)

        cleanup.assert_called_once_with(process)
        self.assertIs(caught.exception, interrupted)

    def test_interrupt_remains_primary_when_process_tree_cleanup_fails(self):
        interrupted = KeyboardInterrupt('caller cancelled')
        cleanup_error = ADAPTER.ProcessTreeCleanupIncomplete('cleanup failed')
        process = mock.Mock()
        process.communicate.side_effect = interrupted
        with mock.patch.object(ADAPTER.subprocess, 'Popen', return_value=process), \
                mock.patch.object(ADAPTER, '_terminate_and_reap',
                                  side_effect=cleanup_error) as cleanup:
            with self.assertRaises(KeyboardInterrupt) as caught:
                ADAPTER._run_process(['heimdall', '--version'], timeout=5)

        cleanup.assert_called_once_with(process)
        self.assertIs(caught.exception, interrupted)
        self.assertIs(caught.exception.__cause__, cleanup_error)

    def test_artifact_monitor_bounds_final_pipe_drain_after_parent_exit(self):
        process = mock.Mock()
        process.poll.return_value = 0
        process.communicate.side_effect = subprocess.TimeoutExpired(['tool'], 1)
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(ADAPTER, '_preflight_process_tree_rss_monitor'), \
                mock.patch.object(ADAPTER.subprocess, 'Popen', return_value=process), \
                mock.patch.object(ADAPTER, '_terminate_and_reap', return_value=(b'', b'')) as cleanup:
            with self.assertRaisesRegex(ADAPTER.ArtifactBudgetExceeded, 'child_process_outlived_parent'):
                ADAPTER._run_process(['tool'], timeout=5, artifact_dir=Path(temporary))

        cleanup.assert_called_once_with(process)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_artifact_usage_scans_are_throttled_and_final_scan_checks_budget(self):
        clock = [0.0]
        scan_times = []
        process = mock.Mock(pid=1234, returncode=0)
        process.poll.side_effect = lambda: None if clock[0] < 0.35 else 0
        process.communicate.return_value = (b'', b'')

        def scan(path):
            scan_times.append(clock[0])
            if clock[0] >= 0.35:
                (Path(path) / 'late-artifact.bin').write_bytes(b'xx')
            return real_scan(path)

        def sleep(seconds):
            clock[0] += seconds

        real_scan = ADAPTER._scan_artifact_usage
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(ADAPTER, '_preflight_process_tree_rss_monitor'), \
                mock.patch.object(ADAPTER.subprocess, 'Popen', return_value=process), \
                mock.patch.object(ADAPTER, '_scan_artifact_usage', side_effect=scan), \
                mock.patch.object(ADAPTER, '_process_tree_rss_bytes', return_value=0), \
                mock.patch.object(ADAPTER, '_process_group_exists', return_value=False), \
                mock.patch.object(ADAPTER, '_kill_observed_descendants', return_value=(False, True)), \
                mock.patch.object(ADAPTER, '_terminate_and_reap', return_value=(b'', b'')) as cleanup, \
                mock.patch.object(ADAPTER.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(ADAPTER.time, 'sleep', side_effect=sleep), \
                mock.patch.object(ADAPTER, 'MAX_TOTAL_ARTIFACT_BYTES', 1):
            with self.assertRaisesRegex(
                    ADAPTER.ArtifactBudgetExceeded, 'artifact_total_bytes_limit_exceeded'):
                ADAPTER._run_process(['tool'], timeout=5, artifact_dir=temporary)

        self.assertGreaterEqual(len(scan_times), 4)
        periodic_scans = scan_times[:-1]
        for first, second in zip(periodic_scans, periodic_scans[1:]):
            interval = second - first
            self.assertGreaterEqual(interval, ADAPTER.ARTIFACT_USAGE_POLL_INTERVAL_SECONDS)
            self.assertLess(interval, ADAPTER.ARTIFACT_USAGE_POLL_INTERVAL_SECONDS + 0.05)
        self.assertEqual(scan_times[-1], 0.35)
        cleanup.assert_called_once_with(process)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_periodic_artifact_budget_overrun_terminates_process(self):
        clock = [0.0]
        scan_times = []
        process = mock.Mock(pid=1234)
        process.poll.return_value = None

        def scan(_path):
            scan_times.append(clock[0])
            if len(scan_times) == 2:
                raise ADAPTER.ArtifactBudgetExceeded('artifact_total_bytes_limit_exceeded')
            return 0, 0, 0

        def sleep(seconds):
            clock[0] += seconds

        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(ADAPTER, '_preflight_process_tree_rss_monitor'), \
                mock.patch.object(ADAPTER.subprocess, 'Popen', return_value=process), \
                mock.patch.object(ADAPTER, '_scan_artifact_usage', side_effect=scan), \
                mock.patch.object(ADAPTER, '_process_tree_rss_bytes', return_value=0), \
                mock.patch.object(ADAPTER, '_terminate_and_reap', return_value=(b'', b'')) as cleanup, \
                mock.patch.object(ADAPTER.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(ADAPTER.time, 'sleep', side_effect=sleep):
            with self.assertRaisesRegex(
                    ADAPTER.ArtifactBudgetExceeded, 'artifact_total_bytes_limit_exceeded'):
                ADAPTER._run_process(['tool'], timeout=5, artifact_dir=temporary)

        self.assertEqual(scan_times, [0.0, ADAPTER.ARTIFACT_USAGE_POLL_INTERVAL_SECONDS])
        cleanup.assert_called_once_with(process)

    @unittest.skipUnless(os.name != 'nt' and ADAPTER.resource is not None,
                         'POSIX resource limits are required')
    def test_artifact_process_receives_cpu_and_open_file_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            code = (
                'import resource; '
                'print(resource.getrlimit(resource.RLIMIT_CPU)[1]); '
                'print(resource.getrlimit(resource.RLIMIT_NOFILE)[1])'
            )
            result = ADAPTER._run_process(
                [sys.executable, '-c', code], timeout=2, artifact_dir=temporary,
            )
            lines = (result.stdout or b'').decode().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertLessEqual(int(lines[0]), 3)
            self.assertLessEqual(int(lines[1]), ADAPTER.MAX_DECOMPILER_OPEN_FILES)

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_process_tree_rss_sums_only_root_and_descendants(self):
        output = (
            '101 1 100 501 S Wed Oct 19 10:00:00 2026\n'
            '102 101 200 501 S Wed Oct 19 10:00:01 2026\n'
            '103 102 300 501 S Wed Oct 19 10:00:02 2026\n'
            '104 1 900 501 S Wed Oct 19 10:00:03 2026\n'
        )
        completed = subprocess.CompletedProcess(['ps'], 0, stdout=output, stderr='')
        with mock.patch.object(ADAPTER.shutil, 'which', return_value='/bin/ps'), \
                mock.patch.object(ADAPTER.subprocess, 'run', return_value=completed) as run:
            rss_bytes = ADAPTER._process_tree_rss_bytes(101)

        self.assertEqual(rss_bytes, (100 + 200 + 300) * 1024)
        run.assert_called_once()

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_process_tree_rss_counts_identity_matched_reparented_descendants(self):
        start = ('Wed', 'Oct', '19', '10:00:01', '2026')
        rows = {
            101: {'parent': 1, 'rss': 100, 'uid': 501, 'state': 'S', 'start': start},
            102: {'parent': 1, 'rss': 900, 'uid': 501, 'state': 'S', 'start': start},
            103: {'parent': 102, 'rss': 300, 'uid': 501, 'state': 'S', 'start': start},
            104: {'parent': 1, 'rss': 700, 'uid': 501, 'state': 'S', 'start': start},
        }
        observed = {102: (501, start)}
        with mock.patch.object(ADAPTER, '_read_process_table', return_value=(
                rows, {1: [101, 102, 104], 102: [103]})):
            rss_bytes = ADAPTER._process_tree_rss_bytes(101, observed)

        self.assertEqual(rss_bytes, 100 + 900 + 300)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process snapshots are required')
    def test_process_tree_rss_ignores_reused_observed_pid(self):
        original_start = ('Wed', 'Oct', '19', '10:00:01', '2026')
        replacement_start = ('Wed', 'Oct', '19', '10:00:02', '2026')
        rows = {
            101: {'parent': 1, 'rss': 100, 'uid': 501, 'state': 'S', 'start': original_start},
            102: {'parent': 1, 'rss': 900, 'uid': 501, 'state': 'S', 'start': replacement_start},
        }
        observed = {102: (501, original_start)}
        with mock.patch.object(ADAPTER, '_read_process_table', return_value=(rows, {1: [101, 102]})):
            rss_bytes = ADAPTER._process_tree_rss_bytes(101, observed)

        self.assertEqual(rss_bytes, 100)
        self.assertEqual(observed[102], (501, original_start))

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_preflight_rejects_snapshot_without_current_process(self):
        rows = {999: {'parent': 1, 'rss': 100, 'uid': 501, 'state': 'S', 'start': ('start',)}}
        with mock.patch.object(ADAPTER, '_read_process_table', return_value=(rows, {})), \
                mock.patch.object(ADAPTER.os, 'getpid', return_value=101):
            with self.assertRaisesRegex(
                    ADAPTER.ArtifactBudgetExceeded,
                    'process_memory_monitor_target_missing'):
                ADAPTER._preflight_process_tree_rss_monitor()

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_empty_process_snapshot_fails_monitor_preflight(self):
        completed = subprocess.CompletedProcess(['ps'], 0, stdout='', stderr='')
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(ADAPTER.shutil, 'which', return_value='/bin/ps'), \
                mock.patch.object(ADAPTER.subprocess, 'run', return_value=completed):
            with self.assertRaisesRegex(
                    ADAPTER.ArtifactBudgetExceeded,
                    'process_memory_monitor_invalid_output'):
                ADAPTER._preflight_process_tree_rss_monitor()

    @unittest.skipUnless(os.name != 'nt', 'POSIX process snapshots are required')
    def test_invalid_process_snapshot_is_reported_as_unavailable_resource_monitor(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'
            with mock.patch.object(ADAPTER, '_run_process', side_effect=ADAPTER.ArtifactBudgetExceeded('process_memory_monitor_invalid_output')), \
                    mock.patch.object(ADAPTER.shutil, 'which', return_value='/bin/ps'):
                result = ADAPTER.run_heimdall('0x6000', binary=sys.executable, output_dir=output)

        self.assertEqual(result['state'], 'partial')
        self.assertEqual(result['error'], 'process_memory_monitor_invalid_output')
        self.assertEqual(result['memoryLimitEnforcement'], 'unavailable')
        self.assertIsNone(result['processTreeRssLimitBytes'])

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_process_snapshot_rejects_duplicate_process_ids(self):
        output = (
            '101 1 100 501 S Wed Oct 19 10:00:00 2026\n'
            '101 1 200 501 S Wed Oct 19 10:00:01 2026\n'
        )
        completed = subprocess.CompletedProcess(['ps'], 0, stdout=output, stderr='')
        with mock.patch.object(ADAPTER.shutil, 'which', return_value='/bin/ps'), \
                mock.patch.object(ADAPTER.subprocess, 'run', return_value=completed):
            with self.assertRaisesRegex(
                    ADAPTER.ArtifactBudgetExceeded,
                    'process_memory_monitor_invalid_output'):
                ADAPTER._read_process_table()

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_observed_cleanup_continues_after_one_descendant_permission_error(self):
        start = ('Wed', 'Oct', '19', '10:00:01', '2026')
        rows = {
            102: {'parent': 1, 'rss': 200, 'uid': 501, 'state': 'S', 'start': start},
            103: {'parent': 1, 'rss': 300, 'uid': 501, 'state': 'S', 'start': start},
        }
        observed = {102: (501, start), 103: (501, start)}
        with mock.patch.object(ADAPTER, '_read_process_table', return_value=(rows, {})), \
                mock.patch.object(ADAPTER.os, 'pidfd_open', return_value=None, create=True), \
                mock.patch.object(ADAPTER.os, 'kill', side_effect=[PermissionError(), None]) as kill:
            escaped, terminated = ADAPTER._kill_observed_descendants(observed)

        self.assertTrue(escaped)
        self.assertFalse(terminated)
        self.assertEqual([call.args[0] for call in kill.call_args_list], [102, 103])

    @unittest.skipUnless(os.name != 'nt', 'POSIX process snapshots are required')
    def test_observed_descendant_pid_generation_is_refreshed_while_still_in_tree(self):
        old_start = ('Wed', 'Oct', '19', '10:00:01', '2026')
        new_start = ('Wed', 'Oct', '19', '10:00:02', '2026')
        root_row = {'parent': 1, 'rss': 100, 'uid': 501, 'state': 'S', 'start': old_start}
        old_child = {'parent': 101, 'rss': 200, 'uid': 501, 'state': 'S', 'start': old_start}
        new_child = {**old_child, 'start': new_start}
        old_rows = {101: root_row, 102: old_child}
        new_rows = {101: root_row, 102: new_child}
        children = {1: [101], 101: [102]}
        observed = {}

        with mock.patch.object(ADAPTER, '_read_process_table', side_effect=[
                (old_rows, children), (new_rows, children),
                (new_rows, children), (new_rows, children), ({}, {}),
        ]), mock.patch.object(ADAPTER.os, 'pidfd_open', return_value=None, create=True), \
                mock.patch.object(ADAPTER.os, 'kill') as kill, \
                mock.patch.object(ADAPTER.time, 'sleep'):
            ADAPTER._process_tree_rss_bytes(101, observed)
            ADAPTER._process_tree_rss_bytes(101, observed)
            escaped, terminated = ADAPTER._kill_observed_descendants(observed)

        self.assertEqual(observed[102], (501, new_start))
        self.assertTrue(escaped)
        self.assertTrue(terminated)
        kill.assert_called_once_with(102, ADAPTER.signal.SIGKILL)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process snapshots are required')
    def test_observed_cleanup_revalidates_pid_before_signalling_replacement(self):
        old_start = ('Wed', 'Oct', '19', '10:00:01', '2026')
        new_start = ('Wed', 'Oct', '19', '10:00:02', '2026')
        old_row = {'parent': 1, 'rss': 200, 'uid': 501, 'state': 'S', 'start': old_start}
        new_row = {**old_row, 'start': new_start}
        observed = {102: (501, old_start)}
        with mock.patch.object(ADAPTER, '_read_process_table', side_effect=[
                ({102: old_row}, {}), ({102: new_row}, {}), ({102: new_row}, {}),
        ]), mock.patch.object(ADAPTER.os, 'pidfd_open', return_value=77, create=True), \
                mock.patch.object(ADAPTER.signal, 'pidfd_send_signal', create=True) as signal_fd, \
                mock.patch.object(ADAPTER.os, 'close') as close, \
                mock.patch.object(ADAPTER.os, 'kill') as kill, \
                mock.patch.object(ADAPTER.time, 'sleep'):
            escaped, terminated = ADAPTER._kill_observed_descendants(observed)

        self.assertTrue(escaped)
        self.assertTrue(terminated)
        signal_fd.assert_not_called()
        kill.assert_not_called()
        close.assert_called_once_with(77)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process snapshots are required')
    def test_observed_cleanup_uses_pidfd_when_available(self):
        start = ('Wed', 'Oct', '19', '10:00:01', '2026')
        row = {'parent': 1, 'rss': 200, 'uid': 501, 'state': 'S', 'start': start}
        with mock.patch.object(ADAPTER, '_read_process_table', side_effect=[
                ({102: row}, {}), ({102: row}, {}), ({}, {}),
        ]), mock.patch.object(ADAPTER.os, 'pidfd_open', return_value=77, create=True), \
                mock.patch.object(ADAPTER.signal, 'pidfd_send_signal', create=True) as signal_fd, \
                mock.patch.object(ADAPTER.os, 'close') as close, \
                mock.patch.object(ADAPTER.os, 'kill') as kill, \
                mock.patch.object(ADAPTER.time, 'sleep'):
            escaped, terminated = ADAPTER._kill_observed_descendants({102: (501, start)})

        self.assertTrue(escaped)
        self.assertTrue(terminated)
        signal_fd.assert_called_once_with(77, ADAPTER.signal.SIGKILL)
        kill.assert_not_called()
        close.assert_called_once_with(77)

    def test_missing_process_tree_monitor_fails_before_starting_artifact_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(ADAPTER.shutil, 'which', return_value=None), \
                    mock.patch.object(ADAPTER.subprocess, 'Popen') as popen:
                with self.assertRaisesRegex(
                        ADAPTER.ArtifactBudgetExceeded,
                        'process_memory_monitor_unavailable'):
                    ADAPTER._run_process(
                        [sys.executable, '-c', 'print("must not run")'],
                        timeout=5, artifact_dir=temporary,
                    )

        popen.assert_not_called()

    @unittest.skipUnless(os.name != 'nt', 'POSIX ps process snapshots are required')
    def test_rss_budget_exceeded_terminates_artifact_process_group(self):
        process = mock.Mock(pid=1234)
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(ADAPTER.subprocess, 'Popen', return_value=process), \
                mock.patch.object(ADAPTER, '_scan_artifact_usage', return_value=(0, 0, 0)), \
                mock.patch.object(ADAPTER, '_process_tree_rss_bytes',
                                  side_effect=[0, ADAPTER.MAX_PROCESS_TREE_RSS_BYTES + 1]), \
                mock.patch.object(ADAPTER, '_terminate_and_reap', return_value=(b'', b'')) as cleanup:
            with self.assertRaisesRegex(
                    ADAPTER.ArtifactBudgetExceeded,
                    'process_tree_memory_limit_exceeded'):
                ADAPTER._run_process(
                    [sys.executable, '-c', 'print("must be terminated")'],
                    timeout=5, artifact_dir=temporary,
                )

        cleanup.assert_called_once_with(process)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process snapshots are required')
    def test_missing_target_snapshot_after_process_exit_is_normal_completion(self):
        process = mock.Mock(pid=1234)
        process.poll.side_effect = [None, 0]
        process.communicate.return_value = (b'done', b'')
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(ADAPTER, '_preflight_process_tree_rss_monitor'), \
                mock.patch.object(ADAPTER.subprocess, 'Popen', return_value=process), \
                mock.patch.object(ADAPTER, '_scan_artifact_usage', return_value=(0, 0, 0)), \
                mock.patch.object(ADAPTER, '_process_tree_rss_bytes',
                                  side_effect=ADAPTER.ArtifactBudgetExceeded('process_memory_monitor_target_missing')), \
                mock.patch.object(ADAPTER, '_process_group_exists', return_value=False), \
                mock.patch.object(ADAPTER, '_kill_observed_descendants', return_value=(False, True)):
            result = ADAPTER._run_process(
                [sys.executable, '-c', 'print("finished")'], timeout=5, artifact_dir=temporary,
            )

        self.assertEqual(result.stdout, b'done')

    @unittest.skipUnless(os.name != 'nt', 'POSIX process snapshots are required')
    def test_missing_target_snapshot_while_process_is_alive_fails_closed(self):
        process = mock.Mock(pid=1234)
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(ADAPTER, '_preflight_process_tree_rss_monitor'), \
                mock.patch.object(ADAPTER.subprocess, 'Popen', return_value=process), \
                mock.patch.object(ADAPTER, '_scan_artifact_usage', return_value=(0, 0, 0)), \
                mock.patch.object(ADAPTER, '_process_tree_rss_bytes',
                                  side_effect=ADAPTER.ArtifactBudgetExceeded('process_memory_monitor_target_missing')), \
                mock.patch.object(ADAPTER, '_terminate_and_reap', return_value=(b'', b'')) as cleanup:
            with self.assertRaisesRegex(
                    ADAPTER.ArtifactBudgetExceeded,
                    'process_memory_monitor_target_missing'):
                ADAPTER._run_process(
                    [sys.executable, '-c', 'print("finished")'], timeout=5, artifact_dir=temporary,
                )

        cleanup.assert_called_once_with(process)

    def test_windows_timeout_kills_the_entire_process_tree(self):
        process = mock.Mock(pid=1234)
        with mock.patch.object(ADAPTER.os, 'name', 'nt'), mock.patch.object(
                ADAPTER.subprocess, 'run') as run:
            run.return_value.returncode = 0
            self.assertTrue(ADAPTER._kill_process_group(process))
        run.assert_called_once_with(
            ['taskkill', '/PID', '1234', '/T', '/F'],
            check=False, stdout=ADAPTER.subprocess.DEVNULL,
            stderr=ADAPTER.subprocess.DEVNULL, timeout=1,
        )
        process.kill.assert_not_called()

    def test_windows_taskkill_failure_falls_back_to_killing_direct_child(self):
        process = mock.Mock(pid=1234)
        with mock.patch.object(ADAPTER.os, 'name', 'nt'), mock.patch.object(
                ADAPTER.subprocess, 'run') as run:
            run.return_value.returncode = 1
            self.assertFalse(ADAPTER._kill_process_group(process))
        process.kill.assert_called_once_with()

    def test_posix_group_signal_permission_error_falls_back_and_reports_incomplete(self):
        process = mock.Mock(pid=1234)
        with mock.patch.object(ADAPTER.os, 'name', 'posix'), mock.patch.object(
                ADAPTER.os, 'killpg', side_effect=PermissionError):
            self.assertFalse(ADAPTER._kill_process_group(process))
        process.kill.assert_called_once_with()

    def test_unconfirmed_process_tree_cleanup_is_reported(self):
        process = mock.Mock(pid=1234)
        process.communicate.return_value = (b'', b'')
        with mock.patch.object(ADAPTER, '_kill_process_group', return_value=False), \
                mock.patch.object(ADAPTER, '_process_group_exists', return_value=True), \
                mock.patch.object(ADAPTER.time, 'sleep'):
            with self.assertRaisesRegex(
                    ADAPTER.ProcessTreeCleanupIncomplete,
                    'decompiler_process_tree_cleanup_incomplete'):
                ADAPTER._terminate_and_reap(process)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_cleanup_does_not_report_success_while_process_group_remains(self):
        process = mock.Mock(pid=1234)
        process.communicate.return_value = (b'', b'')
        with mock.patch.object(ADAPTER, '_kill_process_group', return_value=True), \
                mock.patch.object(ADAPTER, '_process_group_exists', return_value=True):
            with self.assertRaisesRegex(
                    ADAPTER.ProcessTreeCleanupIncomplete,
                    'decompiler_process_tree_cleanup_incomplete'):
                ADAPTER._terminate_and_reap(process)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_cleanup_rechecks_transient_process_group_after_pipe_drain(self):
        process = mock.Mock(pid=1234)
        process.communicate.return_value = (b'', b'')
        with mock.patch.object(ADAPTER, '_kill_process_group', return_value=False), \
                mock.patch.object(ADAPTER, '_process_group_exists', side_effect=[True, False]), \
                mock.patch.object(ADAPTER.time, 'sleep'):
            output = ADAPTER._terminate_and_reap(process)

        self.assertEqual(output, (b'', b''))

    def test_unknown_process_tree_state_cannot_report_success_for_artifact_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(ADAPTER, '_process_group_exists', return_value=None):
                with self.assertRaises(ADAPTER.ArtifactBudgetExceeded):
                    ADAPTER._run_process(
                        [sys.executable, '-c', 'print("finished")'],
                        timeout=5, artifact_dir=temporary,
                    )

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_keyboard_interrupt_cleans_up_the_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child_pid = root / 'child.pid'
            output = root / 'artifacts'
            output.mkdir()
            code = (
                'import os, pathlib, time\n'
                'pid = os.fork()\n'
                f'if pid:\n    ready = pathlib.Path({str(child_pid)!r})\n'
                '    pending = ready.with_suffix(".pending")\n'
                '    pending.write_text(str(pid))\n'
                '    pending.replace(ready)\n'
                'time.sleep(30)\n'
            )

            def interrupt_after_child_starts(_output_dir):
                deadline = time.monotonic() + 2
                while not child_pid.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not child_pid.exists():
                    raise AssertionError('child process did not start')
                raise KeyboardInterrupt

            with mock.patch.object(
                    ADAPTER, '_scan_artifact_usage', side_effect=interrupt_after_child_starts):
                with self.assertRaises(KeyboardInterrupt):
                    ADAPTER._run_process(
                        [sys.executable, '-c', code], timeout=5, artifact_dir=output,
                    )

            child = int(child_pid.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail('descendant process remained alive after interrupted cleanup')

    def test_success_records_raw_hash_command_and_pseudocode_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'decompilation'
            calls = []

            def run(command, **kwargs):
                calls.append((command, kwargs))
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2\n', stderr='')
                self.assertEqual(command[1], 'decompile')
                self.assertEqual(Path(command[2]).read_text(), '0x6000')
                self.assertIn('--skip-resolving', command)
                self.assertIn('--include-sol', command)
                self.assertNotIn('--llm-postprocess', command)
                Path(command[command.index('--output') + 1], 'decompiled.sol').write_text(
                    'contract DecompiledContract {}\n', encoding='utf-8',
                )
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall(
                    '0x6000', binary=sys.executable, output_dir=output,
                )

            self.assertEqual(result['state'], 'completed')
            self.assertEqual(result['toolVersion'], 'heimdall 0.9.2')
            self.assertEqual(result['inputSha256'], hashlib.sha256(bytes.fromhex('6000')).hexdigest())
            self.assertEqual(result['inputBytecodeBytes'], 2)
            self.assertEqual(result['hardfork'], 'latest')
            self.assertEqual(result['crossValidation']['state'], 'not_performed')
            self.assertEqual(result['crossValidation']['enginesConfigured'], ['heimdall-rs'])
            self.assertEqual(result['crossValidation']['enginesCompleted'], [])
            self.assertEqual(result['crossValidation']['comparedEngineCount'], 0)
            self.assertEqual(result['crossValidation']['artifactReferenceState'], 'available')
            self.assertFalse(result['sourceVerified'])
            self.assertEqual(result['outputKind'], 'inferred_pseudocode_not_verified_source')
            self.assertEqual(result['artifactUsageSampleIntervalMs'], 100)
            self.assertEqual(result['processTreeRssSampleIntervalMs'], 250)
            self.assertIn('periodic_monitor_100ms_and_post_run_inventory',
                          result['artifactAggregateBudgetEnforcement'])
            self.assertEqual(result['command'][2], '<runtime-bytecode-file>')
            self.assertEqual(len(calls), 2)
            artifact = next(item for item in result['artifacts'] if item['path'] == 'decompiled.sol')
            self.assertEqual(artifact['sha256'], hashlib.sha256(
                b'contract DecompiledContract {}\n',
            ).hexdigest())
            artifact_ref = next(item for item in result['crossValidation']['artifactRefs'] if item['path'] == 'decompiled.sol')
            self.assertEqual(artifact_ref['sha256'], artifact['sha256'])
            self.assertEqual(artifact_ref['size'], artifact['size'])
            self.assertTrue((output / 'stdout.log').is_file())
            self.assertTrue((output / 'stderr.log').is_file())

    @unittest.skipUnless(os.name != 'nt' and ADAPTER.resource is not None,
                         'POSIX resource limits are required')
    def test_file_backed_version_probe_still_allows_a_valid_decompilation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'fake-heimdall.py'
            binary.write_text(
                '#!/usr/bin/env python3\n'
                'import pathlib, sys\n'
                'if "--version" in sys.argv:\n'
                '    print("heimdall fake 1.0")\n'
                'else:\n'
                '    output = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])\n'
                '    (output / "decompiled.sol").write_text("contract Recovered {}")\n',
                encoding='utf-8',
            )
            binary.chmod(0o755)
            output = root / 'decompilation'

            result = ADAPTER.run_heimdall(
                '0x6000', binary=binary, output_dir=output, timeout_seconds=3,
            )

            self.assertEqual(result['state'], 'completed')
            self.assertEqual(result['toolVersion'], 'heimdall fake 1.0')
            self.assertEqual(result['crossValidation']['state'], 'not_performed')
            self.assertTrue((output / 'decompiled.sol').is_file())

    def test_timeout_preserves_output_logs_and_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                kwargs['stderr'].write(b'partial diagnostic')
                raise subprocess.TimeoutExpired(command, timeout=1)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall(
                    '0x6000', binary=sys.executable, output_dir=output,
                    timeout_seconds=1,
                )

            self.assertEqual(result['state'], 'timeout')
            self.assertTrue(result['timedOut'])
            self.assertIsNone(result['exitCode'])
            self.assertEqual((output / 'stderr.log').read_bytes(), b'partial diagnostic')
            self.assertEqual(result['toolVersion'], 'heimdall 0.9.2')

    def test_version_process_cleanup_failure_returns_a_bounded_timeout_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'
            cleanup = ADAPTER.ProcessTreeCleanupIncomplete(
                'decompiler_process_tree_cleanup_incomplete', timed_out=True,
                output=b'partial version output', stderr=b'partial version error',
            )
            with mock.patch.object(ADAPTER, '_run_process', side_effect=cleanup):
                result = ADAPTER.run_heimdall('0x6000', binary=sys.executable, output_dir=output)

            self.assertEqual(result['state'], 'timeout')
            self.assertTrue(result['timedOut'])
            self.assertEqual((output / 'stdout.log').read_bytes(), b'partial version output')
            self.assertIn(b'partial version error', (output / 'stderr.log').read_bytes())
            self.assertIn(b'decompiler_process_tree_cleanup_incomplete', (output / 'stderr.log').read_bytes())

    @unittest.skipUnless(os.name != 'nt' and ADAPTER.resource is not None,
                         'POSIX resource limits are required')
    def test_version_output_is_file_backed_and_subject_to_artifact_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'noisy-heimdall.py'
            binary.write_text(
                '#!/usr/bin/env python3\n'
                'import sys\n'
                'if "--version" in sys.argv:\n'
                '    sys.stdout.write("x" * 8192)\n'
                '    raise SystemExit(0)\n'
                'raise SystemExit(0)\n',
                encoding='utf-8',
            )
            binary.chmod(0o755)
            output = root / 'decompilation'

            with mock.patch.object(ADAPTER, 'MAX_ARTIFACT_BYTES', 1024):
                result = ADAPTER.run_heimdall(
                    '0x6000', binary=binary, output_dir=output,
                )

            self.assertEqual(result['state'], 'partial')
            self.assertEqual(result['error'], 'artifact_file_size_limit_exceeded')
            self.assertLessEqual((output / 'stdout.log').stat().st_size, 1024)
            self.assertFalse(result['artifactInventoryComplete'])

    def test_decompile_cleanup_failure_preserves_timeout_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                raise ADAPTER.ProcessTreeCleanupIncomplete(
                    'decompiler_process_tree_cleanup_incomplete', timed_out=True,
                )

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall('0x6000', binary=sys.executable, output_dir=output)

            self.assertEqual(result['state'], 'timeout')
            self.assertTrue(result['timedOut'])

    def test_nonzero_exit_is_failed_even_if_tool_writes_pseudocode(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                Path(command[command.index('--output') + 1], 'partial.sol').write_text('partial')
                return subprocess.CompletedProcess(command, 2)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall(
                    '0x6000', binary=sys.executable, output_dir=output,
                )

            self.assertEqual(result['state'], 'failed')
            self.assertEqual(result['exitCode'], 2)

    def test_binary_replacement_during_decompilation_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'decompilation'
            binary = root / 'fake-heimdall'
            binary.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            binary.chmod(0o755)

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                binary.write_text('#!/bin/sh\nexit 1\n', encoding='utf-8')
                (Path(command[command.index('--output') + 1]) / 'decompiled.sol').write_text(
                    'contract Decompiled {}', encoding='utf-8',
                )
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall(
                    '0x6000', binary=binary, output_dir=output,
                )

            self.assertEqual(result['state'], 'unavailable')
            self.assertEqual(result['error'], 'heimdall_binary_changed_during_execution')

    def test_artifact_overflow_is_partial_even_when_pseudocode_is_beyond_inventory_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                destination = Path(command[command.index('--output') + 1])
                for index in range(256):
                    (destination / f'a{index:03d}.txt').write_text('noise')
                (destination / 'z.sol').write_text('contract Decompiled {}')
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall(
                    '0x6000', binary=sys.executable, output_dir=output,
                )

            self.assertEqual(result['state'], 'partial')
            self.assertEqual(result['error'], 'artifact_inventory_truncated')
            self.assertFalse(result['artifactInventoryComplete'])
            self.assertGreater(result['artifactOverflowCount'], 0)

    def test_omitted_artifact_prevents_complete_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                destination = Path(command[command.index('--output') + 1])
                (destination / 'decompiled.sol').write_text('contract Decompiled {}')
                (destination / 'outside.txt').symlink_to('/etc/hosts')
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall(
                    '0x6000', binary=sys.executable, output_dir=output,
                )

            self.assertEqual(result['state'], 'partial')
            self.assertEqual(result['error'], 'artifact_inventory_incomplete')
            self.assertFalse(result['artifactInventoryComplete'])
            self.assertEqual(result['artifactOmittedCount'], 1)

    def test_inventory_rejects_a_file_at_the_per_file_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / 'decompiled.sol').write_bytes(b'12345')
            with mock.patch.object(ADAPTER, 'MAX_ARTIFACT_BYTES', 5):
                artifacts, overflow, omitted, total_bytes = ADAPTER._artifact_inventory(output)
            self.assertEqual(overflow, 0)
            self.assertEqual(omitted, 1)
            self.assertEqual(total_bytes, 5)
            self.assertEqual(artifacts[0]['omittedReason'], 'file_at_or_exceeds_per_file_limit')
            self.assertNotIn('sha256', artifacts[0])

    def test_combined_artifact_hash_and_decode_handles_multibyte_chunk_boundaries(self):
        content = 'contract Café { string constant VALUE = "é"; }'.encode('utf-8')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'decompiled.sol'
            path.write_bytes(content)
            with mock.patch.object(ADAPTER, 'HASH_CHUNK_BYTES', 5):
                digest, text = ADAPTER._sha256_and_text(path)

        self.assertEqual(digest, hashlib.sha256(content).hexdigest())
        self.assertEqual(text, content.decode('utf-8', errors='replace'))

    def test_inventory_hashes_and_validates_pseudocode_in_one_read_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            content = b'contract Recovered {}\n'
            (output / 'decompiled.sol').write_bytes(content)
            pseudocode_paths = set()
            with mock.patch.object(
                    ADAPTER, '_sha256_and_text', wraps=ADAPTER._sha256_and_text) as combined, \
                    mock.patch.object(ADAPTER, '_sha256') as separate_hash, \
                    mock.patch.object(ADAPTER, '_has_pseudocode_artifact',
                                      side_effect=AssertionError('artifact was reread')):
                artifacts, overflow, omitted, total_bytes = ADAPTER._artifact_inventory(
                    output, pseudocode_paths=pseudocode_paths,
                )

        self.assertEqual(combined.call_count, 1)
        separate_hash.assert_not_called()
        self.assertEqual(pseudocode_paths, {'decompiled.sol'})
        self.assertEqual(overflow, 0)
        self.assertEqual(omitted, 0)
        self.assertEqual(total_bytes, len(content))
        self.assertEqual(artifacts[0]['sha256'], hashlib.sha256(content).hexdigest())

    def test_aggregate_artifact_budget_makes_the_result_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                destination = Path(command[command.index('--output') + 1])
                (destination / 'decompiled.sol').write_bytes(b'x' * 12)
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(ADAPTER, 'MAX_TOTAL_ARTIFACT_BYTES', 10), \
                    mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall('0x6000', binary=sys.executable, output_dir=output)

            self.assertEqual(result['state'], 'partial')
            self.assertEqual(result['error'], 'artifact_total_bytes_limit_exceeded')
            self.assertEqual(result['artifactTotalBytes'], 12)
            self.assertFalse(result['artifactInventoryComplete'])
            artifact = next(item for item in result['artifacts'] if item['path'] == 'decompiled.sol')
            self.assertEqual(artifact['omittedReason'], 'total_artifact_bytes_limit_exceeded')
            self.assertNotIn('sha256', artifact)

    def test_runtime_artifact_budget_terminates_the_child_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            started = time.monotonic()
            command = [sys.executable, '-c',
                       'import pathlib,time; pathlib.Path(r"' + str(output / 'large.bin') + '").write_bytes(b"x"*2048); time.sleep(5)']
            with mock.patch.object(ADAPTER, 'MAX_TOTAL_ARTIFACT_BYTES', 1024), \
                    self.assertRaisesRegex(ADAPTER.ArtifactBudgetExceeded, 'artifact_total_bytes_limit_exceeded'):
                ADAPTER._run_process(command, timeout=10, artifact_dir=output)
            self.assertLess(time.monotonic() - started, 3)

    def test_runtime_file_limit_is_applied_by_exec_wrapper_without_preexec(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            artifact = output / 'large.bin'
            code = f'import pathlib; pathlib.Path({str(artifact)!r}).write_bytes(b"x" * 64)'
            command = [sys.executable, '-c', code]
            real_popen = ADAPTER.subprocess.Popen
            popen_kwargs = []

            def popen(*args, **kwargs):
                popen_kwargs.append(kwargs.copy())
                return real_popen(*args, **kwargs)

            with mock.patch.object(ADAPTER, 'MAX_ARTIFACT_BYTES', 32), \
                    mock.patch.object(ADAPTER.subprocess, 'Popen', side_effect=popen), \
                    self.assertRaisesRegex(ADAPTER.ArtifactBudgetExceeded, 'artifact_file_size_limit_exceeded'):
                ADAPTER._run_process(command, timeout=5, artifact_dir=output)

            self.assertTrue(popen_kwargs)
            self.assertNotIn('preexec_fn', popen_kwargs[0])
            self.assertLessEqual(artifact.stat().st_size, 32)

    def test_inventory_stops_at_the_tree_entry_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for index in range(4):
                (output / f'{index}.txt').write_text('x')
            with mock.patch.object(ADAPTER, 'MAX_ARTIFACT_TREE_ENTRIES', 2):
                artifacts, overflow, _, _ = ADAPTER._artifact_inventory(output)
            self.assertEqual(overflow, 1)
            self.assertLessEqual(len(artifacts), 2)

    def test_invalid_input_and_existing_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for bytecode in ('0x', '0x1', '0xgg', '6000', None):
                with self.subTest(bytecode=bytecode), self.assertRaises(ValueError):
                    ADAPTER.run_heimdall(
                        bytecode, binary=sys.executable, output_dir=root / 'unused',
                    )
            with self.assertRaises(ValueError):
                ADAPTER.run_heimdall(
                    '0x6000', binary=sys.executable, output_dir=root,
                )

    def test_missing_binary_is_reported_as_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'
            with mock.patch.object(ADAPTER.shutil, 'which', return_value=None):
                result = ADAPTER.run_heimdall(
                    '0x6000', binary='heimdall-missing', output_dir=output,
                )
            self.assertEqual(result['state'], 'unavailable')
            self.assertEqual(result['error'], 'heimdall_binary_unavailable')

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_timeout_kills_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'fake-heimdall.py'
            child_pid = root / 'child.pid'
            binary.write_text(
                '#!/usr/bin/env python3\n'
                'import os, pathlib, sys, time\n'
                'if "--version" in sys.argv:\n'
                '    print("heimdall fake")\n'
                '    raise SystemExit(0)\n'
                f'pid=os.fork();\nif pid != 0: pathlib.Path({str(child_pid)!r}).write_text(str(pid))\n'
                'if pid == 0: time.sleep(30)\n'
                'time.sleep(30)\n',
                encoding='utf-8',
            )
            binary.chmod(0o755)
            result = ADAPTER.run_heimdall(
                '0x6000', binary=binary, output_dir=root / 'decompilation',
                timeout_seconds=0.1,
            )
            self.assertEqual(result['state'], 'timeout')
            child = int(child_pid.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_timeout_kills_descendant_that_ignores_term_after_parent_exits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'stubborn-heimdall.py'
            child_pid = root / 'child.pid'
            binary.write_text(
                '#!/usr/bin/env python3\n'
                'import os, pathlib, signal, sys, time\n'
                'if "--version" in sys.argv:\n'
                '    print("heimdall fake")\n'
                '    raise SystemExit(0)\n'
                f'pid=os.fork();\nif pid != 0: pathlib.Path({str(child_pid)!r}).write_text(str(pid))\n'
                'if pid == 0:\n'
                '    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                'else:\n'
                '    signal.signal(signal.SIGTERM, lambda *_: raise_exit())\n'
                'time.sleep(30)\n',
                encoding='utf-8',
            )
            # Define the parent-only exit handler without changing the child path.
            binary.write_text(binary.read_text().replace(
                'signal.signal(signal.SIGTERM, lambda *_: raise_exit())',
                'signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))',
            ), encoding='utf-8')
            binary.chmod(0o755)
            started = time.monotonic()
            result = ADAPTER.run_heimdall(
                '0x6000', binary=binary, output_dir=root / 'decompilation',
                timeout_seconds=0.1,
            )
            self.assertEqual(result['state'], 'timeout')
            self.assertLess(time.monotonic() - started, 3)
            child = int(child_pid.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_keyboard_interrupt_kills_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child_pid = root / 'child.pid'
            child_ready = root / 'child.ready'
            output = root / 'artifacts'
            output.mkdir()
            code = (
                'import os,pathlib,signal,time\n'
                'pid=os.fork()\n'
                f'if pid: pathlib.Path({str(child_pid)!r}).write_text(str(pid))\n'
                'else:\n'
                ' signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                f' pathlib.Path({str(child_ready)!r}).write_text("ready")\n'
                'time.sleep(30)\n'
            )
            original_sleep = time.sleep

            def interrupt_after_descendant_starts(_):
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    if child_ready.exists():
                        raise KeyboardInterrupt
                    original_sleep(0.01)
                self.fail('descendant did not start before the cleanup test interrupted')

            with mock.patch.object(
                    ADAPTER, '_scan_artifact_usage', side_effect=interrupt_after_descendant_starts):
                with self.assertRaises(KeyboardInterrupt):
                    ADAPTER._run_process(
                        [sys.executable, '-c', code], timeout=20, artifact_dir=output,
                    )

            child = int(child_pid.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail('descendant process remained alive after interrupt cleanup')

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_successful_parent_exit_detects_descendant_that_closed_output_pipes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child_pid = root / 'child.pid'
            output = root / 'artifacts'
            output.mkdir()
            code = (
                'import os, pathlib, time\n'
                'pid = os.fork()\n'
                f'if pid:\n    pathlib.Path({str(child_pid)!r}).write_text(str(pid))\n'
                'else:\n    os.close(1)\n    os.close(2)\n    time.sleep(0.5)\n'
            )
            started = time.monotonic()
            with self.assertRaises(ADAPTER.ArtifactBudgetExceeded):
                ADAPTER._run_process(
                    [sys.executable, '-c', code], timeout=5, artifact_dir=output,
                )
            child = int(child_pid.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail('descendant process remained alive after bounded cleanup window')
            self.assertLess(time.monotonic() - started, 3)

    def test_runtime_artifact_count_budget_terminates_the_child_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            code = (
                'import pathlib,time; d=pathlib.Path(' + repr(str(output)) + '); '
                '[ (d / str(i)).write_text("x") for i in range(3) ]; time.sleep(5)'
            )
            started = time.monotonic()
            with mock.patch.object(ADAPTER, 'MAX_ARTIFACTS', 2), \
                    self.assertRaisesRegex(
                        ADAPTER.ArtifactBudgetExceeded,
                        'artifact_count_limit_exceeded'):
                ADAPTER._run_process(
                    [sys.executable, '-c', code], timeout=10, artifact_dir=output,
                )
            self.assertLess(time.monotonic() - started, 3)

    def test_successful_parent_exit_detects_descendant_without_artifact_monitor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child_pid = root / 'child.pid'
            code = (
                'import os, pathlib, time\n'
                'pid = os.fork()\n'
                f'if pid:\n    pathlib.Path({str(child_pid)!r}).write_text(str(pid))\n'
                'else:\n    os.close(1)\n    os.close(2)\n    time.sleep(0.5)\n'
            )
            with self.assertRaises(ADAPTER.ArtifactBudgetExceeded):
                ADAPTER._run_process([sys.executable, '-c', code], timeout=5)
            child = int(child_pid.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail('version-check descendant remained alive after bounded cleanup window')

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_process_tree_result_discloses_process_group_escape_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = ADAPTER._base_result(b'\x00', Path(temporary))

        self.assertEqual(result['processTreeCleanup'], {
            'mechanism': 'posix_process_group_plus_observed_descendant_pids',
            'trackedScope': 'initial_process_group_and_descendants_seen_in_periodic_process_snapshots',
            'detachedDescendants': 'observed_descendants_terminated_on_exit_or_cleanup; unobserved_descendants_may_escape',
            'escapeCondition': 'descendant_detaches_or_is_reparented_before_its_first_process_snapshot',
            'pidIdentityPrecision': 'uid_and_ps_lstart_seconds_with_immediate_pre_signal_revalidation; same_second_pid_reuse_remains_possible_without_pidfd',
        })
        expected_rss_coverage = (
            'sampled_parent_child_lineage_and_identity_matched_observed_descendants; unsampled fast descendants may escape'
            if ADAPTER.shutil.which('ps') else 'unavailable'
        )
        self.assertEqual(
            result['processTreeRssCoverage'],
            expected_rss_coverage,
        )
        expected_cpu_scope = (
            'per_process_not_aggregate_across_descendants'
            if ADAPTER.resource is not None else 'wall_timeout_only'
        )
        self.assertEqual(result['cpuLimitScope'], expected_cpu_scope)

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_artifact_monitor_kills_observed_detached_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / 'child.pid'
            output = root / 'artifacts'
            output.mkdir()
            code = (
                'import os, pathlib, time\n'
                'pid = os.fork()\n'
                'if pid == 0:\n'
                '    os.close(1)\n'
                '    os.close(2)\n'
                '    os.setsid()\n'
                '    time.sleep(30)\n'
                'else:\n'
                f'    pathlib.Path({str(marker)!r}).write_text(str(pid))\n'
                '    time.sleep(0.6)\n'
            )
            try:
                with self.assertRaisesRegex(
                        ADAPTER.ArtifactBudgetExceeded,
                        'decompiler_child_process_outlived_parent'):
                    ADAPTER._run_process(
                        [sys.executable, '-c', code], timeout=5, artifact_dir=output,
                    )
            finally:
                if marker.exists():
                    try:
                        os.kill(int(marker.read_text()), ADAPTER.signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(os.name != 'nt', 'POSIX process groups are required')
    def test_descendant_in_new_session_is_outside_cleanup_scope(self):
        launcher = (
            'import subprocess,sys; '
            'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"], '
            'start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); '
            'print(child.pid, flush=True)'
        )
        child_pid = None
        try:
            result = ADAPTER._run_process([sys.executable, '-c', launcher], timeout=5)
            child_pid = int(result.stdout.strip())
            os.kill(child_pid, 0)
        finally:
            if child_pid is not None:
                try:
                    os.kill(child_pid, ADAPTER.signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_empty_pseudocode_artifact_does_not_count_as_completed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                destination = Path(command[command.index('--output') + 1])
                (destination / 'decompiled.sol').write_text('')
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall('0x6000', binary=sys.executable, output_dir=output)

            self.assertEqual(result['state'], 'partial')
            self.assertEqual(result['error'], 'heimdall_completed_without_pseudocode_artifact')

    def test_comment_only_pseudocode_artifact_does_not_count_as_completed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                destination = Path(command[command.index('--output') + 1])
                (destination / 'decompiled.sol').write_text(
                    '// contract MentionedInComment {}\n/* interface AlsoCommented {} */\npragma solidity >=0.8.0;\n',
                    encoding='utf-8',
                )
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall('0x6000', binary=sys.executable, output_dir=output)

            self.assertEqual(result['state'], 'partial')
            self.assertEqual(result['error'], 'heimdall_completed_without_pseudocode_artifact')

    def test_yul_object_counts_as_pseudocode(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'decompilation'

            def run(command, **kwargs):
                if command[-1] == '--version':
                    return subprocess.CompletedProcess(command, 0, stdout='heimdall 0.9.2', stderr='')
                destination = Path(command[command.index('--output') + 1])
                (destination / 'decompiled.yul').write_text('object "Recovered" { code { stop() } }\n', encoding='utf-8')
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(ADAPTER, '_run_process', side_effect=run):
                result = ADAPTER.run_heimdall('0x6000', binary=sys.executable, output_dir=output)

            self.assertEqual(result['state'], 'completed')

    def test_pseudocode_lexer_ignores_comments_and_literal_declarations(self):
        cases = [
            ('.sol', '// contract Comment {}\r\n/* library Comment {} */', False),
            ('.sol', '// ignored\r\nlibrary Visible {}', True),
            ('.sol', '/* contract Unclosed {}', False),
            ('.sol', '"contract OnlyInString {}"', False),
            ('.sol', "'interface OnlyInString {}'", False),
            ('.sol', '"unclosed string contract Hidden {}', False),
            ('.sol', '/* ignored */ contract Recovered {} // ignored', True),
            ('.sol', 'interface/* ignored */Recovered {}', True),
            ('.sol', 'con/* ignored */tract NotADeclaration {}', False),
            ('.sol', '"https://example.invalid/*path*/"; library Recovered {}', True),
            ('.yul', 'object "Recovered//name/*text*/" { code { stop() } }', True),
            ('.yul', '"function OnlyInString()"', False),
            ('.yul', '/* object "Hidden" { code {} } */', False),
            ('.yul', 'function/* ignored */recovered() {}', True),
            ('.yul', 'object "" { code {} }', False),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            for suffix, content, expected in cases:
                with self.subTest(suffix=suffix, content=content):
                    path = Path(temporary) / ('decompiled' + suffix)
                    path.write_text(content, encoding='utf-8')
                    self.assertEqual(ADAPTER._has_pseudocode_artifact(path), expected)

    def test_pseudocode_lexer_reuses_plain_text_without_special_tokens(self):
        text = 'contract Plain { function f() external {} }'
        self.assertIs(ADAPTER._pseudocode_code(text), text)

    def test_pseudocode_lexer_handles_escaped_quotes_and_backslashes(self):
        cases = [quote + 'escaped ' + '\\' * count + quote + ' contract Hidden {}' + quote
                 for quote in ('"', "'") for count in (1, 3, 5)]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'decompiled.sol'
            for content in cases:
                with self.subTest(content=content):
                    path.write_text(content, encoding='utf-8')
                    self.assertFalse(ADAPTER._has_pseudocode_artifact(path))
                    path.write_text(content + '\ncontract Visible {}', encoding='utf-8')
                    self.assertTrue(ADAPTER._has_pseudocode_artifact(path))
            for count in (2, 4):
                content = '"ends in ' + '\\' * count + '"; contract Visible {}'
                path.write_text(content, encoding='utf-8')
                self.assertTrue(ADAPTER._has_pseudocode_artifact(path))

    def test_unclosed_comment_openers_are_skipped_with_one_linear_search(self):
        class CountedText(str):
            find_calls = 0
            startswith_calls = 0
            def find(self, *args):
                self.find_calls += 1
                return super().find(*args)
            def startswith(self, *args):
                self.startswith_calls += 1
                return super().startswith(*args)

        for prefix, expected in (('', False), ('contract Visible {}\n', True)):
            with self.subTest(real_code_before_comment=bool(prefix)):
                content = CountedText(prefix + '/* ' * 100_000 + 'contract Hidden {}')
                with mock.patch.object(Path, 'read_text', return_value=content):
                    self.assertEqual(ADAPTER._has_pseudocode_artifact('decompiled.sol'), expected)
                self.assertEqual(content.find_calls, 1)
                self.assertLessEqual(content.startswith_calls, 2 * (len(prefix) + 1))

    def test_many_closed_comments_do_not_rescan_previous_or_later_blocks(self):
        class CountedText(str):
            searched_bytes = 0
            find_calls = 0
            def find(self, target, start=0, end=None):
                boundary = len(self) if end is None else end
                result = super().find(target, start, boundary)
                self.find_calls += 1
                self.searched_bytes += (boundary if result < 0 else result + len(target)) - start
                return result

        content = CountedText('/* not code */' * 10_000 + 'library Visible {}')
        with mock.patch.object(Path, 'read_text', return_value=content):
            self.assertTrue(ADAPTER._has_pseudocode_artifact('decompiled.sol'))
        self.assertEqual(content.find_calls, 10_000)
        self.assertLessEqual(content.searched_bytes, len(content))

    def test_many_short_comments_bound_pending_fragments_and_batch_output_writes(self):
        count = 5000
        content = '/**/' * count + 'library Visible {}'
        output = ADAPTER.StringIO()
        peak_parts = [0]
        function = ADAPTER._pseudocode_code

        def observe(frame, event, arg):
            if (event == 'line' and frame.f_code.co_filename == function.__code__.co_filename and
                    frame.f_code.co_name in ('_pseudocode_code', 'append')):
                peak_parts[0] = max(peak_parts[0], len(frame.f_locals.get('pieces', [])))
            return observe

        previous = sys.gettrace()
        with mock.patch.object(ADAPTER, 'StringIO', return_value=output), \
                mock.patch.object(output, 'write', wraps=output.write) as write:
            try:
                sys.settrace(observe)
                result = function(content)
            finally:
                sys.settrace(previous)

        self.assertEqual(result, ' ' * count + 'library Visible {}')
        self.assertLessEqual(peak_parts[0], ADAPTER.MAX_PSEUDOCODE_BUFFER_PARTS)
        self.assertGreater(write.call_count, 1)
        self.assertLessEqual(write.call_count, (count + 1) // ADAPTER.MAX_PSEUDOCODE_BUFFER_PARTS + 1)

    def test_dense_short_comments_do_not_allocate_a_list_entry_for_every_comment(self):
        if tracemalloc.is_tracing():
            self.skipTest('requires isolated allocation tracking')
        count = 200_000
        content = '/**/' * count + 'library Visible {}'
        tracemalloc.start()
        try:
            result = ADAPTER._pseudocode_code(content)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(result, ' ' * count + 'library Visible {}')
        # Allows output copies and interpreter overhead, but not O(comments)
        # temporary list slots (the previous buffer used over 3.4 MiB here).
        self.assertLess(peak, len(content) * 2)


if __name__ == '__main__':
    unittest.main()
