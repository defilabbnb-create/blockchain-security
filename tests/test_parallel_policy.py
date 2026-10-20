import fcntl
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import unittest
from unittest import mock
from importlib.util import spec_from_file_location, module_from_spec

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location('policy_static', ROOT / 'scripts' / 'review-static.py')
mod = module_from_spec(spec)
spec.loader.exec_module(mod)


class TestParallelPolicy(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.tmpdir = temp.name
        self.addCleanup(temp.cleanup)
        env = mock.patch.dict(os.environ, {'FLARE_ANALYSIS_PARALLEL': 'auto'})
        env.start()
        self.addCleanup(env.stop)
        self.patcher = mock.patch.object(mod, 'ROOT', Path(self.tmpdir))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def acquire(self, *args, **kwargs):
        handle, err = mod._acquire_parallel_analysis_slot(*args, **kwargs)
        if handle is not None:
            self.addCleanup(mod._release_parallel_analysis_slot, handle)
        return handle, err

    def test_auto_cpu_none_fallback(self):
        with mock.patch.object(mod.os, 'cpu_count', return_value=None):
            handle, err = self.acquire()
        assert handle is None
        assert err == 'insufficient_logical_cpus'

    def test_auto_cpu3_fallback(self):
        with mock.patch.object(mod.os, 'cpu_count', return_value=3):
            handle, err = self.acquire()
        assert handle is None
        assert err == 'insufficient_logical_cpus'

    def test_auto_memory_none_fallback(self):
        with mock.patch.object(mod.os, 'cpu_count', return_value=4):
            with mock.patch.object(mod, '_available_memory_bytes', return_value=None):
                handle, err = self.acquire()
        assert handle is None
        assert err == 'available_memory_unknown'

    def test_auto_memory_4gib_minus_1_fallback(self):
        with mock.patch.object(mod.os, 'cpu_count', return_value=4):
            with mock.patch.object(mod, '_available_memory_bytes', return_value=4*1024**3-1):
                handle, err = self.acquire()
        assert handle is None
        assert err == 'less_than_4_gib_available'

    def test_auto_cpu4_memory_4gib_admit(self):
        with mock.patch.object(mod.os, 'cpu_count', return_value=4):
            with mock.patch.object(mod, '_available_memory_bytes', return_value=4*1024**3):
                handle, err = self.acquire()
        assert handle is not None
        assert err is None

    def test_forced_on_mock_cpu_memory_not_called(self):
        with mock.patch.dict(os.environ, {'FLARE_ANALYSIS_PARALLEL': 'on'}):
            with mock.patch.object(mod.os, 'cpu_count', side_effect=AssertionError):
                with mock.patch.object(mod, '_available_memory_bytes', side_effect=AssertionError):
                    handle, err = self.acquire()
        assert handle is not None
        assert err is None

    def test_acquire_twice_parallel_slot_busy_then_release_reacquire(self):
        with mock.patch.object(mod.os, 'cpu_count', return_value=4):
            with mock.patch.object(mod, '_available_memory_bytes', return_value=4*1024**3):
                handle1, err1 = self.acquire()
                assert handle1 is not None
                assert err1 is None
                handle2, err2 = self.acquire()
                assert handle2 is None
                assert err2 == 'parallel_slot_busy'
        mod._release_parallel_analysis_slot(handle1)
        with mock.patch.object(mod.os, 'cpu_count', return_value=4):
            with mock.patch.object(mod, '_available_memory_bytes', return_value=4*1024**3):
                handle3, err3 = self.acquire()
        assert handle3 is not None
        assert err3 is None

    def test_off_fallback(self):
        with mock.patch.dict(os.environ, {'FLARE_ANALYSIS_PARALLEL': 'off'}):
            handle, err = self.acquire()
        assert handle is None
        assert err == 'disabled_by_environment'

    def test_invalid_fallback(self):
        with mock.patch.dict(os.environ, {'FLARE_ANALYSIS_PARALLEL': 'invalid'}):
            handle, err = self.acquire()
        assert handle is None
        assert err == 'invalid_parallel_setting'

    def test_release_closed_handle_idempotent(self):
        with mock.patch.object(mod.os, 'cpu_count', return_value=4), mock.patch.object(mod, '_available_memory_bytes', return_value=4*1024**3):
            handle, err = self.acquire()
        self.assertIsNotNone(handle)
        self.assertIsNone(err)
        mod._release_parallel_analysis_slot(handle)
        self.assertTrue(handle.closed)
        mod._release_parallel_analysis_slot(handle)
        mod._release_parallel_analysis_slot(handle)

    def test_platform_error_memory_returns_none(self):
        with mock.patch.object(mod.subprocess, 'run', side_effect=OSError):
            with mock.patch.object(mod.Path, 'read_text', side_effect=OSError):
                with mock.patch.dict(sys.modules, {'psutil': None}):
                    assert mod._available_memory_bytes() is None
