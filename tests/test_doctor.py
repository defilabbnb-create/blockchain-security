import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('project_doctor', ROOT / 'scripts' / 'doctor.py')
DOCTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOCTOR)


class DoctorReadinessTests(unittest.TestCase):
    def test_missing_optional_capability_does_not_block_readiness(self):
        checks = []
        DOCTOR.record(checks, 'Node.js', True, 'available')
        DOCTOR.record(checks, 'Docker', False, 'optional binary unavailable', required=False)

        ready, optional_failures = DOCTOR.summarize_checks(checks)

        self.assertTrue(ready)
        self.assertEqual(optional_failures, ['Docker'])
        self.assertEqual([check['required'] for check in checks], [True, False])

    def test_missing_required_toolchain_item_blocks_readiness(self):
        checks = []
        DOCTOR.record(checks, 'Node.js', True, 'available')
        DOCTOR.record(checks, 'Slither', False, 'missing')
        DOCTOR.record(checks, 'Docker', False, 'optional binary unavailable', required=False)

        ready, optional_failures = DOCTOR.summarize_checks(checks)

        self.assertFalse(ready)
        self.assertEqual(optional_failures, ['Docker'])

    def test_heimdall_is_reported_as_a_required_local_decompiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'work' / 'tools' / 'heimdall' / 'heimdall'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'heimdall')
            with mock.patch.object(DOCTOR, 'command_output', return_value='heimdall 0.9.2'):
                checks = DOCTOR.collect_checks(root)

        check = next(item for item in checks if item['check'] == 'Heimdall decompiler')
        self.assertTrue(check['ok'])
        self.assertTrue(check['required'])
        self.assertEqual(check['detail'], 'heimdall 0.9.2')

    def test_macos_memory_diagnostics_parses_vm_stat_format(self):
        vm_stat = '''Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free: 2.
Pages inactive: 3.
Pages speculative: 4.
Pages purgeable: 5.
'''
        with mock.patch.object(DOCTOR.platform, 'system', return_value='Darwin'), \
                mock.patch.object(DOCTOR, 'command_output', side_effect=['17179869184', vm_stat]):
            result = DOCTOR.memory_diagnostics()

        self.assertEqual(result['totalMemoryBytes'], 17179869184)
        self.assertEqual(result['availableMemoryBytes'], 14 * 16384)

    def test_macos_memory_diagnostics_keeps_total_if_vm_stat_fails(self):
        with mock.patch.object(DOCTOR.platform, 'system', return_value='Darwin'), \
                mock.patch.object(DOCTOR, 'command_output', side_effect=['17179869184', None]):
            result = DOCTOR.memory_diagnostics()

        self.assertEqual(result, {
            'totalMemoryBytes': 17179869184,
            'availableMemoryBytes': None,
        })

    def test_cloud_model_diagnostics_checks_configuration_without_network_or_key_output(self):
        environment = {
            'DEFI_CLOUD_AI_BASE_URL': 'https://api.example.com/v1',
            'DEFI_CLOUD_AI_API_KEY': 'secret-value',
            'DEFI_CLOUD_AI_MODEL': 'review-model',
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            result = DOCTOR.cloud_model_diagnostics()

        self.assertTrue(result['configured'])
        self.assertTrue(result['environmentComplete'])
        self.assertTrue(result['baseUrlValid'])
        self.assertEqual(result['baseUrlHost'], 'api.example.com')
        self.assertEqual(result['model'], 'review-model')
        self.assertFalse(result['networkRequested'])
        self.assertNotIn('secret-value', str(result))

    def test_cloud_model_diagnostics_rejects_insecure_or_credentialed_urls(self):
        for base_url in ('http://api.example.com/v1', 'https://user:pass@api.example.com/v1'):
            with self.subTest(base_url=base_url), mock.patch.dict(os.environ, {
                'DEFI_CLOUD_AI_BASE_URL': base_url,
                'DEFI_CLOUD_AI_API_KEY': 'secret-value',
                'DEFI_CLOUD_AI_MODEL': 'review-model',
            }, clear=True):
                result = DOCTOR.cloud_model_diagnostics()
            self.assertFalse(result['configured'])
            self.assertFalse(result['baseUrlValid'])
            self.assertIsNone(result['baseUrlHost'])

    def test_cloud_model_diagnostics_reports_missing_environment_values(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            result = DOCTOR.cloud_model_diagnostics()
        self.assertFalse(result['configured'])
        self.assertFalse(result['environmentComplete'])
        self.assertFalse(result['networkRequested'])


if __name__ == '__main__':
    unittest.main()
