import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('toolchain_lock', ROOT / 'scripts' / 'toolchain-lock.py')
LOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCK)


class ToolchainLockTests(unittest.TestCase):
    def test_npm_snapshot_records_integrity_installed_hash_and_scoped_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_dir = root / 'solc-0819'
            package_dir.mkdir()
            (package_dir / 'package.json').write_text('{"name":"solc-0819"}')
            lock_path = package_dir / 'package-lock.json'
            lock_data = {
                'packages': {
                    '': {'name': 'solc-0819'},
                    'node_modules/solc': {
                        'version': '0.8.19',
                        'resolved': 'https://registry.npmjs.org/solc/-/solc-0.8.19.tgz',
                        'integrity': 'sha512-example',
                    },
                    'node_modules/@scope/lib': {'version': '1.0.0'},
                    'node_modules/a/node_modules/@scope/lib': {'version': '2.0.0'},
                },
            }
            lock_path.write_text(json.dumps(lock_data))
            installed = package_dir / 'node_modules' / 'solc'
            installed.mkdir(parents=True)
            (installed / 'package.json').write_text('{"version":"0.8.19"}')
            (installed / 'soljson.js').write_bytes(b'compiled solidity compiler')

            result = LOCK.npm_lock_snapshot(root, lock_path)
            expected_lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
            expected_manifest_sha = hashlib.sha256((package_dir / 'package.json').read_bytes()).hexdigest()

        self.assertTrue(result['available'])
        self.assertEqual(result['lockSha256'], expected_lock_sha)
        self.assertEqual(result['manifestSha256'], expected_manifest_sha)
        packages = {(item['name'], item['version']): item for item in result['packages']}
        self.assertIn(('@scope/lib', '1.0.0'), packages)
        self.assertIn(('@scope/lib', '2.0.0'), packages)
        self.assertEqual(packages[('solc', '0.8.19')]['integrity'], 'sha512-example')
        self.assertTrue(result['installedSolc']['matchesLock'])
        self.assertEqual(result['installedSolc']['soljsonSha256'],
                         hashlib.sha256(b'compiled solidity compiler').hexdigest())

    def test_missing_lock_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = LOCK.npm_lock_snapshot(root, root / 'missing' / 'package-lock.json')
        self.assertFalse(result['available'])
        self.assertEqual(result['reason'], 'missing_lock')

    def test_invalid_lock_structure_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock_path = root / 'package-lock.json'
            lock_path.write_text('{"packages": []}')
            with self.assertRaisesRegex(ValueError, 'invalid npm lock structure'):
                LOCK.npm_lock_snapshot(root, lock_path)

    def test_heimdall_snapshot_records_release_and_actual_binary_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'work' / 'tools' / 'heimdall' / 'heimdall'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'fake heimdall binary')
            expected_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
            with mock.patch.object(LOCK.platform, 'system', return_value='Darwin'), \
                    mock.patch.object(LOCK.platform, 'machine', return_value='arm64'), \
                    mock.patch.object(LOCK, 'command_version', return_value='heimdall 0.9.2'):
                result = LOCK.heimdall_snapshot(root)

        self.assertTrue(result['available'])
        self.assertEqual(result['version'], 'heimdall 0.9.2')
        self.assertEqual(result['releaseTag'], '0.9.3')
        self.assertTrue(result['releaseTagVersionMismatch'])
        self.assertEqual(result['expectedAsset'], 'heimdall-macos-arm64')
        self.assertEqual(result['expectedSha256'],
                         'c279e92aa5a2178cb6327861f206eddee5d53209bb19a863915159b844cc0d23')
        self.assertEqual(result['sha256'], expected_hash)
        self.assertFalse(result['verifiedReleaseAsset'])
        self.assertEqual(result['installationTimeStatus'], 'unknown_existing_install')

    def test_check_ignores_only_observed_at_and_reports_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / 'toolchain.lock.json'
            inventory = {
                'node': {'version': 'v1'},
                'npmLockfiles': [],
                'pythonDistributions': {'distributionCount': 0},
            }
            with mock.patch.object(LOCK, 'collect_inventory', return_value=inventory):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(LOCK.main(['--output', str(lock_path)]), 0)
                    self.assertEqual(LOCK.main(['--output', str(lock_path), '--check']), 0)

                data = json.loads(lock_path.read_text())
                data['observedAt'] = '2000-01-01T00:00:00+00:00'
                lock_path.write_text(json.dumps(data))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(LOCK.main(['--output', str(lock_path), '--check']), 0)

                data['unexpected'] = True
                lock_path.write_text(json.dumps(data))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(LOCK.main(['--output', str(lock_path), '--check']), 1)
                    self.assertEqual(LOCK.main(['--output', str(lock_path / 'absent'), '--check']), 1)


if __name__ == '__main__':
    unittest.main()
