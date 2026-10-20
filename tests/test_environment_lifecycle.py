import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SETUP = load('setup.py', 'project_setup')
UPGRADE = load('upgrade-check.py', 'project_upgrade_check')
UNINSTALL = load('uninstall.py', 'project_uninstall')


class EnvironmentLifecycleTests(unittest.TestCase):
    def test_setup_plan_is_dry_run_and_keeps_install_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'package.json').write_text('{}')
            (root / 'package-lock.json').write_text('{}')
            plan = SETUP.build_plan(root)
            self.assertEqual(plan['state'], 'planned')
            self.assertFalse((root / 'work').exists())
            self.assertEqual(plan['commands'][0]['selected'], False)

    def test_setup_apply_records_optional_install_failure_without_throwing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'package.json').write_text('{}')
            (root / 'package-lock.json').write_text('{}')
            plan = SETUP.build_plan(root, install=True)

            def failed(*args, **kwargs):
                return subprocess.CompletedProcess(args[0], 1, stdout='', stderr='offline')

            result = SETUP.apply_plan(plan, root, install=True, runner=failed)
            self.assertEqual(result['state'], 'partial')
            self.assertTrue((root / 'work' / 'raw').is_dir())
            self.assertEqual(result['commandResults'][0]['returncode'], 1)

    def test_upgrade_check_reports_lock_missing_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = UPGRADE.compare(Path(tmp) / 'missing.json', Path(tmp), lock_module=mock.Mock())
        self.assertEqual(result['state'], 'lock_missing')
        self.assertTrue(result['recommendedActions'])

    def test_upgrade_check_detects_inventory_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / 'toolchain.lock.json'
            inventory = {'node': {'version': 'v1'}}
            lock.write_text(json.dumps({'schemaVersion': 1, 'inventory': inventory}))
            module = mock.Mock()
            module.collect_inventory.return_value = {'node': {'version': 'v2'}}
            result = UPGRADE.compare(lock, root, lock_module=module)
        self.assertEqual(result['state'], 'changes_available')
        self.assertEqual(result['changes'][0]['path'], '$.inventory.node.version')

    def test_uninstall_preview_never_deletes_and_apply_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'work' / 'raw'
            target.mkdir(parents=True)
            (target / 'raw.json').write_text('{}')
            plan = UNINSTALL.build_plan(root)
            self.assertTrue(next(item for item in plan['entries'] if item['path'] == 'work/raw')['exists'])
            self.assertTrue(target.exists())
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                UNINSTALL.main(['--root', str(root), '--apply'])
            self.assertTrue(target.exists())
            result = UNINSTALL.apply_plan(plan, root)
            self.assertEqual(result['state'], 'applied')
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
