import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("project_import", ROOT / "scripts" / "project_import.py")
IMPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORT)


class ProjectImportTests(unittest.TestCase):
    def test_import_archives_sources_and_records_git_without_executing_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            (root / "contracts").mkdir()
            (root / "contracts" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
            (root / "test").mkdir()
            (root / "test" / "Vault.t.sol").write_text("contract VaultTest {}", encoding="utf-8")
            (root / "package.json").write_text('{"scripts":{"test":"throw new Error(\\"must not run\\")"}}', encoding="utf-8")
            (root / ".env").write_text("PRIVATE_KEY=secret", encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignored.sol").write_text("contract Ignored {}", encoding="utf-8")
            (root / "work").mkdir()
            (root / "work" / "old.json").write_text("{}", encoding="utf-8")
            output = root / "work" / "import.json"
            archive = root / "evidence"
            with mock.patch.object(IMPORT, "_git_snapshot", return_value={"available": False, "reason": "test"}):
                report = IMPORT.import_project(root, output=output, archive_root=archive, project_id="fixture")

            self.assertFalse(report["complete"])
            self.assertEqual(report["projectId"], "fixture")
            self.assertEqual(report["fileCounts"]["included"], 3)
            self.assertEqual(report["fileCounts"]["byKind"], {"config": 1, "source": 1, "test": 1})
            paths = {item["path"] for item in report["files"] if item["included"]}
            self.assertEqual(paths, {"contracts/Vault.sol", "package.json", "test/Vault.t.sol"})
            self.assertTrue(any("secret-like" in item["reason"] for item in report["errors"]))
            self.assertTrue(output.is_file())
            archived = [item["archive"] for item in report["files"] if item["included"]]
            self.assertTrue(all(IMPORT._PROVENANCE.verify_archive(item) for item in archived))
            self.assertFalse((root / "package.json").read_bytes() == b"executed")

    def test_import_is_partial_when_limits_skip_files_and_keeps_reasons(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.sol").write_text("a", encoding="utf-8")
            (root / "b.sol").write_text("b", encoding="utf-8")
            report = IMPORT.import_project(
                root, output=Path(tmp) / "report.json", archive_root=Path(tmp) / "archive",
                project_id="limits", max_file_bytes=1, max_total_bytes=1, max_files=2,
            )
            self.assertFalse(report["complete"])
            self.assertTrue(report["limits"]["limitReached"])
            self.assertEqual(report["fileCounts"]["included"], 1)
            self.assertEqual(report["fileCounts"]["bytes"], 1)
            self.assertGreaterEqual(report["errorCount"], 1)
            self.assertTrue(any("max_total_bytes" in item["reason"] for item in report["errors"]))

    def test_import_rejects_invalid_project_id_and_file_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "project-id"):
                IMPORT.import_project(root, project_id="../escape")
            with self.assertRaisesRegex(ValueError, "max_file_bytes"):
                IMPORT.import_project(root, max_file_bytes=0)

    def test_default_project_id_is_stable_for_same_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = IMPORT.import_project(root, output=root / "work" / "one.json", archive_root=root / "evidence-a")
            second = IMPORT.import_project(root, output=root / "work" / "two.json", archive_root=root / "evidence-b")
            self.assertEqual(first["projectId"], second["projectId"])
            self.assertEqual(first["sourceFingerprint"], second["sourceFingerprint"])

    def test_empty_git_repository_is_a_valid_snapshot_without_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            import subprocess
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            report = IMPORT.import_project(root, output=root / "work" / "import.json", archive_root=root / "evidence")
            self.assertTrue(report["complete"])
            self.assertTrue(report["git"]["available"])
            self.assertEqual(report["git"]["commitState"], "no_commit_yet")
            self.assertEqual(report["git"]["errors"], [])

    def test_existing_output_cannot_replace_source_or_a_prior_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "Vault.sol"
            original = b"contract Vault {}"
            source.write_bytes(original)
            with self.assertRaisesRegex(ValueError, "output already exists"):
                IMPORT.import_project(root, output=source)
            self.assertEqual(source.read_bytes(), original)
            # A file created after the initial validation is also preserved.
            with self.assertRaises(FileExistsError):
                IMPORT._atomic_json(source, {"replacement": True})
            self.assertEqual(source.read_bytes(), original)

    def test_env_variants_are_omitted_with_explicit_partial_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name in [".env.staging", ".env.test.local", "secrets.yaml"]:
                (root / name).write_text("SYNTHETIC_FIXTURE_TOKEN=not-a-real-secret")
            (root / ".env.example").write_text("TOKEN=placeholder")
            report = IMPORT.import_project(root)
            self.assertFalse(report["complete"])
            self.assertEqual([item["path"] for item in report["files"]], [".env.example"])
            self.assertEqual({item["path"] for item in report["errors"]},
                             {".env.staging", ".env.test.local", "secrets.yaml"})

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_fifo_does_not_block_or_enter_the_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            os.mkfifo(root / "input.pipe")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/project_import.py"), str(root)],
                capture_output=True, text=True, timeout=3,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads((root / "work/project-import.json").read_text())
            self.assertEqual(report["fileCounts"]["included"], 0)
            self.assertEqual(report["errors"][0]["reason"], "not a regular file")

    def test_file_growth_between_stat_and_read_cannot_exceed_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "Vault.sol"
            source.write_bytes(b"x")
            reader = IMPORT._read_regular_file
            def grow_before_open(project, path, limit):
                source.write_bytes(b"x" * 9)
                return reader(project, path, limit)
            with mock.patch.object(IMPORT, "_read_regular_file", side_effect=grow_before_open):
                report = IMPORT.import_project(root, max_file_bytes=4, max_total_bytes=4)
            self.assertFalse(report["complete"])
            self.assertTrue(report["limits"]["limitReached"])
            self.assertEqual(report["fileCounts"]["bytes"], 0)
            self.assertEqual(report["fileCounts"]["archived"], 0)

    def test_file_and_directory_links_are_reported_as_coverage_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            root = base / "project"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (outside / "C.sol").write_text("contract C {}")
            (root / "linked-directory").symlink_to(outside, target_is_directory=True)
            (root / "linked.sol").symlink_to(outside / "C.sol")
            report = IMPORT.import_project(root)
            self.assertFalse(report["complete"])
            self.assertEqual(report["fileCounts"]["included"], 0)
            self.assertEqual({item["path"] for item in report["errors"]},
                             {"linked-directory", "linked.sol"})
            self.assertTrue(all(item["reason"] == "symbolic link omitted" for item in report["errors"]))

    def test_scan_budget_counts_skipped_entries_and_stops_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for index in range(5):
                (root / (".env." + str(index))).write_text("fixture")
            report = IMPORT.import_project(root, max_files=2)
            self.assertEqual(report["fileCounts"]["seen"], 2)
            self.assertEqual(report["fileCounts"]["skipped"], 2)
            self.assertTrue(report["limits"]["limitReached"])
            self.assertFalse(report["complete"])
            self.assertTrue(any("remaining entries not visited" in row["reason"] for row in report["errors"]))

    def test_git_status_preserves_worktree_status_and_rename_paths(self):
        responses = [("true\n", None), ("a" * 40 + "\n", None), ("main\n", None),
                     (" M file with spaces.sol\0R  renamed.sol\0old.sol\0?? new.sol\0", None)]
        with mock.patch.object(IMPORT, "_run_git", side_effect=responses):
            git = IMPORT._git_snapshot(ROOT)
        self.assertEqual(git["status"], [
            {"status": " M", "path": "file with spaces.sol"},
            {"status": "R ", "path": "renamed.sol", "oldPath": "old.sol"},
            {"status": "??", "path": "new.sol"},
        ])

    def test_unverified_archive_is_never_counted_as_included(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "C.sol").write_text("contract C {}")
            with mock.patch.object(IMPORT._PROVENANCE, "verify_archive", return_value=False):
                report = IMPORT.import_project(root)
            self.assertFalse(report["complete"])
            self.assertEqual(report["fileCounts"]["included"], 0)
            self.assertEqual(report["fileCounts"]["archived"], 0)
            self.assertFalse(report["files"][0]["included"])
            self.assertIn("verification failed", report["files"][0]["error"])

    def test_archive_root_cannot_hide_the_entire_input_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            root = base / "project"
            root.mkdir()
            for archive in [root, base]:
                with self.subTest(archive=archive), self.assertRaisesRegex(ValueError, "must not contain"):
                    IMPORT.import_project(root, archive_root=archive)

    def test_directory_scan_failure_prevents_complete_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            def fail_walk(*args, **kwargs):
                kwargs["onerror"](PermissionError(13, "denied", str(root / "unreadable")))
                return iter(())
            with mock.patch.object(IMPORT.os, "walk", side_effect=fail_walk):
                report = IMPORT.import_project(root)
            self.assertFalse(report["complete"])
            self.assertIn("directory scan failed", report["errors"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
