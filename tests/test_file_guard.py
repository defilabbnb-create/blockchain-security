"""scripts/file_guard.py 的行为测试。全部在临时目录里运行，不读写真实仓库的受保护文件。"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import file_guard as G


def make_repo(files=None, protected=None):
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    files = files if files is not None else {"a.py": "x = 1\n", "b.py": "y = 2\n"}
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "config").mkdir(exist_ok=True)
    (root / "config/protected-files.json").write_text(
        json.dumps({"version": 1, "protected": protected if protected is not None else ["a.py", "b.py"]}), encoding="utf-8")
    return tmp, root


def statuses(report):
    return {row["path"]: row["status"] for row in report["rows"]}


def run_cli(root, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = G.main(["--root", str(root), *argv])
    return code, out.getvalue(), err.getvalue()


class SnapshotAndCheck(unittest.TestCase):
    def test_unchanged_files_pass(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            report = G.check(root, "t1")
            self.assertTrue(report["ok"])
            self.assertEqual(statuses(report), {"a.py": "ok", "b.py": "ok"})

    def test_unacknowledged_edit_is_drift(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "a.py").write_text("x = 2\n", encoding="utf-8")
            report = G.check(root, "t1")
            self.assertFalse(report["ok"])
            self.assertEqual(statuses(report), {"a.py": "drift", "b.py": "ok"})

    def test_same_size_edit_is_still_drift(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            before = (root / "a.py").stat()
            (root / "a.py").write_text("x = 9\n", encoding="utf-8")  # 大小相同
            os.utime(root / "a.py", ns=(before.st_atime_ns, before.st_mtime_ns))  # 连 mtime 都还原
            self.assertEqual(statuses(G.check(root, "t1"))["a.py"], "drift")

    def test_syntax_damage_is_reported_even_when_acked_content_matches(self):
        tmp, root = make_repo()
        with tmp:
            (root / "a.py").write_text("def f(:\n", encoding="utf-8")  # 基线本身就是坏的
            G.snapshot(root, "t1")
            report = G.check(root, "t1")
            self.assertFalse(report["ok"])
            self.assertEqual(statuses(report)["a.py"], "syntax_error")

    def test_drift_that_also_breaks_syntax_says_so(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "a.py").write_text("else:\n    pass\n", encoding="utf-8")
            row = next(r for r in G.check(root, "t1")["rows"] if r["path"] == "a.py")
            self.assertEqual(row["status"], "drift")
            self.assertIn("语法损坏", row["detail"])

    def test_mtime_only_change_is_a_notice_not_a_failure(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            stat = (root / "a.py").stat()
            os.utime(root / "a.py", ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))
            report = G.check(root, "t1")
            self.assertTrue(report["ok"])
            self.assertEqual(statuses(report)["a.py"], "touched")

    def test_deleted_file(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "b.py").unlink()
            report = G.check(root, "t1")
            self.assertFalse(report["ok"])
            self.assertEqual(statuses(report)["b.py"], "deleted")

    def test_new_file_matching_glob_is_flagged(self):
        tmp, root = make_repo({"core/one.py": "a = 1\n"}, protected=["core/*.py"])
        with tmp:
            G.snapshot(root, "t1")
            (root / "core/two.py").write_text("b = 2\n", encoding="utf-8")
            report = G.check(root, "t1")
            self.assertFalse(report["ok"])
            self.assertEqual(statuses(report), {"core/one.py": "ok", "core/two.py": "new_match"})

    def test_recursive_glob(self):
        tmp, root = make_repo({"core/deep/one.py": "a = 1\n", "core/two.py": "b = 1\n"}, protected=["core/**/*.py"])
        with tmp:
            state = G.snapshot(root, "t1")
            self.assertEqual(sorted(state["files"]), ["core/deep/one.py", "core/two.py"])

    def test_glob_that_loses_all_files_is_flagged(self):
        tmp, root = make_repo({"core/one.py": "a = 1\n"}, protected=["core/*.py"])
        with tmp:
            G.snapshot(root, "t1")
            (root / "core/one.py").unlink()
            statuses_now = statuses(G.check(root, "t1"))
            self.assertEqual(statuses_now["core/one.py"], "deleted")
            self.assertEqual(statuses_now["core/*.py"], "pattern_unmatched")

    def test_non_python_file_has_no_syntax_status(self):
        tmp, root = make_repo({"cfg.json": "{not json"}, protected=["cfg.json"])
        with tmp:
            G.snapshot(root, "t1")
            row = G.check(root, "t1")["rows"][0]
            self.assertEqual(row["status"], "ok")
            self.assertIsNone(row["syntax"])


class Acknowledge(unittest.TestCase):
    def test_declared_edit_passes_and_undeclared_edit_is_still_caught(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "a.py").write_text("x = 2\n", encoding="utf-8")   # 自己的改动
            (root / "b.py").write_text("y = 3\n", encoding="utf-8")   # 别人的改动
            G.ack(root, "t1", ["a.py"])
            report = G.check(root, "t1")
            self.assertEqual(statuses(report), {"a.py": "ok", "b.py": "drift"})
            self.assertFalse(report["ok"])

    def test_edit_after_ack_is_caught(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "a.py").write_text("x = 2\n", encoding="utf-8")
            G.ack(root, "t1", ["a.py"])
            (root / "a.py").write_text("x = 3\n", encoding="utf-8")  # ack 之后又有人写
            self.assertEqual(statuses(G.check(root, "t1"))["a.py"], "drift")

    def test_ack_keeps_baseline_so_total_change_stays_visible(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "a.py").write_text("x = 2\n", encoding="utf-8")
            G.ack(root, "t1", ["a.py"])
            rows = {r["path"]: r for r in G.check(root, "t1")["rows"]}
            self.assertTrue(rows["a.py"]["changedFromBaseline"])
            self.assertFalse(rows["b.py"]["changedFromBaseline"])

    def test_ack_refuses_untracked_path(self):
        tmp, root = make_repo({"a.py": "x = 1\n", "c.py": "z = 1\n"}, protected=["a.py"])
        with tmp:
            G.snapshot(root, "t1")
            with self.assertRaisesRegex(G.GuardError, "ack_not_tracked"):
                G.ack(root, "t1", ["c.py"])

    def test_ack_refuses_to_bless_broken_python(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "a.py").write_text("def f(:\n", encoding="utf-8")
            with self.assertRaisesRegex(G.GuardError, "ack_syntax_error"):
                G.ack(root, "t1", ["a.py"])
            self.assertEqual(statuses(G.check(root, "t1"))["a.py"], "drift")  # 未登记，仍被监视
            G.ack(root, "t1", ["a.py"], allow_syntax_error=True)
            self.assertEqual(statuses(G.check(root, "t1"))["a.py"], "syntax_error")  # 显式放行后仍持续报语法问题

    def test_ack_requires_files(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            with self.assertRaisesRegex(G.GuardError, "ack_requires_files"):
                G.ack(root, "t1", [])

    def test_ack_records_history(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "a.py").write_text("x = 2\n", encoding="utf-8")
            G.ack(root, "t1", ["a.py"])
            state = json.loads((root / "work/file-guard/t1.json").read_text(encoding="utf-8"))
            self.assertEqual([h["event"] for h in state["history"]], ["snapshot", "ack"])
            self.assertNotEqual(state["history"][1]["files"][0]["from"], state["history"][1]["files"][0]["to"])


class RefusesToLieAboutScope(unittest.TestCase):
    def test_pattern_with_no_match_fails_snapshot(self):
        tmp, root = make_repo(protected=["a.py", "tpyo.py"])
        with tmp:
            with self.assertRaisesRegex(G.GuardError, "pattern_unmatched:tpyo.py"):
                G.snapshot(root, "t1")
            self.assertFalse((root / "work/file-guard/t1.json").exists())

    def test_existing_label_is_not_overwritten(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            before = (root / "work/file-guard/t1.json").read_bytes()
            (root / "a.py").write_text("x = 2\n", encoding="utf-8")
            with self.assertRaisesRegex(G.GuardError, "snapshot_exists"):
                G.snapshot(root, "t1")
            self.assertEqual((root / "work/file-guard/t1.json").read_bytes(), before)

    def test_check_without_snapshot_fails(self):
        tmp, root = make_repo()
        with tmp:
            with self.assertRaisesRegex(G.GuardError, "snapshot_missing"):
                G.check(root, "nope")

    def test_corrupt_state_fails_instead_of_passing(self):
        tmp, root = make_repo()
        with tmp:
            G.snapshot(root, "t1")
            (root / "work/file-guard/t1.json").write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(G.GuardError, "snapshot_corrupt"):
                G.check(root, "t1")
            (root / "work/file-guard/t1.json").write_text('{"version": 1, "files": []}', encoding="utf-8")
            with self.assertRaisesRegex(G.GuardError, "snapshot_corrupt"):
                G.check(root, "t1")

    def test_bad_labels_are_rejected(self):
        tmp, root = make_repo()
        with tmp:
            for label in ["", "../x", "a/b", ".hidden", "x" * 80, "a b"]:
                with self.assertRaisesRegex(G.GuardError, "label_invalid", msg=label):
                    G.snapshot(root, label)

    def test_bad_patterns_are_rejected(self):
        for pattern in ["", "   ", "/etc/passwd", "../outside.py", "a/../../b.py", "C:/x.py", "a\\b.py"]:
            with self.assertRaises(G.GuardError, msg=pattern):
                G.validate_pattern(pattern)

    def test_config_problems(self):
        tmp, root = make_repo()
        with tmp:
            cfg = root / "config/protected-files.json"
            for text, expected in [("{bad", "config_invalid"), ('{"version": 2, "protected": ["a.py"]}', "config_version_unsupported"),
                                   ('{"version": 1, "protected": []}', "config_protected_invalid"),
                                   ('{"version": 1, "protected": [1]}', "config_protected_invalid"),
                                   ('{"version": 1}', "config_protected_invalid")]:
                cfg.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(G.GuardError, expected, msg=text):
                    G.load_patterns(root)
            cfg.unlink()
            with self.assertRaisesRegex(G.GuardError, "config_missing"):
                G.load_patterns(root)

    def test_symlink_pointing_outside_root_is_refused(self):
        tmp, root = make_repo()
        outside = tempfile.TemporaryDirectory()
        with tmp, outside:
            target = Path(outside.name) / "secret.py"
            target.write_text("z = 1\n", encoding="utf-8")
            os.symlink(target, root / "link.py")
            (root / "config/protected-files.json").write_text(json.dumps({"version": 1, "protected": ["link.py"]}), encoding="utf-8")
            with self.assertRaisesRegex(G.GuardError, "path_escapes_root"):
                G.snapshot(root, "t1")


class CommandLine(unittest.TestCase):
    def test_exit_codes_follow_the_contract(self):
        tmp, root = make_repo()
        with tmp:
            self.assertEqual(run_cli(root, "snapshot", "--label", "t1")[0], 0)
            self.assertEqual(run_cli(root, "check", "--label", "t1")[0], 0)
            (root / "a.py").write_text("x = 2\n", encoding="utf-8")
            code, out, _ = run_cli(root, "check", "--label", "t1")
            self.assertEqual(code, 1)
            self.assertIn("drift", out)
            self.assertEqual(run_cli(root, "ack", "--label", "t1", "--files", "a.py")[0], 0)
            self.assertEqual(run_cli(root, "check", "--label", "t1")[0], 0)
            code, _, err = run_cli(root, "check", "--label", "missing")
            self.assertEqual(code, 2)
            self.assertIn("snapshot_missing", err)

    def test_json_output_is_parseable_and_carries_failure(self):
        tmp, root = make_repo()
        with tmp:
            run_cli(root, "snapshot", "--label", "t1")
            (root / "b.py").unlink()
            code, out, _ = run_cli(root, "--json", "check", "--label", "t1")
            self.assertEqual(code, 1)
            report = json.loads(out)
            self.assertFalse(report["ok"])
            self.assertEqual({r["path"]: r["status"] for r in report["rows"]}["b.py"], "deleted")

    def test_real_config_lists_the_two_guarded_generators(self):
        patterns = G.load_patterns(ROOT)
        self.assertIn("scripts/invariant_gen.py", patterns)
        self.assertIn("scripts/defi-campaign.py", patterns)


if __name__ == "__main__":
    unittest.main()
