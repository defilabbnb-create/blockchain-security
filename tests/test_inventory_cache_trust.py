"""Tests for cache trust in the SWC vulnerability inventory.

The property locked here is that trust comes from content, never from a file
merely existing or parsing.  A truncated download, an empty file, a stub with
no title and a cache that has been partially emptied all load without raising,
so without a content gate each of them would be reported exactly like an entry
whose text was really read at the pinned commit.  The second property is that
prose counts describe the run that produced them: an empty cache must say it is
empty instead of reusing a previous run's total.

These tests assert on the failure modes themselves, so reverting any one of
the guards makes a named test fail rather than quietly changing a number.
"""
from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "scripts" / "vulnerability_inventory.py"

COMMIT = "1b6227074ecd"


def _load_module():
    spec = importlib.util.spec_from_file_location("vuln_inventory_mod", INVENTORY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INV = _load_module()
REAL_CACHE = ROOT / "work" / "vulnerability-inventory-cache"


def _entry_doc() -> str:
    """One real cached entry document, used as the known-good fixture."""
    return (REAL_CACHE / f"{COMMIT}-entries_docs_SWC-100.md").read_text(encoding="utf-8")


def _index_doc(*numbers: int) -> str:
    return "".join(f"[SWC-{n}](./docs/SWC-{n}.md)\n" for n in numbers)


class CacheTrustTests(unittest.TestCase):
    """A cache file earns verified:true only by passing the content gate."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="inventory-cache-trust-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._original_cache = INV.CACHE
        INV.CACHE = self.tmp
        self.addCleanup(setattr, INV, "CACHE", self._original_cache)

    def _write(self, name: str, body: str) -> Path:
        path = self.tmp / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_intact_entry_document_is_verified(self):
        """The gate must not reject good data, or the check is useless."""
        self._write(f"{COMMIT}-entries_docs_SWC-100.md", _entry_doc())
        entries = INV._entries_from_cache(COMMIT)
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["verified"],
                        f"完整条目文档应通过内容校验，实际：{entries[0]}")
        self.assertEqual(entries[0]["title"], "Function Default Visibility")

    def test_entry_with_cut_off_title_is_not_verified(self):
        """A document long enough to clear every other gate, but whose title
        heading stops mid-word: only the title-length check can catch it.
        """
        doc = _entry_doc()
        broken = doc.replace("# Title\n\nFunction Default Visibility",
                            "# Title\n\nSWC-", 1)
        self._write(f"{COMMIT}-entries_docs_SWC-100.md", broken)
        entries = INV._entries_from_cache(COMMIT)
        self.assertGreater(len(broken.encode("utf-8")), INV.MIN_ENTRY_BYTES,
                           "前置条件：本例必须已通过字节下限，才能单独检验标题长度")
        self.assertIn("## Description", broken, "前置条件：必需章节必须仍在")
        self.assertEqual(broken.count("```") % 2, 0, "前置条件：围栏必须配平")
        self.assertFalse(entries[0]["verified"],
                         f"被截断的标题仍被当作已验证：{entries[0]}")
        self.assertIn("标题", entries[0]["reason"])

    def test_truncated_entry_is_not_verified(self):
        """A file cut mid-write must not read as a checked entry."""
        self._write(f"{COMMIT}-entries_docs_SWC-100.md", "# Title\n\nSWC-")
        entries = INV._entries_from_cache(COMMIT)
        self.assertFalse(entries[0]["verified"], "截断的条目被标成了已验证")
        self.assertIn("字节", entries[0]["reason"])

    def test_zero_byte_entry_is_not_verified(self):
        self._write(f"{COMMIT}-entries_docs_SWC-102.md", "")
        entries = INV._entries_from_cache(COMMIT)
        self.assertFalse(entries[0]["verified"], "0 字节条目被标成了已验证")
        self.assertIn("空", entries[0]["reason"])

    def test_entry_without_title_is_not_verified(self):
        """A body large enough to clear the byte floor but with no heading is
        still not a registry entry, so the byte floor must not be the only gate.
        """
        self._write(f"{COMMIT}-entries_docs_SWC-101.md",
                    "prose with no Title heading\n" * 80)
        entries = INV._entries_from_cache(COMMIT)
        self.assertFalse(entries[0]["verified"], "无标题条目被标成了已验证")
        self.assertIn("Title", entries[0]["reason"])

    def test_entry_missing_required_section_is_not_verified(self):
        """Cutting a document so all headings remain but a section is gone."""
        doc = _entry_doc()
        stripped = doc.replace("## Remediation", "## Appendix", 1)
        self._write(f"{COMMIT}-entries_docs_SWC-100.md", stripped)
        entries = INV._entries_from_cache(COMMIT)
        self.assertFalse(entries[0]["verified"], "缺章节的条目被标成了已验证")
        self.assertIn("Remediation", entries[0]["reason"])

    def test_entry_cut_inside_code_fence_is_not_verified(self):
        """Truncation inside a fenced block keeps every heading, so only the
        unbalanced-fence check can catch it.
        """
        lines = _entry_doc().split("\n")
        self._write(f"{COMMIT}-entries_docs_SWC-100.md",
                    "\n".join(lines[:len(lines) // 2]))
        entries = INV._entries_from_cache(COMMIT)
        self.assertFalse(entries[0]["verified"], "围栏不成对的条目被标成了已验证")
        self.assertIn("围栏", entries[0]["reason"])

    def test_entries_missing_from_cache_are_reported_not_silently_dropped(self):
        """A trimmed cache must be visible as incomplete."""
        self._write(f"{COMMIT}-entries_index.md", _index_doc(100, 101, 102))
        self._write(f"{COMMIT}-entries_docs_SWC-100.md", _entry_doc())
        entries = INV._entries_from_cache(COMMIT)
        ids = {item["id"]: item for item in entries}
        self.assertEqual(set(ids), {"SWC-100", "SWC-101", "SWC-102"},
                         "index 列出的三个条目只应报出两个")
        self.assertTrue(ids["SWC-100"]["verified"])
        for missing in ("SWC-101", "SWC-102"):
            self.assertFalse(ids[missing]["verified"],
                             f"{missing} 已从缓存消失却被当作已验证")
            self.assertIn("缓存", ids[missing]["reason"])

    def test_damaged_entry_is_not_counted_twice_as_missing(self):
        """A corrupt file is already reported as corrupt; it must not also be
        listed as absent, or the entry count overstates how many are broken.
        """
        self._write(f"{COMMIT}-entries_index.md", _index_doc(100, 101))
        self._write(f"{COMMIT}-entries_docs_SWC-100.md", "# Title\n\nSWC-")
        self._write(f"{COMMIT}-entries_docs_SWC-101.md", _entry_doc())
        entries = INV._entries_from_cache(COMMIT)
        ids = [item["id"] for item in entries]
        self.assertEqual(len(ids), len(set(ids)), f"同一编号被重复计入：{ids}")

    def test_unparsable_filename_is_reported_instead_of_crashing_the_sort(self):
        self._write(f"{COMMIT}-entries_docs_SWC-abc.md", _entry_doc())
        entries = INV._entries_from_cache(COMMIT)
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]["verified"], "文件名不可解析的缓存被标成了已验证")
        self.assertIn("编号", entries[0]["reason"])

    def test_report_counts_split_verified_from_unverified(self):
        self._write(f"{COMMIT}-entries_index.md", _index_doc(100, 101))
        self._write(f"{COMMIT}-entries_docs_SWC-100.md", _entry_doc())
        self._write(f"{COMMIT}-entries_docs_SWC-101.md", "")
        swc = INV.build(offline=True)["swc"]
        self.assertEqual(swc["entryCount"], 2)
        self.assertEqual(swc["verifiedCount"], 1)
        self.assertEqual(swc["unverifiedCount"], 1)
        self.assertEqual(swc["unverifiedIds"], ["SWC-101"])

    def test_verified_count_counts_only_verified_rows(self):
        """`verifiedCount` has to be a count of verified rows in its own right.

        Re-deriving it as `entryCount - unverifiedCount` looks equivalent and
        would stay that way until a row appears that is neither verified nor
        listed as unverified, at which point the two would disagree silently.
        """
        self._write(f"{COMMIT}-entries_index.md", _index_doc(100, 101))
        self._write(f"{COMMIT}-entries_docs_SWC-100.md", _entry_doc())
        self._write(f"{COMMIT}-entries_docs_SWC-101.md", "no title\n" * 60)
        report = INV.build(offline=True)
        swc = report["swc"]
        actual = sum(1 for item in swc["entries"] if item.get("verified"))
        self.assertEqual(swc["verifiedCount"], actual,
                         "verifiedCount 与实际 verified 行数不一致")
        self.assertEqual(swc["verifiedCount"] + swc["unverifiedCount"],
                         swc["entryCount"],
                         "条目总数应等于已验证与未验证之和")


class ProseCountsTests(unittest.TestCase):
    """Reported prose must describe this run, not a previous one."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="inventory-empty-cache-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._original_cache = INV.CACHE
        INV.CACHE = self.tmp
        self.addCleanup(setattr, INV, "CACHE", self._original_cache)

    def test_empty_cache_does_not_claim_entries_were_checked(self):
        swc = INV.build(offline=True)["swc"]
        self.assertEqual(swc["entryCount"], 0)
        self.assertNotIn("37", swc["severityNote"],
                         f"空缓存的文案仍在引用上一次的条目数：{swc['severityNote']}")
        self.assertIn("未取得任何 SWC 条目", swc["severityNote"])

    def test_empty_cache_reports_no_verified_entries(self):
        swc = INV.build(offline=True)["swc"]
        self.assertEqual(swc["verifiedCount"], 0,
                         "空缓存却报告了已验证条目")
        self.assertEqual(swc["unverifiedCount"], 0)

    def test_id_range_note_uses_the_index_that_was_actually_read(self):
        """Without an index the total cannot be checked, so it must not be quoted."""
        swc = INV.build(offline=True)["swc"]
        self.assertIn("未能读取", swc["idRangeNote"])

    def test_severity_note_counts_match_the_entries_present(self):
        (self.tmp / f"{COMMIT}-entries_index.md").write_text(
            _index_doc(100, 101), encoding="utf-8")
        (self.tmp / f"{COMMIT}-entries_docs_SWC-100.md").write_text(
            _entry_doc(), encoding="utf-8")
        (self.tmp / f"{COMMIT}-entries_docs_SWC-101.md").write_text(
            "# Title\n\nSWC-", encoding="utf-8")
        swc = INV.build(offline=True)["swc"]
        self.assertIn("1 个条目正文均无 Severity 字段", swc["severityNote"])
        self.assertIn("条目总数 2", swc["severityNote"])

    def test_all_entries_unusable_says_so(self):
        (self.tmp / f"{COMMIT}-entries_docs_SWC-100.md").write_text(
            "no title at all\n" * 60, encoding="utf-8")
        swc = INV.build(offline=True)["swc"]
        self.assertEqual(swc["verifiedCount"], 0)
        self.assertIn("没有任何一个通过条目文档内容校验", swc["severityNote"])

    def test_unverified_entries_carry_a_reason_and_are_printed(self):
        (self.tmp / f"{COMMIT}-entries_docs_SWC-100.md").write_text(
            "", encoding="utf-8")
        report = INV.build(offline=True)
        self.assertTrue(report["swc"]["unverifiedReasons"])
        for item in report["swc"]["entries"]:
            if not item["verified"]:
                self.assertTrue(item.get("reason"),
                                f"{item['id']} 未验证却没有说明原因")


class NetworkEntryTests(unittest.TestCase):
    """The same content gate applies to a freshly fetched document."""

    def test_validate_entry_document_rejects_none(self):
        self.assertEqual(INV._validate_entry_document(None),
                         "条目在固定提交上读取失败")

    def test_validate_entry_document_accepts_a_real_entry(self):
        self.assertIsNone(INV._validate_entry_document(_entry_doc()))

    def test_validate_entry_document_rejects_whitespace_only(self):
        self.assertIn("空", INV._validate_entry_document("   \n\n  "))


class RealCacheTests(unittest.TestCase):
    """The gate must hold on the cache this repository actually ships."""

    def test_every_cached_entry_document_passes_the_gate(self):
        """If the gate rejects a genuine entry the report silently drops real
        coverage, which is as bad as accepting a corrupt one.
        """
        commit = INV._pinned_swc_commit()
        self.assertIsNotNone(commit, "找不到固定的 SWC 提交")
        INV.CACHE = REAL_CACHE
        entries = INV._entries_from_cache(commit[0])
        self.assertEqual(len(entries), 37, f"实际缓存条目数变了：{len(entries)}")
        unverified = [item for item in entries if not item["verified"]]
        self.assertEqual(unverified, [], f"真实缓存里有条目未通过校验：{unverified}")

    def test_offline_report_still_separates_counts_from_claims(self):
        commit = INV._pinned_swc_commit()
        self.assertIsNotNone(commit)
        INV.CACHE = REAL_CACHE
        try:
            swc = INV.build(offline=True)["swc"]
        finally:
            INV.CACHE = REAL_CACHE
        self.assertEqual(swc["verifiedCount"], swc["entryCount"])
        self.assertEqual(swc["unverifiedCount"], 0)
        self.assertIn("条目总数 37", swc["severityNote"])


if __name__ == "__main__":
    unittest.main()