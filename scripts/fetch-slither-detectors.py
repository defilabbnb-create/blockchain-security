#!/usr/bin/env python3
"""从 Slither 仓库读取各检测器的 WIKI / WIKI_TITLE / IMPACT / CONFIDENCE。

用途：让漏洞库里的 patterns.slitherDetector 取仓库里真实声明的标识，
而不是凭记忆填写。只读取文本，不执行任何分析。
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

TREE_API = "https://api.github.com/repos/crytic/slither/git/trees/master?recursive=1"
COMMIT_API = "https://api.github.com/repos/crytic/slither/commits/master"
RAW = "https://raw.githubusercontent.com/crytic/slither/{sha}/{path}"
OUT = Path("/tmp/slither-detectors.json")
UA = "vulnerability-library-provenance"
SKIP = {"__init__.py", "abstract_detector.py", "all_detectors.py"}


def fetch(url: str, timeout: float = 10.0, attempts: int = 3) -> tuple[int, str]:
    """带退避重试的 GET；raw.githubusercontent 偶发限流，重试即可恢复。"""
    for attempt in range(attempts):
        request = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return 404, ""
            time.sleep(0.6 * (attempt + 1))
        except Exception:  # noqa: BLE001 - 探测失败统一按不可读处理
            time.sleep(0.6 * (attempt + 1))
    return 0, ""


def classify(text: str) -> str | None:
    """把 DetectorClassification 常量引用还原成小写严重度名。"""
    match = re.search(
        r'IMPACT\s*=\s*DetectorClassification\.([A-Z_]+)', text
    )
    if match:
        return match.group(1).lower()
    return None


def parse_detector(path: str, text: str) -> dict:
    if not text or "WIKI_TITLE" not in text:
        return {"path": path, "readable": False}
    detector: dict = {"path": path, "readable": True, "repo": "crytic/slither"}
    title = re.search(r'WIKI_TITLE\s*=\s*"((?:[^"\\]|\\.)*)"', text)
    if title:
        detector["wikiTitle"] = title.group(1)
    wiki = re.search(r'WIKI\s*=\s*"((?:[^"\\]|\\.)*)"', text)
    if wiki:
        detector["wiki"] = wiki.group(1)
    detector["impact"] = classify(text)
    confidence = re.search(
        r'CONFIDENCE\s*=\s*DetectorClassification\.([A-Z_]+)', text
    )
    if confidence:
        detector["confidence"] = confidence.group(1).lower()
    slugs = dict(re.findall(
        r'WIKI_TITLE\s*=\s*"((?:[^"\\]|\\.)*)"\s*\n\s*WIKI\s*=\s*"([^"]+)"', text
    ))
    return detector


def main() -> None:
    tree_status, tree_body = fetch(TREE_API)
    tree = json.loads(tree_body)["tree"] if tree_status == 200 else []
    paths = sorted(
        item["path"]
        for item in tree
        if item["path"].startswith("slither/detectors/")
        and item["path"].endswith(".py")
        and item["path"].rsplit("/", 1)[-1] not in SKIP
    )
    if not paths:
        print("无法读取检测器清单，tree status =", tree_status)
        raise SystemExit(1)

    commit_status, commit_body = fetch(COMMIT_API)
    sha = json.loads(commit_body).get("sha") if commit_status == 200 else None
    if not sha:
        print("无法解析 slither 提交 SHA")
        raise SystemExit(1)

    def load(path: str) -> dict:
        _, text = fetch(RAW.format(sha=sha, path=path))
        return parse_detector(path, text)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(load, paths))

    readable = [item for item in results if item.get("readable")]
    # WIKI 常量写的是完整 wiki URL，取其 # 锚点作为命令行可用的检测器标识。
    detectors: dict[str, dict] = {}
    for item in readable:
        name = item.get("wiki") or ""
        slug = name.rsplit("#", 1)[-1] if "#" in name else name
        if not slug:
            slug = item["path"].rsplit("/", 1)[-1][:-3]
        item["slug"] = slug
        detectors.setdefault(slug, item)

    payload = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "repo": "crytic/slither",
        "commit": sha,
        "fileCount": len(results),
        "readableCount": len(readable),
        "detectorCount": len(detectors),
        "detectors": dict(sorted(detectors.items())),
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        "写入", OUT, "文件数", len(results),
        "可读", len(readable), "检测器", len(detectors), "commit", sha,
    )
    for name, item in payload["detectors"].items():
        print(
            f"{name:44s} impact={str(item.get('impact')):14s} "
            f"conf={str(item.get('confidence')):12s} {item.get('wikiTitle', '')}"
        )


if __name__ == "__main__":
    main()