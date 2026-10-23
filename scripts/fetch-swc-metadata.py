#!/usr/bin/env python3
"""从固定提交抓取 SWC Registry 条目元数据，并逐个探测公开 URL 可达性。

只读取文本，不执行任何合约或 EVM 调用。超时固定 5 秒，失败不阻塞。
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

REPO = "SmartContractSecurity/SWC-registry"
COMMIT = "1b6227074ecd180b374e4844153afdda0332f979"
RAW = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/entries/docs"
TIMEOUT = 5.0
UA = "Mozilla/5.0 (vulnerability-library-provenance)"

OUT = Path("/tmp/swc-metadata.json")


def fetch(url: str) -> dict:
    """返回访问记录：状态码、是否可读、访问方式与耗时。"""
    started = time.monotonic()
    record = {
        "url": url,
        "method": "urllib.request",
        "httpStatus": None,
        "readable": False,
        "error": None,
        "durationMs": None,
    }
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            payload = response.read()
            record["httpStatus"] = response.status
            record["readable"] = True
            record["byteLength"] = len(payload)
            record["contentType"] = response.headers.get("Content-Type")
            record["body"] = payload.decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        record["httpStatus"] = error.code
        record["error"] = f"HTTPError: {error.reason}"
    except Exception as error:  # noqa: BLE001 - 网络异常统一记录，不阻塞
        record["error"] = f"{type(error).__name__}: {error}"
    record["durationMs"] = int((time.monotonic() - started) * 1000)
    return record


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}


def parse_markdown(record: dict) -> dict:
    """从 SWC 条目 Markdown 中抽取标题、严重度、状态与 CWE。"""
    body = record.get("body") or ""
    lines = body.splitlines()
    result = {
        "title": None,
        "severity": None,
        "statusRaw": None,
        "cwe": None,
        "url": None,
    }
    for line in lines:
        text = line.strip()
        if text.startswith("# ") and result["title"] is None:
            result["title"] = text[2:].strip()
        if text.startswith("- **Severity:**"):
            value = text.split(":", 1)[1].strip().strip("*").strip()
            result["severity"] = SEVERITY_MAP.get(value.lower(), value.lower() or None)
        if text.startswith("- **Status:**"):
            result["statusRaw"] = text.split(":", 1)[1].strip().strip("*").strip()
        if text.startswith("- **CWE:**"):
            value = text.split(":", 1)[1].strip().strip("*").strip()
            match = re.search(r"CWE-(\d+)", value)
            result["cwe"] = f"CWE-{match.group(1)}" if match else value or None
        if text.startswith("* [pdf]"):
            continue
    return result


def main() -> None:
    ids = list(range(101, 144))
    # 先抓固定提交内容（权威来源），再并行探测公开文档站 URL。
    content_records = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for ident, record in zip(ids, pool.map(lambda i: fetch(f"{RAW}/SWC-{i}.md"), ids)):
            content_records[f"SWC-{ident}"] = record

    site_records = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        urls = [f"https://swcregistry.io/docs/SWC-{i}/" for i in ids]
        for ident, record in zip(ids, pool.map(fetch, urls)):
            site_records[f"SWC-{ident}"] = record

    entries = {}
    for ident in ids:
        key = f"SWC-{ident}"
        parsed = parse_markdown(content_records[key])
        parsed["rawUrl"] = f"{RAW}/SWC-{key}.md"
        parsed["rawHttpStatus"] = content_records[key]["httpStatus"]
        parsed["rawReadable"] = content_records[key]["readable"]
        parsed["rawDurationMs"] = content_records[key]["durationMs"]
        parsed["rawError"] = content_records[key]["error"]
        parsed["siteUrl"] = site_records[key]["url"]
        parsed["siteHttpStatus"] = site_records[key]["httpStatus"]
        parsed["siteReadable"] = site_records[key]["readable"]
        parsed["siteDurationMs"] = site_records[key]["durationMs"]
        parsed["siteError"] = site_records[key]["error"]
        entries[key] = parsed

    payload = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "commit": COMMIT,
        "count": len(entries),
        "entries": entries,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print("写入", OUT)
    for key, item in entries.items():
        print(
            key,
            "|", item["title"],
            "| severity=", item["severity"],
            "| status=", item["statusRaw"],
            "| cwe=", item["cwe"],
            "| raw=", item["rawHttpStatus"],
            "| site=", item["siteHttpStatus"],
        )


if __name__ == "__main__":
    main()