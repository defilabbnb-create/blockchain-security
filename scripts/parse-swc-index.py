#!/usr/bin/env python3
"""从 SWC Registry 固定提交的 index.md 抽取权威标题与 CWE 映射。

index.md 是该仓库自带的总表，包含每个 SWC 的 Title 与 Relationships(CWE)。
只读取文本，不执行任何合约或 EVM 调用。
"""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

COMMIT = "1b6227074ecd180b374e4844153afdda0332f979"
INDEX_URL = f"https://raw.githubusercontent.com/SmartContractSecurity/SWC-registry/{COMMIT}/entries/index.md"
README_URL = f"https://raw.githubusercontent.com/SmartContractSecurity/SWC-registry/{COMMIT}/README.md"
OUT = Path("/tmp/swc-index-parsed.json")


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "vulnerability-library-provenance"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read().decode("utf-8", "replace")


def main() -> None:
    body = fetch(INDEX_URL)
    readme = fetch(README_URL)
    entries = {}
    for line in body.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        ident = re.search(r"SWC-(\d+)", cells[0])
        title = cells[1].strip()
        cwe = re.search(r"CWE-(\d+)", cells[2])
        if not ident or not title or set(title) <= {"-", " "}:
            continue
        entries[f"SWC-{ident.group(1)}"] = {
            "title": title,
            "cwe": f"CWE-{cwe.group(1)}" if cwe else None,
        }
    payload = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "commit": COMMIT,
        "indexUrl": INDEX_URL,
        "readmeUrl": README_URL,
        "registryStatusLine": readme.splitlines()[0].strip(),
        "count": len(entries),
        "entries": dict(sorted(entries.items(), key=lambda item: int(item[0].split("-")[1]))),
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print("写入", OUT, "条目数", len(entries))
    for key, item in payload["entries"].items():
        print(key, "|", item["title"], "|", item["cwe"])


if __name__ == "__main__":
    main()