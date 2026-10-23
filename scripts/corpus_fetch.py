#!/usr/bin/env python3
"""Fetch allowlisted, pinned Solidity examples into an independent v2 corpus.

This command only downloads text files and license metadata. It never imports,
installs, or executes repository code. Existing v1 and benchmark data are read
only for SHA-256 duplicate annotations.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / "scripts/corpus-source-allowlist.json"
OUTPUT = ROOT / "training-data/github-vulnerabilities-v2"
CACHE = ROOT / "work/corpus-fetch-cache"
V1 = ROOT / "training-data/github-vulnerabilities/manifest.json"
BENCHMARK = ROOT / "benchmark/contracts"


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def atomic_json(path: Path, value: object) -> None:
    atomic_bytes(path, (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode())


def request(url: str, timeout: float, *, json_response: bool) -> object:
    headers = {"User-Agent": "offline-corpus-lane-A", "Accept": "application/vnd.github+json"}
    with urlopen(Request(url, headers=headers), timeout=timeout) as response:
        body = response.read(32_000_001)
    if len(body) > 32_000_000:
        raise ValueError("response_exceeds_32mb_limit")
    return json.loads(body) if json_response else body


def safe_path(value: object) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("unsafe_repository_path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("unsafe_repository_path")
    return path.as_posix()


def normalize_source(value: bytes) -> bytes:
    if not value or b"\x00" in value:
        raise ValueError("empty_or_binary_source")
    value = value.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return value[3:] if value.startswith(b"\xef\xbb\xbf") else value


def load_allowlist(path: Path = ALLOWLIST) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("sources") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError("allowlist_sources_missing")
    result = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("allowlist_row_invalid")
        repo, commit, license_name = row.get("repo"), row.get("commit"), row.get("license")
        if (not isinstance(repo, str) or not re.fullmatch(r"[^/ ]+/[^/ ]+", repo)
                or not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
                or not isinstance(license_name, str) or not license_name):
            raise ValueError("allowlist_identity_invalid")
        key = (repo, commit)
        if key in seen:
            raise ValueError("allowlist_duplicate_identity")
        seen.add(key)
        prefixes = row.get("prefixes", [""])
        if not isinstance(prefixes, list) or any(not isinstance(prefix, str) for prefix in prefixes):
            raise ValueError("allowlist_prefixes_invalid")
        row = dict(row)
        row["prefixes"] = prefixes
        result.append(row)
    return result


def cache_path(kind: str, source: dict, suffix: str = "", cache_root: Path = CACHE) -> Path:
    safe_repo = source["repo"].replace("/", "__")
    return Path(cache_root) / safe_repo / source["commit"] / f"{kind}{suffix}"


def pinned_tree(source: dict, timeout: float, offline: bool, cache_root: Path = CACHE) -> list[dict]:
    path = cache_path("tree", source, ".json", cache_root)
    if path.is_file():
        payload = json.loads(path.read_text(encoding="utf-8"))
    elif offline:
        raise ValueError("offline_tree_cache_missing")
    else:
        payload = request(f"https://api.github.com/repos/{source['repo']}/git/trees/{source['commit']}?recursive=1",
                          timeout, json_response=True)
        atomic_json(path, payload)
    if not isinstance(payload, dict) or payload.get("truncated") is True or not isinstance(payload.get("tree"), list):
        raise ValueError("github_tree_invalid_or_truncated")
    prefixes = tuple(source.get("prefixes", [""]))
    rows = []
    for item in payload["tree"]:
        if not isinstance(item, dict) or item.get("type") != "blob" or not isinstance(item.get("path"), str):
            continue
        item_path = safe_path(item["path"])
        if item_path.lower().endswith(".sol") and any(item_path.startswith(prefix) for prefix in prefixes):
            rows.append({"path": item_path})
    return sorted(rows, key=lambda row: row["path"])


def pinned_bytes(source: dict, repo_path: str, timeout: float, offline: bool, cache_root: Path = CACHE) -> bytes:
    cache = cache_path("blob", source, f"/{repo_path}", cache_root)
    if cache.is_file():
        return cache.read_bytes()
    if offline:
        raise ValueError("offline_blob_cache_missing")
    value = request(f"https://raw.githubusercontent.com/{source['repo']}/{source['commit']}/{quote(repo_path, safe='/')}",
                    timeout, json_response=False)
    if not isinstance(value, bytes):
        raise ValueError("source_response_invalid")
    atomic_bytes(cache, value)
    return value


def existing_duplicates() -> dict[str, str]:
    result = {}
    if V1.is_file():
        try:
            payload = json.loads(V1.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        for row in payload.get("samples", []):
            if isinstance(row, dict) and isinstance(row.get("sha256"), str):
                result.setdefault(row["sha256"], f"v1:{row.get('repo')}:{row.get('commit')}:{row.get('path')}")
    for case in sorted(BENCHMARK.glob("*/ground-truth.json")):
        try:
            truth = json.loads(case.read_text(encoding="utf-8"))
            source_file = case.parent / truth["sourceFile"]
            if source_file.is_file():
                result.setdefault(sha256(source_file.read_bytes()), f"benchmark:{case.parent.name}")
        except (OSError, KeyError, json.JSONDecodeError):
            continue
    return result


def fetch_source(source: dict, repo_path: str, timeout: float, offline: bool, cache_root: Path = CACHE) -> dict:
    raw = pinned_bytes(source, repo_path, timeout, offline, cache_root)
    normalized = normalize_source(raw)
    return {"rawSha256": sha256(raw), "sourceSha256": sha256(normalized), "content": normalized}


def object_reference(path: Path) -> str:
    """Keep repository-relative references for default output, support custom roots."""
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        # Custom output directories may be outside the project (for example in
        # a temporary directory during tests). An absolute reference is
        # unambiguous and avoids failing a successful fetch after writing it.
        return str(resolved)


def collect(*, output: Path = OUTPUT, cache: Path = CACHE, timeout: float = 25.0,
            workers: int = 4, offline: bool = False, include_disabled: bool = False) -> dict:
    if not 1 <= workers <= 8:
        raise ValueError("workers_must_be_1_to_8")
    sources = [row for row in load_allowlist() if row.get("default") is True or include_disabled]
    duplicates = existing_duplicates()
    jobs = []
    failures = []
    for source in sources:
        try:
            for item in pinned_tree(source, timeout, offline, cache):
                jobs.append((source, item["path"]))
        except (OSError, ValueError, HTTPError, URLError, TimeoutError) as error:
            failures.append({"repo": source["repo"], "commit": source["commit"],
                             "status": "failed", "failureReason": f"{type(error).__name__}:{str(error)[:240]}"})
    rows = []
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(jobs))), thread_name_prefix="corpus-fetch-v2") as pool:
        futures = {pool.submit(fetch_source, source, path, timeout, offline, cache): (source, path) for source, path in jobs}
        for future in as_completed(futures):
            source, repo_path = futures[future]
            try:
                fetched = future.result()
                digest = fetched["sourceSha256"]
                object_path = output / "objects" / digest[:2] / f"{digest}.sol"
                if object_path.is_file() and sha256(object_path.read_bytes()) != digest:
                    raise ValueError("existing_content_address_collision")
                if not object_path.is_file():
                    atomic_bytes(object_path, fetched["content"])
                duplicate = duplicates.get(digest)
                parts = repo_path.split("/")
                category = parts[1] if len(parts) > 2 and parts[0] == "dataset" else (parts[0] if parts else "unclassified")
                label = {"kind": source.get("kind", "无标签"), "value": source.get("label") or category}
                row = {"status": "collected", "repo": source["repo"], "commit": source["commit"],
                       "path": repo_path, "sourceUrl": f"https://github.com/{source['repo']}/blob/{source['commit']}/{repo_path}",
                       "rawUrl": f"https://raw.githubusercontent.com/{source['repo']}/{source['commit']}/{quote(repo_path, safe='/')}",
                       "license": source["license"], "licensePath": source.get("licensePath"), "category": category,
                       "labelSource": label, "sha256": digest, "rawSha256": fetched["rawSha256"],
                       "bytes": len(fetched["content"]), "objectPath": object_reference(object_path),
                       "duplicateOf": duplicate, "analysisEligible": duplicate is None}
                rows.append(row)
                if duplicate is None:
                    duplicates[digest] = f"v2:{source['repo']}:{source['commit']}:{repo_path}"
            except (OSError, ValueError, HTTPError, URLError, TimeoutError) as error:
                failures.append({"repo": source["repo"], "commit": source["commit"], "path": repo_path,
                                 "status": "failed", "failureReason": f"{type(error).__name__}:{str(error)[:240]}"})
    rows.sort(key=lambda row: (row["repo"], row["path"]))
    payload = {"schemaVersion": 2, "generatedAt": datetime.now(timezone.utc).isoformat(),
               "sourcePolicy": "固定 Git commit；只下载 UTF-8 Solidity 文本和许可证元数据；不执行仓库代码。",
               "cachePolicy": "network fetches are cached by repo/commit/path; --offline reads cache only",
               "workerCount": workers, "offline": offline, "sources": sources, "candidateCount": len(jobs),
               "collectedCount": len(rows), "failedCount": len(failures), "samples": rows,
               "failures": failures, "analysisScope": "仅 labelSource.kind != 无标签且 duplicateOf 为空的样本进入精度统计"}
    atomic_json(output / "manifest.json", payload)
    return payload


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--include-disabled", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = collect(output=args.output, cache=args.cache, timeout=args.timeout, workers=args.workers,
                         offline=args.offline, include_disabled=args.include_disabled)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "completed", "manifest": str(args.output / 'manifest.json'),
                      "candidateCount": result["candidateCount"], "collectedCount": result["collectedCount"],
                      "failedCount": result["failedCount"], "offline": result["offline"]}, ensure_ascii=False))
    return 0 if result["candidateCount"] == result["collectedCount"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
