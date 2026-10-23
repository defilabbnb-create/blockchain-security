#!/usr/bin/env python3
"""Collect pinned Solidity vulnerability examples into a provenance-bound local corpus."""
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
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "training-data" / "github-vulnerabilities"
DATASETS = (
    {"repo": "crytic/not-so-smart-contracts", "commit": "020dbdbde3e0c2e8de5f3944e7455e438b0995d5", "license": "Apache-2.0"},
    {"repo": "smartbugs/smartbugs-curated", "commit": "230e649123477eff332742a59a1c7cc6dc286cab", "license": "Apache-2.0"},
)
CATEGORY_MAP = {
    "access_control": "unprotected_function", "arithmetic": "integer_overflow",
    "bad_randomness": "bad_randomness", "denial_of_service": "denial_of_service",
    "forced_ether": "forced_ether_reception", "reentrancy": "reentrancy",
    "unchecked_call": "unchecked_external_call", "unchecked_low_level_calls": "unchecked_external_call",
    "constructor": "wrong_constructor_name", "front_running": "front_running",
    "time_manipulation": "time_manipulation", "short_addresses": "short_addresses",
    "honeypots": "honeypots", "incorrect_interface": "incorrect_interface",
    "race_condition": "race_condition", "variable_shadowing": "variable_shadowing",
}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _request_json(url: str, timeout: float) -> object:
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "defi-scan-vulnerability-corpus"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(30_000_001))


def _request_bytes(url: str, timeout: float) -> bytes:
    request = Request(url, headers={"User-Agent": "defi-scan-vulnerability-corpus"})
    with urlopen(request, timeout=timeout) as response:
        body = response.read(4_000_001)
    if len(body) > 4_000_000:
        raise ValueError("source_exceeds_4mb_limit")
    return body


def _safe_path(value: object) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("unsafe_repository_path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("unsafe_repository_path")
    return path.as_posix()


def _category(repo_path: str) -> str:
    parts = [part.replace(" ", "_") for part in repo_path.lower().split("/") if part]
    for category in CATEGORY_MAP:
        if category in parts:
            return "unchecked_low_level_calls" if category == "unchecked_call" else category
    lowered = repo_path.lower()
    for category, segment in CATEGORY_MAP.items():
        if segment in lowered:
            return "unchecked_low_level_calls" if category == "unchecked_call" else category
    return "unclassified"


def _collect_one(dataset: dict, item: dict, timeout: float) -> dict:
    repo_path = _safe_path(item.get("path"))
    repo, commit = dataset["repo"], dataset["commit"]
    source_url = f"https://github.com/{repo}/blob/{commit}/{repo_path}"
    raw_url = f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(repo_path, safe='/')}"
    try:
        content = _request_bytes(raw_url, timeout)
        if not content or b"\x00" in content:
            raise ValueError("empty_or_binary_source")
        digest = hashlib.sha256(content).hexdigest()
        output = CORPUS / "objects" / digest[:2] / f"{digest}.sol"
        if output.exists() and hashlib.sha256(output.read_bytes()).hexdigest() != digest:
            raise ValueError("existing_content_address_collision")
        if not output.exists():
            _atomic_write(output, content)
        try:
            object_path = str(output.relative_to(ROOT))
        except ValueError:
            object_path = str(output)
        return {"status": "collected", "repo": repo, "commit": commit, "path": repo_path,
                "sourceUrl": source_url, "rawUrl": raw_url, "license": dataset["license"],
                "category": _category(repo_path), "language": "Solidity",
                "sha256": digest, "bytes": len(content), "objectPath": object_path,
                "analysis": {"static": "not_run", "dynamic": "not_run", "decompiler": "not_run"}}
    except (OSError, ValueError, HTTPError, URLError, TimeoutError) as error:
        reason = f"{type(error).__name__}:{getattr(error, 'code', '')}:{str(error)[:240]}"
        return {"status": "failed", "repo": repo, "commit": commit, "path": repo_path,
                "sourceUrl": source_url, "license": dataset["license"],
                "category": _category(repo_path), "failureReason": reason}


def reclassify_manifest(manifest: dict) -> dict:
    """Repair category labels in an existing pinned corpus without network access."""
    for sample in manifest.get("samples", []):
        if isinstance(sample, dict) and sample.get("status") == "collected" and isinstance(sample.get("path"), str):
            sample["category"] = _category(sample["path"])
    manifest["categoryPolicy"] = "Category is derived from the pinned repository path segment; it remains a dataset label, not a verified finding."
    return manifest


def collect(*, workers: int = 6, timeout: float = 25.0, include_smartbugs: bool = True) -> dict:
    if isinstance(workers, bool) or not 1 <= workers <= 16:
        raise ValueError("workers must be in [1, 16]")
    datasets = DATASETS if include_smartbugs else DATASETS[:1]
    jobs = []
    failures = []
    for dataset in datasets:
        try:
            tree = _request_json(f"https://api.github.com/repos/{dataset['repo']}/git/trees/{dataset['commit']}?recursive=1", timeout)
            if not isinstance(tree, dict) or tree.get("truncated") is True or not isinstance(tree.get("tree"), list):
                raise ValueError("github_tree_invalid_or_truncated")
            rows = [item for item in tree["tree"] if isinstance(item, dict) and item.get("type") == "blob"
                    and isinstance(item.get("path"), str) and item["path"].lower().endswith(".sol")]
            if not rows:
                raise ValueError("repository_has_no_solidity_files")
            jobs.extend((dataset, item) for item in rows)
        except (OSError, ValueError, HTTPError, URLError, TimeoutError) as error:
            failures.append({"status": "failed", "repo": dataset["repo"], "commit": dataset["commit"],
                             "failureReason": f"{type(error).__name__}:{getattr(error, 'code', '')}:{str(error)[:240]}"})
    results = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="github-vuln") as pool:
        futures = [pool.submit(_collect_one, dataset, item, timeout) for dataset, item in jobs]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda row: (row.get("repo", ""), row.get("path", "")))
    collected = sum(row["status"] == "collected" for row in results)
    failed = failures + [row for row in results if row["status"] == "failed"]
    manifest = {"schemaVersion": 1, "generatedAt": datetime.now(timezone.utc).isoformat(),
                "sourcePolicy": "Pinned Git commit only; raw content is content-addressed; failures remain explicit.",
                "workerCount": workers, "datasetCount": len(datasets), "candidateCount": len(jobs),
                "collectedCount": collected, "failedCount": len(failed),
                "notAnalyzedCount": collected, "datasets": list(datasets),
                "samples": results, "datasetFailures": failures,
                "trainingPolicy": "Raw-source corpus only. Do not treat labels or source comments as verified findings; add reviewed labels and static/dynamic/decompiler results separately."}
    encoded = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _atomic_write(CORPUS / "manifest.json", encoded)
    return manifest


def main(argv: list[str] | None = None) -> int:
    # v1 is frozen for the offline debugging lanes. New downloads belong in
    # github-vulnerabilities-v2 and cannot replace existing evidence/labels.
    if (CORPUS / "manifest.json").is_file():
        print(json.dumps({"status": "rejected", "reason": "旧语料已冻结；新增下载请使用 corpus_fetch.py，层结果请写分片并调用 corpus_merge.py。"}, ensure_ascii=False))
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=25)
    parser.add_argument("--not-so-smart-only", action="store_true")
    parser.add_argument("--reclassify-only", action="store_true", help="repair existing category labels without contacting GitHub")
    args = parser.parse_args(argv)
    if args.reclassify_only:
        try:
            manifest = reclassify_manifest(json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8")))
            _atomic_write(CORPUS / "manifest.json", (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(json.dumps({"status": "failed", "reason": str(error)}, ensure_ascii=False))
            return 2
        categories = {}
        for sample in manifest.get("samples", []):
            category = sample.get("category", "unclassified")
            categories[category] = categories.get(category, 0) + 1
        print(json.dumps({"manifest": str(CORPUS / "manifest.json"), "reclassifiedCount": len(manifest.get("samples", [])),
                          "categories": categories}, ensure_ascii=False))
        return 0
    try:
        manifest = collect(workers=args.workers, timeout=args.timeout, include_smartbugs=not args.not_so_smart_only)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({"manifest": str(CORPUS / "manifest.json"), "candidateCount": manifest["candidateCount"],
                      "collectedCount": manifest["collectedCount"], "failedCount": manifest["failedCount"],
                      "workerCount": manifest["workerCount"]}, ensure_ascii=False))
    return 0 if manifest["candidateCount"] and manifest["collectedCount"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
