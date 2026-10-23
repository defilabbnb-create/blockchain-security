#!/usr/bin/env python3
"""Prefetch checksum-verified Solidity releases concurrently.

The compiler loader remains lazy for normal scans. This command is the
optional warm-up step for a large corpus so independent releases download in
parallel while each release keeps its own lock and atomic cache entry.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
TRAINING_MANIFEST_ROOT = ROOT / "training-data"
BENCHMARK_ROOT = ROOT / "benchmark/contracts"
COMPILER_LOADER = ROOT / "scripts/review-static.py"
_TRAINING_SELECTION_MODULE = None


def _load_compiler():
    spec = importlib.util.spec_from_file_location("prepare_solc_review_static", COMPILER_LOADER)
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.compiler


def _version_key(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))


def _valid_version(value: object) -> bool:
    return _normalize_version(value) is not None


def _normalize_version(value: object) -> str | None:
    """Return the release part of an exact version with an optional build suffix."""
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(0\.\d+\.\d+)(?:\+[^\s]+)?", value.strip())
    return match.group(1) if match else None


def _exact_pragma_version(value: object) -> str | None:
    """Return a release from a pragma only when it is an exact pin."""
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"\s*=\s*(0\.\d+\.\d+)\s*", value)
    if match:
        return match.group(1)
    match = re.fullmatch(r"\s*(0\.\d+\.\d+)\s*", value)
    return match.group(1) if match else None


def _cached_versions(cache: Path | None = None) -> set[str]:
    cache = cache or (ROOT / "work/compiler-cache")
    versions = set()
    for path in cache.glob("soljson-v*.cjs"):
        match = re.match(r"soljson-v(0\.\d+\.\d+)\+", path.name)
        if match:
            versions.add(match.group(1))
    return versions


def _catalog_versions() -> set[str]:
    """Load official release names through the same verified catalog as scans."""
    spec = importlib.util.spec_from_file_location("prepare_solc_review_static_catalog", COMPILER_LOADER)
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cache = ROOT / "work/compiler-cache"
    cache.mkdir(parents=True, exist_ok=True)
    index, _catalog_hash = module._compiler_catalog(cache)
    return {version for version in index.get("releases", {}) if _normalize_version(version)}


def _training_selection_module():
    """Load the shared pragma selector once per prefetch process."""
    global _TRAINING_SELECTION_MODULE
    if _TRAINING_SELECTION_MODULE is not None:
        return _TRAINING_SELECTION_MODULE
    spec = importlib.util.spec_from_file_location(
        "prepare_solc_training_selection", ROOT / "scripts/analyze-training-corpus.py"
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _TRAINING_SELECTION_MODULE = module
    return module


def _pragma_candidates(sample: dict, *, cached_versions: set[str], released_versions: set[str]) -> list[str]:
    pragmas = sample.get("compilerPragmas")
    if not isinstance(pragmas, list):
        return []
    expressions = [value.strip() for value in pragmas if isinstance(value, str) and value.strip()]
    if not expressions:
        return []
    module = _training_selection_module()
    if module is None:
        return []
    source = "\n".join(f"pragma solidity {expression};" for expression in expressions)
    version, _reason = module.infer_version(source, cached_versions, released_versions)
    return [version] if version else []


def versions_from_manifest(path: Path, *, released_versions: set[str] | None = None,
                           cached_versions: set[str] | None = None) -> list[str]:
    """Collect selected versions and optionally resolve recorded pragma ranges.

    Without a release catalog this preserves the historical exact-only behavior;
    callers opting into all-manifest warming pass the official catalog so ranges
    such as ``^0.8.0`` are resolved by the same selector as static analysis.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    versions: set[str] = set()
    for sample in document.get("samples", []):
        if not isinstance(sample, dict):
            continue
        analysis = sample.get("analysis")
        if isinstance(analysis, dict):
            for key in ("compilerVersion", "compilerPinnedVersion"):
                normalized = _normalize_version(analysis.get(key))
                if normalized is not None:
                    versions.add(normalized)
        pragmas = sample.get("compilerPragmas")
        if not isinstance(pragmas, list):
            pragmas = []
        for pragma in pragmas:
            normalized = _exact_pragma_version(pragma)
            if normalized is not None:
                versions.add(normalized)
        if released_versions is not None:
            versions.update(_pragma_candidates(
                sample, cached_versions=cached_versions or set(), released_versions=released_versions))
    return sorted(versions, key=_version_key)


def versions_from_benchmarks(root: Path = BENCHMARK_ROOT) -> list[str]:
    """Collect exact compiler pins from benchmark ground-truth records."""
    versions = set()
    for path in sorted(root.glob("*/ground-truth.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        normalized = _normalize_version(document.get("solcVersion")) if isinstance(document, dict) else None
        if normalized is not None:
            versions.add(normalized)
    return sorted(versions, key=_version_key)


def all_manifest_paths(root: Path = TRAINING_MANIFEST_ROOT) -> list[Path]:
    return sorted(path for path in root.glob("*/manifest.json") if path.is_file())


def prefetch(versions: list[str], *, workers: int = 4, compiler_loader=None) -> list[dict]:
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 16:
        raise ValueError("workers must be 1..16")
    normalized_values = [_normalize_version(value) for value in versions]
    normalized = sorted({value for value in normalized_values if value is not None}, key=_version_key)
    if any(value is None for value in normalized_values):
        invalid = [value for value, normalized_value in zip(versions, normalized_values)
                   if normalized_value is None]
        if invalid:
            raise ValueError("invalid Solidity release: " + ",".join(map(str, invalid)))
    loader = compiler_loader or _load_compiler()

    def fetch(version: str) -> dict:
        try:
            path, metadata = loader(version)
            return {"version": version, "state": "ready", "path": str(path),
                    "sha256": metadata.get("sha256"), "longVersion": metadata.get("longVersion"),
                    "catalogSha256": metadata.get("catalogSha256")}
        except Exception as error:  # preserve per-version diagnostics and continue
            return {"version": version, "state": "failed",
                    "reason": f"{type(error).__name__}:{str(error)[:240]}"}

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(normalized))),
                            thread_name_prefix="solc-prefetch") as pool:
        futures = [pool.submit(fetch, version) for version in normalized]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda row: _version_key(row["version"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="append", dest="versions", default=[],
                        help="exact release to prefetch; repeat or use comma-separated values")
    parser.add_argument("--manifest", action="append", type=Path,
                        help="manifest whose recorded compiler versions should be prefetched; repeatable")
    parser.add_argument("--all-manifests", action="store_true",
                        help="include every training-data/*/manifest.json and resolve pragma ranges")
    parser.add_argument("--include-benchmarks", action="store_true",
                        help="include exact solcVersion pins from benchmark/contracts ground truth")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    versions = [item.strip() for value in args.versions for item in value.split(",") if item.strip()]
    manifest_paths = [path.expanduser().resolve() for path in (args.manifest or [])]
    if args.all_manifests:
        manifest_paths.extend(all_manifest_paths())
    catalog = None
    cached = None
    if args.all_manifests:
        catalog = _catalog_versions()
        cached = _cached_versions()
    for manifest in dict.fromkeys(manifest_paths):
        versions.extend(versions_from_manifest(manifest, released_versions=catalog,
                                                cached_versions=cached))
    if args.include_benchmarks:
        versions.extend(versions_from_benchmarks())
    if not versions and DEFAULT_MANIFEST.is_file():
        versions.extend(versions_from_manifest(DEFAULT_MANIFEST))
    if not versions:
        parser.error("provide --version, --manifest, --all-manifests, or --include-benchmarks")
    results = prefetch(versions, workers=args.workers)
    print(json.dumps({"requested": len(sorted(set(versions))), "results": results,
                      "ready": sum(row["state"] == "ready" for row in results),
                      "failed": sum(row["state"] == "failed" for row in results)},
                     ensure_ascii=False, sort_keys=True))
    return 0 if all(row["state"] == "ready" for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
