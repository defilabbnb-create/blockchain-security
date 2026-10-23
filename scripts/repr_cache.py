"""Content-addressed cache for contract representations."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE_ROOT = ROOT / "work" / "repr-cache"
MAX_CACHE_BYTES = 5 * 1024 * 1024 * 1024
ARTIFACT_NAMES = ("source-ir.json", "bytecode-ir.json", "decompiled.json", "ir-reconciliation.json")
KEY_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def source_bundle_sha256(source_bundle) -> str:
    """Hash source units only, independent of JSON formatting and key order."""
    sources = source_bundle.get("sources") if isinstance(source_bundle, dict) else None
    if not isinstance(sources, dict):
        raise ValueError("source bundle must contain a sources object")
    normalized = {}
    for name, entry in sorted(sources.items()):
        if not isinstance(name, str) or not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
            raise ValueError("source bundle entries must contain source text")
        normalized[name] = entry["content"]
    return hashlib.sha256(canonical_json(normalized)).hexdigest()


def _builder_fingerprint():
    """Digest the code that decides what a cached artifact contains.

    The cache key used to be derived from the source text, the compiler version
    and the compile settings alone.  That is enough to say *which contract* was
    analysed, but not *how*: after `unified_ir.py` was corrected, a run kept
    replaying the previously cached IR, so the fix appeared to have no effect and
    the same samples stayed undetectable.  Folding the builder's own digest into
    the key makes a change to the analysis logic invalidate every entry it could
    have produced, which is what a cache has to do to stay trustworthy.
    """
    here = Path(__file__).resolve().parent
    parts = []
    for name in ("repr_cache.py", "unified_ir.py", "review-static.py"):
        path = here / name
        parts.append(path.read_bytes() if path.is_file() else b"")
    return hashlib.sha256(b"\x00".join(parts)).hexdigest()


def cache_key(source_bundle_sha256_value: str, solc_version: str, compile_settings,
              builder: str | None = None) -> str:
    if not isinstance(source_bundle_sha256_value, str) or not re.fullmatch(r"[0-9a-f]{64}", source_bundle_sha256_value):
        raise ValueError("sourceBundleSha256 must be a lowercase SHA-256 digest")
    if not isinstance(solc_version, str) or not solc_version:
        raise ValueError("solcVersion must be a non-empty string")
    payload = {"sourceBundleSha256": source_bundle_sha256_value,
               "solcVersion": solc_version, "compileSettings": compile_settings,
               "builder": builder or _builder_fingerprint()}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _encode_artifact(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def _locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _entry_path(cache_root: Path, key: str) -> Path:
    if not KEY_PATTERN.fullmatch(key):
        raise ValueError("cache key must be a lowercase SHA-256 digest")
    return cache_root / key


def _read_valid_entry(entry: Path, key: str, inputs: dict, tool_versions: dict):
    try:
        meta = json.loads((entry / "meta.json").read_text(encoding="utf-8"))
        if (not isinstance(meta, dict) or meta.get("schemaVersion") != 1 or meta.get("key") != key
                or meta.get("inputs") != inputs or meta.get("toolVersions") != tool_versions):
            return None
        expected_hashes = meta.get("artifactsSha256")
        if not isinstance(expected_hashes, dict):
            return None
        artifacts = {}
        for name in ARTIFACT_NAMES:
            path = entry / name
            raw = path.read_bytes()
            if expected_hashes.get(name) != hashlib.sha256(raw).hexdigest():
                return None
            artifacts[name] = raw
        return meta, artifacts
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _clean_lru(cache_root: Path, *, max_bytes: int, preserve: Path) -> None:
    entries = []
    total_bytes = 0
    for entry in cache_root.iterdir():
        if not entry.is_dir() or not KEY_PATTERN.fullmatch(entry.name):
            continue
        size = 0
        for path in entry.iterdir():
            if path.is_file() and not path.is_symlink():
                try:
                    size += path.stat().st_size
                except OSError:
                    continue
        total_bytes += size
        try:
            meta = json.loads((entry / "meta.json").read_text(encoding="utf-8"))
            accessed = meta.get("lastAccessAt", "") if isinstance(meta, dict) else ""
        except (OSError, ValueError):
            accessed = ""
        entries.append((accessed, entry, size))
    for _, entry, size in sorted(entries, key=lambda row: (row[0], row[1].name)):
        if total_bytes <= max_bytes:
            break
        if entry == preserve:
            continue
        shutil.rmtree(entry)
        total_bytes -= size


def get_or_build(key: str, builder_fn: Callable[[], Mapping[str, object]], *,
                 cache_root: Path = DEFAULT_CACHE_ROOT, inputs: dict | None = None,
                 tool_versions: dict | None = None, required_artifacts=ARTIFACT_NAMES,
                 max_cache_bytes: int = MAX_CACHE_BYTES) -> dict:
    """Load verified artifacts or build/update them atomically under a per-key lock."""
    cache_root = Path(cache_root).resolve()
    entry = _entry_path(cache_root, key)
    inputs = inputs or {}
    tool_versions = tool_versions or {}
    required = tuple(required_artifacts)
    if not required or any(name not in ARTIFACT_NAMES for name in required):
        raise ValueError("required_artifacts must contain known representation names")
    if isinstance(max_cache_bytes, bool) or not isinstance(max_cache_bytes, int) or max_cache_bytes < 0:
        raise ValueError("max_cache_bytes must be a non-negative integer")
    lock_dir = cache_root / ".locks"
    with _locked(lock_dir / f"{key}.lock"):
        valid = _read_valid_entry(entry, key, inputs, tool_versions)
        if valid:
            meta, existing = valid
            try:
                states = {name: json.loads(existing[name].decode("utf-8")).get("state")
                          for name in required}
            except (ValueError, UnicodeDecodeError, AttributeError):
                states = {}
            if all(states.get(name) not in (None, "not_available", "not_built") for name in required):
                meta["cacheHit"] = True
                meta["lastAccessAt"] = _utc_now()
                _atomic_write(entry / "meta.json", _encode_artifact(meta))
                with _locked(lock_dir / "lru.lock"):
                    _clean_lru(cache_root, max_bytes=max_cache_bytes, preserve=entry)
                return {"key": key, "cacheHit": True, "artifacts": existing, "meta": meta}
        else:
            meta, existing = None, {}
        built = builder_fn()
        if not isinstance(built, Mapping) or any(name not in ARTIFACT_NAMES for name in built):
            raise ValueError("builder must return a mapping of known artifact names")
        combined = dict(existing)
        for name, value in built.items():
            combined[name] = _encode_artifact(value)
        for name in ARTIFACT_NAMES:
            combined.setdefault(name, _encode_artifact({"state": "not_available"}))
        entry.mkdir(parents=True, exist_ok=True)
        for name in ARTIFACT_NAMES:
            _atomic_write(entry / name, combined[name])
        now = _utc_now()
        artifact_hashes = {name: hashlib.sha256(combined[name]).hexdigest() for name in ARTIFACT_NAMES}
        new_meta = {"schemaVersion": 1, "key": key, "inputs": inputs, "toolVersions": tool_versions,
                    "createdAt": meta.get("createdAt", now) if meta else now,
                    "lastAccessAt": now, "artifactsSha256": artifact_hashes, "cacheHit": False}
        _atomic_write(entry / "meta.json", _encode_artifact(new_meta))
        with _locked(lock_dir / "lru.lock"):
            _clean_lru(cache_root, max_bytes=max_cache_bytes, preserve=entry)
        return {"key": key, "cacheHit": False, "artifacts": combined, "meta": new_meta}
