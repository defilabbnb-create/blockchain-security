#!/usr/bin/env python3
"""Immutable raw-data storage and provenance helpers.

The collector keeps the bytes returned by a source separate from normalized
records.  Payloads are content addressed and never overwritten; provenance
records are addressed independently so the same response can be observed from
multiple sources without duplicating or mutating the raw payload.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = 1
_HASH = re.compile(r"^[0-9a-f]{64}$")
_HEX_HASH = re.compile(r"^(?:0x)?[0-9a-f]{64}$", re.IGNORECASE)
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$", re.IGNORECASE)


class ArchiveError(ValueError):
    """Raised when an archive or provenance record is invalid."""


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON, rejecting non-finite values."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArchiveError(f"value is not canonical JSON: {exc}") from exc


def sha256_bytes(payload: bytes) -> str:
    if not isinstance(payload, bytes):
        raise ArchiveError("payload must be bytes")
    return hashlib.sha256(payload).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _iso(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or not value.endswith("Z"):
        raise ArchiveError(f"{field} must be an ISO-8601 UTC timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ArchiveError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    return value


def _hash(value: str | None, field: str, *, allow_none: bool = True, prefixed: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    pattern = _HEX_HASH if prefixed else _HASH
    if not isinstance(value, str) or not pattern.fullmatch(value):
        suffix = " with an optional 0x prefix" if prefixed else ""
        raise ArchiveError(f"{field} must be 64 lowercase hexadecimal characters{suffix}")
    return value


def build_provenance(
    *,
    content_hash: str,
    project_id: str,
    source_ref: str | Mapping[str, Any],
    tool_version: str,
    chain_id: int | str | None = None,
    block_number: int | str | None = None,
    block_hash: str | None = None,
    contract_address: str | None = None,
    code_hash: str | None = None,
    created_at: str | None = None,
    updated_at: str | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and validate the common metadata required by derived records."""
    _hash(content_hash, "content_hash", allow_none=False)
    if not isinstance(project_id, str) or not project_id.strip() or len(project_id) > 256:
        raise ArchiveError("project_id must be a non-empty string")
    if not isinstance(source_ref, (str, Mapping)) or not source_ref:
        raise ArchiveError("source_ref must be a non-empty string or object")
    if not isinstance(tool_version, str) or not tool_version.strip() or len(tool_version) > 256:
        raise ArchiveError("tool_version must be a non-empty string")
    if chain_id is not None and (isinstance(chain_id, bool) or not isinstance(chain_id, (int, str))):
        raise ArchiveError("chain_id must be an integer, string, or null")
    if block_number is not None and (isinstance(block_number, bool) or not isinstance(block_number, (int, str))):
        raise ArchiveError("block_number must be an integer, string, or null")
    if contract_address is not None and (not isinstance(contract_address, str) or not _ADDRESS.fullmatch(contract_address)):
        raise ArchiveError("contract_address must be a 20-byte hexadecimal address")
    _hash(block_hash, "block_hash", prefixed=True)
    _hash(code_hash, "code_hash", prefixed=True)
    created = _iso(created_at or utc_now(), "created_at")
    updated = _iso(updated_at or created, "updated_at")
    if not isinstance(provenance, Mapping):
        raise ArchiveError("provenance must be an object")
    # Copy caller-owned values through canonical JSON so metadata cannot be
    # changed after it has been hashed or written.
    source_copy = json.loads(canonical_json(source_ref)) if isinstance(source_ref, Mapping) else source_ref
    provenance_copy = json.loads(canonical_json(provenance))
    return {
        "project_id": project_id,
        "chain_id": chain_id,
        "block_number": block_number,
        "block_hash": block_hash,
        "contract_address": contract_address,
        "code_hash": code_hash,
        "content_hash": content_hash,
        "schema_version": SCHEMA_VERSION,
        "tool_version": tool_version,
        "source_ref": source_copy,
        "created_at": created,
        "updated_at": updated,
        "provenance": provenance_copy,
    }


def validate_provenance(record: Mapping[str, Any]) -> bool:
    """Validate a metadata record without accepting unknown schema versions."""
    if not isinstance(record, Mapping) or record.get("schema_version") != SCHEMA_VERSION:
        return False
    required = {
        "project_id", "chain_id", "block_number", "block_hash", "contract_address",
        "code_hash", "content_hash", "schema_version", "tool_version", "source_ref",
        "created_at", "updated_at", "provenance",
    }
    if set(record) != required:
        return False
    try:
        expected = build_provenance(
            content_hash=record["content_hash"], project_id=record["project_id"],
            source_ref=record["source_ref"], tool_version=record["tool_version"],
            chain_id=record["chain_id"], block_number=record["block_number"],
            block_hash=record["block_hash"], contract_address=record["contract_address"],
            code_hash=record["code_hash"], created_at=record["created_at"],
            updated_at=record["updated_at"], provenance=record["provenance"],
        )
    except ArchiveError:
        return False
    return expected == dict(record)


def _exclusive_write(path: Path, payload: bytes, *, archive_root: Path | None = None) -> bool:
    """Atomically create a file, returning False for an already identical file."""
    if archive_root is None:
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        _ensure_archive_directory(archive_root, path.parent)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # A hard-link gives an atomic create-if-absent operation without
            # allowing os.replace() to overwrite an existing archive.
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file():
                raise ArchiveError(f"archive path is not a regular file: {path}")
            if path.read_bytes() != payload:
                raise ArchiveError(f"immutable archive collision at {path}")
            return False
        return True
    except Exception:
        try:
            Path(temporary).unlink()
        except OSError:
            pass
        raise
    finally:
        try:
            Path(temporary).unlink()
        except OSError:
            pass


def _ensure_archive_directory(root: Path, directory: Path) -> None:
    """Create archive directories without following links below the chosen root."""
    root = root.absolute()
    try:
        parts = directory.relative_to(root).parts
    except ValueError as exc:
        raise ArchiveError("archive directory escaped its root") from exc
    try:
        root_info = os.lstat(root)
    except FileNotFoundError:
        root.mkdir(parents=True, exist_ok=True)
        root_info = os.lstat(root)
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ArchiveError(f"archive directory is not a regular directory: {root}")
    current = root
    for part in parts:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current)
            except FileExistsError:
                info = os.lstat(current)
            else:
                info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ArchiveError(f"archive directory is not a regular directory: {current}")


def _valid_archive_layout(payload_path: Path, metadata_path: Path, content_hash: str, compression: str, metadata_hash: str) -> bool:
    """Require content-addressed filenames and reject symlinked archive parents."""
    if not _HASH.fullmatch(metadata_hash):
        return False
    expected_payload = "payload.bin.gz" if compression == "gzip" else "payload.bin"
    if payload_path.name != expected_payload or metadata_path.name != f"{metadata_hash}.metadata.json":
        return False
    directory = payload_path.parent
    if metadata_path.parent != directory or directory.name != content_hash:
        return False
    if directory.parent.name != content_hash[:2] or directory.parent.parent.name != "raw":
        return False
    current = directory
    while current != directory.parent.parent.parent:
        if current.is_symlink() or not current.is_dir():
            return False
        current = current.parent
    return True


def _safe_kind(kind: str) -> str:
    if not isinstance(kind, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", kind):
        raise ArchiveError("kind must contain only lowercase letters, digits, '.', '_' or '-'")
    return kind


def archive_bytes(
    root: str | Path,
    payload: bytes,
    *,
    kind: str,
    project_id: str,
    source_ref: str | Mapping[str, Any],
    tool_version: str,
    chain_id: int | str | None = None,
    block_number: int | str | None = None,
    block_hash: str | None = None,
    contract_address: str | None = None,
    code_hash: str | None = None,
    provenance: Mapping[str, Any] | None = None,
    compression: str | None = "gzip",
    parse_error: str | None = None,
) -> dict[str, Any]:
    """Archive raw bytes and return an immutable payload/provenance reference."""
    if not isinstance(payload, bytes):
        raise ArchiveError("payload must be bytes")
    kind = _safe_kind(kind)
    if compression not in (None, "gzip"):
        raise ArchiveError("compression must be null or 'gzip'")
    if parse_error is not None and (not isinstance(parse_error, str) or not parse_error.strip()):
        raise ArchiveError("parse_error must be a non-empty string when provided")
    content_hash = sha256_bytes(payload)
    record = build_provenance(
        content_hash=content_hash, project_id=project_id, source_ref=source_ref,
        tool_version=tool_version, chain_id=chain_id, block_number=block_number,
        block_hash=block_hash, contract_address=contract_address, code_hash=code_hash,
        provenance=provenance or {},
    )
    metadata = {
        "kind": kind,
        "byte_length": len(payload),
        "compression": compression,
        "provenance": record,
        "processing": {"status": "failed" if parse_error else "raw", "error": parse_error},
        "schema_version": SCHEMA_VERSION,
    }
    metadata_hash = hashlib.sha256(canonical_json(metadata)).hexdigest()
    root = Path(root).expanduser().absolute()
    directory = root / "raw" / content_hash[:2] / content_hash
    _ensure_archive_directory(root, directory)
    stored = gzip.compress(payload, mtime=0) if compression == "gzip" else payload
    payload_path = directory / ("payload.bin.gz" if compression == "gzip" else "payload.bin")
    metadata_path = directory / f"{metadata_hash}.metadata.json"
    _exclusive_write(payload_path, stored, archive_root=root)
    _exclusive_write(metadata_path, canonical_json(metadata) + b"\n", archive_root=root)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "content_hash": content_hash,
        "metadata_hash": metadata_hash,
        "byte_length": len(payload),
        "compression": compression,
        "payload_path": str(payload_path),
        "metadata_path": str(metadata_path),
        "provenance": record,
        "processing": metadata["processing"],
    }


def archive_json(root: str | Path, value: Any, **kwargs: Any) -> dict[str, Any]:
    """Archive a JSON value using deterministic encoding.

    Callers that need byte-for-byte preservation of an HTTP/RPC body should
    pass the received bytes to :func:`archive_bytes` instead.
    """
    return archive_bytes(root, canonical_json(value), **kwargs)


def verify_archive(reference: Mapping[str, Any]) -> bool:
    """Verify payload bytes, metadata, and provenance against an archive ref."""
    try:
        if not isinstance(reference, Mapping):
            return False
        content_hash = reference["content_hash"]
        payload_path = Path(reference["payload_path"])
        metadata_path = Path(reference["metadata_path"])
        metadata_hash = reference["metadata_hash"]
        compression = reference.get("compression")
        if (not _HASH.fullmatch(content_hash) or compression not in (None, "gzip") or
                not _valid_archive_layout(payload_path, metadata_path, content_hash, compression, metadata_hash)):
            return False
        if any(not stat.S_ISREG(os.lstat(path).st_mode) for path in (payload_path, metadata_path)):
            return False
        metadata_bytes = metadata_path.read_bytes()
        metadata = json.loads(metadata_bytes.decode("utf-8"))
        if not isinstance(metadata, dict) or metadata.get("schema_version") != SCHEMA_VERSION:
            return False
        if any(reference.get(key) != metadata.get(key) for key in ("schema_version", "kind", "compression", "processing", "provenance")):
            return False
        if not validate_provenance(metadata.get("provenance")):
            return False
        if metadata["provenance"]["content_hash"] != content_hash:
            return False
        stored = payload_path.read_bytes()
        raw = gzip.decompress(stored) if metadata.get("compression") == "gzip" else stored
        return (
            len(raw) == metadata.get("byte_length") == reference.get("byte_length")
            and sha256_bytes(raw) == content_hash
            and hashlib.sha256(canonical_json(metadata)).hexdigest() == metadata_hash
            and metadata_bytes == canonical_json(metadata) + b"\n"
        )
    except (OSError, KeyError, TypeError, ValueError, EOFError):
        return False

