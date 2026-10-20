#!/usr/bin/env python3
"""Import a local smart-contract project into an auditable raw evidence set.

The importer is deliberately read-only with respect to the input project. It
walks a bounded set of regular files, records Git/worktree state when
available, and stores each accepted file in the immutable content-addressed
archive implemented by ``data_provenance.py``. Generated output and ignored
dependency/build directories are never recursively re-imported.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = 1
TOOL_VERSION = "project-import/1"
DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_FILES = 20_000
MAX_GIT_STATUS_ENTRIES = 200
PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

IGNORED_DIRECTORIES = frozenset({
    ".git", ".hg", ".svn", "node_modules", "work", ".venv", "venv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist",
    "build", "artifacts", "cache", "coverage", "target",
})
SECRET_NAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.development",
    ".npmrc", ".pypirc", "credentials", "credentials.json", "secrets.json",
})
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".secret")
SOURCE_EXTENSIONS = frozenset({".sol", ".vy", ".yul", ".vyi"})
DOC_EXTENSIONS = frozenset({".md", ".rst", ".txt", ".adoc"})
CONFIG_NAMES = frozenset({
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "foundry.toml", "foundry.lock", "hardhat.config.js",
    "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts",
    "truffle-config.js", "remappings.txt", "dockerfile", "makefile",
})


def _load_provenance_module():
    path = Path(__file__).with_name("data_provenance.py")
    spec = importlib.util.spec_from_file_location("project_import_data_provenance", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 data_provenance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_PROVENANCE = _load_provenance_module()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _atomic_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Publish a new manifest without ever replacing an existing input.
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _relative(root: Path, path: Path) -> str:
    return _safe_text(path.relative_to(root).as_posix())


def _safe_text(value: str) -> str:
    """Make filesystem/Git names JSON-safe even when the OS uses undecodable bytes."""
    return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def _safe_project_id(value: str | None, root: Path) -> str:
    if value is None:
        digest = hashlib.sha256(str(root).encode("utf-8", "surrogateescape")).hexdigest()[:16]
        return f"local-{digest}"
    if not PROJECT_ID.fullmatch(value):
        raise ValueError("project-id 只能包含 ASCII 字母、数字、点、下划线和连字符")
    return value


def _run_git(root: Path, args: list[str], timeout: float = 5.0) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root),
             "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
            capture_output=True, text=False,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, f"{type(error).__name__}: {_safe_text(str(error))}"
    if result.returncode != 0:
        return None, (result.stderr or b"git command failed").decode("utf-8", "replace").strip()[:300]
    return (result.stdout or b"").decode("utf-8", "replace"), None


def _git_snapshot(root: Path) -> dict[str, Any]:
    is_repo, error = _run_git(root, ["rev-parse", "--is-inside-work-tree"])
    if is_repo is None or is_repo.strip().lower() != "true":
        return {"available": False, "reason": error or "not a Git worktree"}
    commit, commit_error = _run_git(root, ["rev-parse", "HEAD"])
    branch, branch_error = _run_git(root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    status, status_error = _run_git(root, ["status", "--porcelain=v1", "--untracked-files=all", "-z"])
    entries: list[dict[str, str]] = []
    status_count = 0
    if status is not None:
        fields = status.split("\x00")
        index = 0
        while index < len(fields):
            item = fields[index]
            index += 1
            if not item:
                continue
            # XY is fixed-width; worktree modifications begin with a space.
            status_code, name = item[:2], item[3:]
            row = {"status": status_code[:2], "path": name}
            # Porcelain v1 -z adds the old path as a second NUL field for
            # renames/copies. Keep both names without trying to interpret them.
            if any(code in status_code for code in ("R", "C")) and index < len(fields) and fields[index]:
                row["oldPath"] = fields[index]
                index += 1
            status_count += 1
            if len(entries) < MAX_GIT_STATUS_ENTRIES:
                entries.append(row)
    return {
        "available": True,
        "commit": commit.strip() if commit else None,
        "branch": branch.strip() if branch else None,
        "detached": not bool(branch and branch.strip()),
        "commitState": "present" if commit else "no_commit_yet",
        "branchState": "attached" if branch and branch.strip() else "detached_or_empty",
        "statusCount": status_count,
        "status": entries,
        "statusTruncated": status_count > len(entries),
        # An empty repository has no HEAD and a detached checkout has no
        # symbolic branch; both are valid snapshots. Only status failure
        # means that workspace state could not be captured.
        "errors": [item for item in (status_error,) if item],
    }


def _is_secret(path: Path) -> bool:
    name = path.name.lower()
    if name == ".env.example":
        return False
    return (name in SECRET_NAMES or name.startswith(".env.") or
            name.endswith(SECRET_SUFFIXES) or name.startswith(("credentials.", "secrets.")))


def _kind(path: Path) -> str:
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    suffix = path.suffix.lower()
    if any(part in {"test", "tests", "spec", "specs", "forge-test"} for part in parts):
        return "test"
    if any(part in {"lib", "vendor", "deps", "dependencies"} for part in parts):
        return "dependency"
    if suffix in SOURCE_EXTENSIONS:
        return "source"
    if name in CONFIG_NAMES or suffix in {".toml", ".yaml", ".yml", ".ini", ".cfg", ".lock"}:
        return "config"
    if suffix in DOC_EXTENSIONS:
        return "documentation"
    if suffix in {".js", ".cjs", ".mjs", ".ts", ".tsx", ".py", ".rs", ".sh"}:
        return "code"
    return "other"


def _iter_files(root: Path, excluded: set[Path], *, onerror=None):
    excluded = {path.resolve() for path in excluded}
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        current_path = Path(current)
        resolved_current = current_path.resolve()
        if any(resolved_current == path or path in resolved_current.parents for path in excluded):
            directories[:] = []
            continue
        retained = []
        for name in sorted(directories):
            if (current_path / name).is_symlink():
                yield current_path / name
                continue
            if name in IGNORED_DIRECTORIES:
                continue
            candidate = (current_path / name).resolve()
            if any(candidate == path or path in candidate.parents for path in excluded):
                continue
            retained.append(name)
        directories[:] = retained
        for name in sorted(filenames):
            path = current_path / name
            if path.resolve() in excluded:
                continue
            yield path


class _ReadLimitError(ValueError):
    pass


def _read_regular_file(root: Path, path: Path, limit: int) -> bytes:
    """Bound reads and reject special files or links, including raced parents."""
    parts = path.relative_to(root).parts
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(file_fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("not a regular file")
            if before.st_size > limit:
                raise _ReadLimitError("file exceeds remaining byte budget")
            payload = handle.read(limit + 1)
            if len(payload) > limit:
                raise _ReadLimitError("file exceeds remaining byte budget")
            after = os.fstat(handle.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(payload) != after.st_size:
                raise ValueError("file changed while reading")
            return payload
    finally:
        os.close(directory_fd)


def _source_fingerprint(files: list[dict[str, Any]]) -> str:
    rows = [
        {"path": item["path"], "sha256": item["sha256"], "bytes": item["bytes"]}
        for item in files if item.get("included") is True
    ]
    encoded = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def import_project(
    root: str | Path,
    *,
    output: str | Path | None = None,
    archive_root: str | Path | None = None,
    project_id: str | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    """Import ``root`` and return a provenance-bound manifest.

    A partial result is still useful: every skipped or unreadable item is
    retained with a reason, and accepted bytes remain verifiable through the
    archive references. No input file is modified.
    """
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("项目路径必须是目录")
    for name, value in (("max_file_bytes", max_file_bytes), ("max_total_bytes", max_total_bytes), ("max_files", max_files)):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} 必须是正整数")
    if max_file_bytes > max_total_bytes:
        raise ValueError("max_file_bytes 不能大于 max_total_bytes")
    project = _safe_project_id(project_id, root)
    requested_output = Path(output).expanduser() if output else root / "work" / "project-import.json"
    if requested_output.exists() or requested_output.is_symlink():
        raise ValueError("output already exists; choose a new manifest path")
    output_path = requested_output.resolve()
    archive_path = (Path(archive_root).expanduser() if archive_root else root / "work").resolve()
    if archive_path == root or archive_path in root.parents:
        raise ValueError("archive_root must not contain the input project root")
    excluded = {output_path, archive_path}
    files: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    counters = {"seen": 0, "included": 0, "archived": 0, "skipped": 0, "bytes": 0}
    by_kind: dict[str, int] = {}
    total_bytes = 0
    limit_reached = False

    def walk_error(error):
        errors.append({"path": _safe_text(str(error.filename or root)),
                       "reason": f"directory scan failed: {type(error).__name__}"})

    for path in _iter_files(root, excluded, onerror=walk_error):
        if counters["seen"] >= max_files:
            limit_reached = True
            errors.append({"path": _relative(root, path),
                           "reason": "max_files scan limit reached; remaining entries not visited"})
            break
        counters["seen"] += 1
        try:
            relative = _relative(root, path)
        except ValueError:
            counters["skipped"] += 1
            errors.append({"path": _safe_text(str(path)), "reason": "outside project root"})
            continue
        if _is_secret(path):
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": "secret-like file omitted"})
            continue
        if path.is_symlink():
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": "symbolic link omitted"})
            continue
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("not a regular file")
            size = info.st_size
        except ValueError as error:
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": str(error)})
            continue
        except OSError as error:
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": f"stat failed: {type(error).__name__}"})
            continue
        if counters["included"] >= max_files:
            limit_reached = True
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": "max_files limit reached"})
            continue
        if size > max_file_bytes:
            limit_reached = True
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": f"file exceeds max_file_bytes ({size})"})
            continue
        if total_bytes + size > max_total_bytes:
            limit_reached = True
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": "max_total_bytes limit reached"})
            continue
        try:
            payload = _read_regular_file(root, path, min(max_file_bytes, max_total_bytes - total_bytes))
        except (OSError, ValueError) as error:
            if isinstance(error, _ReadLimitError):
                limit_reached = True
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": f"read failed: {type(error).__name__}: {_safe_text(str(error))}"})
            continue
        if len(payload) != size:
            size = len(payload)
        content_hash = hashlib.sha256(payload).hexdigest()
        kind = _kind(Path(relative))
        entry: dict[str, Any] = {
            "path": relative,
            "kind": kind,
            "bytes": size,
            "sha256": content_hash,
            "encoding": "utf-8" if _is_utf8(payload) else "binary",
            "included": True,
        }
        try:
            reference = _PROVENANCE.archive_bytes(
                archive_path, payload, kind=f"project.{kind}", project_id=project,
                source_ref={"kind": "local_project_file", "path": relative},
                tool_version=TOOL_VERSION,
                provenance={"projectRoot": str(root), "relativePath": relative},
            )
            entry["archive"] = reference
            if not _PROVENANCE.verify_archive(reference):
                raise ValueError("raw archive verification failed")
            counters["archived"] += 1
        except Exception as error:  # Keep the raw import manifest auditable on one-file failures.
            entry["included"] = False
            entry["error"] = f"archive failed: {type(error).__name__}: {str(error)[:240]}"
            counters["skipped"] += 1
            errors.append({"path": relative, "reason": entry["error"]})
        else:
            counters["included"] += 1
            counters["bytes"] += size
            total_bytes += size
            by_kind[kind] = by_kind.get(kind, 0) + 1
        files.append(entry)

    git = _git_snapshot(root)
    git_errors = [str(item) for item in git.get("errors", []) if item]
    if git_errors:
        errors.extend({"path": ".git", "reason": item} for item in git_errors)
    errors_truncated = len(errors) > 1000
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "local-project-import",
        "projectId": project,
        "projectRoot": str(root),
        "createdAt": _now(),
        "git": git,
        "files": files,
        "fileCounts": {**counters, "byKind": dict(sorted(by_kind.items()))},
        "sourceFingerprint": _source_fingerprint(files),
        "limits": {
            "maxFileBytes": max_file_bytes,
            "maxTotalBytes": max_total_bytes,
            "maxFiles": max_files,
            "maxFilesScope": "examined non-ignored entries, including skipped entries",
            "limitReached": limit_reached,
        },
        "errors": errors[:1000],
        "errorCount": len(errors),
        "errorsTruncated": errors_truncated,
        "complete": not errors and not limit_reached,
        "limitations": [
            "输入项目仅做文件读取，不执行构建脚本、测试脚本或依赖安装。",
            "默认跳过 .git、node_modules、构建产物、缓存和疑似凭据文件。",
            "Git 状态是采集时快照；未连接远程仓库，也不证明工作区内容已提交。",
            "凭据过滤仅基于文件名；不能保证任意源文件或示例配置不含敏感内容。",
            "文件逐个读取，不是整个工作区的原子快照；已存在的清单输出不会被覆盖。",
        ],
    }
    _atomic_json(output_path, manifest)
    return manifest


def _is_utf8(payload: bytes) -> bool:
    try:
        payload.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="要导入的本地项目目录")
    parser.add_argument("--output", type=Path, default=None, help="导入清单输出路径")
    parser.add_argument("--archive-root", type=Path, default=None, help="不可变原始归档根目录")
    parser.add_argument("--project-id", default=None)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    args = parser.parse_args(argv)
    try:
        report = import_project(
            args.path, output=args.output, archive_root=args.archive_root,
            project_id=args.project_id, max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes, max_files=args.max_files,
        )
    except (OSError, ValueError) as error:
        print(f"项目导入失败：{error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "output": str((args.output or Path(args.path) / "work" / "project-import.json").resolve()),
        "projectId": report["projectId"], "complete": report["complete"],
        "files": report["fileCounts"], "errors": report["errorCount"],
    }, ensure_ascii=False))
    return 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
