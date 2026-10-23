#!/usr/bin/env python3
"""Run a Foundry command with one checksum-verified solc-js release."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Callable, Sequence

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "scripts" / "campaign-solc.cjs"


def _selection_module():
    """Load the corpus selector used by the normal analysis pipeline."""
    spec = importlib.util.spec_from_file_location(
        "forge_solc_training_selection", ROOT / "scripts" / "analyze-training-corpus.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_selection_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _released_versions(cache: Path) -> set[str]:
    """Read the official solc-bin release catalog from the local compiler cache.

    只读取 work/compiler-cache 下已缓存的 list.json，绝不联网：forge 桥接的 auto 模式
    必须与 review-static.py 的编译器加载器使用同一份发布目录，否则自动选版会与
    离线缓存不一致。缓存缺失时退回已缓存的 soljson 文件名推断出的版本集合。
    """
    catalog = cache / "list.json"
    if catalog.is_file():
        try:
            index = json.loads(catalog.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            index = {}
        releases = index.get("releases")
        if isinstance(releases, dict) and releases:
            return {version for version in releases if isinstance(version, str)}
    # 缓存无目录时，用已缓存的 soljson 文件名回推版本集合（同样是离线来源）。
    return {
        path.name.split("+", 1)[0].removeprefix("soljson-v")
        for path in cache.glob("soljson-v*.cjs")
    }


def _forge_root(forge_args: Sequence[str]) -> Path:
    """Resolve Foundry's project root from argv without interpreting shell text."""
    args = list(forge_args)
    for index, argument in enumerate(args):
        if argument == "--root" and index + 1 < len(args):
            return Path(args[index + 1]).expanduser().resolve()
        if argument.startswith("--root="):
            return Path(argument.split("=", 1)[1]).expanduser().resolve()
    return Path.cwd().resolve()


def _foundry_config(project_root: Path, forge_args: Sequence[str], forge: Path) -> dict:
    """Ask Foundry for the active source layout and profile."""
    command = [str(forge), "config", "--json", "--root", str(project_root)]
    args = list(forge_args)
    for index, argument in enumerate(args):
        if argument == "--profile" and index + 1 < len(args):
            command.extend(("--profile", args[index + 1]))
            break
        if argument.startswith("--profile="):
            command.extend(("--profile", argument.split("=", 1)[1]))
            break
    for index, argument in enumerate(args):
        if argument in {"--contracts", "-C"} and index + 1 < len(args):
            command.extend(("--contracts", args[index + 1]))
            break
        if argument.startswith("--contracts="):
            command.extend(("--contracts", argument.split("=", 1)[1]))
            break

    result = subprocess.run(command, cwd=Path.cwd(), capture_output=True, text=True,
                            check=False, timeout=20)
    if result.returncode != 0:
        raise ValueError("compiler_auto_foundry_config_failed")
    try:
        config = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("compiler_auto_foundry_config_invalid") from error
    if not isinstance(config, dict):
        raise ValueError("compiler_auto_foundry_config_invalid")
    return config


def _solidity_sources(project_root: Path, config: dict) -> list[tuple[Path, str]]:
    """Read Solidity sources from Foundry's configured compile roots."""
    ignored = {".git", "cache", "out", "node_modules", "artifacts", "broadcast"}
    roots: list[Path] = []
    for key in ("src", "test", "script"):
        value = config.get(key)
        if isinstance(value, str) and value:
            roots.append((project_root / value).resolve())
    libraries = config.get("libs")
    if isinstance(libraries, list):
        roots.extend((project_root / value).resolve() for value in libraries
                     if isinstance(value, str) and value)

    rows: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for source_root in roots:
        if not source_root.is_dir():
            continue
        for path in sorted(source_root.rglob("*.sol")):
            try:
                relative_path = path.relative_to(project_root)
            except ValueError:
                relative_path = path
            if path in seen or any(part in ignored for part in relative_path.parts):
                continue
            seen.add(path)
            try:
                if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                    continue
                rows.append((path, path.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError):
                continue
    return rows


def _auto_compiler_version(forge_args: Sequence[str], forge: Path,
                           config_loader: Callable[[Path, Sequence[str], Path], dict] = _foundry_config
                           ) -> tuple[str, str]:
    """Choose one compiler for a Foundry project from all Solidity pragmas."""
    project_root = _forge_root(forge_args)
    if not project_root.is_dir():
        raise ValueError("compiler_auto_project_root_missing")
    config = config_loader(project_root, forge_args, forge)
    sources = _solidity_sources(project_root, config)
    if not sources:
        raise ValueError("compiler_auto_no_solidity_sources")
    selector = _selection_module()
    source_text = "\n".join(content for _path, content in sources)
    cache = ROOT / "work" / "compiler-cache"
    cached = {path.name.split("+", 1)[0].removeprefix("soljson-v")
              for path in cache.glob("soljson-v*.cjs")}
    released = _released_versions(cache)
    version, reason = selector.infer_version(source_text, cached, released)
    if not version:
        raise ValueError(f"compiler_auto_selection_failed:{reason}")
    return version, reason


def _compiler(version: str):
    spec = importlib.util.spec_from_file_location("review_static_compiler", ROOT / "scripts" / "review-static.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.compiler(version)


def _find_forge(explicit: Path | None) -> Path:
    if explicit is not None:
        candidate = explicit.expanduser().resolve()
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise FileNotFoundError("forge_executable_unavailable")
        return candidate
    bundled = ROOT / "work" / "tools" / "forge"
    if bundled.is_file() and os.access(bundled, os.X_OK):
        return bundled
    found = shutil.which("forge")
    if found:
        return Path(found).resolve()
    raise FileNotFoundError("forge_executable_unavailable")


def run_with_solc(version: str, forge_args: Sequence[str], *, forge: Path | None = None,
                  compiler_loader: Callable[[str], tuple[Path, dict]] = _compiler,
                  config_loader: Callable[[Path, Sequence[str], Path], dict] = _foundry_config,
                  command_runner: Callable = subprocess.run) -> int:
    args = list(forge_args)
    if args and args[0] == "--":
        args.pop(0)
    if not args:
        raise ValueError("foundry_command_required")
    if any(arg == "--use" or arg.startswith("--use=") for arg in args):
        raise ValueError("do_not_override_selected_solc")

    selection = None
    forge_path = _find_forge(forge)
    if version.strip().lower() == "auto":
        version, selection = _auto_compiler_version(args, forge_path, config_loader)

    soljson, metadata = compiler_loader(version)
    command = [str(forge_path), *args, "--use", str(WRAPPER)]
    environment = os.environ.copy()
    if "--offline" not in args and environment.get("FOUNDRY_OFFLINE", "").lower() not in {"false", "0", "no"}:
        command.append("--offline")
    environment["CAMPAIGN_SOLJSON"] = str(Path(soljson).resolve())
    environment["CAMPAIGN_FOUNDRY_COMPAT"] = "1"
    environment.pop("SOLC_VERSION", None)

    provenance = {key: metadata.get(key) for key in
                  ("version", "longVersion", "build", "filename", "sha256", "catalogSha256")}
    if selection:
        provenance["selection"] = selection
    print(json.dumps({"event": "selected_solc", "compiler": provenance}, sort_keys=True), file=sys.stderr)
    # Preserve the caller's working directory so relative --root/--contracts
    # arguments retain Foundry's normal meaning outside this repository.
    result = command_runner(command, cwd=Path.cwd(), env=environment, check=False)
    return result.returncode


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler-version", required=True,
                        help="Solidity release, full build version, or auto pragma selection; for example 0.4.18 or 0.4.18+commit.9cf6e910")
    parser.add_argument("--forge", type=Path, help="Foundry executable; defaults to the bundled Forge")
    parser.add_argument("forge_args", nargs=argparse.REMAINDER,
                        help="Foundry command and arguments after --, for example test --root ./challenge")
    args = parser.parse_args(argv)
    try:
        return run_with_solc(args.compiler_version, args.forge_args, forge=args.forge)
    except (FileNotFoundError, ValueError, OSError, RuntimeError) as error:
        print(f"forge_with_solc_error:{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
