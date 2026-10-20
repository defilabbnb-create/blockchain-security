"""Local-only source collection and representation-cache pipeline stages."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in os.sys.path:
    os.sys.path.insert(0, str(SCRIPT_DIR))

from repr_cache import source_bundle_sha256
from representation_pipeline import build_representations


class SourceStageError(ValueError):
    pass


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _representation_input(value: Any, *, json_document: bool) -> Any:
    if value is None or isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        raise SourceStageError("representation_input_invalid")
    path = Path(value).expanduser()
    if path.is_file():
        raw = path.read_bytes()
        if json_document:
            return json.loads(raw.decode("utf-8"))
        return raw.decode("utf-8")
    if json_document:
        raise SourceStageError("representation_input_file_missing")
    return value


def _source_path(target: dict[str, Any]) -> Path:
    value = target.get("sourceBundlePath") or target.get("source")
    if not isinstance(value, str) or not value:
        raise SourceStageError("target_source_path_missing")
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_file():
        raise SourceStageError("target_source_not_file")
    if path.name == ".env" or path.name.startswith(".env."):
        raise SourceStageError("secret_source_path_rejected")
    return path


def _bundle(path: Path, raw: bytes) -> tuple[dict[str, Any], str]:
    digest = hashlib.sha256(raw).hexdigest()
    if path.suffix.lower() == ".sol":
        text = raw.decode("utf-8")
        match = re.search(r"pragma\s+solidity\s+[^;]*?(\d+\.\d+\.\d+)", text)
        if not match:
            raise SourceStageError("solidity_compiler_version_missing")
        name = path.name
        bundle = {"sources": {name: {"content": text}},
                  "compilation": {"compilerVersion": match.group(1)},
                  "metadata": {"settings": {"compilationTarget": {name: name.removesuffix(".sol")}}}}
    else:
        try:
            bundle = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SourceStageError("source_bundle_invalid_json") from error
        if not isinstance(bundle, dict) or not isinstance(bundle.get("sources"), dict) or not bundle["sources"]:
            raise SourceStageError("source_bundle_missing_sources")
        for name, entry in bundle["sources"].items():
            if not isinstance(name, str) or not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
                raise SourceStageError("source_bundle_invalid_entry")
        compilation = bundle.get("compilation")
        if not isinstance(compilation, dict) or not isinstance(compilation.get("compilerVersion"), str):
            raise SourceStageError("source_bundle_compiler_version_missing")
    return bundle, digest


def collect_source(target: dict[str, Any], stage_dir: str | Path) -> dict[str, Any]:
    root = Path(stage_dir).resolve()
    source = _source_path(target)
    raw = source.read_bytes()
    bundle, raw_digest = _bundle(source, raw)
    expected = target.get("sourceSha256") or target.get("sha256")
    if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected) or expected != raw_digest):
        raise SourceStageError("source_sha256_mismatch")
    canonical_digest = source_bundle_sha256(bundle)
    destination = (root / "source" / "verified-source.json").resolve()
    if not _inside(destination, root):
        raise SourceStageError("stage_output_path_escape")
    payload = json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    _atomic_write(destination, payload)
    return {"state": "completed", "sourcePath": str(destination), "sourceSha256": raw_digest,
            "sourceBundleSha256": canonical_digest, "sourceBytes": len(raw)}


def build_representation(target: dict[str, Any], stage_dir: str | Path) -> dict[str, Any]:
    root = Path(stage_dir).resolve()
    source_path = Path(target.get("sourcePath", "")).resolve()
    if not source_path.is_file():
        return {"state": "unavailable", "reason": "collected_source_missing"}
    try:
        bundle = json.loads(source_path.read_text(encoding="utf-8"))
        source_digest = source_bundle_sha256(bundle)
        version = bundle["compilation"]["compilerVersion"]
        settings = (bundle.get("stdJsonInput") or {}).get("settings") or (bundle.get("metadata") or {}).get("settings") or {}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"state": "unavailable", "reason": "collected_source_bundle_invalid"}
    try:
        source_ir = _representation_input(target.get("sourceIR", target.get("unifiedIR")), json_document=True)
        bytecode_ir = _representation_input(target.get("bytecodeIR"), json_document=True)
        decompiler_input = _representation_input(target.get("decompilerInput"), json_document=False)
        representation = build_representations(
            bundle,
            source_ir=source_ir,
            bytecode_ir=bytecode_ir,
            source_sha256=source_digest,
            source_ir_sha256=target.get("sourceIRSha256"),
            bytecode_ir_sha256=target.get("bytecodeIRSha256"),
            decompiler_input_sha256=target.get("decompilerInputSha256"),
            solc_version=version,
            compile_settings=settings,
            cache_root=target.get("reprCacheRoot") or (root.parent / "repr-cache"),
            contract=target.get("contract"),
        )
    except (OSError, ValueError, TypeError) as error:
        return {"state": "failed", "reason": f"repr_cache_error:{str(error)[:160] or type(error).__name__}"}
    artifact_paths = {name: str(Path(representation["cachePath"]) / name)
                      for name in representation["artifacts"]}
    states = {name: artifact.get("state") for name, artifact in representation["artifacts"].items()}
    return {"state": "completed", "cacheKey": representation["cacheKey"],
            "cacheHit": representation["cacheHit"], "sourceBundleSha256": source_digest,
            "artifactPath": artifact_paths["source-ir.json"], "artifactPaths": artifact_paths,
            "representationStates": states, "representationArtifactSha256": representation["artifactSha256"],
            "sourceIrSha256": representation["artifacts"]["source-ir.json"].get("representationSha256"),
            "bytecodeIrSha256": representation["artifacts"]["bytecode-ir.json"].get("representationSha256"),
            "decompilerInputSha256": representation["artifacts"]["decompiled.json"].get("representationSha256"),
            "semanticsProven": False}


def run_stage(stage: str, target: dict[str, Any], stage_dir: str | Path, mode: str) -> dict[str, Any]:
    if mode != "local":
        return {"state": "unavailable", "reason": "source_stage_requires_local_mode"}
    if stage == "collect":
        try:
            return collect_source(target, stage_dir)
        except (OSError, UnicodeDecodeError, SourceStageError) as error:
            if str(error) in {"target_source_path_missing", "target_source_not_file"}:
                return {"state": "unavailable", "reason": str(error)}
            return {"state": "failed", "reason": str(error)[:200]}
    if stage == "repr":
        return build_representation(target, stage_dir)
    return {"state": "unavailable", "reason": f"unsupported_source_stage:{stage}"}
