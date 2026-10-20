"""Build and cache linked source, bytecode and decompiler representations."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from decompiler_semantics import extract_semantics
from ir_reconcile import reconcile
from repr_cache import ARTIFACT_NAMES, cache_key, get_or_build, source_bundle_sha256


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _check_digest(name: str, value: str | None, expected: str | None) -> str | None:
    if expected is None:
        return value
    if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    if value != expected:
        raise ValueError(f"{name}_sha256_mismatch")
    return value


def _envelope(document: dict | None, *, kind: str, source_digest: str, digest: str | None) -> dict:
    if document is None:
        return {"schemaVersion": 1, "state": "not_available", "representation": kind,
                "sourceBundleSha256": source_digest, "representationSha256": None, "document": None}
    # Preserve an explicitly declared representation label (for example the
    # canonical source bundle used by the lightweight local adapter) while
    # keeping the outer envelope hash-bound to the verified source bundle.
    label = document.get("representation", kind) if isinstance(document, dict) else kind
    return {"schemaVersion": 1, "state": "available", "representation": label,
            "sourceBundleSha256": source_digest, "representationSha256": digest, "document": document}


def build_representations(source_bundle: dict, *, source_ir: dict | None = None,
                          bytecode_ir: dict | None = None, decompiler_input: Any = None,
                          source_sha256: str | None = None, source_ir_sha256: str | None = None,
                          bytecode_ir_sha256: str | None = None, decompiler_input_sha256: str | None = None,
                          solc_version: str | None = None, compile_settings: dict | None = None,
                          cache_root: str | Path | None = None, contract: str | None = None) -> dict:
    """Create four hash-bound cache artifacts; missing optional inputs stay explicit."""
    if not isinstance(source_bundle, dict):
        raise ValueError("source_bundle must be an object")
    computed_source_digest = source_bundle_sha256(source_bundle)
    _check_digest("source_bundle", computed_source_digest, source_sha256)
    compilation = source_bundle.get("compilation") or {}
    version = solc_version or compilation.get("compilerVersion") or "unknown"
    settings = compile_settings
    if settings is None:
        settings = ((source_bundle.get("stdJsonInput") or {}).get("settings") or
                    (source_bundle.get("metadata") or {}).get("settings") or {})
    key = cache_key(computed_source_digest, version, settings)
    source_ir_digest = _check_digest("source_ir", _sha256(source_ir) if source_ir is not None else None, source_ir_sha256)
    bytecode_digest = _check_digest("bytecode_ir", _sha256(bytecode_ir) if bytecode_ir is not None else None, bytecode_ir_sha256)
    decompiler_digest = _check_digest("decompiler_input", _sha256(decompiler_input) if decompiler_input is not None else None,
                                     decompiler_input_sha256)

    def build() -> dict[str, dict]:
        source_document = source_ir or {
            "representation": "source_bundle",
            "sourceBundle": source_bundle,
            "semanticsProven": False,
            "limitations": ["Compiler IR is unavailable; this artifact contains verified source only."],
        }
        source_artifact = _envelope(source_document, kind="unified_source_ir", source_digest=computed_source_digest,
                                    digest=source_ir_digest or computed_source_digest)
        bytecode_artifact = _envelope(bytecode_ir, kind="unified_bytecode_ir", source_digest=computed_source_digest,
                                      digest=bytecode_digest)
        if decompiler_input is None:
            decompiled_doc = None
            decompiled_digest = None
        else:
            decompiled_doc = extract_semantics(decompiler_input)
            decompiled_digest = decompiled_doc["inputSha256"]
        decompiled_artifact = _envelope(decompiled_doc, kind="decompiler_semantics", source_digest=computed_source_digest,
                                        digest=decompiled_digest)
        if source_ir is None or bytecode_ir is None:
            reconciliation = {"schemaVersion": 1, "state": "not_available", "contract": contract,
                              "sourceBundleSha256": computed_source_digest,
                              "sourceIrSha256": source_ir_digest, "bytecodeIrSha256": bytecode_digest,
                              "unresolved": {"reason": "source or bytecode IR is missing"},
                              "confirmedVulnerability": False}
        else:
            reconciliation = reconcile(source_ir, bytecode_ir, source_sha256=computed_source_digest, contract=contract)
            reconciliation["state"] = "completed"
        reconciliation.update({"sourceBundleSha256": computed_source_digest,
                               "sourceRepresentationSha256": source_ir_digest,
                               "bytecodeRepresentationSha256": bytecode_digest,
                               "decompilerInputSha256": decompiler_digest})
        return {"source-ir.json": source_artifact, "bytecode-ir.json": bytecode_artifact,
                "decompiled.json": decompiled_artifact, "ir-reconciliation.json": reconciliation}

    cached = get_or_build(key, build, cache_root=Path(cache_root) if cache_root else ROOT / "work" / "repr-cache",
                          inputs={"sourceBundleSha256": computed_source_digest, "solcVersion": version,
                                  "compileSettingsCanonicalJson": settings,
                                  "sourceIrSha256": source_ir_digest, "bytecodeIrSha256": bytecode_digest,
                                  "decompilerInputSha256": decompiler_digest},
                          tool_versions={"representationPipelineSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
                          required_artifacts=ARTIFACT_NAMES)
    return {"state": "completed", "cacheKey": key, "cacheHit": cached["cacheHit"],
            "cachePath": str(Path(cache_root) / key if cache_root else ROOT / "work" / "repr-cache" / key),
            "sourceBundleSha256": computed_source_digest,
            "artifacts": {name: json.loads(raw.decode("utf-8")) for name, raw in cached["artifacts"].items()},
            "artifactSha256": cached["meta"]["artifactsSha256"], "semanticsProven": False}
