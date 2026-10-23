"""离线语料分片协议：执行器只写样本/层分片，主 manifest 由合并器写入。"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
SHARDS = ROOT / "work/corpus-shards"
LAYERS = {"static", "dynamic", "decompiler", "fetch"}
STATIC_KEYS = {"compilerVersion", "compilerSelection", "compilerCandidates", "compilerPinnedVersion",
               "compilerAttempts", "compilerFallbackUsed", "findingCount", "analysisState",
               "analysisOutputSha256", "analysisEvidence", "failureKind", "findingsSha256"}
DECOMPILER_KEYS = {"artifact", "artifactSha256", "bytecodeReport", "selectorComparison"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sample_id(sample: dict) -> str:
    identity = {key: sample.get(key) for key in ("repo", "commit", "path")}
    if any(not isinstance(value, str) or not value for value in identity.values()):
        raise ValueError("分片样本缺少 repo/commit/path")
    return digest(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode())


def owns_key(layer: str, key: str) -> bool:
    if layer == "static":
        return key.startswith("static") or key in STATIC_KEYS
    if layer == "dynamic":
        return key.startswith("dynamic") or key == "confirmedVulnerability"
    if layer == "decompiler":
        return key.startswith("decompiler") or key in DECOMPILER_KEYS
    return key.startswith("fetch")


def layer_patch(layer: str, analysis: dict) -> dict:
    return {key: value for key, value in analysis.items() if owns_key(layer, key)}


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate_shard(row: dict) -> None:
    if not isinstance(row, dict) or row.get("schemaVersion") != 1:
        raise ValueError("分片 schemaVersion 无效")
    if row.get("layer") not in LAYERS:
        raise ValueError("分片 layer 无效")
    if row.get("sampleId") != sample_id(row.get("identity", {})):
        raise ValueError("分片 sampleId 与身份不匹配")
    if not isinstance(row.get("sourceSha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", row["sourceSha256"]):
        raise ValueError("分片 sourceSha256 无效")
    if not isinstance(row.get("laneId"), str) or not row["laneId"]:
        raise ValueError("分片 laneId 缺失")
    if not isinstance(row.get("toolVersions"), dict) or not row["toolVersions"]:
        raise ValueError("分片 toolVersions 缺失")
    stamp = datetime.fromisoformat(str(row.get("generatedAt", "")).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("分片 generatedAt 必须包含时区")
    patch = row.get("analysis")
    if not isinstance(patch, dict) or not patch or any(not owns_key(row["layer"], key) for key in patch):
        raise ValueError("分片包含非本层字段或空 analysis")


def lane_shard_dir(lane_id: str, shard_root: Path = SHARDS) -> Path:
    lane_segment = re.sub(r"[^A-Za-z0-9_.-]+", "_", lane_id).strip("._")
    if not lane_segment:
        raise ValueError("分片 laneId 无效")
    return Path(shard_root) / lane_segment


def write_shard(sample: dict, layer: str, analysis: dict, *, lane_id: str,
                tool_versions: dict, shard_dir: Path | None = None) -> Path:
    row = {"schemaVersion": 1, "sampleId": sample_id(sample),
           "identity": {key: sample[key] for key in ("repo", "commit", "path")},
           "sourceSha256": sample.get("sha256"), "layer": layer,
           "analysis": layer_patch(layer, analysis), "laneId": lane_id,
           "toolVersions": tool_versions, "generatedAt": now()}
    validate_shard(row)
    shard_dir = lane_shard_dir(lane_id) if shard_dir is None else Path(shard_dir)
    shard_dir.mkdir(parents=True, exist_ok=True)
    path = shard_dir / f"{row['sampleId']}.{layer}.json"
    # 同一层同时重跑时也保留每次结果；不能用后一次通过覆盖失败证据。
    with path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        roots = [candidate for candidate in (shard_dir, *shard_dir.parents)
                 if candidate.name == "corpus-shards"]
        shard_root = roots[0] if roots else shard_dir
        history = shard_root.parent / "corpus-shard-history" / row["sampleId"]
        atomic_json(history / f"{layer}.{uuid.uuid4().hex}.json", row)
        atomic_json(path, row)
    return path


def provenance(source_sha256: str, lane_id: str, tool_versions: dict) -> dict:
    return {"sourceSha256": source_sha256, "laneId": lane_id,
            "toolVersions": tool_versions, "generatedAt": now()}
