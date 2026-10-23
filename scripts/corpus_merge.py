#!/usr/bin/env python3
"""带 flock 的离线语料单写者；校验分片后合并各层，保留其他层和历史证据。"""
from __future__ import annotations

import argparse
from collections import Counter
import fcntl
import json
import os
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from corpus_shards import SHARDS, ROOT, atomic_json, digest, now, owns_key, sample_id, validate_shard

MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"


def summary(samples: list[dict], previous: dict) -> dict:
    result = dict(previous)
    rows = [sample.get("analysis", {}) for sample in samples]
    for layer, states in {"static": {"Passed": {"passed"}, "Partial": {"partial"}, "Failed": {"failed", "unavailable"}},
                          "dynamic": {"Passed": {"passed"}, "Failed": {"failed", "unavailable"},
                                      "Unconfirmed": {"unconfirmed"}, "NotRun": {"not_run"},
                                      "HarnessNotFeasible": {"harness_not_feasible"}, "Flaky": {"flaky"}},
                          "decompiler": {"Completed": {"completed"}, "Partial": {"partial"},
                                         "Failed": {"failed", "unavailable"}, "NotRun": {"not_run"}}}.items():
        for suffix, values in states.items():
            result[layer + suffix] = sum(row.get(layer) in values for row in rows)
    result["dynamicConfirmed"] = sum(row.get("confirmedVulnerability") is True for row in rows)
    return result


def active_shard_files(shard_dir: Path) -> list[Path]:
    """列出待合并的活跃分片，排除归档目录。

    归档有两种落点：标准位置 ``work/corpus-shard-history/<sampleId>/``，
    以及泳道目录下的 ``history/`` 子目录。归档是失败与历史证据的保留区，
    不是待合并的输入；把它当成分片会因文件名格式不同而中断整批合并。
    """
    paths = []
    for path in sorted(shard_dir.rglob("*.json")):
        relative = path.relative_to(shard_dir)
        if any(part == "history" for part in relative.parts[:-1]):
            continue
        paths.append(path)
    return paths


def merge(manifest_path: Path = MANIFEST, shard_dir: Path = SHARDS, root: Path = ROOT) -> dict:
    manifest_path, shard_dir, root = Path(manifest_path), Path(shard_dir), Path(root)
    with manifest_path.with_suffix(".merge.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("samples"), list):
            raise ValueError("主 manifest schema 无效")
        by_id = {sample_id(row): row for row in manifest["samples"]}
        if len(by_id) != len(manifest["samples"]):
            raise ValueError("主 manifest 存在重复样本身份")
        pending = []
        for path in active_shard_files(shard_dir):
            encoded = path.read_bytes()
            shard = json.loads(encoded)
            validate_shard(shard)
            if path.name != f"{shard['sampleId']}.{shard['layer']}.json":
                raise ValueError("分片文件名与身份不匹配")
            sample = by_id.get(shard["sampleId"])
            if sample is None or sample.get("sha256") != shard["sourceSha256"]:
                raise ValueError(f"分片源码绑定不匹配: {path.name}")
            source = (root / sample["objectPath"]).resolve()
            if not source.is_relative_to(root.resolve()) or digest(source.read_bytes()) != shard["sourceSha256"]:
                raise ValueError(f"源码对象哈希不匹配: {path.name}")
            prior = sample.get("analysisProvenance", {}).get(shard["layer"], {})
            shard_hash = digest(encoded)
            if prior.get("shardSha256") == shard_hash:
                continue
            if prior.get("generatedAt", "") > shard["generatedAt"]:
                continue
            pending.append((sample, shard, shard_hash))
        # 所有分片先通过校验才修改内存并写盘，坏分片不能造成半批次合并。
        counts = Counter()
        for sample, shard, shard_hash in pending:
            layer = shard["layer"]
            analysis = sample.setdefault("analysis", {})
            for key in list(analysis):
                if owns_key(layer, key):
                    del analysis[key]
            analysis.update(shard["analysis"])
            sample.setdefault("analysisProvenance", {})[layer] = {
                key: shard[key] for key in ("sourceSha256", "generatedAt", "laneId", "toolVersions")}
            sample["analysisProvenance"][layer]["shardSha256"] = shard_hash
            counts[layer] += 1
        if pending:
            manifest["analysisSummary"] = summary(manifest["samples"], manifest.get("analysisSummary", {}))
            manifest["corpusMergedAt"] = now()
            archive = root / "work/corpus-manifest-history" / f"{uuid.uuid4().hex}.json"
            atomic_json(archive, json.loads(manifest_bytes))
            atomic_json(manifest_path, manifest)
        return {"schemaVersion": 1, "laneId": "0", "generatedAt": now(),
                "toolVersions": {"corpus_merge": "1", "python": sys.version.split()[0]},
                "mergedShards": len(pending), "layers": dict(counts), "sampleCount": len(by_id),
                "manifestSha256": digest(manifest_path.read_bytes()),
                "analysisSummary": manifest.get("analysisSummary", {})}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--shards", type=Path, default=SHARDS)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if os.environ.get("CORPUS_DEFER_MERGE") == "1":
        print(json.dumps({"schemaVersion": 1, "state": "deferred",
                          "reason": "CORPUS_DEFER_MERGE=1", "manifestModified": False},
                         ensure_ascii=False))
        return 0
    result = merge(args.manifest, args.shards, args.root)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
