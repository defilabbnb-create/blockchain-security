#!/usr/bin/env python3
"""Collect a pinned, dependency-free Ethernaut vulnerability subset.

The upstream tests and attack contracts are retained as provenance metadata;
they are not treated as a successful local exploit until our own runner emits
dynamic evidence.
"""
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
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "training-data" / "ethernaut"
REPO = "OpenZeppelin/ethernaut"
COMMIT = "c6174bb3b68dde01ff15571e67ad5254cc6939a9"
LICENSE = "MIT"
LICENSE_PATH = "LICENSE"
LICENSE_SHA256 = "f61964c4ee238d4798b6bf7f961ace16926bc06f3d525333fc732e1b7bdb51a3"

CHALLENGES = {
    "fallback": {
        "vulnerabilityType": "fallback_owner_takeover",
        "attack": "Make a small contribution, then send ether through receive() to become owner and withdraw the balance.",
        "targetPath": "contracts/contracts/levels/Fallback.sol",
        "attackPath": None,
        "promptPath": "client/src/gamedata/en/descriptions/levels/fallback.md",
        "harnessPath": "contracts/test/levels/Fallback.test.js",
        "testPattern": r"it\('should allow the player to solve the level'",
    },
    "telephone": {
        "vulnerabilityType": "tx_origin_authorization",
        "attack": "Call changeOwner through an intermediate contract so tx.origin differs from msg.sender.",
        "targetPath": "contracts/contracts/levels/Telephone.sol",
        "attackPath": "contracts/contracts/attacks/TelephoneAttack.sol",
        "promptPath": "client/src/gamedata/en/descriptions/levels/telephone.md",
        "harnessPath": "contracts/test/levels/Telephone.test.js",
        "testPattern": r"it\('should allow the player to solve the level'",
    },
    "coinflip": {
        "vulnerabilityType": "predictable_block_randomness",
        "attack": "Reuse blockhash-derived state in the same block context to predict the boolean coin flip.",
        "targetPath": "contracts/contracts/levels/CoinFlip.sol",
        "attackPath": "contracts/contracts/attacks/CoinFlipAttack.sol",
        "promptPath": "client/src/gamedata/en/descriptions/levels/coinflip.md",
        "harnessPath": "contracts/test/levels/CoinFlip.test.js",
        "testPattern": r"it\('should allow the player to solve the level'",
    },
    "force": {
        "vulnerabilityType": "forced_ether_selfdestruct",
        "attack": "Deploy a payable helper and selfdestruct it into a target with no payable entry point.",
        "targetPath": "contracts/contracts/levels/Force.sol",
        "attackPath": "contracts/contracts/attacks/ForceAttack.sol",
        "promptPath": "client/src/gamedata/en/descriptions/levels/force.md",
        "harnessPath": "contracts/test/levels/Force.test.js",
        "testPattern": r"it\('should allow the player to solve the level'",
    },
    "king": {
        "vulnerabilityType": "denial_of_service_push_payment",
        "attack": "Become king with a contract that rejects the next payment, permanently blocking the push-based crown transfer.",
        "targetPath": "contracts/contracts/levels/King.sol",
        "attackPath": "contracts/contracts/attacks/KingAttack.sol",
        "promptPath": "client/src/gamedata/en/descriptions/levels/king.md",
        "harnessPath": "contracts/test/levels/King.test.js",
        "testPattern": r"it\('should allow the player to solve the level'",
    },
}


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
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


def safe_path(value: object) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("unsafe_repository_path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("unsafe_repository_path")
    return path.as_posix()


def request_bytes(path: str, timeout: float) -> bytes:
    path = safe_path(path)
    url = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{quote(path, safe='/')}"
    request = Request(url, headers={"User-Agent": "defi-scan-ethernaut-corpus"})
    with urlopen(request, timeout=timeout) as response:
        body = response.read(4_000_001)
    if len(body) > 4_000_000:
        raise ValueError("source_exceeds_4mb_limit")
    return body


def object_path(content: bytes, suffix: str = ".sol") -> str:
    digest = sha256(content)
    path = CORPUS / "objects" / digest[:2] / f"{digest}{suffix}"
    if path.exists() and sha256(path.read_bytes()) != digest:
        raise ValueError("existing_content_address_collision")
    if not path.exists():
        atomic_write(path, content)
    return str(path.relative_to(ROOT))


def metadata(challenge: str, kind: str, path: str, content: bytes) -> dict:
    suffix = Path(path).suffix or ".txt"
    destination = CORPUS / "metadata" / challenge / f"{kind}{suffix}"
    atomic_write(destination, content)
    return {"path": path, "sha256": sha256(content), "bytes": len(content),
            "metadataPath": str(destination.relative_to(ROOT))}


def collect_one(challenge: str, spec: dict, timeout: float) -> dict:
    paths = [spec["targetPath"], spec["promptPath"], spec["harnessPath"], LICENSE_PATH]
    if spec["attackPath"]:
        paths.append(spec["attackPath"])
    fetched = {safe_path(path): request_bytes(path, timeout) for path in paths}
    license_bytes = fetched[LICENSE_PATH]
    if sha256(license_bytes) != LICENSE_SHA256 or not license_bytes.startswith(b"The MIT License"):
        raise ValueError("pinned_license_does_not_match_expected_mit")
    harness_text = fetched[spec["harnessPath"]].decode("utf-8")
    if not re.search(spec["testPattern"], harness_text):
        raise ValueError("challenge_test_entry_missing")
    target = fetched[spec["targetPath"]]
    pragma = sorted(set(match.decode("ascii") for match in re.findall(rb"pragma\s+solidity\s+([^;]+);", target)))
    sources = [{"path": spec["targetPath"], "sourceUrl": f"https://github.com/{REPO}/blob/{COMMIT}/{spec['targetPath']}",
                "sha256": sha256(target), "bytes": len(target), "objectPath": object_path(target)}]
    if spec["attackPath"]:
        attack = fetched[spec["attackPath"]]
        sources.append({"path": spec["attackPath"], "sourceUrl": f"https://github.com/{REPO}/blob/{COMMIT}/{spec['attackPath']}",
                        "sha256": sha256(attack), "bytes": len(attack), "objectPath": object_path(attack)})
        pragma.extend(match.decode("ascii") for match in re.findall(rb"pragma\s+solidity\s+([^;]+);", attack))
    source_bundle = sha256("".join(f"{row['path']}:{row['sha256']}\n" for row in sources).encode())
    return {"status": "collected", "dataset": "ethernaut", "repo": REPO, "commit": COMMIT,
            "sourceLicense": LICENSE, "sourceUrl": f"https://github.com/{REPO}/tree/{COMMIT}",
            "challenge": challenge, "vulnerabilityType": spec["vulnerabilityType"], "attack": spec["attack"],
            "compilerPragmas": sorted(set(pragma)), "sourceBundleSha256": source_bundle, "sourceFiles": sources,
            "prompt": metadata(challenge, "prompt", spec["promptPath"], fetched[spec["promptPath"]]),
            "harness": {**metadata(challenge, "harness", spec["harnessPath"], fetched[spec["harnessPath"]]),
                        "testPattern": spec["testPattern"], "requiresExternalRpc": False,
                        "command": f"npx hardhat test --grep \"{challenge}\""},
            "license": {"path": LICENSE_PATH, "license": LICENSE, "sha256": sha256(license_bytes),
                        "bytes": len(license_bytes), "localPath": str((CORPUS / LICENSE_PATH).relative_to(ROOT))},
            "staticState": "not_run", "dynamicState": "not_run",
            "dynamicNotRunReason": "upstream_test_and_attack_are_provenance_only; local evidence runner has not executed this sample",
            "decompilerState": "not_run"}


def collect(*, challenges: list[str] | None = None, workers: int = 5, timeout: float = 25.0) -> dict:
    selected = list(challenges or CHALLENGES)
    if not selected or any(item not in CHALLENGES for item in selected) or len(set(selected)) != len(selected):
        raise ValueError("challenges_must_be_a_non_empty_unique_allowlist")
    workers = min(workers, len(selected))
    if isinstance(workers, bool) or not 1 <= workers <= 16:
        raise ValueError("workers_must_be_in_1_16")
    failures, results = [], []
    try:
        license_bytes = request_bytes(LICENSE_PATH, timeout)
        if sha256(license_bytes) != LICENSE_SHA256:
            raise ValueError("pinned_license_does_not_match_expected_mit")
        atomic_write(CORPUS / LICENSE_PATH, license_bytes)
    except (OSError, ValueError, HTTPError, URLError, TimeoutError) as error:
        failures.append({"status": "failed", "dataset": "ethernaut", "repo": REPO, "commit": COMMIT,
                         "failureReason": f"license:{type(error).__name__}:{str(error)[:240]}"})
    if not failures:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ethernaut-collect") as pool:
            pending = {pool.submit(collect_one, item, CHALLENGES[item], timeout): item for item in selected}
            for future in as_completed(pending):
                challenge = pending[future]
                try:
                    results.append(future.result())
                except (OSError, ValueError, HTTPError, URLError, TimeoutError) as error:
                    failures.append({"status": "failed", "dataset": "ethernaut", "repo": REPO,
                                     "commit": COMMIT, "challenge": challenge,
                                     "failureReason": f"{type(error).__name__}:{str(error)[:240]}"})
    results.sort(key=lambda row: row["challenge"])
    manifest = {"schemaVersion": 1, "generatedAt": datetime.now(timezone.utc).isoformat(),
                "dataset": "ethernaut", "repo": REPO, "commit": COMMIT, "sourceLicense": LICENSE,
                "licensePath": LICENSE_PATH, "workerCount": workers, "challengeAllowlist": selected,
                "candidateCount": len(selected), "collectedCount": len(results), "failedCount": len(failures),
                "samples": results, "failures": failures,
                "sourcePolicy": "Pinned Ethernaut commit and explicit target/attack/test allowlist; tests do not imply local exploit confirmation.",
                "trainingPolicy": "Keep source, attack, prompt and evidence separate; only a completed local PoC promotes dynamicState."}
    atomic_write(CORPUS / "manifest.json", (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode())
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", action="append", dest="challenges", choices=tuple(CHALLENGES))
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args(argv)
    try:
        manifest = collect(challenges=args.challenges, workers=args.workers, timeout=args.timeout)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({"manifest": str(CORPUS / "manifest.json"), "candidateCount": manifest["candidateCount"],
                      "collectedCount": manifest["collectedCount"], "failedCount": manifest["failedCount"],
                      "workerCount": manifest["workerCount"]}, ensure_ascii=False))
    return 0 if manifest["candidateCount"] == manifest["collectedCount"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
