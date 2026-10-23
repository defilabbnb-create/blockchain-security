#!/usr/bin/env python3
"""Collect a small, pinned Damn Vulnerable DeFi challenge subset.

The challenge tests in the upstream repository are intentionally solution
templates.  This collector therefore records the local Foundry entry point
without claiming that a dynamic exploit has passed.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import tempfile
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "training-data" / "damn-vulnerable-defi"
REPO = "theredguild/damn-vulnerable-defi"
COMMIT = "64fddf9f96de2782f8868898d68673acb295119c"
LICENSE = "MIT"
LICENSE_PATH = "LICENSE"
LICENSE_SHA256 = "ed4450f0d63ff98ad63473635714117a9bfa2ba1175768b0163f76c3f1425468"
SOURCE_URL = f"https://github.com/{REPO}/tree/{COMMIT}"

# Gitlink SHAs read from `lib/*` in COMMIT. Import prefixes are kept as
# compiler source-unit names; repository paths are only used to fetch bytes.
DEPENDENCIES = {
    "@openzeppelin/contracts/": {
        "repo": "OpenZeppelin/openzeppelin-contracts",
        "commit": "acd4ff74de833399287ed6b31b4debf6b2b35527",
        "license": "MIT",
        "licensePath": "LICENSE",
        "repoPrefix": "contracts/",
        "expectedLicensePrefix": b"The MIT License",
    },
    "solady/": {
        "repo": "vectorized/solady",
        "commit": "77b41d04aa0aa80d6c455d8c9a379ae067ab4c98",
        "license": "MIT",
        "licensePath": "LICENSE.txt",
        "repoPrefix": "src/",
        "expectedLicensePrefix": b"MIT License",
    },
    "solmate/": {
        "repo": "transmissions11/solmate",
        "commit": "97bdb2003b70382996a79a406813f76417b1cf90",
        "license": "AGPL-3.0-only",
        "licensePath": "LICENSE",
        "repoPrefix": "src/",
        "expectedLicensePrefix": b"GNU AFFERO GENERAL PUBLIC LICENSE",
    },
}
FIRST_PARTY_DEPENDENCIES = {"src/DamnValuableToken.sol"}
IMPORT_PATTERN = re.compile(r"\bimport\s+(?:[^;]*?\bfrom\s+)?[\"']([^\"']+)[\"']\s*;")

# These are deliberately explicit.  A recursive tree walk could accidentally
# import a fixed solution, a test-only helper, or a dependency as the target.
CHALLENGES = {
    "side-entrance": {
        "vulnerabilityType": "side_entrance_flash_loan_accounting",
        "attack": "Deposit during the flash-loan callback to satisfy the lender's balance check, then withdraw the credited deposit.",
        "sourcePaths": ["src/side-entrance/SideEntranceLenderPool.sol"],
        "promptPath": "src/side-entrance/README.md",
        "harnessPath": "test/side-entrance/SideEntrance.t.sol",
        "testName": "test_sideEntrance",
    },
    "naive-receiver": {
        "vulnerabilityType": "unrestricted_flash_loan_receiver_fee_drain",
        "attack": "Use the permissionless flash-loan path to charge the receiver a fee repeatedly without receiver-owner authorization.",
        "sourcePaths": [
            "src/naive-receiver/BasicForwarder.sol",
            "src/naive-receiver/FlashLoanReceiver.sol",
            "src/naive-receiver/Multicall.sol",
            "src/naive-receiver/NaiveReceiverPool.sol",
        ],
        "promptPath": "src/naive-receiver/README.md",
        "harnessPath": "test/naive-receiver/NaiveReceiver.t.sol",
        "testName": "test_naiveReceiver",
    },
    "truster": {
        "vulnerabilityType": "arbitrary_target_call_in_flash_loan",
        "attack": "Pass an attacker-controlled target and calldata to make the pool approve the attacker, then transfer the pool's tokens away.",
        "sourcePaths": ["src/truster/TrusterLenderPool.sol"],
        "promptPath": "src/truster/README.md",
        "harnessPath": "test/truster/Truster.t.sol",
        "testName": "test_truster",
    },
}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
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


def _safe_repo_path(value: object) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("unsafe_repository_path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("unsafe_repository_path")
    return path.as_posix()


def _request_bytes(url: str, timeout: float) -> bytes:
    request = Request(url, headers={"User-Agent": "defi-scan-dvd-corpus"})
    with urlopen(request, timeout=timeout) as response:
        body = response.read(4_000_001)
    if len(body) > 4_000_000:
        raise ValueError("source_exceeds_4mb_limit")
    return body


def _raw_url(path: str) -> str:
    return f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{quote(path, safe='/')}"


def _source_object(content: bytes) -> str:
    digest = _sha256_bytes(content)
    output = CORPUS / "objects" / digest[:2] / f"{digest}.sol"
    if output.exists() and _sha256_bytes(output.read_bytes()) != digest:
        raise ValueError("existing_content_address_collision")
    if not output.exists():
        _atomic_write(output, content)
    try:
        return str(output.relative_to(ROOT))
    except ValueError:
        return str(output)


def _metadata_path(challenge: str, kind: str, source_path: str) -> Path:
    suffix = "".join(Path(source_path).suffixes) or ".txt"
    return CORPUS / "metadata" / challenge / f"{kind}{suffix}"


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _fetch_file(path: str, timeout: float) -> bytes:
    safe = _safe_repo_path(path)
    return _request_bytes(_raw_url(safe), timeout)


def _source_unit_imports(source: bytes) -> list[str]:
    text = source.decode("utf-8")
    # Preserve quoted import strings while masking comments, so commented-out
    # imports cannot expand the pinned dependency allowlist.
    comments = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')
    masked = comments.sub(lambda match: re.sub(r"[^\n]", " ", match.group())
                          if match.group().startswith(("//", "/*")) else match.group(), text)
    return IMPORT_PATTERN.findall(masked)


def _resolve_source_unit(importer: str, import_path: str) -> str:
    if import_path.startswith("."):
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(importer), import_path))
    else:
        resolved = import_path
    return _safe_repo_path(resolved)


def _dependency_location(source_unit: str) -> tuple[str, dict, str] | None:
    for prefix, dependency in DEPENDENCIES.items():
        if source_unit.startswith(prefix):
            relative = source_unit[len(prefix):]
            return dependency["repo"], dependency, _safe_repo_path(dependency["repoPrefix"] + relative)
    if source_unit in FIRST_PARTY_DEPENDENCIES:
        return REPO, {"commit": COMMIT, "license": LICENSE}, source_unit
    return None


def _fetch_source_unit(source_unit: str, timeout: float) -> tuple[bytes, dict]:
    location = _dependency_location(source_unit)
    if location is None:
        raise ValueError(f"import_outside_pinned_dependency_allowlist:{source_unit}")
    repo, dependency, repo_path = location
    commit = dependency["commit"]
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(repo_path, safe='/')}"
    content = _request_bytes(url, timeout)
    if not content or b"\x00" in content:
        raise ValueError(f"empty_or_binary_dependency:{source_unit}")
    return content, {"repo": repo, "commit": commit, "path": repo_path, "url": url,
                     "license": dependency["license"]}


def _dependency_license(repo: str, dependency: dict, timeout: float) -> dict:
    commit = dependency["commit"]
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{dependency['licensePath']}"
    content = _request_bytes(url, timeout)
    if not content.lstrip().startswith(dependency["expectedLicensePrefix"]):
        raise ValueError(f"pinned_dependency_license_mismatch:{repo}")
    digest = _sha256_bytes(content)
    local = CORPUS / "licenses" / repo.lower().replace("/", "__") / commit / dependency["licensePath"]
    _atomic_write(local, content)
    return {"repo": repo, "commit": commit, "license": dependency["license"],
            "path": dependency["licensePath"], "url": url, "sha256": digest,
            "bytes": len(content), "localPath": _display_path(local)}


def _materialize_analysis_bundle(challenge: str, spec: dict, source_units: dict[str, bytes],
                                 source_origins: dict[str, dict]) -> dict:
    bundle_dir = CORPUS / "bundles" / challenge
    bundle_files = []
    targets = {}
    for source_unit, content in sorted(source_units.items()):
        local = bundle_dir / source_unit
        _atomic_write(local, content)
        digest = _sha256_bytes(content)
        bundle_files.append({"sourceUnit": source_unit, "path": _display_path(local),
                             "sha256": digest, "bytes": len(content),
                             "dependency": source_unit not in spec["sourcePaths"]})
        if source_unit in spec["sourcePaths"]:
            text = content.decode("utf-8")
            contracts = re.findall(r"\b(?:abstract\s+)?(?:contract|library)\s+([A-Za-z_$][A-Za-z0-9_$]*)", text)
            if contracts:
                targets[source_unit] = contracts[0]
    if not targets:
        raise ValueError("analysis_bundle_has_no_contract_targets")
    source_bundle_sha256 = _sha256_bytes("".join(
        f"{source_unit}:{_sha256_bytes(content)}\n" for source_unit, content in sorted(source_units.items())
    ).encode())
    analysis_input = {
        "schemaVersion": 1,
        "sources": {source_unit: {"content": content.decode("utf-8")}
                    for source_unit, content in sorted(source_units.items())},
        "metadata": {"settings": {"compilationTarget": targets}},
        "compilation": {"compilerVersion": "0.8.25",
                         "compilerSettings": {"optimizer": {"enabled": True, "runs": 200}}},
    }
    input_path = bundle_dir / "static-input.json"
    input_bytes = (json.dumps(analysis_input, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    _atomic_write(input_path, input_bytes)
    dependency_files = []
    for source_unit, content in sorted(source_units.items()):
        if source_unit in spec["sourcePaths"]:
            continue
        origin = source_origins[source_unit]
        dependency_files.append({
            "importPath": source_unit, "compilerSourceUnit": source_unit,
            "repo": origin["repo"], "commit": origin["commit"], "path": origin["path"],
            "sourceUrl": f"https://github.com/{origin['repo']}/blob/{origin['commit']}/{origin['path']}",
            "rawUrl": origin["url"], "license": origin["license"],
            "sha256": _sha256_bytes(content), "bytes": len(content),
            "objectPath": _source_object(content),
            "bundlePath": _display_path(bundle_dir / source_unit),
        })
    return {
        "directory": _display_path(bundle_dir),
        "inputPath": _display_path(input_path),
        "inputSha256": _sha256_bytes(input_bytes),
        "sourceBundleSha256": source_bundle_sha256,
        "sourceUnitCount": len(source_units),
        "targetCount": len(targets),
        "targets": targets,
        "files": bundle_files,
        "dependencyFiles": dependency_files,
    }


def _collect_challenge(challenge: str, spec: dict, timeout: float) -> dict:
    if challenge not in CHALLENGES:
        raise ValueError(f"unsupported_challenge:{challenge}")
    source_files = []
    fetched = {}
    source_units: dict[str, bytes] = {}
    source_origins: dict[str, dict] = {}
    paths = [*spec["sourcePaths"], spec["promptPath"], spec["harnessPath"], LICENSE_PATH]
    for path in paths:
        safe = _safe_repo_path(path)
        content = _fetch_file(safe, timeout)
        if not content or b"\x00" in content:
            raise ValueError(f"empty_or_binary_file:{safe}")
        fetched[safe] = content
        if safe in spec["sourcePaths"]:
            source_units[safe] = content

    prompt_content = fetched[spec["promptPath"]]
    harness_content = fetched[spec["harnessPath"]]
    license_content = fetched[LICENSE_PATH]
    if _sha256_bytes(license_content) != LICENSE_SHA256 or not license_content.startswith(b"The MIT License"):
        raise ValueError("pinned_license_does_not_match_expected_mit")
    harness_text = harness_content.decode("utf-8")
    if f"function {spec['testName']}()" not in harness_text:
        raise ValueError("challenge_test_entry_missing")
    template_pattern = rf"function\s+{re.escape(spec['testName'])}\s*\(\)\s+public[^{{]*\{{\s*\}}"
    template_only = re.search(template_pattern, harness_text) is not None
    compiler_pragmas = sorted({
        pragma.decode("ascii")
        for path in spec["sourcePaths"]
        for pragma in re.findall(rb"pragma\s+solidity\s+([^;]+);", fetched[path])
    })
    for path in spec["sourcePaths"]:
        if not path.startswith("src/") or not path.endswith(".sol"):
            raise ValueError(f"source_outside_src_allowlist:{path}")
        content = fetched[path]
        digest = _sha256_bytes(content)
        source_files.append({
            "path": path,
            "sourceUrl": f"https://github.com/{REPO}/blob/{COMMIT}/{path}",
            "rawUrl": _raw_url(path),
            "sha256": digest,
            "bytes": len(content),
            "objectPath": _source_object(content),
        })
    pending = list(source_units)
    scanned = set()
    while pending:
        importer = pending.pop(0)
        if importer in scanned:
            continue
        scanned.add(importer)
        for import_path in _source_unit_imports(source_units[importer]):
            source_unit = _resolve_source_unit(importer, import_path)
            if source_unit in source_units:
                continue
            content, origin = _fetch_source_unit(source_unit, timeout)
            source_units[source_unit] = content
            source_origins[source_unit] = origin
            pending.append(source_unit)
    dependency_repos = sorted({origin["repo"] for origin in source_origins.values() if origin["repo"] != REPO})
    dependency_licenses = []
    for repo in dependency_repos:
        dependency = next(item for item in DEPENDENCIES.values() if item["repo"] == repo)
        dependency_licenses.append(_dependency_license(repo, dependency, timeout))
    # First-party DVT code is from the same pinned DvD commit/license and needs
    # explicit provenance even though it is not a third-party submodule.
    for source_unit, content in source_units.items():
        if source_unit in spec["sourcePaths"]:
            continue
        if source_unit not in source_origins:
            location = _dependency_location(source_unit)
            if location is None:
                raise ValueError(f"source_origin_missing:{source_unit}")
            repo, dependency, repo_path = location
            source_origins[source_unit] = {"repo": repo, "commit": dependency["commit"],
                                           "path": repo_path,
                                           "url": f"https://raw.githubusercontent.com/{repo}/{dependency['commit']}/{quote(repo_path, safe='/')}",
                                           "license": dependency["license"]}
    for source_unit, origin in source_origins.items():
        if origin["repo"] == REPO and not any(item["repo"] == REPO for item in dependency_licenses):
            dependency_licenses.append({"repo": REPO, "commit": COMMIT, "license": LICENSE,
                                        "path": LICENSE_PATH, "url": f"https://github.com/{REPO}/blob/{COMMIT}/{LICENSE_PATH}",
                                        "sha256": _sha256_bytes(license_content), "bytes": len(license_content),
                                        "localPath": "training-data/damn-vulnerable-defi/LICENSE"})
    dependency_licenses.sort(key=lambda row: (row["repo"], row["commit"]))
    analysis_bundle = _materialize_analysis_bundle(challenge, spec, source_units, source_origins)
    source_bundle_sha256 = analysis_bundle["sourceBundleSha256"]
    prompt_meta = {
        "path": spec["promptPath"],
        "sha256": _sha256_bytes(prompt_content),
        "bytes": len(prompt_content),
        "metadataPath": _display_path(_metadata_path(challenge, "prompt", spec["promptPath"])),
    }
    harness_meta = {
        "path": spec["harnessPath"],
        "sha256": _sha256_bytes(harness_content),
        "bytes": len(harness_content),
        "metadataPath": _display_path(_metadata_path(challenge, "harness", spec["harnessPath"])),
    }
    _atomic_write(_metadata_path(challenge, "prompt", spec["promptPath"]), prompt_content)
    _atomic_write(_metadata_path(challenge, "harness", spec["harnessPath"]), harness_content)
    license_meta = {
        "path": LICENSE_PATH,
        "license": LICENSE,
        "sha256": _sha256_bytes(license_content),
        "bytes": len(license_content),
        "url": f"https://github.com/{REPO}/blob/{COMMIT}/{LICENSE_PATH}",
        "localPath": "training-data/damn-vulnerable-defi/LICENSE",
    }
    _atomic_write(CORPUS / "LICENSE", license_content)
    return {
        "status": "collected",
        "dataset": "damn-vulnerable-defi",
        "repo": REPO,
        "commit": COMMIT,
        "sourceLicense": LICENSE,
        "sourceUrl": SOURCE_URL,
        "challenge": challenge,
        "vulnerabilityType": spec["vulnerabilityType"],
        "attack": spec["attack"],
        "compilerPragmas": compiler_pragmas,
        "sourceBundleSha256": source_bundle_sha256,
        "sourceFiles": source_files,
        "dependencyFiles": analysis_bundle["dependencyFiles"],
        "dependencyLicenses": dependency_licenses,
        "analysisBundle": analysis_bundle,
        "prompt": prompt_meta,
        "harness": {
            **harness_meta,
            "testName": spec["testName"],
            "command": f"forge test --match-path {spec['harnessPath']} --match-test {spec['testName']}",
            "commandContext": f"{REPO}@{COMMIT}",
            "requiresExternalRpc": False,
            "templateOnly": template_only,
        },
        "license": license_meta,
        "staticState": "not_run",
        "dynamicState": "not_run",
        "dynamicNotRunReason": "upstream_harness_is_solution_template; exploit body is intentionally empty and must not be called a passing PoC" if template_only else "dynamic_execution_not_performed_by_collector",
        "decompilerState": "not_run",
    }


def collect(*, challenges: list[str] | None = None, workers: int = 3, timeout: float = 25.0) -> dict:
    selected = list(challenges or CHALLENGES)
    if not selected or any(challenge not in CHALLENGES for challenge in selected):
        raise ValueError("challenges must be a non-empty subset of the pinned allowlist")
    if len(set(selected)) != len(selected):
        raise ValueError("duplicate_challenge")
    if isinstance(workers, bool) or not 1 <= workers <= 16:
        raise ValueError("workers must be in [1, 16]")
    worker_count = min(workers, len(selected))
    results, failures = [], []
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="dvd-collect") as pool:
        pending = {pool.submit(_collect_challenge, challenge, CHALLENGES[challenge], timeout): challenge for challenge in selected}
        for future in as_completed(pending):
            challenge = pending[future]
            try:
                results.append(future.result())
            except (OSError, ValueError, HTTPError, URLError, TimeoutError) as error:
                failures.append({
                    "status": "failed", "dataset": "damn-vulnerable-defi", "repo": REPO,
                    "commit": COMMIT, "challenge": challenge,
                    "failureReason": f"{type(error).__name__}:{getattr(error, 'code', '')}:{str(error)[:240]}",
                })
    results.sort(key=lambda row: row["challenge"])
    manifest = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "dataset": "damn-vulnerable-defi",
        "repo": REPO,
        "commit": COMMIT,
        "sourceLicense": LICENSE,
        "licensePath": LICENSE_PATH,
        "sourcePolicy": "Pinned commit and explicit challenge/source allowlist; challenge tests are metadata only and never imply a verified exploit.",
        "challengeAllowlist": selected,
        "workerCount": worker_count,
        "candidateCount": len(selected),
        "collectedCount": len(results),
        "failedCount": len(failures),
        "samples": results,
        "failures": failures,
        "trainingPolicy": "Keep source, prompt, harness and dynamic evidence separate; only a completed local PoC may promote dynamicState to confirmed.",
    }
    _atomic_write(CORPUS / "manifest.json", (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode())
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", action="append", dest="challenges", choices=tuple(CHALLENGES), help="repeat to select a pinned challenge (default: all three)")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args(argv)
    try:
        manifest = collect(challenges=args.challenges, workers=args.workers, timeout=args.timeout)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({"manifest": str(CORPUS / "manifest.json"), "candidateCount": manifest["candidateCount"], "collectedCount": manifest["collectedCount"], "failedCount": manifest["failedCount"], "workerCount": manifest["workerCount"]}, ensure_ascii=False))
    return 0 if manifest["candidateCount"] == manifest["collectedCount"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
