#!/usr/bin/env python3
"""Run bounded static checks over the pinned local GitHub Solidity corpus."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from corpus_shards import write_shard, provenance as evidence_provenance
MANIFEST = ROOT / "training-data/github-vulnerabilities/manifest.json"
ANALYZER = ROOT / "scripts/review-static.py"
CATALOG = ROOT / "work/compiler-cache/list.json"
EVIDENCE_ROOT = ROOT / "training-data/github-vulnerabilities/evidence"
BENCHMARK_ROOT = ROOT / "benchmark/contracts"


def _load_benchmark_compiler_pins() -> dict[tuple[str, str, str], str]:
    """Load explicit compiler pins from local benchmark ground truth files."""
    pins: dict[tuple[str, str, str], str] = {}
    for path in sorted(BENCHMARK_ROOT.glob("*/ground-truth.json")):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        version = row.get("solcVersion")
        source_url = row.get("source")
        commit = row.get("datasetCommit")
        if not (isinstance(version, str) and re.fullmatch(r"0\.\d+\.\d+", version)
                and isinstance(source_url, str) and isinstance(commit, str)):
            continue
        marker = f"/blob/{commit}/"
        if marker not in source_url:
            continue
        prefix, source_path = source_url.split(marker, 1)
        repo = prefix.removeprefix("https://github.com/").strip("/")
        if repo and source_path:
            pins[(repo, commit, source_path)] = version
    return pins


BENCHMARK_COMPILER_PINS = _load_benchmark_compiler_pins()

# A no-pragma source cannot be assigned a compiler version from its contents.
# Probe a small, deterministic set of historical releases and retain the
# attempts so a successful result is explicitly marked as an inference.
NO_PRAGMA_CANDIDATES = (
    "0.3.6", "0.3.5", "0.4.0", "0.4.9", "0.4.18", "0.4.25", "0.4.26",
    "0.5.17", "0.6.12", "0.7.6", "0.8.28",
)


def source_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version_key(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))


def strip_solidity_comments(source: str) -> str:
    """Remove comments without changing strings or line structure."""
    output: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char in ('"', "'"):
                state, quote = "string", char
                output.append(char)
            elif char == "/" and next_char == "/":
                state = "line_comment"
                output.extend((" ", " "))
                index += 1
            elif char == "/" and next_char == "*":
                state = "block_comment"
                output.extend((" ", " "))
                index += 1
            else:
                output.append(char)
        elif state == "line_comment":
            if char in "\r\n":
                output.append(char)
                state = "code"
            else:
                output.append(" ")
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                output.extend((" ", " "))
                state = "code"
                index += 1
            else:
                output.append(char if char in "\r\n" else " ")
        else:  # string literal
            output.append(char)
            if char == "\\" and next_char:
                output.append(next_char)
                index += 1
            elif char == quote:
                state = "code"
        index += 1
    return "".join(output)


def _matches_comparator(version: tuple[int, int, int], operator: str, bound: tuple[int, int, int]) -> bool:
    if operator == "=":
        return version == bound
    if operator == ">=":
        return version >= bound
    if operator == ">":
        return version > bound
    if operator == "<=":
        return version <= bound
    if operator == "<":
        return version < bound
    if operator in {"^", "~"}:
        if version < bound:
            return False
        major, minor, patch = bound
        upper = ((major + 1, 0, 0) if operator == "^" and major else
                 (0, minor + 1, 0) if operator == "^" and minor else
                 (0, 0, patch + 1) if operator == "^" else
                 (major, minor + 1, 0))
        return version < upper
    raise ValueError(f"unsupported Solidity pragma operator: {operator}")


def _parse_pragma_version(token: str) -> tuple[tuple[int, int, int], tuple[int, int, int] | None]:
    """Parse full, partial, or wildcard Solidity versions into a bound and upper limit."""
    normalized = token.strip().lower()
    parts = normalized.split(".")
    if not 1 <= len(parts) <= 3 or any(part == "" for part in parts):
        raise ValueError("unsupported Solidity version token")
    numbers: list[int] = []
    wildcard = False
    for part in parts:
        if part in {"x", "*"}:
            wildcard = True
            numbers.append(0)
        elif part.isdigit() and not wildcard:
            numbers.append(int(part))
        else:
            raise ValueError("unsupported Solidity version token")
    while len(numbers) < 3:
        numbers.append(0)
        wildcard = True
    lower = tuple(numbers)
    if len(parts) == 3 and not wildcard:
        return lower, None
    if len(parts) == 1:
        upper = (lower[0] + 1, 0, 0)
    else:
        upper = (lower[0], lower[1] + 1, 0)
    return lower, upper


def version_satisfies(version: str, expression: str) -> bool:
    """Evaluate Solidity's stable-release pragma syntax, including x/* shorthand."""
    candidate = version_key(version)
    for alternative in expression.split("||"):
        token_pattern = r"(\^|~|>=|<=|>|<|=)?\s*(\d+(?:\.(?:\d+|x|X|\*)){0,2})"
        matches = list(re.finditer(token_pattern, alternative))
        residue = re.sub(token_pattern, "", alternative)
        if not matches or re.sub(r"\s+", "", residue):
            continue
        constraints = []
        try:
            for match in matches:
                operator = match.group(1) or "="
                lower, upper = _parse_pragma_version(match.group(2))
                if operator == "=" and upper is not None:
                    constraints.append(lambda value, lo=lower, hi=upper: lo <= value < hi)
                elif upper is not None and operator not in {"^", "~"}:
                    raise ValueError("wildcard comparator is unsupported")
                elif operator in {"^", "~"}:
                    constraints.append(lambda value, op=operator, lo=lower: _matches_comparator(value, op, lo))
                else:
                    constraints.append(lambda value, op=operator, lo=lower: _matches_comparator(value, op, lo))
        except ValueError:
            continue
        if all(constraint(candidate) for constraint in constraints):
            return True
    return False


def infer_version(source: str, cached_versions: set[str], released_versions: set[str] | None = None) -> tuple[str | None, str]:
    expressions = re.findall(r"pragma\s+solidity\s+([^;]+);", strip_solidity_comments(source), re.I)
    if not expressions:
        return None, "pragma_missing"
    releases = released_versions or cached_versions
    compatible = [value for value in releases if all(version_satisfies(value, expression.strip()) for expression in expressions)]
    if not compatible:
        return None, "pragma_no_compatible_release" if len(expressions) == 1 else "pragma_constraints_intersection_empty"
    cached_compatible = [value for value in compatible if value in cached_versions]
    pool = cached_compatible or compatible
    exact = len(expressions) == 1 and re.fullmatch(r"\s*(\d+\.\d+\.\d+)\s*", expressions[0])
    if exact:
        return max(pool, key=version_key), "pragma_exact_cached" if cached_compatible else "pragma_exact"
    return max(pool, key=version_key), "pragma_range_cached" if cached_compatible else "pragma_range_download"


def compiler_candidates(source: str, cached_versions: set[str], released_versions: set[str],
                       pinned_version: str | None = None) -> tuple[list[str], str]:
    """Return deterministic compiler candidates and the provenance of selection."""
    if pinned_version is not None:
        if pinned_version not in released_versions:
            return [], "benchmark_pin_not_in_catalog"
        expressions = re.findall(r"pragma\s+solidity\s+([^;]+);", strip_solidity_comments(source), re.I)
        if expressions and not all(version_satisfies(pinned_version, expression.strip()) for expression in expressions):
            return [], "benchmark_pin_violates_pragma"
        return [pinned_version], "benchmark_pinned_cached" if pinned_version in cached_versions else "benchmark_pinned"
    version, reason = infer_version(source, cached_versions, released_versions)
    if version:
        expressions = re.findall(r"pragma\s+solidity\s+([^;]+);", strip_solidity_comments(source), re.I)
        compatible = [value for value in released_versions
                      if all(version_satisfies(value, expression.strip()) for expression in expressions)]
        # Exact pragmas have one valid candidate. For a range, keep a bounded
        # descending fallback list so a bad historical compiler build does not
        # make an otherwise compatible source look unscannable. The newest
        # compatible release from the official catalog is always retained,
        # even when the cache contains many older releases; a cached compiler
        # is preferred for the first attempt, but cache density must not hide
        # the best compatible remote fallback.
        if len(expressions) > 1 or not re.fullmatch(r"\s*(\d+\.\d+\.\d+)\s*", expressions[0]):
            cached = sorted((value for value in compatible if value in cached_versions), key=version_key, reverse=True)
            remote = sorted((value for value in compatible if value not in cached_versions), key=version_key, reverse=True)
            newest = max(compatible, key=version_key)
            ordered = []
            for value in (cached[:1] + [newest] + remote[:1] + cached[1:] + remote[1:]):
                if value not in ordered:
                    ordered.append(value)
            return ordered[:8], reason
        return [version], reason
    if reason != "pragma_missing":
        return [], reason
    candidates = [version for version in NO_PRAGMA_CANDIDATES if version in released_versions]
    # The matrix is intentionally ordered by historical compatibility rather
    # than cache state. A missing cache entry is downloaded and recorded by
    # the compiler helper; reordering by cache could hide an older source's
    # only compatible release.
    return candidates, "pragma_missing_matrix"


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def target_contract(source: str, path: str) -> str | None:
    """Resolve the compilation target contract name.

    Comments must be stripped first: a naive scan over the raw text matches
    English words inside comment prose (for example the word "with" in the
    DAO header comment), which yields a target contract that does not exist
    and makes the sample look uncompilable on every compiler.
    """
    code = strip_solidity_comments(source)
    for keyword in ("contract", "library", "interface"):
        names = re.findall(r"\b" + keyword + r"\s+([A-Za-z_$][A-Za-z0-9_$]*)", code)
        if names:
            return names[0]
    return None


def run_one(sample: dict, timeout: float, cached_versions: set[str], released_versions: set[str]) -> dict:
    object_path = ROOT / sample["objectPath"]
    previous = sample.get("analysis") if isinstance(sample.get("analysis"), dict) else {}
    result = dict(previous)
    for key in list(result):
        if key.startswith("static") or key in {"compilerVersion", "compilerSelection", "compilerCandidates",
                                                "compilerPinnedVersion", "compilerAttempts", "findingCount", "analysisState",
                                                "analysisOutputSha256", "analysisEvidence"}:
            result.pop(key, None)
    result.setdefault("dynamic", "not_run")
    result.setdefault("decompiler", "not_run")
    result.setdefault("dynamicReason", "training_corpus_has_no_target_specific_harness")
    result.setdefault("decompilerReason", "requires_verified_runtime_bytecode")
    result["static"] = "unavailable"
    attempts: list[dict] = []
    try:
        content = object_path.read_text(encoding="utf-8")
        digest = source_digest(object_path)
        if digest != sample.get("sha256"):
            result["staticReason"] = "source_hash_mismatch"
            return {**sample, "analysis": result}
        pin_key = (str(sample.get("repo") or ""), str(sample.get("commit") or ""), str(sample.get("path") or ""))
        pinned_version = BENCHMARK_COMPILER_PINS.get(pin_key)
        if pinned_version:
            result["compilerPinnedVersion"] = pinned_version
        candidates, versionReason = compiler_candidates(content, cached_versions, released_versions, pinned_version)
        contract = target_contract(content, sample.get("path", ""))
        if not candidates:
            result["staticReason"] = versionReason
            return {**sample, "analysis": result}
        if not contract:
            result["staticReason"] = "compilation_target_not_found"
            return {**sample, "analysis": result}
        for version in candidates:
            with tempfile.TemporaryDirectory(prefix="training-static-", dir=ROOT / "work") as temporary:
                bundle = Path(temporary) / "verified-source.json"
                bundle.write_text(json.dumps({
                    "schemaVersion": 1,
                    "sources": {sample["path"]: {"content": content}},
                    "metadata": {"settings": {"compilationTarget": {sample["path"]: contract}}},
                    "compilation": {"compilerVersion": version},
                }, ensure_ascii=False), encoding="utf-8")
                try:
                    completed = subprocess.run(["python3", str(ANALYZER), str(bundle)], cwd=ROOT,
                                               capture_output=True, text=True, timeout=timeout, check=False,
                                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                except subprocess.TimeoutExpired as error:
                    stdout = error.stdout.decode("utf-8", errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
                    stderr = error.stderr.decode("utf-8", errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
                    attempts.append({
                        "compilerVersion": version, "selection": versionReason,
                        "status": "failed", "state": "timeout", "reason": "analyzer_timeout",
                        "exitCode": None, "stdoutSha256": hashlib.sha256(stdout.encode()).hexdigest(),
                        "stderrSha256": hashlib.sha256(stderr.encode()).hexdigest(),
                        "payload": {}, "stdout": stdout, "stderr": stderr,
                    })
                    # A timeout on one candidate must not discard the rest of the
                    # fallback chain. Range pragmas deliberately emit several
                    # compatible releases, so a hanging build is exactly the case
                    # the next candidate exists to handle.
                    continue
                rows = [line for line in completed.stdout.splitlines() if line.strip().startswith("{")]
                try:
                    payload = json.loads(rows[-1]) if rows else {}
                except json.JSONDecodeError:
                    payload = {}
                state = payload.get("state")
                # A JSON payload is not proof that the analyzer completed
                # successfully. Slither wrappers can emit a final-looking
                # payload before exiting non-zero; the process status is part
                # of the evidence contract and must gate passed/partial.
                status = ("passed" if state == "completed" else "partial" if state == "partial" else "failed") if completed.returncode == 0 else "failed"
                reason = payload.get("reason") or payload.get("error")
                if not reason:
                    reason = payload.get("staticError") or payload.get("staticStages", {}).get("compile")
                if state == "partial" and (not reason or reason == "completed"):
                    stages = payload.get("staticStages") if isinstance(payload.get("staticStages"), dict) else {}
                    partial_stages = [name for name, stage in stages.items() if stage == "partial"]
                    reason = "partial_static_analysis" + (":" + ",".join(partial_stages) if partial_stages else "")
                if completed.returncode != 0:
                    exit_reason = f"analyzer_exit_{completed.returncode}"
                    if not reason or reason == "completed":
                        reason = exit_reason
                    elif not str(reason).startswith(exit_reason + ":"):
                        reason = f"{exit_reason}:{reason}"
                provenance = payload.get("compilerProvenance") if isinstance(payload.get("compilerProvenance"), dict) else {}
                attempts.append({
                    "compilerVersion": version, "selection": versionReason,
                    "compilerSha256": provenance.get("sha256"),
                    "compilerLongVersion": provenance.get("longVersion"),
                    "compilerBuild": provenance.get("build"),
                    "compilerCatalogSha256": provenance.get("catalogSha256"),
                    "status": status, "state": state, "reason": reason,
                    "exitCode": completed.returncode,
                    "stdoutSha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                    "stderrSha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
                    "payload": payload, "stdout": completed.stdout, "stderr": completed.stderr,
                })
                if status in {"passed", "partial"}:
                    break
        selected = next((attempt for attempt in attempts if attempt["status"] in {"passed", "partial"}), attempts[-1])
        result["static"] = selected["status"]
        result["staticReason"] = selected["reason"] or selected["state"] or "analyzer_failed"
        result["staticState"] = selected["state"]
        result["compilerVersion"] = selected["compilerVersion"]
        result["compilerSelection"] = selected["selection"]
        result["compilerCandidates"] = [attempt["compilerVersion"] for attempt in attempts]
        if pinned_version:
            result["compilerPinnedVersion"] = pinned_version
        result["compilerAttempts"] = [{key: value for key, value in attempt.items() if key not in {"payload", "stdout", "stderr"}}
                                       for attempt in attempts]
        payload = selected["payload"]
        result["findingCount"] = payload.get("findingCount") if isinstance(payload.get("findingCount"), int) else None
        result["analysisState"] = payload.get("state")
        result["analysisOutputSha256"] = selected["stdoutSha256"]
        evidence_path = EVIDENCE_ROOT / f"{digest}.json"
        _write_json_atomic(evidence_path, {
            **evidence_provenance(digest, "B", {"solc": selected["compilerVersion"], "analyzer": "review-static.py"}),
            "schemaVersion": 1, "sourceSha256": digest, "sourcePath": sample.get("path"),
            "repo": sample.get("repo"), "commit": sample.get("commit"),
            "selectedCompilerVersion": selected["compilerVersion"],
            "selection": selected["selection"], "attempts": attempts,
        })
        result["analysisEvidence"] = str(evidence_path.relative_to(ROOT))
        if len(attempts) > 1 and selected["status"] in {"passed", "partial"}:
            result["compilerFallbackUsed"] = True
    except subprocess.TimeoutExpired as error:
        result["static"] = "failed"
        result["staticReason"] = "analyzer_timeout"
        result["compilerAttempts"] = [{
            "compilerVersion": version,
            "selection": versionReason,
            "status": "failed",
            "state": "timeout",
            "reason": "analyzer_timeout",
            "exitCode": None,
            "stdoutSha256": hashlib.sha256((error.stdout or "").encode() if isinstance(error.stdout, str) else (error.stdout or b"")).hexdigest(),
            "stderrSha256": hashlib.sha256((error.stderr or "").encode() if isinstance(error.stderr, str) else (error.stderr or b"")).hexdigest(),
        }] if 'version' in locals() and 'versionReason' in locals() else []
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        result["static"] = "failed"
        result["staticReason"] = f"{type(error).__name__}:{str(error)[:200]}"
    return {**sample, "analysis": result}


def build_analysis_summary(samples: list[dict], *, catalog_versions: int,
                           cached_versions: int) -> dict:
    stage_rows = [item.get("analysis", {}) if isinstance(item.get("analysis"), dict) else {}
                  for item in samples]
    return {
        "compilerStrategy": "official-solc-bin-soljson; explicit benchmark compiler pins honored when pragma-compatible; pragma constraints intersected; bounded historical matrix only when pragma is missing; cached bytes preferred and SHA-256 verified",
        "compilerCatalogVersions": catalog_versions,
        "cachedCompilerVersions": cached_versions,
        "staticPassed": sum(row.get("static") == "passed" for row in stage_rows),
        "staticPartial": sum(row.get("static") == "partial" for row in stage_rows),
        "staticFailed": sum(row.get("static") in {"failed", "unavailable"} for row in stage_rows),
        "dynamicPassed": sum(row.get("dynamic") == "passed" for row in stage_rows),
        "dynamicFailed": sum(row.get("dynamic") in {"failed", "unavailable"} for row in stage_rows),
        "dynamicNotRun": sum(row.get("dynamic") == "not_run" for row in stage_rows),
        "dynamicConfirmed": sum(row.get("confirmedVulnerability") is True for row in stage_rows),
        "decompilerCompleted": sum(row.get("decompiler") == "completed" for row in stage_rows),
        "decompilerPartial": sum(row.get("decompiler") == "partial" for row in stage_rows),
        "decompilerFailed": sum(row.get("decompiler") in {"failed", "unavailable"} for row in stage_rows),
        "decompilerNotRun": sum(row.get("decompiler") == "not_run" for row in stage_rows),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--limit", type=int, default=0, help="limit samples for a bounded trial; zero means all")
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= 16 or args.timeout <= 0:
        raise SystemExit("workers must be 1..16 and timeout must be positive")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    cached = {Path(name).stem.removeprefix("soljson-v").split("+")[0] for name in
              (p.name for p in (ROOT / "work/compiler-cache").glob("soljson-*.cjs"))}
    released = set(catalog.get("releases", {}))
    samples = manifest.get("samples", [])
    if args.limit:
        if args.limit < 1:
            raise SystemExit("limit must be positive when provided")
        samples = samples[:args.limit]
    results = []
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="training-static") as pool:
        futures = [pool.submit(run_one, sample, args.timeout, cached, released) for sample in samples]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: (item.get("repo", ""), item.get("path", "")))
    if args.limit:
        by_id = {(item.get("repo"), item.get("commit"), item.get("path")): item for item in results}
        manifest["samples"] = [by_id.get((item.get("repo"), item.get("commit"), item.get("path")), item) for item in manifest.get("samples", [])]
    else:
        manifest["samples"] = results
    manifest["analysisGeneratedAt"] = datetime.now(timezone.utc).isoformat()
    manifest["analysisWorkers"] = args.workers
    manifest["analysisSummary"] = build_analysis_summary(
        manifest["samples"], catalog_versions=len(released), cached_versions=len(cached))
    # Only the corpus single-writer may update manifest.json. Each worker
    # result is published as a source-bound static shard first.
    tool_versions = {"analyzer": "review-static.py", "python": sys.version.split()[0]}
    for sample in results:
        analysis = sample.get("analysis") if isinstance(sample.get("analysis"), dict) else {}
        if analysis:
            write_shard(sample, "static", analysis, lane_id="0-static", tool_versions=tool_versions)
    merger = ROOT / "scripts" / "corpus_merge.py"
    merged = subprocess.run([sys.executable, str(merger)], cwd=ROOT, capture_output=True, text=True,
                            check=True, timeout=60)
    print(merged.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
