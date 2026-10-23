#!/usr/bin/env python3
"""Verify benchmark source files against immutable GitHub commit URLs."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "benchmark" / "contracts"
OUTPUT = ROOT / "benchmark" / "source-verification.json"
MAX_SOURCE_BYTES = 2_000_000


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _raw_url(source: object) -> str | None:
    if not isinstance(source, str):
        return None
    parsed = urlparse(source)
    parts = [part for part in parsed.path.split("/") if part]
    if (parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or len(parts) < 5
            or parts[2] != "blob" or not __import__("re").fullmatch(r"[a-f0-9]{40}", parts[3])):
        return None
    return f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{parts[3]}/{'/'.join(parts[4:])}"


def _fetch(url: str, timeout: float) -> bytes:
    request = Request(url, headers={"User-Agent": "defi-scan-benchmark-source-verifier/1"})
    with urlopen(request, timeout=timeout) as response:
        final = urlparse(response.geturl())
        if final.scheme != "https" or final.netloc.lower() not in {"raw.githubusercontent.com", "github.com"}:
            raise ValueError("source_redirect_left_github")
        value = response.read(MAX_SOURCE_BYTES + 1)
    if len(value) > MAX_SOURCE_BYTES:
        raise ValueError("source_exceeds_size_limit")
    return value


def verify_case(case_dir: Path, fetch=_fetch, timeout: float = 20.0) -> dict:
    truth_path = case_dir / "ground-truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    source_name = truth.get("sourceFile")
    if not isinstance(source_name, str) or not source_name or Path(source_name).name != source_name:
        return {"caseId": case_dir.name, "state": "invalid", "reason": "invalid_source_file"}
    source_path = (case_dir / source_name).resolve()
    if case_dir.resolve() not in source_path.parents or not source_path.is_file():
        return {"caseId": case_dir.name, "state": "invalid", "reason": "source_path_outside_case"}
    local = source_path.read_bytes()
    local_hash = _sha256(local)
    raw_url = _raw_url(truth.get("source"))
    if raw_url is None:
        return {"caseId": case_dir.name, "state": "synthetic_local_fixture", "source": truth.get("source"),
                "sourceSha256": local_hash, "remoteContentVerified": False}
    try:
        remote = fetch(raw_url, timeout)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        return {"caseId": case_dir.name, "state": "unavailable", "source": truth["source"],
                "rawUrl": raw_url, "sourceSha256": local_hash, "remoteContentVerified": False,
                "reason": f"{type(error).__name__}:{str(error)[:240]}"}
    remote_hash = _sha256(remote)
    matches = remote_hash == local_hash
    return {"caseId": case_dir.name, "state": "verified" if matches else "mismatch",
            "source": truth["source"], "rawUrl": raw_url, "sourceSha256": local_hash,
            "remoteContentSha256": remote_hash, "remoteContentVerified": matches,
            "byteLength": len(local), "reason": None if matches else "local_source_differs_from_pinned_commit"}


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def verify_all(contracts_dir: Path = CONTRACTS, output: Path = OUTPUT, *, jobs: int = 6,
               timeout: float = 20.0, fetch=_fetch) -> dict:
    if isinstance(jobs, bool) or not 1 <= jobs <= 16 or timeout <= 0:
        raise ValueError("invalid_verification_limits")
    case_dirs = sorted(path for path in contracts_dir.iterdir()
                       if path.is_dir() and (path / "ground-truth.json").is_file())
    rows = []
    with ThreadPoolExecutor(max_workers=min(jobs, max(1, len(case_dirs))),
                            thread_name_prefix="source-verification") as pool:
        futures = {pool.submit(verify_case, case_dir, fetch, timeout): case_dir.name for case_dir in case_dirs}
        for future in as_completed(futures):
            try:
                rows.append(future.result())
            except (OSError, json.JSONDecodeError, TypeError) as error:
                rows.append({"caseId": futures[future], "state": "invalid",
                             "reason": f"{type(error).__name__}:{str(error)[:240]}"})
    rows.sort(key=lambda row: row["caseId"])
    counts = {state: sum(row["state"] == state for row in rows)
              for state in ("verified", "mismatch", "unavailable", "synthetic_local_fixture", "invalid")}
    report = {"schemaVersion": 1, "generatedAt": datetime.now(timezone.utc).isoformat(),
              "sampleCount": len(rows), "summary": counts,
              "method": "HTTPS raw content fetched from immutable GitHub commit URL and compared byte-for-byte by SHA-256",
              "samples": rows}
    _atomic_json(output, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts", type=Path, default=CONTRACTS)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args(argv)
    try:
        report = verify_all(args.contracts, args.output, jobs=args.jobs, timeout=args.timeout)
    except (OSError, ValueError) as error:
        print(json.dumps({"state": "failed", "reason": f"{type(error).__name__}:{str(error)[:240]}"}, ensure_ascii=False))
        return 2
    print(json.dumps({"report": str(args.output.resolve()), "sampleCount": report["sampleCount"],
                      "summary": report["summary"]}, ensure_ascii=False))
    return 0 if report["summary"]["mismatch"] == report["summary"]["unavailable"] == report["summary"]["invalid"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
