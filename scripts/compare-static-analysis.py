#!/usr/bin/env python3
"""Compare stable analyzer summaries, ignoring execution and per-scenario timing.

This checks report summaries and semantic detector identity, not companion trace
files. Equal partial graphs retain their reported coverage limits.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile

_spec=importlib.util.spec_from_file_location("equivalence_review_static",Path(__file__).with_name("review-static.py"))
_static=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_static)
semantic_finding_fingerprint=_static.semantic_finding_fingerprint

def validate_report(report):
    if not isinstance(report, dict):
        raise ValueError("report")
    state = report.get("state")
    if state not in ("completed", "partial"):
        raise ValueError("report.state")
    compiler = report.get("compiler")
    if not isinstance(compiler, str) or not compiler.strip():
        raise ValueError("report.compiler")
    compilerProvenance = report.get("compilerProvenance")
    if not isinstance(compilerProvenance, dict):
        raise ValueError("report.compilerProvenance")
    contracts = report.get("contracts")
    if type(contracts) is not int or contracts < 0:
        raise ValueError("report.contracts")
    detectors = report.get("detectors")
    if type(detectors) is not int or detectors < 0:
        raise ValueError("report.detectors")
    if contracts == 0 or detectors == 0:
        raise ValueError("report.contracts or report.detectors")
    findingCount = report.get("findingCount")
    if type(findingCount) is not int or findingCount < 0:
        raise ValueError("report.findingCount")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("report.findings")
    if findingCount != len(findings):
        raise ValueError("report.findingCount vs report.findings")
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            raise ValueError(f"report.findings[{i}]")
    findingSemanticFingerprint = report.get("findingSemanticFingerprint")
    if not isinstance(findingSemanticFingerprint, str):
        raise ValueError("report.findingSemanticFingerprint")
    if len(findingSemanticFingerprint) != 64:
        raise ValueError("report.findingSemanticFingerprint length")
    if not re.match(r'^[0-9a-f]+$', findingSemanticFingerprint):
        raise ValueError("report.findingSemanticFingerprint hex")
    if findingSemanticFingerprint != semantic_finding_fingerprint(findings):
        raise ValueError("report.findingSemanticFingerprint mismatch")
    verifiedSourceFingerprint = report.get("verifiedSourceFingerprint")
    if not isinstance(verifiedSourceFingerprint, str):
        raise ValueError("report.verifiedSourceFingerprint")
    if len(verifiedSourceFingerprint) != 64:
        raise ValueError("report.verifiedSourceFingerprint length")
    if not re.match(r'^[0-9a-f]+$', verifiedSourceFingerprint):
        raise ValueError("report.verifiedSourceFingerprint hex")
    verifiedDependencyFingerprint = report.get("verifiedDependencyFingerprint")
    if "verifiedDependencyFingerprint" in report:
        if not isinstance(verifiedDependencyFingerprint, str):
            raise ValueError("report.verifiedDependencyFingerprint")
        if len(verifiedDependencyFingerprint) != 64:
            raise ValueError("report.verifiedDependencyFingerprint length")
        if not re.match(r'^[0-9a-f]+$', verifiedDependencyFingerprint):
            raise ValueError("report.verifiedDependencyFingerprint hex")
    staticStages = report.get("staticStages")
    if not isinstance(staticStages, dict):
        raise ValueError("report.staticStages")
    if staticStages.get("compile") != "completed":
        raise ValueError("report.staticStages.compile")
    if staticStages.get("detectors") != "completed":
        raise ValueError("report.staticStages.detectors")
    if staticStages.get("callGraph") not in ("completed", "partial"):
        raise ValueError("report.staticStages.callGraph")
    callGraph = report.get("callGraph")
    if not isinstance(callGraph, dict):
        raise ValueError("report.callGraph")
    if callGraph.get("state") != staticStages.get("callGraph"):
        raise ValueError("report.callGraph.state vs report.staticStages.callGraph")
    localTests = report.get("localTests")
    if not isinstance(localTests, dict):
        raise ValueError("report.localTests")
    if not isinstance(localTests.get("state"), str) or not localTests["state"]:
        raise ValueError("report.localTests.state")
    if localTests["state"] not in ("passed", "not_performed"):
        raise ValueError("report.localTests.state incomplete or failed")
    return findingSemanticFingerprint

def _stable_local_tests(local):
    out = {k: v for k, v in local.items() if k not in ("report", "verifiedDependencySource")}
    if isinstance(out.get("results"), list):
        out["results"] = [
            {k: v for k, v in r.items() if k != "durationMs"} if isinstance(r, dict) else r
            for r in out["results"]
        ]
    return out

def compare_reports(left, right):
    validate_report(left)
    validate_report(right)
    if ("verifiedDependencyFingerprint" in left) != ("verifiedDependencyFingerprint" in right):
        raise ValueError("verifiedDependencyFingerprint asymmetric presence")
    stable_keys = ["state", "compiler", "compilerProvenance", "contracts", "detectors", "findingCount", "verifiedSourceFingerprint", "staticStages"]
    check_results = []
    for k in stable_keys:
        if left.get(k) != right.get(k):
            check_results.append({"name": k, "pass": False})
        else:
            check_results.append({"name": k, "pass": True})
    left_fingerprint = semantic_finding_fingerprint(left.get("findings"))
    right_fingerprint = semantic_finding_fingerprint(right.get("findings"))
    if left_fingerprint != right_fingerprint:
        check_results.append({"name": "findingSemanticFingerprint", "pass": False})
    else:
        check_results.append({"name": "findingSemanticFingerprint", "pass": True})
    left_call_graph = {k: v for k, v in left.get("callGraph", {}).items() if k != "report"}
    right_call_graph = {k: v for k, v in right.get("callGraph", {}).items() if k != "report"}
    if left_call_graph != right_call_graph:
        check_results.append({"name": "callGraph", "pass": False})
    else:
        check_results.append({"name": "callGraph", "pass": True})
    left_local_tests = _stable_local_tests(left["localTests"])
    right_local_tests = _stable_local_tests(right["localTests"])
    if left_local_tests != right_local_tests:
        check_results.append({"name": "localTests", "pass": False})
    else:
        check_results.append({"name": "localTests", "pass": True})
    check_results.append({"name": "verifiedDependencyFingerprint", "pass": left.get("verifiedDependencyFingerprint") == right.get("verifiedDependencyFingerprint")})
    return {"equivalent": all(c["pass"] for c in check_results), "checks": check_results, "fingerprints": {"left": left_fingerprint, "right": right_fingerprint}}

def _atomic_json(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temp = Path(handle.name)
            handle.write(text + "\n")
        os.replace(temp, path)
        temp = None
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    output_safe = False
    try:
        if args.output is not None:
            for source in (args.left, args.right):
                if args.output.resolve() == source.resolve() or (args.output.exists() and source.exists() and args.output.samefile(source)):
                    raise ValueError("output must not overwrite either input")
        output_safe = True
        with args.left.open(encoding="utf-8") as handle:
            left = json.load(handle)
        with args.right.open(encoding="utf-8") as handle:
            right = json.load(handle)
        result = compare_reports(left, right)
        code = 0 if result["equivalent"] else 1
    except (OSError, ValueError, TypeError, RecursionError) as error:
        result = {"equivalent": False, "error": str(error)}
        code = 2
    text = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if args.output is not None and output_safe:
        try:
            _atomic_json(args.output, text)
        except OSError as error:
            text = json.dumps({"equivalent": False, "error": str(error)}, sort_keys=True, separators=(",", ":"))
            code = 2
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
